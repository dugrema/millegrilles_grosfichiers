use std::collections::HashMap;
use std::error::Error;
use std::time::Duration as std_Duration;
use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{DateTime, doc};
use millegrilles_common_rust::chiffrage_cle::InformationCle;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::DataChiffre;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, UpdateOptions};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::grosfichiers_constantes::*;

const CONST_MAX_RETRY: i64 = 5;
const CONST_LIMITE_BATCH: i64 = 1_000;
const CONST_EXPIRATION_SECS: i64 = 300;
const CONST_INTERVALLE_ENTRETIEN: u64 = 60;

const CONST_CHAMP_RETRY: &str = "retry";
const CONST_CHAMP_DATE_MAJ: &str = "date_maj";
const CHAMP_ETAT: &str = "etat";
const CHAMP_INSTANCES: &str = "instances";

#[async_trait]
pub trait JobHandler: MongoDao + GenerateurMessages + Sized {
    /// Nom de la collection ou se trouvent les jobs
    fn get_nom_collection(&self) -> &str;

    /// Retourne le nom du flag de la table GrosFichiers/versionFichiers pour ce type de job.
    fn get_nom_flag(&self) -> &str;

    /// Emettre un evenement de job disponible.
    /// 1 evenement emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job(&self) -> Result<(), Box<dyn Error>> {
        let visites = trouver_jobs_instances(self).await?;
        if let Some(visites) = visites {
            for instance in visites {
                self.emettre_trigger(instance).await?;
            }
        }
        Ok(())
    }

    /// Emet un evenement pour declencher le traitement pour une instance
    async fn emettre_trigger<I>(&self, instance: I) -> Result<(), Box<dyn Error>>
    where I: AsRef<str> + Send;

    async fn sauvegarder_job<Q,S,T,U,V>(&self, tuuid: Q, fuuid: S, user_id: U, mimetype: T,  instance: V)
        -> Result<(), Box<dyn Error>>
        where Q: AsRef<str> + Send, S: AsRef<str> + Send, T: AsRef<str> + Send, U: AsRef<str> + Send, V: AsRef<str> + Send
    {
        sauvegarder_job(self, tuuid, fuuid, user_id, mimetype, instance).await
    }

    /// Set le flag de traitement complete
    async fn set_flag<S,U>(&self, fuuid: S, user_id: U, valeur: bool) -> Result<(), Box<dyn Error>>
    where S: AsRef<str> + Send, U: AsRef<str> + Send {
        set_flag(self, fuuid, user_id, valeur).await
    }

    async fn entretien_loop(&self, limite_batch: Option<i64>, delai_entretien: Option<u64>) {

        let limite_batch = match limite_batch {
            Some(inner) => inner,
            None => CONST_LIMITE_BATCH
        };

        let delai_entretien = match delai_entretien {
            Some(inner) => inner,
            None => CONST_INTERVALLE_ENTRETIEN
        };

        loop {

            // Note : retirer jobs avec trop de retires fait au travers de ajouts_jobs_manquantes
            if let Err(e) = entretien_jobs(self, limite_batch).await {
                error!("traitement_jobs.JobHandler.entretien {} Erreur sur ajouter_jobs_manquantes : {:?}", self.get_nom_flag(), e);
            }

            sleep(std_Duration::new(delai_entretien, 0)).await;
            debug!("entretien Cycle entretien JobHandler {}", self.get_nom_flag());

        }
    }
}

#[derive(Deserialize)]
struct DocJob {
    visites: Option<HashMap<String, usize>>
}

/// Emet un trigger media image si au moins une job media est due.
pub async fn trouver_jobs_instances<M>(job_handler: &M) -> Result<Option<Vec<String>>, Box<dyn Error>>
    where M: JobHandler
{
    let doc_job: Option<DocJob> = {
        let mut filtre = doc! {
            CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING
        };
        let options = FindOneOptions::builder().projection(doc! {"instances": true}).build();
        let collection = job_handler.get_collection(job_handler.get_nom_collection())?;
        match collection.find_one(filtre, options).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        }
    };

    match doc_job {
        Some(inner) => {
            match inner.visites {
                Some(visites) => {
                    Ok(Some(visites.into_keys().collect()))
                },
                None => Ok(None)
            }
        },
        None => Ok(None)
    }
}

async fn set_flag<M,S,U>(job_handler: &M, fuuid: S, user_id: U, valeur: bool) -> Result<(), Box<dyn Error>>
    where M: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
{

    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();

    let filtre = doc!{
        CHAMP_USER_ID: user_id,
        CHAMP_FUUID: fuuid,
    };

    let collection_versions = job_handler.get_collection(NOM_COLLECTION_VERSIONS)?;

    // Set flag
    let ops = doc! {
        "$set": { job_handler.get_nom_flag(): valeur },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    debug!("set_flag {}={} : modifier table versions pour {}/{}", job_handler.get_nom_flag(), valeur, user_id, fuuid);
    collection_versions.update_one(filtre.clone(), ops, None).await?;

    match valeur {
        true => {
            debug!("set_flag supprimer job ({}) sur {}/{}", job_handler.get_nom_flag(), user_id, fuuid);

            // Set flag
            let ops = doc! {
                "$set": { job_handler.get_nom_flag(): true },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            collection_versions.update_one(filtre.clone(), ops, None).await?;

            // Retirer job
            let collection_jobs = job_handler.get_collection(job_handler.get_nom_collection())?;
            collection_jobs.delete_one(filtre, None).await?;
        },
        false => {
            // Rien a faire
            debug!("set_flag {} true : supprimer job sur {}/{} et modifier table versions", job_handler.get_nom_flag(), user_id, fuuid);
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct RowJobExpiree {
    fuuid: String,
    user_id: String,
}

// async fn retirer_jobs_expirees<M>(job_handler: &M) -> Result<(), Box<dyn Error>>
//     where M: JobHandler
// {
//     let collection_indexation = job_handler.get_collection(job_handler.get_nom_collection())?;
//
//     let filtre = doc! {
//         CONST_CHAMP_RETRY: {"$gte": CONST_MAX_RETRY}
//     };
//     let mut curseur = collection_indexation.find(filtre, None).await?;
//     while let Some(r) = curseur.next().await {
//         let row: RowJobExpiree = convertir_bson_deserializable(r?)?;
//         debug!("retirer_jobs_expirees Desactiver job expiree pour {}/{}, trop de retries", row.user_id, row.fuuid);
//         job_handler.set_flag(row.fuuid, row.user_id, true).await?;
//     }
//
//     Ok(())
// }

#[derive(Deserialize)]
struct RowVersionsIds {
    tuuid: String,
    fuuid: String,
    mimetype: String,
    user_id: String,
    visites: Option<HashMap<String, i64>>,
}

async fn entretien_jobs<M>(job_handler: &M, limite_batch: i64) -> Result<(), Box<dyn Error>>
    where M: JobHandler
{
    debug!("ajouter_jobs_manquantes Debut");

    let collection_versions = job_handler.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection_jobs = job_handler.get_collection(job_handler.get_nom_collection())?;
    let champ_flag_index = job_handler.get_nom_flag();

    // Reset jobs indexation avec start_date expire pour les reprendre immediatement
    {
        let filtre_start_expire = doc! {
            CHAMP_ETAT: VIDEO_CONVERSION_ETAT_RUNNING,
            CONST_CHAMP_DATE_MAJ: { "$lte": Utc::now() - Duration::seconds(CONST_EXPIRATION_SECS) },
        };
        let ops_expire = doc! {
            "$set": { CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING },
            "$unset": { CONST_CHAMP_DATE_MAJ: true },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        collection_jobs.update_many(filtre_start_expire, ops_expire, None).await?;
    }

    let mut curseur = {
        let opts = FindOptions::builder()
            // .hint(Hint::Name(String::from("flag_media_traite")))
            .sort(doc! {champ_flag_index: 1, CHAMP_CREATION: 1})
            .projection(doc!{CHAMP_TUUID: true, CHAMP_FUUID: true, CHAMP_MIMETYPE: true, CHAMP_USER_ID: true})
            .limit(limite_batch)
            .build();
        let filtre = doc! { champ_flag_index: false };
        debug!("traiter_indexation_batch filtre {:?}", filtre);
        collection_versions.find(filtre, Some(opts)).await?
    };

    while let Some(d) = curseur.next().await {
        let doc_version = d?;
        let version_mappe: RowVersionsIds = match convertir_bson_deserializable(doc_version) {
            Ok(inner) => inner,
            Err(e) => {
                warn!("traiter_indexation_batch Erreur mapping document : {:?} - SKIP", e);
                continue;
            }
        };

        let tuuid_ref = version_mappe.tuuid.as_str();
        let fuuid_ref = version_mappe.fuuid.as_str();
        let user_id = version_mappe.user_id.as_str();
        let mimetype_ref = version_mappe.mimetype.as_str();

        let filtre = doc!{CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};

        let job_existante: Option<BackgroundJob> = match collection_jobs.find_one(filtre.clone(), None).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        };

        if let Some(job) = job_existante {
            if job.index_retry > MEDIA_RETRY_LIMIT {
                warn!("traiter_indexation_batch Expirer indexation sur document user_id {} tuuid {} : {} retries",
                    user_id, tuuid_ref, job.index_retry);
                let ops = doc!{
                    "$set": {
                        champ_flag_index: true,
                        format!("{}_erreur", champ_flag_index): ERREUR_MEDIA_TOOMANYRETRIES,
                    }
                };
                collection_versions.update_one(filtre.clone(), ops, None).await?;
                collection_jobs.delete_one(filtre.clone(), None).await?;
                continue;
            }
        }

        // Creer ou mettre a jour la job
        if let Some(visites) = version_mappe.visites {
            for instance in visites.into_keys() {
                job_handler.sauvegarder_job(tuuid_ref, fuuid_ref, user_id, mimetype_ref, instance).await?;
            }
        }
    }

    Ok(())
}

async fn sauvegarder_job<M,Q,S,T,U,V>(job_handler: &M, tuuid: Q, fuuid: S, user_id: U, mimetype: T, instance: V)
    -> Result<(), Box<dyn Error>>
    where M: JobHandler,
          Q: AsRef<str> + Send, S: AsRef<str> + Send, T: AsRef<str> + Send,
          U: AsRef<str> + Send, V: AsRef<str> + Send
{
    // Creer ou mettre a jour la job
    let now = Utc::now();

    let tuuid = tuuid.as_ref();
    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();
    let mimetype = mimetype.as_ref();
    let instance = instance.as_ref();

    let filtre = doc!{CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid};

    let ops_job = doc! {
        "$setOnInsert": {
            CHAMP_TUUID: tuuid,
            CHAMP_FUUID: fuuid,
            CHAMP_USER_ID: user_id,
            CHAMP_MIMETYPE: mimetype,
            CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING,
            CONST_CHAMP_RETRY: 0,
            CHAMP_CREATION: &now,
        },
        "$addToSet": {
            CHAMP_INSTANCES: instance,
        },
        "$currentDate": {
            CHAMP_MODIFICATION: true,
            CONST_CHAMP_DATE_MAJ: true,
        }
    };
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let collection_jobs = job_handler.get_collection(job_handler.get_nom_collection())?;
    collection_jobs.update_one(filtre, ops_job, options).await?;

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct BackgroundJob {
    pub tuuid: String,
    pub fuuid: String,
    pub user_id: String,
    pub etat: i32,
    #[serde(rename="_mg-derniere-modification", skip_serializing)]
    pub date_modification: Value,
    pub index_start: Option<DateTime>,
    pub index_retry: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseJob {
    pub ok: bool,
    pub tuuid: String,
    pub fuuid: String,
    pub user_id: String,
    pub mimetype: String,
    pub metadata: DataChiffre,
    pub cle: InformationCle,
}
