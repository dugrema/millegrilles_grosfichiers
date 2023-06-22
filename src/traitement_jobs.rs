use std::collections::HashMap;
use std::error::Error;
use std::time::Duration as std_Duration;
use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, DateTime, doc};
use millegrilles_common_rust::chiffrage_cle::InformationCle;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::DataChiffre;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, UpdateOptions};
use millegrilles_common_rust::serde_json::{json, Value};
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
pub trait JobHandler: Clone + Sized + Sync {
    /// Nom de la collection ou se trouvent les jobs
    fn get_nom_collection(&self) -> &str;

    /// Retourne le nom du flag de la table GrosFichiers/versionFichiers pour ce type de job.
    fn get_nom_flag(&self) -> &str;

    /// Retourne l'action a utiliser dans le routage de l'evenement trigger.
    fn get_action_evenement(&self) -> &str;

    /// Emettre un evenement de job disponible.
    /// 1 evenement emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job<M>(&self, middleware: &M)
        where M: GenerateurMessages + MongoDao
    {
        let visites = match trouver_jobs_instances(middleware, self).await {
            Ok(visites) => match visites {
                Some(inner) => inner,
                None => {
                    debug!("JobHandler.emettre_evenements_job Aucune job pour {}", self.get_action_evenement());
                    return  // Rien a faire
                }
            },
            Err(e) => {
                error!("JobHandler.emettre_evenements_job Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
                return
            }
        };

        for instance in visites {
            self.emettre_trigger(middleware, instance).await;
        }
    }

    /// Emet un evenement pour declencher le traitement pour une instance
    async fn emettre_trigger<M,I>(&self, middleware: &M, instance: I)
    where M: GenerateurMessages, I: AsRef<str> + Send {
        let instance = instance.as_ref();

        let routage = RoutageMessageAction::builder(DOMAINE_NOM, self.get_action_evenement())
            .exchanges(vec![Securite::L2Prive])
            .partition(instance)
            .build();

        let message = json!({ "instance": instance });

        if let Err(e) = middleware.emettre_evenement(routage, &message).await {
            error!("JobHandler.emettre_trigger Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
        }
    }

    async fn sauvegarder_job<M,S,U,V>(
        &self, middleware: &M, fuuid: S, user_id: U, instance: V,
        champs_cles: HashMap<String, String>,
        parametres: Option<HashMap<String, Bson>>,
        emettre_trigger: bool
    )
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao,
              S: AsRef<str> + Send, U: AsRef<str> + Send, V: AsRef<str> + Send
    {
        let instance = instance.as_ref();
        sauvegarder_job(middleware, self, fuuid, user_id, instance, champs_cles, parametres).await?;
        if emettre_trigger {
            self.emettre_trigger(middleware, instance).await;
        }
        Ok(())
    }

    /// Set le flag de traitement complete
    async fn set_flag<M,S,U>(&self, middleware: &M, fuuid: S, user_id: U, valeur: bool) -> Result<(), Box<dyn Error>>
    where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
        set_flag(middleware, self, fuuid, user_id, valeur).await
    }

    /// Doit etre invoque regulierement pour generer nouvelles jobs, expirer vieilles, etc.
    async fn entretien<M>(&self, middleware: &M, limite_batch: Option<i64>)
        where M: GenerateurMessages + MongoDao
    {
        debug!("entretien Cycle entretien JobHandler {}", self.get_nom_flag());

        let limite_batch = match limite_batch {
            Some(inner) => inner,
            None => CONST_LIMITE_BATCH
        };

        // Note : retirer jobs avec trop de retires fait au travers de ajouts_jobs_manquantes
        if let Err(e) = entretien_jobs(middleware, self, limite_batch).await {
            error!("traitement_jobs.JobHandler.entretien {} Erreur sur ajouter_jobs_manquantes : {:?}", self.get_nom_flag(), e);
        }

        /// Emettre des triggers au besoin.
        self.emettre_evenements_job(middleware).await;
    }
}

#[derive(Deserialize)]
struct DocJob {
    instances: Option<Vec<String>>
}

/// Emet un trigger media image si au moins une job media est due.
pub async fn trouver_jobs_instances<J,M>(middleware: &M, job_handler: &J)
    -> Result<Option<Vec<String>>, Box<dyn Error>>
    where M: MongoDao, J: JobHandler
{
    let doc_job: Option<DocJob> = {
        let mut filtre = doc! {
            CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING
        };
        let options = FindOneOptions::builder().projection(doc! {"instances": true}).build();
        let collection = middleware.get_collection(job_handler.get_nom_collection())?;
        match collection.find_one(filtre, options).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        }
    };

    match doc_job {
        Some(inner) => {
            match inner.instances {
                Some(instances) => Ok(Some(instances)),
                None => Ok(None)
            }
        },
        None => Ok(None)
    }
}

async fn set_flag<M,J,S,U>(middleware: &M, job_handler: &J, fuuid: S, user_id: U, valeur: bool) -> Result<(), Box<dyn Error>>
    where M: MongoDao, J: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
{
    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();

    let filtre = doc!{
        CHAMP_USER_ID: user_id,
        CHAMP_FUUID: fuuid,
    };

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

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
            let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
            collection_jobs.delete_one(filtre, None).await?;
        },
        false => {
            // Rien a faire
            debug!("set_flag {} true : supprimer job sur {}/{} et modifier table versions", job_handler.get_nom_flag(), user_id, fuuid);
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct RowVersionsIds {
    tuuid: String,
    fuuid: String,
    mimetype: String,
    user_id: String,
    visites: Option<HashMap<String, i64>>,
}

async fn entretien_jobs<J,M>(middleware: &M, job_handler: &J, limite_batch: i64) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao, J: JobHandler
{
    debug!("ajouter_jobs_manquantes Debut");

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
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
            .projection(doc!{
                CHAMP_TUUID: true, CHAMP_FUUID: true, CHAMP_MIMETYPE: true, CHAMP_USER_ID: true,
                "visites": true,
            })
            .limit(limite_batch)
            .build();
        let filtre = doc! { champ_flag_index: false };
        debug!("traiter_indexation_batch filtre {:?}", filtre);
        collection_versions.find(filtre, Some(opts)).await?
    };

    while let Some(d) = curseur.next().await {
        let doc_version = d?;
        let version_mappee: RowVersionsIds = match convertir_bson_deserializable(doc_version) {
            Ok(inner) => inner,
            Err(e) => {
                warn!("traiter_indexation_batch Erreur mapping document : {:?} - SKIP", e);
                continue;
            }
        };

        debug!("traiter_indexation_batch Ajouter job (si applicable) pour {:?}", version_mappee);

        let tuuid_ref = version_mappee.tuuid.as_str();
        let fuuid_ref = version_mappee.fuuid.as_str();
        let user_id = version_mappee.user_id.as_str();
        let mimetype_ref = version_mappee.mimetype.as_str();

        let filtre = doc!{CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};

        let job_existante: Option<BackgroundJob> = match collection_jobs.find_one(filtre.clone(), None).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        };

        if let Some(job) = job_existante {
            if job.retry > MEDIA_RETRY_LIMIT {
                warn!("traiter_indexation_batch Expirer indexation sur document user_id {} tuuid {} : {} retries",
                    user_id, tuuid_ref, job.retry);
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
        if let Some(visites) = version_mappee.visites {
            for instance in visites.into_keys() {
                let mut champs_cles = HashMap::new();
                champs_cles.insert("mimetype".to_string(), mimetype_ref.to_string());
                champs_cles.insert("tuuid".to_string(), tuuid_ref.to_string());
                job_handler.sauvegarder_job(middleware, fuuid_ref, user_id, instance, champs_cles, None, false).await?;
            }
        }
    }

    Ok(())
}

pub async fn sauvegarder_job<M,J,S,U,V>(
    middleware: &M, job_handler: &J,
    fuuid: S, user_id: U, instance: V,
    champs_cles: HashMap<String, String>,
    parametres: Option<HashMap<String, Bson>>
)
    -> Result<(), Box<dyn Error>>
    where M: MongoDao, J: JobHandler,
          S: AsRef<str> + Send, U: AsRef<str> + Send, V: AsRef<str> + Send
{
    // Creer ou mettre a jour la job
    let now = Utc::now();

    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();
    let instance = instance.as_ref();

    let mut filtre = doc!{ CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid };
    for (k, v) in champs_cles.iter() {
        filtre.insert(k.to_owned(), v.to_owned());
    }

    let mut set_on_insert = doc!{
        CHAMP_FUUID: fuuid,
        CHAMP_USER_ID: user_id,
        CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING,
        CONST_CHAMP_RETRY: 0,
        CHAMP_CREATION: &now,
    };

    for (k, v) in champs_cles.into_iter() {
        set_on_insert.insert(k, v);
    }

    // Ajouter parametres optionnels (e.g. codecVideo, preset, etc.)
    if let Some(inner) = parametres {
        for (k, v) in inner.into_iter() {
            set_on_insert.insert(k, v);
        }
    }

    let ops_job = doc! {
        "$setOnInsert": set_on_insert,
        "$addToSet": { CHAMP_INSTANCES: instance },
        "$currentDate": {
            CHAMP_MODIFICATION: true,
            CONST_CHAMP_DATE_MAJ: true,
        }
    };
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
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
    pub date_maj: Option<DateTime>,
    pub retry: i32,
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
