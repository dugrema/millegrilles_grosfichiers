use std::collections::HashMap;
use std::error::Error;
use std::time::Duration as std_Duration;
use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, DateTime, doc};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, ValidateurX509};
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{DeleteOptions, FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use serde::{Deserialize, Serialize};

use crate::grosfichiers_constantes::*;
use crate::transactions::{NodeFichierRepOwned, NodeFichierVersionOwned};

const CONST_MAX_RETRY: i32 = 3;
const CONST_LIMITE_BATCH: i64 = 1_000;
const CONST_EXPIRATION_SECS: i64 = 300;
const CONST_INTERVALLE_ENTRETIEN: u64 = 60;

const CONST_CHAMP_RETRY: &str = "retry";
const CONST_CHAMP_DATE_MAJ: &str = "date_maj";

#[async_trait]
pub trait JobHandler: Clone + Sized + Sync {
    /// Nom de la collection ou se trouvent les jobs
    fn get_nom_collection(&self) -> &str;

    /// Retourne le nom du flag de la table GrosFichiers/versionFichiers pour ce type de job.
    fn get_nom_flag(&self) -> &str;

    /// Retourne l'action a utiliser dans le routage de l'evenement trigger.
    fn get_action_evenement(&self) -> &str;

    /// Marque une job comme terminee avec erreur irrecuperable.
    async fn marquer_job_erreur<M,G,S>(&self, middleware: &M, gestionnaire_domaine: &G, job: BackgroundJob, erreur: S)
        -> Result<(), Box<dyn Error>>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage,
            G: GestionnaireDomaine,
            S: ToString + Send;

    /// Emettre un evenement de job disponible.
    /// 1 evenement emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job<M>(&self, middleware: &M)
        where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
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

    async fn sauvegarder_job<M,S,U>(
        &self, middleware: &M, fuuid: S, user_id: U, instance: Option<String>,
        champs_cles: Option<HashMap<String, String>>,
        parametres: Option<HashMap<String, Bson>>,
        emettre_trigger: bool
    )
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao,
              S: AsRef<str> + Send, U: AsRef<str> + Send
    {
        let instances = sauvegarder_job(middleware, self, fuuid, user_id, instance.clone(), champs_cles, parametres).await?;
        if let Some(inner) = instances {
            if emettre_trigger {
                for instance in inner.into_iter() {
                    self.emettre_trigger(middleware, instance).await;
                }
            }
        }
        Ok(())
    }

    /// Set le flag de traitement complete
    async fn set_flag<M,S,U>(
        &self, middleware: &M, fuuid: S, user_id: Option<U>,
        cles_supplementaires: Option<HashMap<String, String>>,
        valeur: bool
    ) -> Result<(), Box<dyn Error>>
    where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
        set_flag(middleware, self, fuuid, user_id, cles_supplementaires, valeur).await
    }

    /// Doit etre invoque regulierement pour generer nouvelles jobs, expirer vieilles, etc.
    async fn entretien<M,G>(&self, middleware: &M, gestionnaire: &G, limite_batch: Option<i64>)
        where
            M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
            G: GestionnaireDomaine
    {
        debug!("entretien Cycle entretien JobHandler {}", self.get_nom_flag());

        let limite_batch = match limite_batch {
            Some(inner) => inner,
            None => CONST_LIMITE_BATCH
        };

        if let Err(e) = entretien_jobs(middleware, gestionnaire, self, limite_batch).await {
            error!("traitement_jobs.JobHandler.entretien {} Erreur sur ajouter_jobs_manquantes : {:?}", self.get_nom_flag(), e);
        }

        /// Emettre des triggers au besoin.
        self.emettre_evenements_job(middleware).await;
    }

    async fn get_prochaine_job<M>(&self, middleware: &M, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
        -> Result<ReponseJob, Box<dyn Error>>
        where M: GenerateurMessages + MongoDao
    {
        get_prochaine_job(middleware, self.get_nom_collection(), certificat, commande).await
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
            CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING
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

async fn set_flag<M,J,S,U>(
    middleware: &M, job_handler: &J, fuuid: S, user_id: Option<U>,
    cles_supplementaires: Option<HashMap<String, String>>,
    valeur: bool
) -> Result<(), Box<dyn Error>>
    where M: MongoDao, J: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
{
    let fuuid = fuuid.as_ref();
    let user_id = match user_id.as_ref() {
        Some(inner) => Some(inner.as_ref()),
        None => None
    };

    let mut filtre = doc!{
        CHAMP_FUUID: fuuid,
    };
    if let Some(inner) = user_id {
        // Lagacy - supporte vieilles transactions sans user_id
        filtre.insert(CHAMP_USER_ID, inner);
    }

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

    // Set flag
    let ops = doc! {
        "$set": { job_handler.get_nom_flag(): valeur },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    debug!("set_flag {}={} : modifier table versions pour {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), valeur, user_id, fuuid, filtre.clone());
    collection_versions.update_one(filtre.clone(), ops, None).await?;

    // Completer flags pour job
    if let Some(inner) = cles_supplementaires {
        for (k, v) in inner.into_iter() {
            filtre.insert(k, v);
        }
    }

    match valeur {
        true => {
            debug!("set_flag supprimer job ({}) sur {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), user_id, fuuid, filtre);

            // Set flag
            // let ops = doc! {
            //     "$set": { job_handler.get_nom_flag(): true },
            //     "$currentDate": { CHAMP_MODIFICATION: true }
            // };
            // collection_versions.update_one(filtre.clone(), ops, None).await?;

            // Retirer job
            let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
            let result = collection_jobs.delete_one(filtre.clone(), None).await?;
            debug!("set_flag Delete result sur table {}, filtre {:?} : {:?}", job_handler.get_nom_collection(), filtre, result);
        },
        false => {
            // Rien a faire
            debug!("set_flag {} false : supprimer job sur {:?}/{} et modifier table versions", job_handler.get_nom_flag(), user_id, fuuid);
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

async fn entretien_jobs<J,G,M>(middleware: &M, gestionnaire: &G, job_handler: &J, limite_batch: i64) -> Result<(), Box<dyn Error>>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
        G: GestionnaireDomaine,
        J: JobHandler
{
    debug!("entretien_jobs Debut");

    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(
        job_handler.get_nom_collection())?;
    let champ_flag_index = job_handler.get_nom_flag();

    // Reset jobs indexation avec start_date expire pour les reprendre immediatement
    {
        let filtre_start_expire = doc! {
            CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_RUNNING,
            CONST_CHAMP_DATE_MAJ: { "$lte": Utc::now() - Duration::seconds(CONST_EXPIRATION_SECS) },
            // CONST_CHAMP_RETRY: { "$lt": CONST_MAX_RETRY },
        };
        let ops_expire = doc! {
            "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING },
            "$unset": { CONST_CHAMP_DATE_MAJ: true },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        let options = UpdateOptions::builder().hint(Hint::Name("etat_jobs_2".to_string())).build();
        collection_jobs.update_many(filtre_start_expire, ops_expire, options).await?;
    }

    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
        NOM_COLLECTION_VERSIONS)?;

    let mut curseur = {
        let opts = FindOptions::builder()
            // .hint(Hint::Name(String::from("flag_media_traite")))
            .sort(doc! {champ_flag_index: 1, CHAMP_CREATION: 1})
            .projection(doc!{
                CHAMP_FUUID: true, CHAMP_TUUID: true, CHAMP_USER_ID: true, CHAMP_MIMETYPE: true, "visites": true,

                // Information requise a cause du format NodeFichierVersionBorrowed
                CHAMP_METADATA: true, CHAMP_TAILLE: true, CHAMP_FUUIDS: true, CHAMP_FUUIDS_RECLAMES: true,
                CHAMP_SUPPRIME: true,
            })
            .limit(limite_batch)
            .build();
        let filtre = doc! { champ_flag_index: false };
        debug!("traiter_indexation_batch filtre {:?}", filtre);
        collection_versions.find(filtre, Some(opts)).await?
    };

    while curseur.advance().await? {
        let version_mappee = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                warn!("traiter_indexation_batch Erreur mapping document : {:?} - SKIP", e);
                continue;
            }
        };
        debug!("traiter_indexation_batch Ajouter job (si applicable) pour {:?}", version_mappee);

        let tuuid_ref = version_mappee.tuuid;
        let fuuid_ref = version_mappee.fuuid;
        let user_id = version_mappee.user_id;
        let mimetype_ref = version_mappee.mimetype;

        let filtre_job = doc!{ CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref };

        let options = FindOneOptions::builder().hint(Hint::Name(NOM_INDEX_USER_ID_TUUIDS.to_string())).build();
        let job_existante = collection_jobs.find_one(filtre_job.clone(), options).await?;

        // if let Some(job) = job_existante {
        //     if let Some(retry) = job.retry {
        //         if retry > CONST_MAX_RETRY {
        //             warn!("traiter_indexation_batch Expirer indexation sur document user_id {} tuuid {} : {} retries",
        //                 user_id, tuuid_ref, retry);
        //             let ops = doc! {
        //                 "$set": {
        //                     champ_flag_index: true,
        //                     format!("{}_erreur", champ_flag_index): ERREUR_MEDIA_TOOMANYRETRIES,
        //                 }
        //             };
        //             let filtre_version = doc! {CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};
        //             collection_versions.update_one(filtre_version, ops, None).await?;
        //             collection_jobs.delete_one(filtre_job, None).await?;
        //             continue;
        //         }
        //     }
        // }

        // Creer ou mettre a jour la job
        for instance in version_mappee.visites.into_keys() {
            let mut champs_cles = HashMap::new();
            champs_cles.insert("mimetype".to_string(), mimetype_ref.to_string());
            champs_cles.insert("tuuid".to_string(), tuuid_ref.to_string());
            if let Err(e) = job_handler.sauvegarder_job(
                middleware, fuuid_ref, user_id,
                Some(instance.to_string()), Some(champs_cles), None,
                false).await
            {
                info!("entretien_jobs Erreur creation job : {:?}", e)
            }
        }
    }

    // Cleanup des jobs avec retry excessifs. Ces jobs sont orphelines (e.g. la correspondante dans
    // versions est deja traitee).
    {
        let filtre = doc! {
            // Inclue etat pour utiliser index etat_jobs_2
            CHAMP_ETAT_JOB: {"$in": [
                VIDEO_CONVERSION_ETAT_PENDING,
                // VIDEO_CONVERSION_ETAT_RUNNING,
                // VIDEO_CONVERSION_ETAT_PERSISTING,
                VIDEO_CONVERSION_ETAT_ERROR,
                VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES,
            ]},
            CHAMP_FLAG_DB_RETRY: {"$gte": MEDIA_RETRY_LIMIT}
        };
        let options = FindOptions::builder().hint(Hint::Name(NOM_INDEX_ETAT_JOBS.to_string())).build();
        let mut curseur = collection_jobs.find(filtre, options).await?;
        while curseur.advance().await? {
            let job = curseur.deserialize_current()?;
            warn!("traiter_indexation_batch Job sur fuuid {} (user_id {}) expiree, on met le flag termine pour annuler la job.", job.fuuid, job.user_id);

            // Fabriquer transaction pour annuler la job et marquer le traitement complete
            if let Err(e) = job_handler.marquer_job_erreur(middleware, gestionnaire, job, "Too many retries").await {
                error!("traiter_indexation_batch Erreur marquer job supprimee : {:?}", e);
            }
        }
    }

    Ok(())
}

pub async fn sauvegarder_job<M,J,S,U>(
    middleware: &M, job_handler: &J,
    fuuid: S, user_id: U, instance: Option<String>,
    champs_cles: Option<HashMap<String, String>>,
    parametres: Option<HashMap<String, Bson>>
)
    -> Result<Option<Vec<String>>, Box<dyn Error>>
    where M: MongoDao, J: JobHandler,
          S: AsRef<str> + Send, U: AsRef<str> + Send
{
    // Creer ou mettre a jour la job
    let now = Utc::now();

    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();
    // let instance = instance.as_ref();

    let mut filtre = doc!{ CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid };

    if let Some(inner) = champs_cles.as_ref() {
        for (k, v) in inner.iter() {
            filtre.insert(k.to_owned(), v.to_owned());
        }
    }

    let mut set_on_insert = doc!{
        CHAMP_FUUID: fuuid,
        CHAMP_USER_ID: user_id,
        CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING,
        CONST_CHAMP_RETRY: 0,
        CHAMP_CREATION: &now,
    };

    if let Some(inner) = champs_cles {
        for (k, v) in inner.iter() {
            set_on_insert.insert(k, v);
        }
    }

    // Ajouter parametres optionnels (e.g. codecVideo, preset, etc.)
    if let Some(inner) = parametres {
        for (k, v) in inner.into_iter() {
            set_on_insert.insert(k, v);
        }
    }

    let instances = match instance {
        Some(inner) => vec![inner],
        None => {
            // Tenter de charger les visites pour le fichier
            let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
            let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid };
            match collection.find_one(filtre, None).await? {
                Some(inner) => {
                    let fichier_mappe: FichierDetail = convertir_bson_deserializable(inner)?;
                    match fichier_mappe.visites {
                        Some(inner) => {
                            let liste_visites: Vec<String> = inner.into_keys().collect();
                            liste_visites
                        },
                        None => {
                            debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (1 - aucunes instance avec visite) - SKIP", fuuid);
                            return Ok(None)
                        }
                    }
                },
                None => {
                    debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (2 - aucunes instance avec visite) - SKIP", fuuid);
                    return Ok(None)
                }
            }
        }
    };

    let mut ops_job = doc! {
        "$setOnInsert": set_on_insert,
        "$addToSet": {CHAMP_INSTANCES: {"$each": &instances}},
        "$currentDate": {
            CHAMP_MODIFICATION: true,
        }
    };

    let options = FindOneAndUpdateOptions::builder()
        .upsert(true)
        .build();

    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(job_handler.get_nom_collection())?;
    if let Some(job) = collection_jobs.find_one_and_update(filtre.clone(), ops_job, options).await? {
        if let Some(retries) = job.retry {
            if retries >= CONST_MAX_RETRY {
                warn!("sauvegarder_job Job excede max retries, on la desactive");
                let ops = doc! {
                    "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES },
                    "$currentDate": { CHAMP_MODIFICATION: true },
                };
                collection_jobs.update_one(filtre, ops, None).await?;
                Err(format!("sauvegarder_job Job existante avec trop de retries"))?
            }
        }
    }

    Ok(Some(instances))
}

#[derive(Debug)]
pub struct CommandeGetJob {
    pub instance_id: Option<String>,
    /// Filtre format de fallback uniquement pour les videos
    pub fallback: Option<bool>,
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
    pub retry: Option<i32>,
    #[serde(flatten)]
    pub champs_optionnels: HashMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseJob {
    pub ok: bool,
    pub err: Option<String>,
    pub tuuid: Option<String>,
    pub fuuid: Option<String>,
    pub user_id: Option<String>,
    pub mimetype: Option<String>,
    pub metadata: Option<DataChiffre>,
    pub cle: Option<InformationCle>,

    // Champs video
    pub cle_conversion: Option<String>,
    #[serde(rename="codecVideo")]
    pub codec_video: Option<String>,
    #[serde(rename="codecAudio")]
    pub codec_audio: Option<String>,
    #[serde(rename="resolutionVideo")]
    pub resolution_video: Option<u32>,
    #[serde(rename="qualityVideo")]
    pub quality_video: Option<i32>,
    #[serde(rename="bitrateVideo")]
    pub bitrate_video: Option<u32>,
    #[serde(rename="bitrateAudio")]
    pub bitrate_audio: Option<u32>,
    pub preset: Option<String>,
}

impl From<&str> for ReponseJob {
    fn from(value: &str) -> Self {
        Self {
            ok: false,
            err: Some(value.to_string()),
            tuuid: None,
            fuuid: None,
            user_id: None,
            mimetype: None,
            metadata: None,
            cle: None,
            cle_conversion: None,
            codec_video: None,
            codec_audio: None,
            resolution_video: None,
            quality_video: None,
            bitrate_video: None,
            bitrate_audio: None,
            preset: None,
        }
    }
}

impl From<BackgroundJob> for ReponseJob {
    fn from(value: BackgroundJob) -> Self {

        // String params
        let mimetype = match value.champs_optionnels.get("mimetype") {
            Some(inner) => Some(inner.to_string()),
            None => None
        };
        let cle_conversion = match value.champs_optionnels.get("cle_conversion") {
            Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
            None => None
        };
        let codec_video = match value.champs_optionnels.get("codecVideo") {
            Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
            None => None
        };
        let codec_audio = match value.champs_optionnels.get("codecAudio") {
            Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
            None => None
        };
        let preset = match value.champs_optionnels.get("preset") {
            Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
            None => None
        };

        // u32 params
        let resolution_video = match value.champs_optionnels.get("resolutionVideo") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as u32),
                None => None
            },
            None => None
        };
        let quality_video = match value.champs_optionnels.get("qualityVideo") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as i32),
                None => None
            },
            None => None
        };
        let bitrate_video = match value.champs_optionnels.get("bitrateVideo") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as u32),
                None => None
            },
            None => None
        };
        let bitrate_audio = match value.champs_optionnels.get("bitrateAudio") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as u32),
                None => None
            },
            None => None
        };

        Self {
            ok: true,
            err: None,
            tuuid: Some(value.tuuid),
            fuuid: Some(value.fuuid),
            user_id: Some(value.user_id),
            mimetype,
            metadata: None,
            cle: None,
            cle_conversion,
            codec_video,
            codec_audio,
            resolution_video,
            quality_video,
            bitrate_video,
            bitrate_audio,
            preset,
        }
    }
}

pub async fn get_prochaine_job<M,S>(middleware: &M, nom_collection: S, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
    -> Result<ReponseJob, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
{
    let nom_collection = nom_collection.as_ref();

    debug!("commande_get_job Get pour {} : {:?}", nom_collection, commande);
    let job = match trouver_prochaine_job_traitement(middleware, nom_collection, &commande).await? {
        Some(inner) => inner,
        None => {
            // Il ne reste aucunes jobs
            return Ok(ReponseJob::from("Aucun fichier a traiter"))
        }
    };

    debug!("commande_get_job Prochaine job : {:?}", job);

    let fuuid = job.fuuid.as_str();

    // Recuperer les metadonnees et information de version
    let (fichier_rep, fichier_version) = {
        let mut filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_TUUID: &job.tuuid };
        let collection_rep = middleware.get_collection_typed::<NodeFichierRepOwned>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let fichier_rep = match collection_rep.find_one(filtre, None).await? {
            Some(inner) => inner,
            None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job pour document inexistant user_id:{} tuuid:{}", job.user_id, job.tuuid))?
        };
        match fichier_rep.fuuids_versions.as_ref() {
            Some(inner) => if !inner.contains(&job.fuuid) {
                Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - fuuid {} non associe au document user_id:{} tuuid:{}", job.fuuid, job.user_id, job.tuuid))?
            },
            None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job pour document sans fuuids user_id:{} tuuid:{}", job.user_id, job.tuuid))?
        };
        let filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_FUUID: fuuid };
        let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(
            NOM_COLLECTION_VERSIONS)?;
        let fichier_version = match collection_versions.find_one(filtre, None).await? {
            Some(inner) => inner,
            None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job pour document version inexistant user_id:{} fuuid:{}", job.user_id, fuuid))?
        };
        (fichier_rep, fichier_version)
    };

    let metadata = fichier_rep.metadata;

    let mimetype = match fichier_rep.mimetype.as_ref() {
        Some(inner) => inner.as_str(),
        None => "application/octet-stream"
    };

    // Recuperer la cle de dechiffrage du fichier
    let cle = get_cle_job_indexation(middleware, fuuid, certificat).await?;

    let mut reponse_job = ReponseJob::from(job);
    reponse_job.metadata = Some(metadata);
    reponse_job.mimetype = Some(mimetype.to_string());
    reponse_job.cle = Some(cle);
    debug!("Reponse job : {:?}", reponse_job);

    Ok(reponse_job)
}

/// Trouver prochaine job
/// Inclue les jobs avec too many retries
pub async fn trouver_prochaine_job_traitement<M,S>(middleware: &M, nom_collection: S, commande: &CommandeGetJob)
                                                   -> Result<Option<BackgroundJob>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
{
    let collection = middleware.get_collection(nom_collection.as_ref())?;

    let job: Option<BackgroundJob> = {
        // Tenter de trouver la prochaine job disponible
        let mut filtre = doc! {
            CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING,
            CHAMP_FLAG_DB_RETRY: {"$lt": MEDIA_RETRY_LIMIT},
        };

        // Verifier si on utilise le filtre fallback pour les videos
        if Some(true) == commande.fallback {
            filtre.insert("fallback", true);
        }

        match commande.instance_id.as_ref() {
            Some(instance_id) => {
                filtre.insert("$or", vec![doc!{"instances": {"$exists": false}}, doc!{"instances": instance_id}]);
            },
            None => {
                filtre.insert("instances.0", doc! {"$exists": true} );
            }
        }
        // if let Some(instance_id) = commande.instance_id.as_ref() {
        //     filtre.insert("$or", vec![doc!{"instances": {"$exists": false}}, doc!{"instances": instance_id}]);
        // }
        let hint = Some(Hint::Name("etat_jobs_2".into()));
        let options = FindOneAndUpdateOptions::builder()
            .hint(hint)
            .return_document(ReturnDocument::Before)
            .build();
        let ops = doc! {
            "$set": {CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_RUNNING},
            "$inc": {CHAMP_FLAG_DB_RETRY: 1},
            "$currentDate": {CHAMP_MODIFICATION: true, CONST_CHAMP_DATE_MAJ: true}
        };
        match collection.find_one_and_update(filtre, ops, options).await? {
            Some(d) => {
                debug!("trouver_prochaine_job_traitement (1) Charger job : {:?}", d);
                Some(convertir_bson_deserializable(d)?)
            },
            None => None
        }
    };

    Ok(job)
}

pub async fn get_cle_job_indexation<M,S>(middleware: &M, fuuid: S, certificat: &EnveloppeCertificat)
    -> Result<InformationCle, Box<dyn Error>>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>
{
    let fuuid = fuuid.as_ref();

    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L4Secure])
        .build();

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage: Vec<String> = {
        let fp_certs = certificat.get_pem_vec();
        fp_certs.into_iter().map(|cert| cert.pem).collect()
    };

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: vec![fuuid.to_string()],
        certificat_rechiffrage: Some(pem_rechiffrage),
    };

    debug!("get_cle_job_indexation Transmettre requete permission dechiffrage cle : {:?}", permission);
    let cle = if let TypeMessage::Valide(reponse) = middleware.transmettre_requete(routage, &permission).await? {
        let reponse: ReponseDechiffrageCles = reponse.message.parsed.map_contenu()?;
        if reponse.acces.as_str() != "1.permis" {
            Err(format!("commandes.get_cle_job_indexation Erreur reception reponse cle : acces refuse ({}) a cle {}", reponse.acces, fuuid))?
        }

        match reponse.cles {
            Some(mut inner) => match inner.remove(fuuid) {
                Some(inner) => inner,
                None => Err(format!("commandes.get_cle_job_indexation Erreur reception reponse cle : cle non recue pour {}", fuuid))?
            },
            None => Err(format!("commandes.get_cle_job_indexation Erreur reception reponse cle : cles vides pour {}", fuuid))?
        }
    } else {
        Err(format!("commandes.get_cle_job_indexation Erreur reception reponse cle : mauvais type message recu"))?
    };

    debug!("get_cle_job_indexation Cle recue pour {}, format dechiffrage  {}", cle.hachage_bytes, cle.format);

    Ok(cle)
}

#[derive(Clone, Debug, Deserialize)]
pub struct ParametresConfirmerJob {
    pub fuuid: String,
    pub user_id: String,
    pub cle_conversion: Option<String>,
}
