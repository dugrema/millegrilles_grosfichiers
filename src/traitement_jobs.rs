use std::collections::HashMap;
use std::str::from_utf8;
use log::{debug, error, info, warn};

use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{Bson, DateTime, doc}, serde_json};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::{InformationDechiffrageV2, ReponseRequeteDechiffrageV2, RequeteDechiffrage};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao, opt_chrono_datetime_as_bson_datetime, start_transaction_regular};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::{chrono, millegrilles_cryptographie, uuid};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleSecreteSerialisee;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::uuid::{uuid, Uuid};
use serde::{Deserialize, Serialize};
use crate::domain_manager::GrosFichiersDomainManager;
use crate::grosfichiers_constantes::*;
use crate::requetes::get_decrypted_keys;
use crate::traitement_entretien::sauvegarder_visites;
use crate::traitement_index::set_flag_index_traite;
use crate::traitement_media::emettre_processing_trigger;
use crate::transactions::{NodeFichierRepBorrowed, NodeFichierRepOwned, NodeFichierRepRow, NodeFichierVersionOwned, TransactionSupprimerJobVideoV2};

const CONST_MAX_RETRY: i32 = 4;
const CONST_LIMITE_BATCH: i64 = 1_000;
const CONST_EXPIRATION_SECS: i64 = 180;
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
        -> Result<(), CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            G: GestionnaireDomaineV2 + AiguillageTransactions,
            S: ToString + Send;

    /// Emettre un evenement de job disponible.
    /// evenements emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job<M>(&self, middleware: &M, batch_size: Option<i64>)
        where M: GenerateurMessages + MongoDao + ValidateurX509
    {
        let batch_size = batch_size.unwrap_or_else(||CONST_LIMITE_BATCH);

        error!("emettre_evenements_job TODO - FIX ME!");
        // let visites = match trouver_jobs_instances(middleware, self).await {
        //     Ok(visites) => match visites {
        //         Some(inner) => inner,
        //         None => {
        //             debug!("JobHandler.emettre_evenements_job Aucune job pour {}", self.get_action_evenement());
        //             return  // Rien a faire
        //         }
        //     },
        //     Err(e) => {
        //         error!("JobHandler.emettre_evenements_job Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
        //         return
        //     }
        // };
        //
        // for filehost_id in visites {
        //     self.emettre_trigger(middleware, filehost_id, fuuid, mimetype).await;
        // }
    }

    /// Emet un evenement pour declencher le traitement pour une instance
    async fn emettre_trigger<M,I>(&self, middleware: &M, background_job: &BackgroundJob)
    where M: GenerateurMessages {

        let trigger = JobTrigger::from(background_job);

        for filehost_id in &background_job.filehost_ids {
            let routage = RoutageMessageAction::builder("media", self.get_action_evenement(), vec![Securite::L3Protege])
                .partition(filehost_id)
                .build();
            if let Err(e) = middleware.emettre_evenement(routage, &trigger).await {
                error!("JobHandler.emettre_trigger Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
            }
        }
    }
}

#[async_trait]
pub trait JobHandlerVersions: JobHandler {

}

#[derive(Debug, Deserialize)]
struct RowVersionsIds {
    tuuid: String,
    fuuid: String,
    mimetype: String,
    user_id: String,
    // visites: Option<HashMap<String, i64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackgroundJobParams {
    #[serde(skip_serializing_if="Option::is_none")]
    pub defaults: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub thumbnails: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(rename="codecVideo", skip_serializing_if="Option::is_none")]
    pub codec_video: Option<String>,
    #[serde(rename="codecAudio", skip_serializing_if="Option::is_none")]
    pub codec_audio: Option<String>,
    #[serde(rename="resolutionVideo", skip_serializing_if="Option::is_none")]
    pub resolution_video: Option<u32>,
    #[serde(rename="qualityVideo", skip_serializing_if="Option::is_none")]
    pub quality_video: Option<i32>,
    #[serde(rename="bitrateVideo", skip_serializing_if="Option::is_none")]
    pub bitrate_video: Option<u32>,
    #[serde(rename="bitrateAudio", skip_serializing_if="Option::is_none")]
    pub bitrate_audio: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub preset: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio_stream_idx: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitle_stream_idx: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackgroundJob {
    pub job_id: String,

    // Parametres de la job
    pub tuuid: String,
    pub fuuid: Option<String>,
    pub mimetype: String,
    pub filehost_ids: Vec<String>,
    pub params: Option<BackgroundJobParams>,

    // Valeurs pour video (progress update) et index (access rights)
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<String>,

    // Dechiffrage fichier (fuuid)
    pub cle_id: String,
    pub format: String,
    pub nonce: String,

    // Etat de la job
    pub etat: i32,
    // #[serde(rename="_mg-creation", with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    // pub date_creation: chrono::DateTime<Utc>,
    #[serde(rename="_mg-derniere-modification", with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub date_modification: chrono::DateTime<Utc>,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime")]
    pub date_maj: Option<chrono::DateTime<Utc>>,
    pub retry: i32,

    // Business key, combined with tuuid to make a unique job value
    pub cle_conversion: Option<String>,
}

impl BackgroundJob {
    pub fn new<T,F,M,I,C,E,N>(tuuid: T, fuuid: F, mimetype: M, filehost_ids: &Vec<I>, cle_id: C, format: E, nonce: N) -> BackgroundJob
        where T: ToString, F: ToString, M: ToString, I: ToString, E: ToString, C: ToString, N: ToString
    {
        let job_id = Uuid::new_v4();  // Generate random identifier
        Self {
            job_id: job_id.to_string(),
            tuuid: tuuid.to_string(),
            fuuid: Some(fuuid.to_string()),
            mimetype: mimetype.to_string(),
            filehost_ids: filehost_ids.iter().map(|id| id.to_string()).collect(),
            params: None,
            user_id: None,
            cle_id: cle_id.to_string(),
            format: format.to_string(),
            nonce: nonce.to_string(),
            etat: VIDEO_CONVERSION_ETAT_PENDING,
            // date_creation: Utc::now(),
            date_modification: Utc::now(),
            date_maj: None,
            retry: 0,
            cle_conversion: None,
        }
    }

    pub fn new_index<T,F,U,M,I,C,E,N>(tuuid: T, fuuid: Option<F>, user_id: U, mimetype: M, filehost_ids: &Vec<I>, cle_id: C, format: E, nonce: N) -> BackgroundJob
    where T: ToString, F: ToString, U: ToString, M: ToString, I: ToString, E: ToString, C: ToString, N: ToString
    {
        let job_id = Uuid::new_v4();  // Generate random identifier
        Self {
            job_id: job_id.to_string(),
            tuuid: tuuid.to_string(),
            fuuid: match fuuid {Some(inner) => Some(inner.to_string()), None => None},
            mimetype: mimetype.to_string(),
            filehost_ids: filehost_ids.iter().map(|id| id.to_string()).collect(),
            params: None,
            user_id: Some(user_id.to_string()),
            cle_id: cle_id.to_string(),
            format: format.to_string(),
            nonce: nonce.to_string(),
            etat: VIDEO_CONVERSION_ETAT_PENDING,
            // date_creation: Utc::now(),
            date_modification: Utc::now(),
            date_maj: None,
            retry: 0,
            cle_conversion: None,
        }
    }
}

#[derive(Serialize)]
pub struct JobTrigger<'a> {
    pub job_id: &'a str,
    pub tuuid: &'a str,
    pub fuuid: Option<&'a str>,
    pub mimetype: &'a str,
    pub filehost_ids: &'a Vec<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub params: Option<&'a BackgroundJobParams>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<&'a str>,
    pub cle_id: &'a str,
    pub format: &'a str,
    pub nonce: &'a str,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_cuuids: Option<Vec<String>>,
}

impl<'a> From<&'a BackgroundJob> for JobTrigger<'a> {
    fn from(value: &'a BackgroundJob) -> JobTrigger<'a> {
        Self {
            job_id: value.job_id.as_str(),
            tuuid: value.tuuid.as_str(),
            fuuid: match &value.fuuid {Some(inner)=>Some(inner), None=>None},
            mimetype: value.mimetype.as_str(),
            filehost_ids: &value.filehost_ids,
            params: match &value.params {Some(inner)=>Some(inner), None=>None},
            user_id: match value.user_id.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None},
            cle_id: value.cle_id.as_str(),
            format: value.format.as_str(),
            nonce: value.nonce.as_str(),
            metadata: None,
            path_cuuids: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ParametresConfirmerJobIndexation {
    pub job_id: String,
    pub tuuid: String,
    pub fuuid: Option<String>,
    pub supprimer: Option<bool>,
    // pub user_id: String,
    // pub cle_conversion: Option<String>,
}

pub async fn sauvegarder_job<'a, M>(middleware: &M, job: &BackgroundJob, trigger: Option<JobTrigger<'a>>, nom_collection: &str, domain: &str, action_trigger: &str, session: &mut ClientSession)
    -> Result<BackgroundJob, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;

    // Verifier si une job existe deja pour le fichier represente
    let cle_conversion = match job.params.as_ref() {
        Some(params) => {
            if Some(true) == params.defaults {
                "defaults".to_string()
            } else {
                // Generate unique key from params
                format!("{:?};{:?};{:?};{:?};{:?};{:?}", params.mimetype, params.codec_video,
                        params.resolution_video, params.bitrate_audio, params.audio_stream_idx,
                        params.subtitle_stream_idx)
            }
        },
        None => "defaults".to_string()
    };
    let filtre = doc!{"tuuid": &job.tuuid, "cle_conversion": &cle_conversion};
    let ops = doc! {
        "$addToSet": {"filehost_ids": {"$each": &job.filehost_ids}},  // Merge the filehost_ids if appropriate
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = FindOneAndUpdateOptions::builder().return_document(ReturnDocument::After).build();
    let updated_job = match collection.find_one_and_update_with_session(filtre, ops, options, session).await? {
        Some(inner) => inner,
        None => {
            debug!("sauvegarder_job No job updated, returning cloned job");
            let mut job_copy = job.clone();
            job_copy.cle_conversion = Some(cle_conversion);
            collection.insert_one_with_session(job_copy, None, session).await?;
            job.clone()
        }
    };

    // Commit to ensure job is available before emitting trigger
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    // Emettre job pour traitement.
    match trigger {
        Some(inner) => emettre_processing_trigger(middleware, inner, domain, action_trigger).await,
        None => emettre_processing_trigger(middleware, &updated_job, domain, action_trigger).await
    }

    Ok(updated_job)
}

pub async fn create_missing_jobs<M>(middleware: &M) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    if let Err(e) = create_missing_jobs_indexing(middleware).await {
        error!("create_missing_jobs Erreur creation jobs manquantes indexing: {:?}", e);
    }
    if let Err(e) = create_missing_jobs_media(middleware, NOM_COLLECTION_IMAGES_JOBS, CHAMP_FLAG_MEDIA_TRAITE).await {
        error!("create_missing_jobs Erreur creation jobs manquantes images: {:?}", e);
    }
    if let Err(e) = create_missing_jobs_media(middleware, NOM_COLLECTION_VIDEO_JOBS, CHAMP_FLAG_VIDEO_TRAITE).await {
        error!("create_missing_jobs Erreur creation jobs manquantes videos: {:?}", e);
    }
    Ok(())
}

#[derive(Deserialize, Debug)]
struct MissingJobIndexMapping {
    fichierrep: NodeFichierRepOwned,
    versions: Vec<NodeFichierVersionOwned>,
    jobs: Vec<BackgroundJob>,
}

/// Create missing jobs for all entries not already indexed.
pub async fn create_missing_jobs_indexing<M>(middleware: &M) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    let collection_reps = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(NOM_COLLECTION_INDEXATION_JOBS)?;

    // Remove all file indexing jobs with empty filehosts ([]). They will get recreated. Ignore directories (fuuid is null).
    let filtre_empty = doc!{"filehost_ids.0": {"$exists": false}, "fuuid": {"$exists": true}};
    collection_jobs.delete_many(filtre_empty, None).await?;

    let pipeline = vec![
        doc! { "$match": {CHAMP_SUPPRIME: false, CHAMP_FLAG_INDEX: false} },
        doc! { "$replaceRoot": {"newRoot": {"_id": "$tuuid", "fichierrep": "$$ROOT"}}},
        doc! { "$lookup": {
            "from": NOM_COLLECTION_INDEXATION_JOBS,
            "localField": "fichierrep.tuuid",
            "foreignField": "tuuid",
            "as": "jobs",
        }},
        // Filter out files that already have a job
        doc! { "$match": {"jobs.0": {"$exists": false} } },
        // Get version when present
        doc! { "$lookup": {
            "from": NOM_COLLECTION_VERSIONS,
            "localField": "fichierrep.fuuids_versions",
            "foreignField": "fuuid",
            "as": "versions",
        }},
    ];
    debug!("create_missing_jobs_indexing Pipeline: {:?}", pipeline);

    let mut batch = Vec::with_capacity(50);
    let mut cursor = collection_reps.aggregate(pipeline, None).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let mut row: MissingJobIndexMapping = convertir_bson_deserializable(row)?;
        // debug!("Mapping job: {:?}", row);
        let row_reps = row.fichierrep;
        let row_version = row.versions.first();

        let tuuid = row_reps.tuuid.as_str();
        let user_id = row_reps.user_id.as_str();

        match row_version {
            Some(fichier_version) => {
                // This is a file with associated content
                let fuuid = fichier_version.fuuid.as_str();
                let mimetype = match row_reps.mimetype {
                    Some(inner) => inner,
                    None => fichier_version.mimetype.to_owned()
                };

                let visites: Vec<&String> = fichier_version.visites.keys().collect();
                // Ensure the "nouveau" visit is not counted
                let visites = visites.into_iter().filter(|v| v.as_str() != "nouveau").collect();

                // File
                if fichier_version.cle_id.is_some() && fichier_version.format.is_some() && fichier_version.nonce.is_some() {
                    // Current format with cle_id directly available
                    let cle_id = fichier_version.cle_id.as_ref().expect("cle_id").to_owned();
                    let format: &str = fichier_version.format.clone().expect("format").into();
                    let nonce = fichier_version.nonce.as_ref().expect("nonce").to_owned();

                    let mut job = BackgroundJob::new(tuuid, fuuid, mimetype, &visites, cle_id, format, nonce);
                    job.user_id = Some(user_id.to_string());
                    batch.push(job);
                } else {
                    // Old format. The keymaster has the key where cle_id == fuuid.
                    let cle_id = fuuid;

                    // Values for format and header (nonce) are available directly from the key.
                    let mut key_information = get_decrypted_keys(middleware, vec![cle_id.to_owned()]).await?;
                    if key_information.len() == 1 {
                        let key = key_information.pop().expect("pop key_information");
                        if key.format.is_some() && key.nonce.is_some() {
                            debug!("Cle_id {} information recovered successfully from keymaster", cle_id);
                            let format: &str = key.format.expect("format").into();
                            let nonce = key.nonce.expect("nonce");
                            let job = BackgroundJob::new_index(tuuid, Some(fuuid), user_id, mimetype, &visites, cle_id, format, nonce);
                            batch.push(job);
                        }
                    }
                }
            }
            None => {
                // Directory/Collection
                let metadata = row_reps.metadata;
                if metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
                    let cle_id = metadata.cle_id.expect("cle_id");
                    let format = metadata.format.expect("format");
                    let nonce = metadata.nonce.expect("nonce");
                    let mimetype = row_reps.mimetype.unwrap_or_else(|| "application/octet-stream".to_string());
                    let visites: Vec<&String> = vec![];
                    let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, mimetype, &visites, cle_id, format, nonce);
                    batch.push(job);
                } else if metadata.format.is_some() && metadata.header.is_some() && metadata.ref_hachage_bytes.is_some() {
                    // Old format. The keymaster has the key where cle_id == ref_hachage_bytes.
                    let cle_id = metadata.ref_hachage_bytes.expect("ref_hachage_bytes");
                    let format = metadata.format.expect("format");
                    let header = metadata.header.expect("header");
                    let nonce = &header[1..]; // Remove multibase marker
                    let mimetype = row_reps.mimetype.unwrap_or_else(|| "application/octet-stream".to_string());
                    let visites: Vec<&String> = vec![];
                    let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, mimetype, &visites, cle_id, format, nonce);
                    batch.push(job);
                }
            }
        }

        if batch.len() >= 50 {
            // Save batch to database
            debug!("Saving batch of index jobs");
            collection_jobs.insert_many(&batch, None).await?;
            batch.clear();
        }
    }

    if batch.len() > 0 {
        // Save last batch to database
        debug!("Saving last batch of {} index jobs", batch.len());
        collection_jobs.insert_many(batch, None).await?;
        batch = Vec::new();
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
struct MissingMediaJobMapping {
    version: NodeFichierVersionOwned,
    fichierreps: Vec<NodeFichierRepOwned>,
    jobs: Vec<BackgroundJob>,
}

pub async fn create_missing_jobs_media<M>(middleware: &M, jobs_collection_name: &str, flag_job: &str) -> Result<(), CommonError>
where M: MongoDao + GenerateurMessages
{
    let collection_version = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(jobs_collection_name)?;

    // Remove all file indexing jobs with empty filehosts ([]). They will get recreated.
    let filtre_empty = doc! {"filehost_ids.0": {"$exists": false}};
    collection_jobs.delete_many(filtre_empty, None).await?;

    let pipeline = vec![
        // Find file versions that are not processed and not deleted (at least 1 tuuid).
        doc! { "$match": {flag_job: false, format!("{}.0", CHAMP_TUUIDS): {"$exists": true}} },
        // Restructure to keep version structure intact for mapping
        doc! { "$replaceRoot": {"newRoot": {"_id": "$fuuid", "version": "$$ROOT"}}},
        doc! { "$lookup": {
            "from": jobs_collection_name,
            "localField": "version.fuuid",
            "foreignField": "fuuid",
            "as": "jobs",
        }},
        // Filter out files that already have a job
        doc! { "$match": {"jobs.0": {"$exists": false} } },
        // Get fichiersrep when present
        doc! { "$lookup": {
            "from": NOM_COLLECTION_FICHIERS_REP,
            "localField": "version.fuuid",
            "foreignField": "fuuids_versions",
            "as": "fichierreps",
        }},
    ];
    debug!("create_missing_jobs_media Pipeline: {:?}", pipeline);

    let mut batch = Vec::with_capacity(50);
    let mut cursor = collection_version.aggregate(pipeline, None).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let row: MissingMediaJobMapping = convertir_bson_deserializable(row)?;
        let fichier_version = row.version;

        let fuuid = fichier_version.fuuid.as_str();

        let visites: Vec<&String> = fichier_version.visites.keys().collect();
        // Ensure the "nouveau" visit is not counted
        let visites = visites.into_iter().filter(|v| v.as_str() != "nouveau").collect();

        for fichier_rep in row.fichierreps {
            let tuuid = fichier_rep.tuuid.as_str();
            let user_id = fichier_rep.user_id.as_str();

            let mimetype = match fichier_rep.mimetype {
                Some(inner) => inner,
                None => fichier_version.mimetype.clone()
            };

            let mut job = if fichier_version.cle_id.is_some() && fichier_version.format.is_some() && fichier_version.nonce.is_some() {
                // Current format with cle_id directly available
                let cle_id = fichier_version.cle_id.as_ref().expect("cle_id").to_owned();
                let format: &str = fichier_version.format.clone().expect("format").into();
                let nonce = fichier_version.nonce.as_ref().expect("nonce").to_owned();

                let mut job = BackgroundJob::new(tuuid, fuuid, mimetype, &visites, cle_id, format, nonce);
                job.user_id = Some(user_id.to_string());
                job
            } else {
                // Old format. The keymaster has the key where cle_id == fuuid.
                let cle_id = fuuid;

                // Values for format and header (nonce) are available directly from the key.
                let mut key_information = get_decrypted_keys(middleware, vec![cle_id.to_owned()]).await?;
                if key_information.len() == 1 {
                    let key = key_information.pop().expect("pop key_information");
                    if key.format.is_some() && key.nonce.is_some() {
                        debug!("Cle_id {} information recovered successfully from keymaster", cle_id);
                        let format: &str = key.format.expect("format").into();
                        let nonce = key.nonce.expect("nonce");
                        let job = BackgroundJob::new(tuuid, fuuid, mimetype, &visites, cle_id, format, nonce);
                        job
                    } else {
                        warn!("Key information missing from keymaster for fuuid: {}", fuuid);
                        continue
                    }
                } else {
                    warn!("Key information missing from keymaster for fuuid: {}", fuuid);
                    continue
                }
            };

            if flag_job == CHAMP_FLAG_VIDEO_TRAITE {
                // Champs supplementaires pour video
                let params_initial = BackgroundJobParams {
                    defaults: Some(true),
                    thumbnails: Some(true),
                    mimetype: None,
                    codec_video: None,
                    codec_audio: None,
                    resolution_video: None,
                    quality_video: None,
                    bitrate_video: None,
                    bitrate_audio: None,
                    preset: None,
                    audio_stream_idx: None,
                    subtitle_stream_idx: None,
                };
                job.params = Some(params_initial);
            }
            job.user_id = Some(user_id.to_string());

            batch.push(job);

            if batch.len() >= 50 {
                // Save batch to database
                debug!("Saving batch of media jobs");
                collection_jobs.insert_many(&batch, None).await?;
                batch.clear();
            }
        }

        if batch.len() > 0 {
            // Save batch to database
            debug!("Saving last batch of media jobs");
            collection_jobs.insert_many(&batch, None).await?;
            batch.clear();
        }
    }

    Ok(())
}

// pub async fn creer_jobs_manquantes_queue<M>(middleware: &M, nom_collection: &str, flag_job: &str, session: &mut ClientSession) -> Result<(), CommonError>
//     where M: MongoDao + GenerateurMessages
// {
//     // Avoid session, this is a batch operation
//     session.commit_transaction().await?;
//
//     let collection_reps = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
//     let collection_version = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
//     let filtre_version = doc!{flag_job: false, "tuuids.0": {"$exists": true}, "visites.nouveau": {"$exists": false}};
//     let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;
//     // let mut curseur = collection_version.find_with_session(filtre_version, None, session).await?;
//     let mut curseur = collection_version.find(filtre_version, None).await?;
//     let mut fuuids = Vec::new();
//     // while curseur.advance(session).await? {
//     while curseur.advance().await? {
//         let row = curseur.deserialize_current()?;
//         let fuuid = row.fuuid;
//         // let tuuid = row.tuuid;
//
//         // Verifier si une job existe pour ce fuuid. Ignorer fichiers en cours d'upload (nouveau).
//         let filtre_job = doc! {"fuuid": fuuid};
//         // let count = collection_jobs.count_documents_with_session(filtre_job, None, session).await?;
//         let count = collection_jobs.count_documents(filtre_job, None).await?;
//
//         if count == 0 {
//             debug!("creer_jobs_manquantes_queue Creer job {} manquante pour fuuid {}", flag_job, fuuid);
//             let filtre_reps = doc!{"fuuids_versions": fuuid};
//             // let mut cursor_reps = collection_reps.find_with_session(filtre_reps, None, session).await?;
//             let mut cursor_reps = collection_reps.find(filtre_reps, None).await?;
//             // while cursor_reps.advance(session).await? {
//             while cursor_reps.advance().await? {
//                 let row_reps = cursor_reps.deserialize_current()?;
//                 let tuuid = row_reps.tuuid.as_str();
//                 let user_id = row_reps.user_id.as_str();
//
//                 if row.cle_id.is_some() && row.format.is_some() && row.nonce.is_some() {
//                     let cle_id = row.cle_id.expect("cle_id");
//                     let format: &str = row.format.clone().expect("format").into();
//                     let nonce = row.nonce.expect("nonce");
//                     let visites: Vec<&String> = row.visites.keys().collect();
//
//                     let mut job = BackgroundJob::new(tuuid, fuuid, row.mimetype, &visites, cle_id, format, nonce);
//                     if flag_job == CHAMP_FLAG_VIDEO_TRAITE {
//                         // Champs supplementaires pour video
//                         let params_initial = BackgroundJobParams {
//                             defaults: Some(true),
//                             thumbnails: Some(true),
//                             mimetype: None,
//                             codec_video: None,
//                             codec_audio: None,
//                             resolution_video: None,
//                             quality_video: None,
//                             bitrate_video: None,
//                             bitrate_audio: None,
//                             preset: None,
//                             audio_stream_idx: None,
//                             subtitle_stream_idx: None,
//                         };
//                         job.params = Some(params_initial);
//
//                         job.user_id = Some(user_id.to_string());
//                     } else if flag_job == CHAMP_FLAG_INDEX {
//                         job.user_id = Some(user_id.to_string());
//                     }
//                     // collection_jobs.insert_one_with_session(job, None, session).await?;
//                     collection_jobs.insert_one(job, None).await?;
//                     fuuids.push(fuuid.to_owned());
//                 } else {
//                     // Old format. The keymaster has the key where cle_id == fuuid.
//                     let cle_id = fuuid;
//                     let mimetype = row.mimetype;
//
//                     // Values for format and header (nonce) are available directly from the key.
//                     let mut key_information = get_decrypted_keys(middleware, vec![cle_id.to_owned()]).await?;
//                     if key_information.len() == 1 {
//                         let key = key_information.pop().expect("pop key_information");
//                         if key.format.is_some() && key.nonce.is_some() {
//                             debug!("Cle_id {} information recovered successfully from keymaster", cle_id);
//                             let format: &str = key.format.expect("format").into();
//                             let nonce = key.nonce.expect("nonce");
//                             let visites: Vec<&String> = vec![];
//                             let job = BackgroundJob::new_index(tuuid, Some(fuuid), user_id, mimetype, &visites, cle_id, format, nonce);
//                             // collection_jobs.insert_one_with_session(job, None, session).await?;
//                             collection_jobs.insert_one(job, None).await?;
//                         }
//                     }
//                 }
//             }
//         }
//     }
//
//     // Restart session for wrap-up of the call
//     start_transaction_regular(session).await?;
//
//     Ok(())
// }

pub async fn entretien_jobs_expirees<M>(middleware: &M, fetch_filehosts: bool) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match entretien_jobs_expirees_session(middleware, fetch_filehosts, &mut session).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            // error!("creer_jobs_manquantes_session Error: {:?}", e);
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn entretien_jobs_expirees_session<M>(middleware: &M, fetch_filehosts: bool, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_IMAGES_JOBS, 180, 1000 , "media", "processImage", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees_session Erreur entretien images: {:?}", e);
    }
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_VIDEO_JOBS, 600, 100, "media", "processVideo", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees_session Erreur entretien videos: {:?}", e);
    }
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_INDEXATION_JOBS, 180, 2000, "solrrelai", "processIndex", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees_session Erreur entretien index: {:?}", e);
    }
    Ok(())
}

pub async fn maintenance_impossible_jobs<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match maintenance_impossible_jobs_session(middleware, gestionnaire, &mut session).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            // error!("creer_jobs_manquantes_session Error: {:?}", e);
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn maintenance_impossible_jobs_session<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    // Cleanup of jobs that will never complete
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_IMAGES_JOBS, 1_000, "processImage", session).await {
        error!("maintenance_impossible_jobs_session Erreur entretien images: {:?}", e);
    }
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_VIDEO_JOBS, 1_000, "processVideo", session).await {
        error!("maintenance_impossible_jobs_session Erreur entretien videos: {:?}", e);
    }
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_INDEXATION_JOBS, 1_000, "processIndex", session).await {
        error!("maintenance_impossible_jobs_session Erreur entretien index: {:?}", e);
    }

    Ok(())
}

/// Resubmits a batch of pending jobs to queue. Reactivates running jobs that have expired.
pub async fn reactiver_jobs<M>(middleware: &M,
                               nom_collection: &str, timeout: i64, limit: i64,
                               domain: &str, action: &str, fetch_filehosts: bool, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;

    // Reset le flag des jobs expirees
    let expiration = Utc::now() - chrono::Duration::new(timeout, 0).expect("duration");
    let filtre = doc!{"etat": VIDEO_CONVERSION_ETAT_RUNNING, "date_maj": {"$lte": expiration}};
    let ops = doc!{
        "$set": {"etat": VIDEO_CONVERSION_ETAT_PENDING},
        "$inc": {"retry": 1},
    };
    let result = collection.update_many_with_session(filtre.clone(), ops, None, session).await?;
    info!("reactiver_jobs Collection {}, {} filter: {:?}, result {:?}", nom_collection, action, filtre, result);

    let filtre = doc!{"etat": VIDEO_CONVERSION_ETAT_PENDING, "retry": {"$lte": CONST_MAX_RETRY}};
    let options = FindOptions::builder().limit(limit).build();

    // Resubmit jobs - duplicates in the Q will be caught when requesting job decryption key
    let mut fuuids = Vec::new();
    let mut curseur = collection.find_with_session(filtre, options, session).await?;
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        if let Some(fuuid) = row.fuuid.as_ref() {
            fuuids.push(fuuid.to_owned());
        }

        let trigger: JobTrigger = match action {
            "processIndex" => {
                let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
                let filtre = doc!{"tuuid": &row.tuuid};
                match collection.find_one(filtre, None).await? {
                    Some(fichier) => {
                        let mut trigger = JobTrigger::from(&row);
                        trigger.metadata = Some(fichier.metadata);
                        trigger.path_cuuids = fichier.path_cuuids;
                        trigger
                    },
                    None => {
                        // Cleanup job pour fichier inconnu
                        let filtre = doc!{"job_id": &row.job_id};
                        collection.delete_one(filtre, None).await?;
                        Err(CommonError::String(format!("reactiver_jobs Fichier inconnu tuuid (job maintenant supprimee):{}", row.tuuid)))?
                    }
                }
            },
            _ => (&row).into()
        };

        emettre_processing_trigger(middleware, trigger, domain, action).await;
    }

    debug!("reactiver_jobs Job collection {}, fuuids: {}", nom_collection, fuuids.len());

    // Synchronise with core in case some files were received without GrosFichiers being notified.
    if ! fuuids.is_empty() && fetch_filehosts {
        if let Err(e) = sync_jobs_core_filehosts(middleware, nom_collection, &fuuids, session).await {
            warn!("reactiver_jobs Error sync jobs with fuuids in core: {:?}", e);
        }
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct FuuidVisitResponseItem {pub fuuid: String, pub visits: HashMap<String, i64>}

#[derive(Deserialize)]
struct RequestFilehostsForFuuidsResponse {fuuids: Vec<FuuidVisitResponseItem>}

pub async fn sync_jobs_core_filehosts<M>(middleware: &M, nom_collection: &str, fuuids: &Vec<String>, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    debug!("Sync filehost_ids for {} fuuids", fuuids.len());
    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "requestFilehostsForFuuids", vec![Securite::L3Protege])
        .build();
    if let Some(TypeMessage::Valide(response)) = middleware.transmettre_requete(routage, json!({"fuuids": fuuids})).await? {
        debug!("Response: {}", from_utf8(&response.message.buffer)?);
        let response: RequestFilehostsForFuuidsResponse = deser_message_buffer!(response.message);

        let collection_jobs = middleware.get_collection(nom_collection)?;
        for fuuid_visits in response.fuuids {
            // Update the jobs table
            let filehost_ids: Vec<&String> = fuuid_visits.visits.keys().collect();
            let filtre = doc!{"fuuid": &fuuid_visits.fuuid};
            let ops = doc!{"$addToSet": {"filehost_ids": {"$each": filehost_ids}}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection_jobs.update_many_with_session(filtre.clone(), ops, None, session).await?;

            // Update visits in the versions tables
            sauvegarder_visites(middleware, fuuid_visits.fuuid.as_str(), &fuuid_visits.visits, session).await?;
        }
    }

    Ok(())
}

/// Deactivates for good jobs that have never been picked up or that have too many retries.
pub async fn remove_impossible_jobs<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager,
                                       nom_collection: &str, limit: i64, action: &str, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao + GenerateurMessages + ValidateurX509 {

    let expiration = Utc::now() - Duration::hours(8);
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;
    let filtre = doc!{
        "$or": [
            {"retry": {"$gt": CONST_MAX_RETRY}},  // Any job with retry > CONST_MAX_RETRY
            {CHAMP_MODIFICATION: {"$lte": expiration}},
        ]
    };
    // info!("remove_impossible_jobs Collection {} action {}, Filtre: {:?}", nom_collection, action, filtre);

    let options = FindOptions::builder().limit(limit).build();
    let mut curseur = collection.find_with_session(filtre, options, session).await?;
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;

        // Cancel the job, emit a transaction to clear for good
        warn!("remove_impossible_jobs Too many processing failures of type {} on fuuid {:?}, remove job", action, row.fuuid);
        match action {
            "processImage" => {
                match row.fuuid.as_ref() {
                    Some(fuuid) => {
                        // Create transaction to prevent job from running on restore.
                        let transaction = TransactionSupprimerJobImageV2 {
                            tuuid: row.tuuid,
                            fuuid: fuuid.to_owned(),
                            err: None,
                        };
                        sauvegarder_traiter_transaction_serializable_v2(
                            middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_IMAGE_SUPPRIMER_JOB_V2).await?;
                    },
                    None => {
                        warn!("remove_impossible_jobs Job image tuuid:{} with no fuuid, ignore", row.tuuid);
                    }
                }
            },
            "processVideo" => {
                match row.fuuid.as_ref() {
                    Some(fuuid) => {
                        // Create transaction to prevent job from running on restore.
                        let transaction = TransactionSupprimerJobVideoV2 {
                            tuuid: row.tuuid,
                            fuuid: fuuid.to_owned(),
                            job_id: row.job_id.clone(),
                        };
                        info!("remove_impossible_jobs Remove video job {:?}", transaction);
                        sauvegarder_traiter_transaction_serializable_v2(
                            middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_VIDEO_SUPPRIMER_JOB_V2).await?;
                    },
                    None => {
                        warn!("remove_impossible_jobs Job video tuuid:{} with no fuuid, ignore", row.tuuid);
                    }
                }
            },
            "processIndex" => {
                // Toggle index flag in reps/versions collections. There are no transactions for indexing.
                let fuuid = match row.fuuid.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None};
                set_flag_index_traite(middleware, row.job_id.as_str(), row.tuuid.as_str(), fuuid, session).await?;
            },
            _ => warn!("remove_impossible_jobs Unknown expired job type: {}", action)
        }

        // Ensure job removal
        let filtre = doc!{"job_id": &row.job_id};
        collection.delete_one_with_session(filtre, None, session).await?;
    }

    Ok(())
}
