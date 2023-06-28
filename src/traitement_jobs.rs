use std::collections::HashMap;
use std::error::Error;
use std::time::Duration as std_Duration;
use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, DateTime, doc};
use millegrilles_common_rust::certificats::EnveloppeCertificat;
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::grosfichiers_constantes::*;
use crate::transactions::DataChiffre;

const CONST_MAX_RETRY: i32 = 3;
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
        &self, middleware: &M, fuuid: S, user_id: U,
        cles_supplementaires: Option<HashMap<String, String>>,
        valeur: bool
    ) -> Result<(), Box<dyn Error>>
    where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
        set_flag(middleware, self, fuuid, user_id, cles_supplementaires, valeur).await
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

async fn set_flag<M,J,S,U>(
    middleware: &M, job_handler: &J, fuuid: S, user_id: U,
    cles_supplementaires: Option<HashMap<String, String>>,
    valeur: bool
) -> Result<(), Box<dyn Error>>
    where M: MongoDao, J: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
{
    let fuuid = fuuid.as_ref();
    let user_id = user_id.as_ref();

    let mut filtre = doc!{
        CHAMP_USER_ID: user_id,
        CHAMP_FUUID: fuuid,
    };

    if let Some(inner) = cles_supplementaires {
        for (k, v) in inner.into_iter() {
            filtre.insert(k, v);
        }
    }

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
            // CONST_CHAMP_RETRY: { "$lt": CONST_MAX_RETRY },
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

        let filtre_job = doc!{CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};

        let job_existante: Option<BackgroundJob> = match collection_jobs.find_one(filtre_job.clone(), None).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        };

        if let Some(job) = job_existante {
            if job.retry > CONST_MAX_RETRY {
                warn!("traiter_indexation_batch Expirer indexation sur document user_id {} tuuid {} : {} retries",
                    user_id, tuuid_ref, job.retry);
                let ops = doc!{
                    "$set": {
                        champ_flag_index: true,
                        format!("{}_erreur", champ_flag_index): ERREUR_MEDIA_TOOMANYRETRIES,
                    }
                };
                let filtre_version = doc!{CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};
                collection_versions.update_one(filtre_version, ops, None).await?;
                collection_jobs.delete_one(filtre_job, None).await?;
                continue;
            }
        }

        // Creer ou mettre a jour la job
        if let Some(visites) = version_mappee.visites {
            for instance in visites.into_keys() {
                let mut champs_cles = HashMap::new();
                champs_cles.insert("mimetype".to_string(), mimetype_ref.to_string());
                champs_cles.insert("tuuid".to_string(), tuuid_ref.to_string());
                job_handler.sauvegarder_job(
                    middleware, fuuid_ref, user_id,
                    Some(instance), Some(champs_cles), None,
                    false).await?;
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
        CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING,
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

    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
    collection_jobs.update_one(filtre, ops_job, options).await?;

    Ok(Some(instances))
}

pub struct CommandeGetJob {}

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
            Some(inner) => Some(inner.to_string()),
            None => None
        };
        let codec_video = match value.champs_optionnels.get("codec_video") {
            Some(inner) => Some(inner.to_string()),
            None => None
        };
        let codec_audio = match value.champs_optionnels.get("codec_audio") {
            Some(inner) => Some(inner.to_string()),
            None => None
        };
        let preset = match value.champs_optionnels.get("preset") {
            Some(inner) => Some(inner.to_string()),
            None => None
        };

        // u32 params
        let resolution_video = match value.champs_optionnels.get("resolution_video") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as u32),
                None => None
            },
            None => None
        };
        let quality_video = match value.champs_optionnels.get("quality_video") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as i32),
                None => None
            },
            None => None
        };
        let bitrate_video = match value.champs_optionnels.get("bitrate_video") {
            Some(inner) => match inner.as_i64() {
                Some(inner) => Some(inner as u32),
                None => None
            },
            None => None
        };
        let bitrate_audio = match value.champs_optionnels.get("bitrate_audio") {
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
    debug!("commande_get_job Get pour {}", nom_collection);
    let prochaine_job = trouver_prochaine_job_indexation(middleware, nom_collection).await?;

    debug!("commande_get_job Prochaine job : {:?}", prochaine_job);

    match prochaine_job {
        Some(job) => {
            // Recuperer les metadonnees
            let fichier_detail: FichierDetail = {
                let mut filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_TUUID: &job.tuuid };
                debug!("commande_get_job Chargement job pour fichier {:?}", filtre);
                let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
                if let Some(inner) = collection.find_one(filtre, None).await? {
                    convertir_bson_deserializable(inner)?
                } else {
                    Err(format!("commandes.commande_indexation_get_job Erreur indexation - job pour document inexistant user_id:{} tuuid:{}", job.user_id, job.tuuid))?
                }
            };

            let metadata = match fichier_detail.metadata {
                Some(inner) => inner,
                None => Err(format!("commandes.commande_indexation_get_job Erreur indexation - job pour document sans metadata (1) user_id:{} tuuid:{}", job.user_id, job.tuuid))?
            };
            // let metadata = match fichier_detail.version_courante {
            //     Some(inner) => match inner.metadata {
            //         Some(inner) => inner,
            //         None => Err(format!("commandes.commande_indexation_get_job Erreur indexation - job pour document sans metadata (1) user_id:{} tuuid:{}", job.user_id, job.tuuid))?
            //     },
            //     None => Err(format!("commandes.commande_indexation_get_job Erreur indexation - job pour document sans version_courante (2) user_id:{} tuuid:{}", job.user_id, job.tuuid))?
            // };

            let mimetype = match fichier_detail.mimetype.as_ref() {
                Some(inner) => inner.as_str(),
                None => "application/octet-stream"
            };

            // Recuperer la cle de dechiffrage du fichier
            let cle = get_cle_job_indexation(
                middleware, job.fuuid.as_str(), certificat).await?;

            let mut reponse_job = ReponseJob::from(job);
            reponse_job.metadata = Some(metadata);
            reponse_job.mimetype = Some(mimetype.to_string());
            reponse_job.cle = Some(cle);
            debug!("Reponse job : {:?}", reponse_job);

            Ok(reponse_job)
        },
        None => Ok(ReponseJob::from("Aucun fichier a indexer"))
    }
}

pub async fn trouver_prochaine_job_indexation<M,S>(middleware: &M, nom_collection: S)
    -> Result<Option<BackgroundJob>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
{
    let collection = middleware.get_collection(nom_collection.as_ref())?;

    let job: Option<BackgroundJob> = {
        // Tenter de trouver la prochaine job disponible
        let filtre = doc! {CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING};
        //let hint = Some(Hint::Name("etat_jobs".into()));
        let options = FindOneAndUpdateOptions::builder()
            //.hint(hint)
            .return_document(ReturnDocument::Before)
            .build();
        let ops = doc! {
            "$set": {CHAMP_ETAT: VIDEO_CONVERSION_ETAT_PENDING},
            "$inc": {CONST_CHAMP_RETRY: 1},
            "$currentDate": {CHAMP_MODIFICATION: true, CONST_CHAMP_DATE_MAJ: true}
        };
        match collection.find_one_and_update(filtre, ops, options).await? {
            Some(d) => {
                debug!("trouver_prochaine_job_indexation (1) Charger job : {:?}", d);
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

    Ok(cle)
}

#[derive(Clone, Debug, Deserialize)]
pub struct ParametresConfirmerJob {
    pub fuuid: String,
    pub user_id: String,
    pub cle_conversion: Option<String>,
}
