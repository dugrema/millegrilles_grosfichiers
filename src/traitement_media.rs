use std::collections::HashMap;

use crate::domain_manager::GrosFichiersDomainManager;
use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::fichiers::is_mimetype_video;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::CommandeUsager;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::grosfichiers_constantes::*;
use crate::traitement_jobs::{sauvegarder_job, BackgroundJob, JobHandler, JobHandlerVersions};

const EVENEMENT_IMAGE_DISPONIBLE: &str = "jobImageDisponible";
const EVENEMENT_VIDEO_DISPONIBLE: &str = "jobVideoDisponible";

const ACTION_GENERER_POSTER_IMAGE: &str = "genererPosterImage";
const ACTION_GENERER_POSTER_PDF: &str = "genererPosterPdf";
const ACTION_GENERER_POSTER_VIDEO: &str = "genererPosterVideo";
const ACTION_TRANSCODER_VIDEO: &str = "transcoderVideo";

#[derive(Clone, Debug)]
pub struct ImageJobHandler {}

#[async_trait]
impl JobHandler for ImageJobHandler {

    fn get_nom_collection(&self) -> &str { NOM_COLLECTION_IMAGES_JOBS }

    fn get_nom_flag(&self) -> &str { CHAMP_FLAG_MEDIA_TRAITE }

    fn get_action_evenement(&self) -> &str { EVENEMENT_IMAGE_DISPONIBLE }

    async fn marquer_job_erreur<M,G,S>(&self, middleware: &M, gestionnaire_domaine: &G, job: BackgroundJob, erreur: S)
        -> Result<(), CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            G: GestionnaireDomaineV2 + AiguillageTransactions,
            S: ToString + Send
    {
        let erreur = erreur.to_string();
        let transaction = TransactionSupprimerJobImageV2 {
            tuuid: job.tuuid,
            fuuid: job.fuuid,
            err: Some(erreur),
        };

        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction, gestionnaire_domaine,
            DOMAINE_NOM, TRANSACTION_IMAGE_SUPPRIMER_JOB_V2).await?;

        Ok(())
    }

}

#[async_trait]
impl JobHandlerVersions for ImageJobHandler {

    // async fn sauvegarder_job<M, S, U>(
    //     &self, middleware: &M, fuuid: S, user_id: U, instances: Option<Vec<String>>,
    //     mut champs_cles: Option<HashMap<String, String>>,
    //     parametres: Option<HashMap<String, Bson>>,
    //     emettre_trigger: bool,
    // )
    //     -> Result<(), CommonError>
    //     where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send
    // {
    //     let fuuid = fuuid.as_ref();
    //     let user_id = user_id.as_ref();
    //
    //     // Trouver le mimetype
    //     let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
    //     let filtre = doc!{CHAMP_FUUID: fuuid, CHAMP_USER_ID: user_id};
    //     let mut curseur = collection.find(filtre, None).await?;
    //     let mimetype = match curseur.advance().await? {
    //         true => {
    //             let row = curseur.deserialize_current()?;
    //             row.mimetype.to_owned()
    //         },
    //         false => {
    //             debug!("sauvegarder_job Mimetype absent, skip sauvegarder job image");
    //             return Ok(())
    //         }
    //     };
    //
    //     // Tester le mimetype pour savoir si la job s'applique
    //     if job_image_supportee(&mimetype) {
    //         debug!("sauvegarder_job image type {} instances {:?}", mimetype, instances);
    //         sauvegarder_job(middleware, self, fuuid, user_id, instances.clone(), champs_cles, parametres).await?;
    //
    //         if let Some(inner) = instances {
    //             if emettre_trigger {
    //                 for instance in inner {
    //                     self.emettre_trigger(middleware, instance).await;
    //                 }
    //             }
    //         }
    //     }
    //
    //     Ok(())
    // }

}

#[derive(Clone, Debug)]
pub struct VideoJobHandler {}

// #[async_trait]
// impl JobHandler for VideoJobHandler {
//
//     fn get_nom_collection(&self) -> &str { NOM_COLLECTION_VIDEO_JOBS }
//
//     fn get_nom_flag(&self) -> &str { CHAMP_FLAG_VIDEO_TRAITE }
//
//     fn get_action_evenement(&self) -> &str { EVENEMENT_VIDEO_DISPONIBLE }
//
//     // async fn marquer_job_erreur<M,G,S>(&self, middleware: &M, gestionnaire_domaine: &G, job: BackgroundJob, erreur: S)
//     //     -> Result<(), CommonError>
//     //     where
//     //         M: ValidateurX509 + GenerateurMessages + MongoDao,
//     //         G: GestionnaireDomaineV2 + AiguillageTransactions,
//     //         S: ToString + Send
//     // {
//     //     let erreur = erreur.to_string();
//     //
//     //     let fuuid = match job.fuuid {
//     //         Some(inner) => inner,
//     //         None => Err(format!("VideoJobHandler fuuid manquant"))?
//     //     };
//     //     // let fuuid = job.fuuid;
//     //     let user_id = job.user_id;
//     //     let champs_cles = job.champs_optionnels;
//     //     let cle_conversion = match champs_cles.get("cle_conversion") {
//     //         Some(inner) => match inner.as_str() {
//     //             Some(inner) => inner.to_owned(),
//     //             None => Err(format!("VideoJobHandler Erreur suppression job - cle_conversion mauvais format (!str)"))?
//     //         },
//     //         None => Err(format!("VideoJobHandler Erreur suppression job - cle_conversion manquant"))?
//     //     };
//     //     let transaction = TransactionSupprimerJobVideo {
//     //         fuuid,
//     //         cle_conversion,
//     //         user_id: Some(user_id),
//     //         err: Some(erreur),
//     //     };
//     //
//     //     sauvegarder_traiter_transaction_serializable_v2(
//     //         middleware, &transaction, gestionnaire_domaine,
//     //         DOMAINE_NOM, TRANSACTION_VIDEO_SUPPRIMER_JOB).await?;
//     //
//     //     Ok(())
//     // }
//
// }

// #[async_trait]
// impl JobHandlerVersions for VideoJobHandler {
//
//     // async fn sauvegarder_job<M, S, U>(
//     //     &self, middleware: &M, fuuid: S, user_id: U, instances: Option<Vec<String>>,
//     //     mut champs_cles: Option<HashMap<String, String>>,
//     //     parametres: Option<HashMap<String, Bson>>,
//     //     emettre_trigger: bool,
//     // )
//     //     -> Result<(), CommonError>
//     //     where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send
//     // {
//     //     let fuuid = fuuid.as_ref();
//     //     let user_id = user_id.as_ref();
//     //
//     //     // Trouver le mimetype
//     //     let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
//     //     let filtre = doc!{CHAMP_FUUID: fuuid, CHAMP_USER_ID: user_id};
//     //     let mut curseur = collection.find(filtre, None).await?;
//     //     let mimetype = match curseur.advance().await? {
//     //         true => {
//     //             let row = curseur.deserialize_current()?;
//     //             row.mimetype.to_owned()
//     //         },
//     //         false => {
//     //             debug!("sauvegarder_job Mimetype absent, skip sauvegarder job image");
//     //             return Ok(())
//     //         }
//     //     };
//     //
//     //     // let mimetype = match champs_cles.as_ref() {
//     //     //     Some(inner) => {
//     //     //         match inner.get("mimetype") {
//     //     //             Some(inner) => inner,
//     //     //             None => {
//     //     //                 debug!("sauvegarder_job Mimetype absent, skip sauvegarder job video");
//     //     //                 return Ok(())
//     //     //             }
//     //     //         }
//     //     //     },
//     //     //     None => {
//     //     //         debug!("sauvegarder_job Mimetype absent, skip sauvegarder job video");
//     //     //         return Ok(())
//     //     //     }
//     //     // };
//     //
//     //     // Tester le mimetype pour savoir si la job s'applique
//     //     if ! job_video_supportee(&mimetype) {
//     //         debug!("sauvegarder_job video, type {} non supporte", mimetype);
//     //         return Ok(())
//     //     }
//     //
//     //     let mut champs_cles = match champs_cles {
//     //         Some(inner) => inner,
//     //         None => HashMap::new()
//     //     };
//     //     // Ajouter cle de conversion
//     //     champs_cles.insert("cle_conversion".to_string(), "video/mp4;h264;270p;28".to_string());
//     //
//     //     // let instance = instance.as_ref();
//     //
//     //     // S'assurer d'avoir des parametres - ajouter au besoin. Ne fait pas d'override de job existante.
//     //     let mut parametres = match parametres {
//     //         Some(parametres) => parametres.clone(),
//     //         None => HashMap::new()
//     //         //     {
//     //         //     // Ajouter params de la job 270p
//     //         //     let mut parametres = HashMap::new();
//     //         //
//     //         //     parametres.insert("bitrateAudio".to_string(), Bson::Int64(64000));
//     //         //     parametres.insert("bitrateVideo".to_string(), Bson::Int64(250000));
//     //         //     parametres.insert("qualityVideo".to_string(), Bson::Int64(28));
//     //         //     parametres.insert("resolutionVideo".to_string(), Bson::Int64(270));
//     //         //     parametres.insert("codecAudio".to_string(), Bson::String("aac".to_string()));
//     //         //     parametres.insert("codecVideo".to_string(), Bson::String("h264".to_string()));
//     //         //     parametres.insert("preset".to_string(), Bson::String("medium".to_string()));
//     //         //     parametres.insert("fallback".to_string(), Bson::Boolean(true));
//     //         //
//     //         //     parametres
//     //         // }
//     //     };
//     //
//     //     parametres.insert("bitrateAudio".to_string(), Bson::Int64(64000));
//     //     parametres.insert("bitrateVideo".to_string(), Bson::Int64(250000));
//     //     parametres.insert("qualityVideo".to_string(), Bson::Int64(28));
//     //     parametres.insert("resolutionVideo".to_string(), Bson::Int64(270));
//     //     parametres.insert("codecAudio".to_string(), Bson::String("aac".to_string()));
//     //     parametres.insert("codecVideo".to_string(), Bson::String("h264".to_string()));
//     //     parametres.insert("preset".to_string(), Bson::String("medium".to_string()));
//     //     parametres.insert("fallback".to_string(), Bson::Boolean(true));
//     //
//     //     sauvegarder_job(middleware, self, fuuid, user_id, instances.clone(), Some(champs_cles), Some(parametres)).await?;
//     //
//     //     if let Some(inner) = instances {
//     //         if emettre_trigger {
//     //             for instance in inner {
//     //                 self.emettre_trigger(middleware, instance).await;
//     //             }
//     //         }
//     //     }
//     //
//     //     Ok(())
//     // }
//
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobCles {
    fuuid: String,
    cle_conversion: String,
    visites: Option<HashMap<String, DateTime<Utc>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobDetail {
    fuuid: String,
    tuuid: Option<String>,
    cle_conversion: String,
    user_id: Option<String>,
    pct_progres: Option<usize>,
    etat: Option<u16>,
    flag_media_retry: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteJobsVideo {
    toutes_jobs: Option<bool>,
}

pub async fn requete_jobs_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_jobs_video Message : {:?}", & m.type_message);
    let message_ref = m.message.parse()?;
    let requete: RequeteJobsVideo = message_ref.contenu()?.deserialize()?;

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let mut filtre = doc! {};

    if role_prive && user_id.is_some() {
        // Ok
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
        let inserer_userid = match requete.toutes_jobs {
            Some(b) => ! b,  // Ne pas ajouter le filtre user_id - chercher toutes les jobs
            None => true
        };
        if user_id.is_none() && inserer_userid {
            Err(format!("User_id manquant"))?
        }
        if inserer_userid {
            filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
        }
    } else {
        Err(format!("grosfichiers.requete_jobs_video: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    debug!("requete_jobs_video Filtre {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut jobs = Vec::new();
    while let Some(d) = curseur.next().await {
        let job_detail: JobDetail = convertir_bson_deserializable(d?)?;
        jobs.push(job_detail);
    }

    let reponse = json!({ "jobs":  jobs });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn commande_supprimer_job_image<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    Ok(Some(middleware.reponse_err(Some(999), None, Some("Obsolete"))?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSupprimerJobImageV2 {tuuid: String, fuuid: String}

pub async fn commande_supprimer_job_image_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_job_image_v2 Consommer commande : {:?}", & m.type_message);
    let _commande: CommandeSupprimerJobImageV2 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? && m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Err(format!("traitement_media.commande_supprimer_job_image_v2 Certificat doit avoir L3Protege et role media"))?;
    }

    // let tuuid = &commande.tuuid;
    // let fuuid = &commande.fuuid;
    // set_flag_image_traitee(middleware, tuuid, fuuid).await?;

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?)

    // {
    //     // Verifier si on a un flag de traitement video pending sur versions
    //     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let filtre = doc!{ CHAMP_TUUID: tuuid, CHAMP_FUUID: fuuid };
    //     debug!("commande_supprimer_job_image Verifier si flag job image est actif pour {:?}", filtre);
    //     match collection_versions.find_one(filtre, None).await? {
    //         Some(inner) => {
    //             let info_fichier: DBFichierVersionDetail = convertir_bson_deserializable(inner)?;
    //             if let Some(false) = info_fichier.flag_media_traite {
    //                 sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;
    //             }
    //         },
    //         None => warn!("Recu message annuler job image sans doc fichier version")
    //     };
    // }
    //
    // gestionnaire.image_job_handler.set_flag(middleware, fuuid, Some(user_id), None, true).await?;
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSupprimerJobVideoV2 {
    tuuid: String,
    fuuid: String,
    job_id: String,
}

pub async fn commande_supprimer_job_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    Ok(Some(middleware.reponse_err(Some(999), None, Some("Obsolete"))?))
}

pub async fn commande_supprimer_job_video_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    todo!()

    // debug!("commande_supprimer_job_video_v2 Consommer commande : {:?}", & m.type_message);
    // let commande: CommandeSupprimerJobVideoV2 = {
    //     let message_ref = m.message.parse()?;
    //     message_ref.contenu()?.deserialize()?
    // };
    //
    // if m.certificat.verifier_roles(vec![RolesCertificats::Media])? && m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
    //     // Ok
    // } else if m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? || m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
    //     // Ok
    // } else {
    //     Err(format!("traitement_media.commande_supprimer_job_video Echec verification securite, acces refuse"))?
    // };
    //
    // {
    //     // Emettre evenement annulerJobVideo pour media, collections
    //     let routage = RoutageMessageAction::builder(
    //         DOMAINE_NOM, EVENEMENT_ANNULER_JOB_VIDEO, vec![Securite::L3Protege])
    //         .build();
    //     middleware.emettre_evenement(routage, &commande).await?;
    // }
    //
    // // Determiner si la job est active et pour le video initial (params.initial == 'true')
    // let job_initiale = true;
    //
    // if job_initiale {
    //     // Convertir en transaction pour desactiver le flag de traitement video et supprimer la job
    //     sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;
    // } else {
    //     debug!("Supprimer job video {}", commande.job_id);
    //     todo!()
    // }
    //
    // {
    //     // Verifier si on a un flag de traitement video pending sur versions
    //     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let filtre = doc!{ CHAMP_FUUID: fuuid, CHAMP_USER_ID: &user_id };
    //     debug!("commande_supprimer_job_video Verifier si flag job video est actif pour {:?}", filtre);
    //     match collection_versions.find_one(filtre, None).await? {
    //         Some(inner) => {
    //             let info_fichier: DBFichierVersionDetail = convertir_bson_deserializable(inner)?;
    //             if let Some(false) = info_fichier.flag_video_traite {
    //                 sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;
    //             }
    //         },
    //         None => warn!("Recu message annuler job video sans doc fichier version")
    //     };
    // }
    //
    // let mut cles_supplementaires = HashMap::new();
    // cles_supplementaires.insert("cle_conversion".to_string(), commande.cle_conversion.clone());
    // gestionnaire.video_job_handler.set_flag(middleware, fuuid, Some(&user_id), Some(cles_supplementaires), true).await?;
    //
    // // Emettre un evenement pour clients
    // let evenement = json!({
    //     "cle_conversion": commande.cle_conversion,
    //     "fuuid": fuuid,
    // });
    // let routage = RoutageMessageAction::builder(DOMAINE_NOM, "jobSupprimee", vec![Securite::L2Prive])
    //     .partition(user_id)
    //     .build();
    // middleware.emettre_evenement(routage, &evenement).await?;
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
}

fn job_image_supportee<S>(mimetype: S) -> bool
    where S: AsRef<str>
{
    let mimetype = mimetype.as_ref();

    if is_mimetype_video(mimetype) {
        return true;
    }

    match mimetype {
        "application/pdf" => true,
        _ => {
            let subtype = match mimetype.split("/").next() {
                Some(t) => t,
                None => {
                    error!("traitement_media.job_image_supportee Mimetype {}, subtype non identifiable", mimetype);
                    return false
                }
            };
            match subtype {
                // "video" => true,
                "image" => true,
                _ => false
            }
        }
    }
}

fn job_video_supportee<S>(mimetype: S) -> bool
    where S: AsRef<str>
{
    is_mimetype_video(mimetype)
}

pub async fn set_flag_image_traitee<M,S>(middleware: &M, tuuid_in: Option<S>, fuuid: &str) -> Result<(), CommonError>
    where M: MongoDao, S: ToString
{
    let tuuid = match &tuuid_in {Some(inner)=>Some(inner.to_string()), None=>None};

    // Set flag versionFichiers

    // Supprimer job image

    todo!()
}

pub async fn set_flag_video_traite<M,S>(middleware: &M, tuuid_in: Option<S>, fuuid: &str) -> Result<(), CommonError>
    where M: MongoDao, S: ToString
{
    let tuuid = match &tuuid_in {Some(inner)=>Some(inner.to_string()), None=>None};

    // Set flag versionFichiers

    // Supprimer job video initiale (params.initial == 'true')

    todo!()
}

async fn sauvegarder_job_images<M>(middleware: &M, job: &BackgroundJob) -> Result<BackgroundJob, CommonError>
where M: MongoDao
{
    sauvegarder_job(middleware, job, NOM_COLLECTION_IMAGES_JOBS).await
}

async fn sauvegarder_job_video<M>(middleware: &M, job: &BackgroundJob) -> Result<BackgroundJob, CommonError>
where M: MongoDao
{
    sauvegarder_job(middleware, job, NOM_COLLECTION_IMAGES_JOBS).await
}
