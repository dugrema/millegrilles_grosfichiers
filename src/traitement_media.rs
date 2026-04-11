use std::collections::HashMap;

use crate::domain_manager::GrosFichiersDomainManager;
use log::{debug, error};
use millegrilles_common_rust::bson::{doc, Bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::fichiers::is_mimetype_video;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_v2;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{optionepochseconds, MessageMilleGrillesBufferDefault};
use millegrilles_common_rust::mongo_dao::{opt_chrono_datetime_as_bson_datetime, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{json, Value};

use crate::grosfichiers_constantes::*;
use crate::traitement_jobs::{sauvegarder_job, BackgroundJob, JobTrigger};
use crate::transactions::TransactionSupprimerJobVideoV2;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobDetail {
    job_id: String,
    user_id: String,
    tuuid: String,
    fuuid: String,
    mimetype: Option<String>,
    filehost_ids: Vec<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pct_progres: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    etat: Option<u16>,
    #[serde(skip_serializing_if="Option::is_none")]
    retry: Option<u16>,
    #[serde(default, skip_serializing_if="Option::is_none", serialize_with="optionepochseconds::serialize", deserialize_with="opt_chrono_datetime_as_bson_datetime::deserialize")]
    date_maj: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if="Option::is_none")]
    params: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteJobsVideo {
    toutes_jobs: Option<bool>,
}

pub async fn requete_jobs_video<M>(middleware: &M, m: MessageValide, _gestionnaire: &GrosFichiersDomainManager)
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

    let collection = middleware.get_collection_typed::<JobDetail>(NOM_COLLECTION_VIDEO_JOBS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut jobs = Vec::new();
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        jobs.push(row);
    }

    let reponse = json!({ "jobs":  jobs });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSupprimerJobImageV2 {fuuid: String}

pub async fn commande_supprimer_job_image_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let commande: CommandeSupprimerJobImageV2 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? && m.certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        Err(format!("traitement_media.commande_supprimer_job_image_v2 Certificat doit avoir L2Prive et role media"))?;
    }

    debug!("commande_supprimer_job_image_v2 Supprimer job fuuid : {:?}", commande.fuuid);
    sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Remove lease
    let lease_collection = middleware.get_collection(NOM_COLLECTION_JOBS_VERSIONS_LEASES)?;
    let lease_filtre = doc!{CHAMP_FUUID: commande.fuuid, "borrower": CHAMP_FLAG_MEDIA_TRAITE};
    lease_collection.delete_one_with_session(lease_filtre, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_supprimer_job_video_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let commande: TransactionSupprimerJobVideoV2 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    if m.certificat.verifier_roles(vec![RolesCertificats::Media])? && m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
        // Ok
    } else if m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? || m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("traitement_media.commande_supprimer_job_video Echec verification securite, acces refuse"))?
    };

    debug!("commande_supprimer_job_video_v2 Supprimer video fuuid:{} job_id:{}", commande.fuuid, commande.job_id);

    {
        // Emettre evenement annulerJobVideo pour media, collections
        let routage = RoutageMessageAction::builder(
            DOMAINE_NOM, EVENEMENT_ANNULER_JOB_VIDEO, vec![Securite::L3Protege])
            .build();
        middleware.emettre_evenement(routage, &commande).await?;
    }

    // Determiner si la job est active et pour le video initial (params.defaults == 'true')
    let collection = middleware.get_collection_typed::<BackgroundJob>(NOM_COLLECTION_VIDEO_JOBS)?;
    let filtre = doc!{"job_id": &commande.job_id};
    if let Some(job) = collection.find_one_with_session(filtre, None, session).await? {
        let initial = match job.params {
            Some(inner) => inner.defaults.is_some(),
            None => false
        };

        if initial {
            debug!("commande_supprimer_job_video_v2 Error during initial video processing, abort for good on fuuid {}", commande.fuuid);
            // Convertir en transaction pour desactiver le flag de traitement video et supprimer la job
            sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;
        }

        // Emettre un evenement pour clients
        if let Some(user_id) = job.user_id.as_ref() {
            let evenement = json!({"job_id": &commande.job_id, "fuuid": &commande.fuuid, "tuuid": &commande.tuuid});
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, "jobSupprimee", vec![Securite::L2Prive])
                .partition(user_id)
                .build();
            middleware.emettre_evenement(routage, &evenement).await?;
        }
    }

    debug!("Supprimer job video {}", commande.job_id);
    set_flag_video_traite(middleware, Some(&commande.tuuid), &commande.fuuid, Some(&commande.job_id), session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

fn job_video_supportee<S>(mimetype: S) -> bool
    where S: AsRef<str>
{
    is_mimetype_video(mimetype)
}

pub async fn set_flag_image_traitee<M>(middleware: &M, fuuid: &str, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao
{
    // let tuuid = match &tuuid_in {Some(inner)=>Some(inner.to_string()), None=>None};

    // Set flag versionFichiers
    let filtre = doc! {"fuuid": fuuid};
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let ops = doc! {
        "$set": {CHAMP_FLAG_MEDIA_TRAITE: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_many_with_session(filtre, ops, None, session).await?;

    // // Supprimer job image
    // let mut filtre = doc! {"fuuid": fuuid};
    // if let Some(tuuid) = tuuid.as_ref() {
    //     filtre.insert("tuuid", tuuid);
    // }
    // let collection = middleware.get_collection(NOM_COLLECTION_IMAGES_JOBS)?;
    // collection.delete_many_with_session(filtre, None, session).await?;

    Ok(())
}

pub async fn set_flag_video_traite<M,S>(middleware: &M, tuuid_in: Option<S>, fuuid: &str, job_id: Option<&str>, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao, S: ToString
{
    // let tuuid = match &tuuid_in {Some(inner)=>Some(inner.to_string()), None=>None};

    let mut filtre_video = doc! {"fuuid": fuuid};
    if let Some(tuuid) = tuuid_in.as_ref() {
        filtre_video.insert("tuuids", tuuid.to_string());
    }

    // Set flag versionFichiers
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let ops = doc! {
        "$set": {
            CHAMP_FLAG_VIDEO_TRAITE: true,
            CHAMP_FLAG_MEDIA_TRAITE: true,  // legacy pour eviter de laisser un flag actif pre release-2024.9
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_many_with_session(filtre_video.clone(), ops, None, session).await?;

    // Supprimer job image
    let filtre_job = match job_id {
        Some(inner) => doc!{"job_id": inner},
        None => filtre_video
    };
    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    collection.delete_many_with_session(filtre_job, None, session).await?;

    Ok(())
}

// pub async fn sauvegarder_job_images<M>(middleware: &M, job: &BackgroundJob, session: &mut ClientSession) -> Result<Option<BackgroundJob>, CommonError>
// where M: GenerateurMessages + MongoDao
// {
//     let mimetype = job.mimetype.as_str();
//     if job_image_supportee(mimetype) {
//         Ok(Some(sauvegarder_job(middleware, job, None, NOM_COLLECTION_IMAGES_JOBS, "media", "processImage", session).await?))
//     } else {
//         Ok(None)
//     }
// }

pub async fn sauvegarder_job_video<M>(middleware: &M, job: &BackgroundJob, session: &mut ClientSession) -> Result<Option<BackgroundJob>, CommonError>
where M: GenerateurMessages + MongoDao
{
    let mimetype = job.mimetype.as_str();
    if job_video_supportee(mimetype) {
        Ok(Some(sauvegarder_job(middleware, job, None, NOM_COLLECTION_VIDEO_JOBS, "media", "processVideo", session).await?))
    } else {
        Ok(None)
    }
}

pub async fn emettre_processing_trigger<'a, M,T>(middleware: &M, trigger: T, domain: &str, action: &str)
where M: GenerateurMessages, T: Into<JobTrigger<'a>> {
    // let trigger = JobTrigger::from(background_job);
    let trigger = trigger.into();
    if trigger.filehost_ids.is_empty() {
        let routage = RoutageMessageAction::builder(domain, action, vec![Securite::L2Prive])
            .blocking(false)
            .build();
        if let Err(e) = middleware.transmettre_commande(routage, &trigger).await {
            error!("emettre_processing_trigger Erreur emission trigger commande.{}.{} : {:?}", domain, action, e);
        }
    } else {
        for filehost_id in trigger.filehost_ids {
            let routage = RoutageMessageAction::builder(domain, action, vec![Securite::L2Prive])
                .partition(filehost_id)
                .blocking(false)
                .build();
            if let Err(e) = middleware.transmettre_commande(routage, &trigger).await {
                error!("emettre_processing_trigger Erreur emission trigger commande.{}.{}.{} : {:?}", domain, filehost_id, action, e);
            }
        }
    }
}
