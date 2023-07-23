use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::grosfichiers::GestionnaireGrosFichiers;

use crate::grosfichiers_constantes::*;
use crate::requetes::mapper_fichier_db;
use crate::traitement_jobs::{JobHandler, sauvegarder_job};

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

    async fn sauvegarder_job<M, S, U>(
        &self, middleware: &M, fuuid: S, user_id: U, instance: Option<String>,
        mut champs_cles: Option<HashMap<String, String>>,
        parametres: Option<HashMap<String, Bson>>,
        emettre_trigger: bool,
    )
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send
    {
        // Tester le mimetype pour savoir si la job s'applique
        let mimetype = match champs_cles.as_ref() {
            Some(inner) => {
                match inner.get("mimetype") {
                    Some(inner) => inner,
                    None => {
                        debug!("sauvegarder_job Mimetype absent, skip sauvegarder job image");
                        return Ok(())
                    }
                }
            },
            None => {
                debug!("sauvegarder_job Mimetype absent, skip sauvegarder job image");
                return Ok(())
            }
        };

        if job_image_supportee(mimetype) {
            debug!("sauvegarder_job image type {}", mimetype);
            sauvegarder_job(middleware, self, fuuid, user_id, instance.clone(), champs_cles, parametres).await?;

            if let Some(inner) = instance {
                if emettre_trigger {
                    self.emettre_trigger(middleware, inner).await;
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VideoJobHandler {}

#[async_trait]
impl JobHandler for VideoJobHandler {

    fn get_nom_collection(&self) -> &str { NOM_COLLECTION_VIDEO_JOBS }

    fn get_nom_flag(&self) -> &str { CHAMP_FLAG_VIDEO_TRAITE }

    fn get_action_evenement(&self) -> &str { EVENEMENT_VIDEO_DISPONIBLE }

    async fn sauvegarder_job<M, S, U>(
        &self, middleware: &M, fuuid: S, user_id: U, instance: Option<String>,
        mut champs_cles: Option<HashMap<String, String>>,
        parametres: Option<HashMap<String, Bson>>,
        emettre_trigger: bool,
    )
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send
    {

        // Tester le mimetype pour savoir si la job s'applique
        let mimetype = match champs_cles.as_ref() {
            Some(inner) => {
                match inner.get("mimetype") {
                    Some(inner) => inner,
                    None => {
                        debug!("sauvegarder_job Mimetype absent, skip sauvegarder job video");
                        return Ok(())
                    }
                }
            },
            None => {
                debug!("sauvegarder_job Mimetype absent, skip sauvegarder job video");
                return Ok(())
            }
        };

        if ! job_video_supportee(mimetype) {
            debug!("sauvegarder_job video, type {} non supporte", mimetype);
            return Ok(())
            // sauvegarder_job(middleware, self, fuuid, user_id, instance.clone(), champs_cles, parametres).await?;
            //
            // if let Some(inner) = instance {
            //     if emettre_trigger {
            //         self.emettre_trigger(middleware, inner).await;
            //     }
            // }
        }


        let mut champs_cles = match champs_cles {
            Some(inner) => inner,
            None => HashMap::new()
        };
        // Ajouter cle de conversion
        champs_cles.insert("cle_conversion".to_string(), "video/mp4;h264;270p;28".to_string());

        // let instance = instance.as_ref();

        // S'assurer d'avoir des parametres - ajouter au besoin. Ne fait pas d'override de job existante.
        let parametres = match parametres {
            Some(parametres) => parametres,
            None => {
                // Ajouter params de la job 270p
                let mut parametres = HashMap::new();

                parametres.insert("bitrateAudio".to_string(), Bson::Int64(64000));
                parametres.insert("bitrateVideo".to_string(), Bson::Int64(250000));
                parametres.insert("qualityVideo".to_string(), Bson::Int64(28));
                parametres.insert("resolutionVideo".to_string(), Bson::Int64(270));
                parametres.insert("codecAudio".to_string(), Bson::String("aac".to_string()));
                parametres.insert("codecVideo".to_string(), Bson::String("h264".to_string()));
                parametres.insert("preset".to_string(), Bson::String("medium".to_string()));
                parametres.insert("fallback".to_string(), Bson::Boolean(true));

                parametres
            }
        };

        sauvegarder_job(middleware, self, fuuid, user_id, instance.clone(), Some(champs_cles), Some(parametres)).await?;

        if let Some(inner) = instance {
            if emettre_trigger {
                self.emettre_trigger(middleware, inner).await;
            }
        }

        Ok(())
    }
}

pub async fn entretien_video_jobs<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("entretien_video_jobs Debut");

    let date_now = Utc::now();
    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;

    // Expirer jobs en situation de timeout pour persisting
    {
        let expiration_persisting = date_now - Duration::seconds(VIDEO_CONVERSION_TIMEOUT_PERSISTING as i64);
        let filtre = doc! {
            "etat": VIDEO_CONVERSION_ETAT_PERSISTING,
            CHAMP_MODIFICATION: {"$lte": expiration_persisting}
        };
        let ops = doc! {
            "$set": { "etat": VIDEO_CONVERSION_ETAT_PENDING },
            "$inc": { CHAMP_FLAG_MEDIA_RETRY: 1 },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        collection.update_many(filtre, ops, None).await?;
    }

    // Expirer jobs en situation de timeout pour running, erreur
    {
        let expiration_persisting = date_now - Duration::seconds(VIDEO_CONVERSION_TIMEOUT_RUNNING as i64);
        let filtre = doc! {
            "etat": {"$in": vec![VIDEO_CONVERSION_ETAT_RUNNING, VIDEO_CONVERSION_ETAT_ERROR]},
            CHAMP_MODIFICATION: {"$lte": expiration_persisting}
        };
        let ops = doc! {
            "$set": { "etat": VIDEO_CONVERSION_ETAT_PENDING },
            "$inc": { CHAMP_FLAG_MEDIA_RETRY: 1 },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        collection.update_many(filtre, ops, None).await?;
    }

    // Retirer jobs qui sont avec retry_count depasse
    {
        let filtre = doc! {
            "etat": {"$ne": VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES},
            CHAMP_FLAG_MEDIA_RETRY: {"$gte": MEDIA_RETRY_LIMIT}
        };
        let ops = doc! {
            "$set": { "etat": VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES }
        };
        collection.update_many(filtre, ops, None).await?;
    }

    // Re-emettre toutes les jobs pending
    {
        let filtre = doc! { "etat": VIDEO_CONVERSION_ETAT_PENDING };
        let hint = Hint::Name("etat_jobs".into());
        let projection = doc! {CHAMP_FUUID: 1, CHAMP_CLE_CONVERSION: 1};
        let options = FindOptions::builder().hint(hint).build();
        let mut curseur = collection.find(filtre, options).await?;

        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

        while let Some(d) = curseur.next().await {
            let job_cles: JobCles = convertir_bson_deserializable(d?)?;

            // Charger liste serveurs consignations pour ce fichier
            let filtre_version = doc! { "fuuids": &job_cles.fuuid };
            if let Some(doc_version) = collection_versions.find_one(filtre_version, None).await? {
                let info: FichierDetail = convertir_bson_deserializable(doc_version)?;

                // Faire la liste des consignations avec le fichier disponible
                let consignation_disponible = match info.visites.as_ref() {
                    Some(inner) => inner.keys().into_iter().collect(),
                    None => Vec::new()
                };

                let commande = json!({
                    CHAMP_FUUID: job_cles.fuuid,
                    CHAMP_CLE_CONVERSION: job_cles.cle_conversion,
                    "consignations": &consignation_disponible
                });

                debug!("entretien_video_jobs Re-emettre job video {:?}", commande);

                for consignation in consignation_disponible {
                    let routage = RoutageMessageAction::builder(DOMAINE_MEDIA_NOM, COMMANDE_VIDEO_DISPONIBLE)
                        .exchanges(vec![Securite::L2Prive])
                        .partition(consignation)
                        .build();
                    middleware.transmettre_commande(routage, &commande, false).await?;
                }
            }
        }
    }

    debug!("entretien_video_jobs Fin");

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobCles {
    fuuid: String,
    cle_conversion: String,
    visites: Option<HashMap<String, DateEpochSeconds>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobDetail {
    fuuid: String,
    tuuid: String,
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

pub async fn requete_jobs_video<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.message);
    let requete: RequeteJobsVideo = m.message.get_msg().map_contenu()?;
    debug!("requete_documents_par_tuuid cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    let mut filtre = doc! {};

    if role_prive && user_id.is_some() {
        // Ok
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
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
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut jobs = Vec::new();
    while let Some(d) = curseur.next().await {
        let job_detail: JobDetail = convertir_bson_deserializable(d?)?;
        jobs.push(job_detail);
    }

    let reponse = json!({ "jobs":  jobs });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSupprimerJobImage {
    user_id: String,
    fuuid: String,
}

pub async fn commande_supprimer_job_image<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commande_supprimer_job_video Consommer commande : {:?}", & m.message);
    let commande: CommandeSupprimerJobImage = m.message.get_msg().map_contenu()?;

    let fuuid = &commande.fuuid;
    if ! m.verifier_roles(vec![RolesCertificats::Media]) && m.verifier_exchanges(vec![Securite::L4Secure]) {
        Err(format!("traitement_media.commande_supprimer_job_video Certificat n'a pas le role prive ni delegation proprietaire"))?;
    }
    let user_id = &commande.user_id;

    {
        // Verifier si on a un flag de traitement video pending sur versions
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc!{ CHAMP_FUUID: fuuid, CHAMP_USER_ID: &user_id };
        debug!("commande_supprimer_job_image Verifier si flag job image est actif pour {:?}", filtre);
        match collection_versions.find_one(filtre, None).await? {
            Some(inner) => {
                let info_fichier: DBFichierVersionDetail = convertir_bson_deserializable(inner)?;
                if let Some(false) = info_fichier.flag_media_traite {
                    sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;
                }
            },
            None => warn!("Recu message annuler job image sans doc fichier version")
        };
    }

    gestionnaire.image_job_handler.set_flag(middleware, fuuid, Some(user_id), None, true).await?;

    Ok(middleware.reponse_ok()?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSupprimerJobVideo {
    fuuid: String,
    cle_conversion: String,
    user_id: Option<String>,
}

pub async fn commande_supprimer_job_video<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commande_supprimer_job_video Consommer commande : {:?}", & m.message);
    let commande: CommandeSupprimerJobVideo = m.message.get_msg().map_contenu()?;

    let fuuid = &commande.fuuid;
    let user_id = if m.verifier_roles(vec![RolesCertificats::Media]) && m.verifier_exchanges(vec![Securite::L4Secure]) {
        match commande.user_id.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("traitement_media.commande_supprimer_job_video User_id manquant de la commande"))?
        }
    } else if m.verifier_roles(vec![RolesCertificats::ComptePrive]) || m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        match m.get_user_id() {
            Some(u) => u,
            None => Err(format!("traitement_media.commande_supprimer_job_video User_id manquant du certificat"))?
        }
    } else {
        Err(format!("traitement_media.commande_supprimer_job_video Echec verification securite, acces refuse"))?
    };

    {
        // Emettre evenement annulerJobVideo pour media, collections
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_ANNULER_JOB_VIDEO)
            .exchanges(vec![Securite::L2Prive])
            .build();

        let evenement_arreter_job = CommandeSupprimerJobVideo {
            fuuid: fuuid.to_owned(),
            cle_conversion: commande.cle_conversion.to_owned(),
            user_id: Some(user_id.clone()),
        };

        middleware.emettre_evenement(routage, &evenement_arreter_job).await?;
    }

    {
        // Verifier si on a un flag de traitement video pending sur versions
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc!{ CHAMP_FUUID: fuuid, CHAMP_USER_ID: &user_id };
        debug!("commande_supprimer_job_video Verifier si flag job video est actif pour {:?}", filtre);
        match collection_versions.find_one(filtre, None).await? {
            Some(inner) => {
                let info_fichier: DBFichierVersionDetail = convertir_bson_deserializable(inner)?;
                if let Some(false) = info_fichier.flag_video_traite {
                    sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;
                }
            },
            None => warn!("Recu message annuler job video sans doc fichier version")
        };
    }

    let mut cles_supplementaires = HashMap::new();
    cles_supplementaires.insert("cle_conversion".to_string(), commande.cle_conversion.clone());
    gestionnaire.video_job_handler.set_flag(middleware, fuuid, Some(&user_id), Some(cles_supplementaires), true).await?;

    // Emettre un evenement pour clients
    let evenement = json!({
        "cle_conversion": commande.cle_conversion,
        "fuuid": fuuid,
    });
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, "jobSupprimee")
        .exchanges(vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(middleware.reponse_ok()?)
}

fn job_image_supportee<S>(mimetype: S) -> bool
    where S: AsRef<str>
{
    let mimetype = mimetype.as_ref();

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
                "video" => true,
                "image" => true,
                _ => false
            }
        }
    }
}

fn job_video_supportee<S>(mimetype: S) -> bool
    where S: AsRef<str>
{
    let mimetype = mimetype.as_ref();
    let subtype = match mimetype.split("/").next() {
        Some(t) => t,
        None => {
            error!("traitement_media.job_image_supportee Mimetype {}, subtype non identifiable", mimetype);
            return false
        }
    };
    match subtype {
        "video" => true,
        _ => false
    }
}
