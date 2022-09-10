use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::grosfichiers_constantes::*;

const ACTION_GENERER_POSTER_IMAGE: &str = "genererPosterImage";
const ACTION_GENERER_POSTER_PDF: &str = "genererPosterPdf";
const ACTION_GENERER_POSTER_VIDEO: &str = "genererPosterVideo";
const ACTION_TRANSCODER_VIDEO: &str = "transcoderVideo";

pub async fn emettre_commande_media<M, S, T, U>(middleware: &M, tuuid: U, fuuid: S, mimetype: T)
    -> Result<(), String>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>,
        T: AsRef<str>,
        U: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let fuuid_str = fuuid.as_ref();
    let mimetype_str = mimetype.as_ref();
    // let nom_fichier_str = nom_fichier.as_ref();

    // let extension_fichier = match nom_fichier_str.split('.').last() {
    //     Some(e) => Some(e.to_lowercase()),
    //     None => None
    // };

    let filtre = doc! {"tuuid": tuuid_str};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(filtre, None).await {
        Ok(f) => match f {
            Some(f) => match convertir_bson_deserializable::<FichierDetail>(f) {
                Ok(f) => f,
                Err(e) => Err(format!("traitement_media.emettre_commande_media Erreur convertir_bson_deserializable {} : {:?}", tuuid_str, e))?
            },
            None => Err(format!("traitement_media.emettre_commande_media Fichier tuuid {} inconnu", tuuid_str))?
        },
        Err(e) => Err(format!("traitement_media.emettre_commande_media Erreur find_one tuuid {} : {:?}", tuuid_str, e))?
    };
    let user_id = doc_fichier.user_id;

    let message = json!({
        "fuuid": fuuid_str,
        "tuuid": tuuid_str,
        "mimetype": mimetype_str,
        "user_id": &user_id,
        // "extension": extension_fichier,

        // Section permission de dechiffrage
        //"permission_hachage_bytes": [fuuid_str],
        //"permission_duree": 300,  // 300 secondes a partir de la signature de la commande
    });

    let action = match mimetype_str {
        "application/pdf" => ACTION_GENERER_POSTER_PDF,
        _ => {
            let subtype = match mimetype_str.split("/").next() {
                Some(t) => t,
                None => Err(format!("traitement_media.emettre_commande_media Mimetype {}, subtype non identifiable", mimetype_str))?
            };
            match subtype {
                "video" => {
                    // Demarrer transcodage versions 270p h264 (mp4)
                    let routage_video = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_VIDEO_TRANSCODER)
                        .exchanges(vec![Securite::L2Prive])
                        .build();
                    let commande_mp4 = json!({
                        "tuuid": tuuid_str,
                        "fuuid": fuuid_str,
                        "user_id": &user_id,
                        "codecVideo": "h264",
                        "codecAudio": "aac",
                        "mimetype": "video/mp4",
                        "resolutionVideo": 270,
                        "qualityVideo": 28,
                        "bitrateVideo": 250000,
                        "bitrateAudio": 64000,
                        "preset": "medium",
                    });
                    middleware.transmettre_commande(routage_video, &commande_mp4, false).await?;

                    // Faire generer le poster
                    ACTION_GENERER_POSTER_VIDEO
                },
                "image" => ACTION_GENERER_POSTER_IMAGE,
                _ => Err(format!("traitement_media.emettre_commande_media Mimetype {}, subtype non supporte", mimetype_str))?
            }
        }
    };

    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, action)
        .exchanges(vec![Securite::L3Protege])
        .build();

    middleware.transmettre_commande(routage, &message, false).await?;

    Ok(())
}

pub async fn traiter_media_batch<M>(middleware: &M, limite: i64) -> Result<Vec<String>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("flag_media_traite")))
        .sort(doc! {CHAMP_FLAG_MEDIA_TRAITE: 1, CHAMP_CREATION: 1})
        .limit(limite)
        .build();

    let filtre = doc! { CHAMP_FLAG_MEDIA_TRAITE: false };
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;
    let mut tuuids = Vec::new();

    let mut fuuids_media = Vec::new();
    let mut fuuids_retry_expire = Vec::new();

    while let Some(d) = curseur.next().await {
        let doc_version = d?;
        let version_mappe: DBFichierVersionDetail = convertir_bson_deserializable(doc_version)?;
        let tuuid = version_mappe.tuuid;
        let fuuid = version_mappe.fuuid;
        let mimteype = version_mappe.mimetype;
        if let Some(t) = tuuid {
            if let Some(f) = fuuid {
                if let Some(retry_count) = version_mappe.flag_media_retry {
                    if retry_count > MEDIA_RETRY_LIMIT {
                        fuuids_retry_expire.push(f.clone());
                    }
                }
                emettre_commande_media(middleware, &t, &f, mimteype).await?;
                fuuids_media.push(f);
                tuuids.push(t);
            }
        }
    }

    // Desactive apres trop d'echecs de retry
    if fuuids_retry_expire.len() > 0 {
        let filtre_retry = doc!{CHAMP_FUUID: {"$in": fuuids_retry_expire}};
        let ops = doc!{
            "$set": {
                CHAMP_FLAG_MEDIA_TRAITE: true,
                CHAMP_FLAG_MEDIA_ERREUR: ERREUR_MEDIA_TOOMANYRETRIES,
            },
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        collection.update_many(filtre_retry, ops, None).await?;
    }

    // Maj le retry count
    if fuuids_media.len() > 0 {
        let filtre_retry = doc!{CHAMP_FUUID: {"$in": fuuids_media}};
        let ops = doc!{
            "$inc": {
                CHAMP_FLAG_MEDIA_RETRY: 1,
            },
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        collection.update_many(filtre_retry, ops, None).await?;
    }

    Ok(tuuids)
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

        let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS, COMMANDE_VIDEO_DISPONIBLE)
            .exchanges(vec![Securite::L2Prive])
            .build();
        while let Some(d) = curseur.next().await {
            let job_cles: JobCles = convertir_bson_deserializable(d?)?;
            let commande = json!({CHAMP_FUUID: job_cles.fuuid, CHAMP_CLE_CONVERSION: job_cles.cle_conversion});
            middleware.transmettre_commande(routage.clone(), &commande, false).await?;
        }
    }

    debug!("entretien_video_jobs Fin");

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobCles {
    fuuid: String,
    cle_conversion: String,
}
