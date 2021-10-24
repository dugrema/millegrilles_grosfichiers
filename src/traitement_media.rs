use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::grosfichiers_constantes::*;

const ACTION_GENERER_POSTER_IMAGE: &str = "genererPosterImage";
const ACTION_GENERER_POSTER_VIDEO: &str = "genererPosterVideo";

pub async fn emettre_commande_media<M, S, T, U>(middleware: &M, tuuid: U, fuuid: S, mimetype: T)
    -> Result<(), String>
    where
        M: GenerateurMessages,
        S: AsRef<str>,
        T: AsRef<str>,
        U: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let fuuid_str = fuuid.as_ref();
    let mimetype_str = mimetype.as_ref();

    let message = json!({
        "fuuid": fuuid_str,
        "tuuid": tuuid_str,
        "mimetype": mimetype_str,

        // Section permission de dechiffrage
        "permission_hachage_bytes": [fuuid_str],
        "permission_duree": 300,  // 300 secondes a partir de la signature de la commande
    });

    let action = match mimetype_str {
        "application/pdf" => ACTION_GENERER_POSTER_IMAGE,
        _ => {
            let subtype = match mimetype_str.split("/").next() {
                Some(t) => t,
                None => Err(format!("traitement_media.emettre_commande_media Mimetype {}, subtype non identifiable", mimetype_str))?
            };
            match subtype {
                "video" => ACTION_GENERER_POSTER_VIDEO,
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

    while let Some(d) = curseur.next().await {
        let doc_version = d?;
        let version_mappe: DBFichierVersionDetail = convertir_bson_deserializable(doc_version)?;
        let tuuid = version_mappe.tuuid;
        let fuuid = version_mappe.fuuid;
        let mimteype = version_mappe.mimetype;
        if let Some(t) = tuuid {
            if let Some(f) = fuuid {
                emettre_commande_media(middleware, &t, &f, &mimteype).await?;
                tuuids.push(t);
            }
        }
    }

    Ok(tuuids)
}
