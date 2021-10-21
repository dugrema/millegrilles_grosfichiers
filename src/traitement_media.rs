use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use log::{debug, error, warn};

use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
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

pub async fn emettre_commande_indexation<M, S, U>(middleware: &M, tuuid: U, fuuid: S)
    -> Result<(), String>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>,
        U: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let fuuid_str = fuuid.as_ref();

    // domaine_action = 'commande.fichiers.indexerContenu'
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(doc!{CHAMP_TUUID: tuuid_str}, None).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur chargement fichier : {:?}", e))?
    };
    let fichier = match doc_fichier {
        Some(inner) => {
            match convertir_bson_deserializable::<FichierDetail>(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur conversion vers bson : {:?}", e))?
            }
        },
        None => Err(format!("Aucun fichier avec tuuid {}", tuuid_str))?
    };

    // Verifier si on doit chargement une version different
    let fuuid_v_courante = match fichier.fuuid_v_courante {
        Some(inner) => inner,
        None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Fuuid v courante manquant"))?
    };

    if fuuid_v_courante.as_str() != fuuid_str {
        todo!("Charger version precedente du document")
    }

    let version_courante = match fichier.version_courante {
        Some(inner) => inner,
        None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Version courante manquante"))?
    };

    let mimetype = version_courante.mimetype.as_str();

    let document_indexation: DocumentIndexation = version_courante.try_into()?;
    let info_index = InfoDocumentIndexation {
        tuuid: tuuid_str.to_owned(),
        fuuid: fuuid_str.to_owned(),
        doc: document_indexation,
    };

    // match mimetype {
    //     // "application/pdf" => {
    //     //
    //     // },
    //     _ => {
    //         // Format de document de base, aucun contenu a indexer
    //         fichier.try_into()?
    //     }
    // };

    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_INDEXER)
        .exchanges(vec![Securite::L3Protege])
        .build();

    middleware.transmettre_commande(routage, &info_index, false).await?;

    Ok(())
}

/// Format de document pret a etre indexe
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfoDocumentIndexation {
    tuuid: String,
    fuuid: String,
    doc: DocumentIndexation,
}

// impl TryFrom<FichierDetail> for InfoDocumentIndexation {
//     type Error = String;
//
//     fn try_from(value: FichierDetail) -> Result<Self, Self::Error> {
//         let fuuid = match value.fuuid_v_courante {
//             Some(inner) => inner,
//             None => Err(format!("InfoDocumentIndexation.TryFrom Fuuid manquant"))?
//         };
//
//         let doc_index: DocumentIndexation = match value.version_courante {
//             Some(inner) => inner.try_into()?,
//             None => Err(format!("InfoDocumentIndexation.TryFrom Version courante manquante"))?
//         };
//
//         Ok(InfoDocumentIndexation {
//             tuuid: value.tuuid.clone(),
//             fuuid,
//             doc: doc_index,
//         })
//     }
// }

/// Contenu et mots-cles pour l'indexation d'un document
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocumentIndexation {
    nom: String,    // Nom du fichier
    mimetype: String,
    date_v_courante: DateEpochSeconds,

    // Champs qui proviennent du fichierRep (courant uniquement)
    titre: Option<HashMap<String, String>>,          // Dictionnaire combine
    description: Option<HashMap<String, String>>,    // Dictionnaire combine
    cuuids: Option<Vec<String>>,
}

impl TryFrom<DBFichierVersionDetail> for DocumentIndexation {
    type Error = String;

    fn try_from(value: DBFichierVersionDetail) -> Result<Self, Self::Error> {
        Ok(DocumentIndexation {
            nom: value.nom.clone(),
            mimetype: value.mimetype.clone(),
            date_v_courante: value.date_fichier.clone(),
            titre: None,
            description: None,
            cuuids: None,
        })
    }
}
