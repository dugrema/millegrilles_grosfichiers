use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::bson::serde_helpers::deserialize_chrono_datetime_from_bson_datetime;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{Date, DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L3Protege, L4Secure};
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::CommandeDechiffrerCle;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::grosfichiers_constantes::*;
use crate::traitement_index::{ParametresGetClesStream, ParametresGetPermission, ParametresRecherche, ResultatHits, ResultatHitsDetail};
use crate::traitement_media::requete_jobs_video;
use crate::transactions::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    // if role_prive && user_id.is_some() {
    //     // Ok, commande usager
    // } else if message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
    //     // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    //     // Ok
    // } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
    //     // Ok
    // } else {
    //     Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    // }

    let domaine = message.domaine.as_str();
    if domaine != DOMAINE_NOM {
        error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
        return Ok(None)
    }

    if role_prive && user_id.is_some() {
        match message.action.as_str() {
            REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
            REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
            REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
            // REQUETE_RECHERCHE_INDEX => requete_recherche_index(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_JOBS_VIDEO => requete_jobs_video(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue (1): '{}'. Message dropped.", message.action);
                Ok(None)
            }
        }
    } else if message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        match message.action.as_str() {
            REQUETE_CONFIRMER_ETAT_FUUIDS => requete_confirmer_etat_fuuids(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_STREAM => requete_get_cles_stream(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CUUIDS => requete_sync_cuuids(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue pour exchanges 3.protege/4.secure : '{}'. Message dropped.", message.action);
                Ok(None)
            }
        }
    } else if message.verifier_exchanges(vec![Securite::L2Prive]) {
        match message.action.as_str() {
            REQUETE_CONFIRMER_ETAT_FUUIDS => requete_confirmer_etat_fuuids(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CUUIDS => requete_sync_cuuids(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_STREAM => requete_get_cles_stream(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue pour exchange 2.prive : '{}'. Message dropped.", message.action);
                Ok(None)
            }
        }
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        match message.action.as_str() {
            REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
            REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
            REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
            // REQUETE_RECHERCHE_INDEX => requete_recherche_index(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_JOBS_VIDEO => requete_jobs_video(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue (delegation globale): '{}'. Message dropped.", message.action);
                Ok(None)
            }
        }
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

}

async fn requete_activite_recente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_activite_recente Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu()?;
    debug!("requete_activite_recente cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    if user_id.is_none() {
        return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    }

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
        .limit(limit)
        .skip(skip)
        .build();
    let filtre = doc!{CHAMP_SUPPRIME: false, CHAMP_USER_ID: user_id};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn mapper_fichiers_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
    let mut fichiers_mappes = Vec::new();

    while let Some(fresult) = curseur.next().await {
        let fcurseur = fresult?;
        let fichier_db = mapper_fichier_db(fcurseur)?;
        fichiers_mappes.push(fichier_db);
    }

    // Convertir fichiers en Value (serde pour reponse json)
    Ok(serde_json::to_value(fichiers_mappes)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequetePlusRecente {
    limit: Option<i64>,
    skip: Option<u64>,
}

pub fn mapper_fichier_db(fichier: Document) -> Result<FichierDetail, Box<dyn Error>> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    debug!("Ficher charge : {:?}", fichier);
    let mut fichier_mappe: FichierDetail = convertir_bson_deserializable(fichier)?;
    fichier_mappe.date_creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
    fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct FichierVersionCourante {
//     tuuid: String,
//     #[serde(skip_serializing_if="Option::is_none")]
//     cuuids: Option<Vec<String>>,
//     nom: String,
//     titre: Option<HashMap<String, String>>,
//
//     fuuid_v_courante: Option<String>,
//     version_courante: Option<DBFichierVersion>,
//
//     favoris: Option<bool>,
//
//     date_creation: Option<DateEpochSeconds>,
//     derniere_modification: Option<DateEpochSeconds>,
//     supprime: Option<bool>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct DBFichierVersion {
//     nom: String,
//     fuuid: String,
//     tuuid: String,
//     mimetype: String,
//     taille: usize,
//     #[serde(rename="dateFichier")]
//     date_fichier: DateEpochSeconds,
//     #[serde(skip_serializing_if="Option::is_none")]
//     height: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     weight: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     images: Option<HashMap<String, ImageConversion>>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     anime: Option<bool>,
// }

async fn requete_favoris<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_favoris Message : {:?}", & m.message);
    //let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let projection = doc! {CHAMP_NOM: true, CHAMP_TITRE: true, CHAMP_SECURITE: true, CHAMP_TUUID: true, "_mg-creation": true};
    let filtre = doc! { CHAMP_FAVORIS: true, CHAMP_USER_ID: user_id };
    let hint = Hint::Name("collections_favoris".into());
    let opts = FindOptions::builder().projection(projection).hint(hint).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let favoris_mappes = {
        let mut favoris_mappes = Vec::new();
        let mut curseur = collection.find(filtre, opts).await?;
        while let Some(c) = curseur.next().await {
            let favori_doc = c?;
            let favori_mappe: Favoris = convertir_bson_deserializable(favori_doc)?;
            favoris_mappes.push(favori_mappe);
        }
        favoris_mappes
    };

    let reponse = json!({ "favoris": favoris_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Favoris {
    nom: String,
    tuuid: String,
    securite: Option<String>,
    // #[serde(rename(deserialize = "_mg-creation"))]
    // date_creation: Option<DateEpochSeconds>,
    // titre: Option<HashMap<String, String>>,
}

async fn requete_documents_par_tuuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.message);
    let requete: RequeteDocumentsParTuuids = m.message.get_msg().map_contenu()?;
    debug!("requete_documents_par_tuuid cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let mut filtre = doc! { CHAMP_TUUID: {"$in": &requete.tuuids_documents} };
    if user_id.is_some() {
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    }
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let curseur = collection.find(filtre, None).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers":  fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_documents_par_fuuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_documents_par_fuuid Message : {:?}", & m.message);
    let requete: RequeteDocumentsParFuuids = m.message.get_msg().map_contenu()?;
    debug!("requete_documents_par_fuuid cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else if m.verifier_exchanges(vec![Securite::L2Prive]) {
        // Ok
    } else {
        Err(format!("grosfichiers.requete_documents_par_fuuid: Autorisation invalide pour requete {:?}", m.correlation_id))?
    }

    let mut filtre = doc! { CHAMP_FUUIDS: {"$in": &requete.fuuids_documents} };
    if user_id.is_some() {
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    }
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let curseur = collection.find(filtre, None).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers":  fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_verifier_acces_fuuids<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_verifier_acces_fuuids Message : {:?}", & m.message);
    let requete: RequeteVerifierAccesFuuids = m.message.get_msg().map_contenu()?;
    debug!("requete_verifier_acces_fuuids cle parsed : {:?}", requete);

    let user_id_option = m.get_user_id();
    let user_id = match user_id_option.as_ref() {
        Some(u) => u,
        None => {
            if ! m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
                return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "acces refuse"}), None)?))
            }
            match requete.user_id.as_ref() {
                Some(u) => u,
                None => {
                    return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User_id manquant"}), None)?))
                }
            }
        }
    };

    let resultat = verifier_acces_usager(middleware, user_id, &requete.fuuids).await?;

    let acces_tous = resultat.len() == requete.fuuids.len();

    let reponse = json!({ "fuuids_acces": resultat , "acces_tous": acces_tous });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_contenu_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_contenu_collection Message : {:?}", & m.message);
    let requete: RequeteContenuCollection = m.message.get_msg().map_contenu()?;
    debug!("requete_contenu_collection cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let skip = match requete.skip { Some(s) => s, None => 0 };
    let limit = match requete.limit { Some(l) => l, None => 50 };
    let mut filtre_collection = doc! { CHAMP_TUUID: &requete.tuuid_collection, CHAMP_SUPPRIME: false };
    if user_id.is_some() {
        filtre_collection.insert("user_id", Bson::String(user_id.expect("user_id")));
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut doc_info_collection = match collection.find_one(filtre_collection, None).await? {
        Some(c) => c,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Collection introuvable"}), None)?))
    };
    filtrer_doc_id(&mut doc_info_collection);

    let sort = match requete.sort_keys {
        Some(s) => {
            let mut doc_sort = doc!();
            for k in s {
                let colonne = k.colonne;
                let direction = match k.ordre {
                    Some(d) => d,
                    None => 1,
                };
                doc_sort.insert(colonne, direction);
            }
            doc_sort
        },
        None => doc!{"nom": 1}
    };
    let filtre_fichiers = doc! { CHAMP_CUUIDS: {"$all": [&requete.tuuid_collection]}, CHAMP_SUPPRIME: false };
    let ops_fichiers = FindOptions::builder()
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .build();
    let curseur = collection.find(filtre_fichiers, Some(ops_fichiers)).await?;
    let fichiers_reps = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({
        "collection": doc_info_collection,
        "documents": fichiers_reps,
    });

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_get_corbeille<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_corbeille Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu()?;
    debug!("requete_get_corbeille cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
        .limit(limit)
        .skip(skip)
        .build();
    let mut filtre = doc!{CHAMP_SUPPRIME: true};
    if user_id.is_some() {
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

// async fn requete_recherche_index<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + VerificateurMessage,
// {
//     debug!("requete_recherche_index Message : {:?}", & m.message);
//     let mut requete: ParametresRecherche = m.message.get_msg().map_contenu()?;
//     debug!("requete_recherche_index cle parsed : {:?}", requete);
//
//     let user_id = m.get_user_id();
//     let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
//     if role_prive && user_id.is_some() {
//         // Ok
//     } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//         // Ok
//     } else {
//         Err(format!("grosfichiers.requete_recherche_index: Autorisation invalide pour message {:?}", m.correlation_id))?
//     }
//
//     // Ajouter user_id a la requete
//     requete.user_id = user_id.clone();
//
//     let info = match gestionnaire.es_rechercher("grosfichiers", &requete).await {
//         Ok(resultats) => {
//             match resultats.hits {
//                 Some(inner) => {
//                     let total = inner.total.value;
//                     match inner.hits {
//                         Some(hits) => {
//                             let resultats = mapper_fichiers_resultat(middleware, hits, user_id).await?;
//                             Some((total, resultats))
//                         },
//                         None => None
//                     }
//                 },
//                 None => None
//             }
//         },
//         Err(e) => {
//             error!("requetes.requete_recherche_index Erreur recherche index grosfichiers : {}", e);
//             return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": e.clone()}), None)?))
//         }
//     };
//
//     let reponse = match info {
//         Some((total, hits)) => {
//             json!({"ok": true, "total": total, "hits": hits})
//         },
//         None => json!({"ok": true, "total": 0})
//     };
//
//     Ok(Some(middleware.formatter_reponse(&reponse, None)?))
// }

async fn requete_get_cles_fichiers<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
                                      -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_cles_fichiers Message : {:?}", &m.message);
    let requete: ParametresGetPermission = m.message.get_msg().map_contenu()?;
    debug!("requete_get_cles_fichiers cle parsed : {:?}", requete);

    let mut conditions: Vec<Document> = Vec::new();
    if let Some(tuuids) = requete.tuuids {
        conditions.push(doc!{"tuuid": {"$in": tuuids}});
    }
    conditions.push(doc!{"fuuids": {"$in": &requete.fuuids}});
    conditions.push(doc!{"metadata.ref_hachage_bytes": {"$in": &requete.fuuids}});

    let mut filtre = match m.get_user_id() {
        Some(u) => {
            doc!{
                "user_id": u,
                "$or": conditions,
            }
        },
        None => {
            if m.verifier_exchanges(vec![Securite::L4Secure]) && m.verifier_roles(vec![RolesCertificats::Media]) {
                doc! {
                    "$or": conditions,
                }
            } else if m.verifier_exchanges(vec![Securite::L2Prive]) && m.verifier_roles(vec![RolesCertificats::Stream]) {
                doc! {
                    "mimetype": {"$regex": "video\\/"},
                    "$or": conditions,
                }
            } else {
                return Ok(Some(middleware.formatter_reponse(json!({"err": true, "message": "user_id n'est pas dans le certificat/certificat n'est pas de role media/stream"}), None)?))
            }
        }
    };

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage: Vec<String> = match &m.message.certificat {
        Some(c) => {
            let fp_certs = c.get_pem_vec();
            fp_certs.into_iter().map(|cert| cert.pem).collect()
        },
        None => Err(format!(""))?
    };

    debug!("requete_get_cles_fichiers Filtre : {:?}", filtre);
    let projection = doc! {"fuuids": true, "tuuid": true, "metadata": true};
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes_demandes = HashSet::new();
    hachage_bytes_demandes.extend(requete.fuuids.iter().map(|f| f.to_string()));
    let mut hachage_bytes = Vec::new();
    while let Some(fresult) = curseur.next().await {
        debug!("requete_get_cles_fichiers document trouve pour permission cle : {:?}", fresult);
        let doc_mappe: ResultatDocsPermission = convertir_bson_deserializable(fresult?)?;
        if let Some(fuuids) = doc_mappe.fuuids {
            for d in fuuids {
                if hachage_bytes_demandes.remove(d.as_str()) {
                    hachage_bytes.push(d);
                }
            }
        }
        if let Some(metadata) = doc_mappe.metadata {
            if let Some(ref_hachage_bytes) = metadata.ref_hachage_bytes {
                if hachage_bytes_demandes.remove(ref_hachage_bytes.as_str()) {
                    hachage_bytes.push(ref_hachage_bytes);
                }
            }
        }
    }

    // let permission = json!({
    //     "liste_hachage_bytes": hachage_bytes,
    //     "certificat_rechiffrage": pem_rechiffrage,
    //     // Condition d'identite
    //     // "user_id": user_id,
    // });

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: hachage_bytes,
        certificat_rechiffrage: Some(pem_rechiffrage),
    };

    // Emettre requete de rechiffrage de cle, reponse acheminee directement au demandeur
    let reply_to = match m.reply_q {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_permission Pas de reply q pour message"))?
    };
    let correlation_id = match m.correlation_id {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_permission Pas de correlation_id pour message"))?
    };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L4Secure])
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    debug!("Transmettre requete permission dechiffrage cle : {:?}", permission);

    middleware.transmettre_requete(routage, &permission).await?;

    // let permission = json!({
    //     "permission_hachage_bytes": hachage_bytes,
    //     "permission_duree": 30
    // });
    //
    // // Emettre le message de permission vers le maitre des cles, faire repondre directement
    // // au demandeur.
    // let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRER_CLE)
    //     .reply_to(message.reply_q)
    //     .correlation_id(message.correlation_id)
    //     .blocking(false)  // La reponse ne revient pas ici
    //     .build();
    //
    // middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

async fn requete_get_cles_stream<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
                                    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_cles_stream Message : {:?}", &m.message);
    let requete: ParametresGetClesStream = m.message.get_msg().map_contenu()?;
    debug!("requete_get_cles_stream cle parsed : {:?}", requete);

    if ! m.verifier_roles(vec![RolesCertificats::Stream]) {
        let reponse = json!({"err": true, "message": "certificat doit etre de role stream"});
        return Ok(Some(middleware.formatter_reponse(reponse, None)?));
    }

    let user_id = requete.user_id;

    // let mut hachage_bytes = Vec::new();
    // let mut hachage_bytes_demandes = HashSet::new();
    // hachage_bytes_demandes.extend(requete.fuuids.iter().map(|f| f.to_string()));

    let filtre = doc!{
        "fuuids": {"$in": &requete.fuuids},
        "user_id": &user_id,
        "mimetype": {"$regex": "(video\\/|audio\\/)"},
        // "mimetype": {"$regex": "video\\/"},
    };

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage: Vec<String> = match &m.message.certificat {
        Some(c) => {
            let fp_certs = c.get_pem_vec();
            fp_certs.into_iter().map(|cert| cert.pem).collect()
        },
        None => Err(format!(""))?
    };

    debug!("requete_get_cles_stream Filtre : {:?}", filtre);
    let projection = doc! {"fuuids": true, "tuuid": true, "metadata": true};
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes_demandes = HashSet::new();
    hachage_bytes_demandes.extend(requete.fuuids.iter().map(|f| f.to_string()));
    let mut hachage_bytes = Vec::new();
    while let Some(fresult) = curseur.next().await {
        debug!("requete_get_cles_stream document trouve pour permission cle : {:?}", fresult);
        let doc_mappe: ResultatDocsPermission = convertir_bson_deserializable(fresult?)?;
        if let Some(fuuids) = doc_mappe.fuuids {
            for d in fuuids {
                if hachage_bytes_demandes.remove(d.as_str()) {
                    hachage_bytes.push(d);
                }
            }
        }
        if let Some(metadata) = doc_mappe.metadata {
            if let Some(ref_hachage_bytes) = metadata.ref_hachage_bytes {
                if hachage_bytes_demandes.remove(ref_hachage_bytes.as_str()) {
                    hachage_bytes.push(ref_hachage_bytes);
                }
            }
        }
    }

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: hachage_bytes,
        certificat_rechiffrage: Some(pem_rechiffrage),
    };

    // let permission = json!({
    //     "liste_hachage_bytes": hachage_bytes,
    //     "certificat_rechiffrage": pem_rechiffrage,
    // });

    // Emettre requete de rechiffrage de cle, reponse acheminee directement au demandeur
    let reply_to = match m.reply_q {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_cles_stream Pas de reply q pour message"))?
    };
    let correlation_id = match m.correlation_id {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_cles_stream Pas de correlation_id pour message"))?
    };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L4Secure])
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    debug!("requete_get_cles_stream Transmettre requete permission dechiffrage cle : {:?}", permission);

    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

async fn mapper_fichiers_resultat<M>(middleware: &M, resultats: Vec<ResultatHitsDetail>, user_id: Option<String>)
    -> Result<Vec<ResultatDocumentRecherche>, Box<dyn Error>>
    where M: MongoDao
{
    // Generer liste de tous les fichiers par version
    let (resultat_par_fuuid, fuuids) = {
        let mut map = HashMap::new();
        let mut fuuids = Vec::new();
        for r in &resultats {
            map.insert(r.id_.as_str(), r);
            fuuids.push(r.id_.clone());
        }
        (map, fuuids)
    };

    debug!("requete.mapper_fichiers_resultat resultat par fuuid : {:?}", resultat_par_fuuid);

    let mut fichiers_par_tuuid = {
        let mut filtre = doc! { CHAMP_FUUIDS: {"$in": &fuuids} };
        if user_id.is_some() {
            filtre.insert(String::from("user_id"), user_id.expect("user_id"));
        }
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection.find(filtre, None).await?;

        let mut fichiers: HashMap<String, Vec<ResultatDocumentRecherche>> = HashMap::new();
        while let Some(c) = curseur.next().await {
            // let fichier: DBFichierVersionDetail = convertir_bson_deserializable(c?)?;
            let fcurseur = c?;
            let fichier = mapper_fichier_db(fcurseur)?;

            if fichier.fuuid_v_courante.is_none() {
                warn!("Fichier tuuid={} sans fuuid_v_courante", fichier.tuuid);
                continue  // Skip le mapping
            }

            let fuuid = match fichier.fuuid_v_courante.as_ref() {
                Some(f) => f.to_owned(),
                None => {
                    warn!("mapper_fichiers_resultat Erreur mapping fichier tuuid={} sans fuuid", fichier.tuuid);
                    continue;
                }
            };

            let resultat = resultat_par_fuuid.get(fuuid.as_str()).expect("resultat");
            // let fichier_resultat = ResultatDocumentRecherche::new(fichier, *resultat)?;
            let fichier_resultat = match ResultatDocumentRecherche::new_fichier(fichier, *resultat) {
                Ok(fichier_resultat) => fichier_resultat,
                Err(e) => {
                    warn!("mapper_fichiers_resultat Erreur mapping fichier fuuid={}: {:?}", fuuid, e);
                    continue  // Skip le mapping
                }
            };
            let tuuid = fichier_resultat.tuuid.clone();
            match fichiers.get_mut(&tuuid) {
                Some(mut inner) => { inner.push(fichier_resultat); },
                None => { fichiers.insert(tuuid, vec![fichier_resultat]); }
            }

        }

        fichiers
    };

    debug!("requete.mapper_fichiers_resultat Fichiers par tuuid : {:?}", fichiers_par_tuuid);

    // Charger les details "courants" pour les fichiers
    {
        let tuuids: Vec<String> = fichiers_par_tuuid.keys().map(|k| k.clone()).collect();
        let filtre = doc! { CHAMP_TUUID: {"$in": tuuids} };
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(c) = curseur.next().await {
            let fichier: FichierDetail = convertir_bson_deserializable(c?)?;
            let tuuid = &fichier.tuuid;
            if let Some(mut fichier_resultat) = fichiers_par_tuuid.get_mut(tuuid) {
                for f in fichier_resultat {
                    f.nom = fichier.nom.clone();
                    f.titre = fichier.titre.clone();
                    f.description = fichier.description.clone();
                    f.date_creation = fichier.date_creation.clone();
                    f.date_modification = fichier.derniere_modification.clone();
                }
            }
        }
    };

    // Generer liste de fichiers en reponse, garder l'ordre des fuuid
    let mut fichiers_par_fuuid: HashMap<String, ResultatDocumentRecherche> = HashMap::new();
    for (_, vec_fichiers) in fichiers_par_tuuid.into_iter() {
        for f in vec_fichiers {
            fichiers_par_fuuid.insert(f.fuuid.clone(), f);
        }
    }

    let mut liste_reponse = Vec::new();
    for fuuid in &fuuids {
        if let Some(f) = fichiers_par_fuuid.remove(fuuid) {
            liste_reponse.push(f);
        }
    }

    debug!("requete.mapper_fichiers_resultat Liste response hits : {:?}", liste_reponse);

    Ok(liste_reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocumentRecherche {
    tuuid: String,
    fuuid: String,
    nom: Option<String>,
    supprime: Option<bool>,
    archive: Option<bool>,
    nom_version: Option<String>,
    taille: u64,
    mimetype: String,
    date_creation: Option<DateEpochSeconds>,
    date_modification: Option<DateEpochSeconds>,
    date_version: Option<DateEpochSeconds>,
    titre: Option<HashMap<String, String>>,
    description: Option<HashMap<String, String>>,

    version_courante: Option<DBFichierVersionDetail>,

    // Thumbnail
    thumb_hachage_bytes: Option<String>,
    thumb_data: Option<String>,

    // Info recherche
    score: f32,
}

impl ResultatDocumentRecherche {
    fn new(value: DBFichierVersionDetail, resultat: &ResultatHitsDetail) -> Result<Self, Box<dyn Error>> {

        let (thumb_hachage_bytes, thumb_data) = match value.images {
            Some(mut images) => {
                match images.remove("thumb") {
                    Some(inner) => {
                        (Some(inner.hachage), inner.data_chiffre)
                    },
                    None => (None, None)
                }
            },
            None => (None, None)
        };

        Ok(ResultatDocumentRecherche {
            tuuid: value.tuuid.expect("tuuid"),
            fuuid: value.fuuid.expect("fuuid"),
            nom: value.nom.clone(),
            supprime: None,
            archive: None,
            nom_version: value.nom,
            taille: value.taille as u64,
            mimetype: value.mimetype,
            date_creation: None,
            date_modification: None,
            date_version: value.date_fichier,
            titre: None,
            description: None,

            version_courante: None,

            // Thumbnail
            thumb_hachage_bytes,
            thumb_data,

            // Info recherche
            score: resultat.score,
        })
    }

    fn new_fichier(value: FichierDetail, resultat: &ResultatHitsDetail) -> Result<Self, Box<dyn Error>> {

        let (thumb_hachage_bytes, thumb_data, mimetype, taille) = match &value.version_courante {
            Some(v) => {
                let taille = v.taille as u64;
                let mimetype = v.mimetype.to_owned();
                match &v.images {
                    Some(images) => {
                        match images.get("thumb") {
                            Some(inner) => {
                                (Some(inner.hachage.clone()), inner.data_chiffre.clone(), mimetype, taille)
                            },
                            None => (None, None, mimetype, taille)
                        }
                    },
                    None => (None, None, mimetype, taille)
                }
            },
            None => (None, None, String::from("application/data"), 0)
        };

        let fuuid = match value.fuuid_v_courante { Some(t) => t, None => Err(format!("Resultat sans tuuid"))? };

        let date_version = match value.derniere_modification {
            Some(d) => d,
            None => Err(format!("Resultat sans date de derniere_modification"))?
        };

        Ok(ResultatDocumentRecherche {
            tuuid: value.tuuid,
            fuuid,
            nom: value.nom.clone(),
            supprime: value.supprime,
            archive: value.archive,
            nom_version: value.nom,
            taille,
            mimetype,
            date_creation: value.date_creation,
            date_modification: Some(date_version.clone()),
            date_version: Some(date_version),
            titre: value.titre,
            description: value.description,

            version_courante: value.version_courante,

            // Thumbnail
            thumb_hachage_bytes,
            thumb_data,

            // Info recherche
            score: resultat.score,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParTuuids {
    tuuids_documents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParFuuids {
    fuuids_documents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteVerifierAccesFuuids {
    user_id: Option<String>,
    fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteContenuCollection {
    tuuid_collection: String,
    limit: Option<i64>,
    skip: Option<u64>,
    sort_keys: Option<Vec<SortKey>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SortKey {
    colonne: String,
    ordre: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocsPermission {
    tuuid: String,
    fuuids: Option<Vec<String>>,
    metadata: Option<DataChiffre>,
}

async fn requete_confirmer_etat_fuuids<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let uuid_transaction = m.correlation_id.clone();

    if ! m.verifier_exchanges(vec![L2Prive, L3Protege, L4Secure]) {
        error!("requetes.requete_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", uuid_transaction);
        return Ok(None)
    }

    debug!("requete_confirmer_etat_fuuids Message : {:?}", & m.message);
    let requete: RequeteConfirmerEtatFuuids = m.message.get_msg().map_contenu()?;
    debug!("requete_confirmer_etat_fuuids cle parsed : {:?}", requete);

    let mut fuuids = HashSet::new();
    for fuuid in requete.fuuids.iter() {
        fuuids.insert(fuuid.clone());
    }

    let projection = doc! {
        "fuuids": 1,
        "supprime": 1,
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .build();
    let mut filtre = doc!{"fuuids": {"$in": requete.fuuids}};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = Vec::new();
    let mut curseur = collection.find(filtre, opts).await?;
    while let Some(d) = curseur.next().await {
        let record: RowEtatFuuid = convertir_bson_deserializable(d?)?;
        for fuuid in record.fuuids.into_iter() {
            if fuuids.contains(&fuuid) {
                fuuids.remove(&fuuid);
                fichiers_confirmation.push( ConfirmationEtatFuuid { fuuid, supprime: record.supprime } );
            }
        }
    }

    // Ajouter tous les fuuids manquants (encore dans le set)
    // Ces fichiers sont inconnus et presumes supprimes
    for fuuid in fuuids.into_iter() {
        fichiers_confirmation.push( ConfirmationEtatFuuid { fuuid, supprime: true } );
    }

    let confirmation = ReponseConfirmerEtatFuuids { fichiers: fichiers_confirmation };
    let reponse = json!({ "confirmation": confirmation });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

pub async fn verifier_acces_usager<M,S,T,V>(middleware: &M, user_id: S, fuuids: V)
    -> Result<Vec<String>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
          S: AsRef<str>,
          T: AsRef<str>,
          V: AsRef<Vec<T>>
{
    let _user_id = user_id.as_ref();
    let _fuuids: Vec<&str> = fuuids.as_ref().iter().map(|s| s.as_ref()).collect();

    let mut filtre = doc! {
        CHAMP_USER_ID: _user_id,
        CHAMP_FUUIDS: {"$in": &_fuuids},
        CHAMP_SUPPRIME: false,
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let options = FindOptions::builder().projection(doc!{CHAMP_FUUIDS: 1, CHAMP_SUPPRIME: 1}).build();
    let mut curseur = collection.find(filtre, Some(options)).await?;

    let mut fuuids_acces = HashSet::new();

    while let Some(row) = curseur.next().await {
        let doc_row = row?;
        let doc_map: RowEtatFuuid = convertir_bson_deserializable(doc_row)?;
        fuuids_acces.extend(doc_map.fuuids);
    }

    let hashset_requete = HashSet::from_iter(_fuuids);
    let mut hashset_acces = HashSet::new();
    for fuuid in &fuuids_acces {
        hashset_acces.insert(fuuid.as_str());
    }

    let resultat: Vec<&&str> = hashset_acces.intersection(&hashset_requete).collect();

    // String to_owned
    Ok(resultat.into_iter().map(|s| s.to_string()).collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseConfirmerEtatFuuids {
    fichiers: Vec<ConfirmationEtatFuuid>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowEtatFuuid {
    fuuids: Vec<String>,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfirmationEtatFuuid {
    fuuid: String,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncCollection {
    cuuid: Option<String>,
    user_id: Option<String>,
    skip: Option<u64>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncIntervalle {
    user_id: Option<String>,
    debut: DateEpochSeconds,
    fin: Option<DateEpochSeconds>,
    skip: Option<u64>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncCuuids {
    user_id: Option<String>,
    skip: Option<u64>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichierSync {
    tuuid: String,
    #[serde(with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification", skip_serializing)]
    map_derniere_modification: DateTime<Utc>,
    derniere_modification: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if="Option::is_none")]
    favoris: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    supprime: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CuuidsSync {
    tuuid: String,
    #[serde(with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification", skip_serializing)]
    map_derniere_modification: DateTime<Utc>,
    derniere_modification: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if="Option::is_none")]
    favoris: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    supprime: Option<bool>,
    metadata: DataChiffre,
    user_id: String,
    cuuids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseRequeteSyncCollection {
    complete: bool,
    liste: Vec<FichierSync>
}

async fn requete_sync_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let uuid_transaction = m.correlation_id.clone();

    debug!("requete_confirmer_etat_fuuids Message : {:?}", & m.message);
    let requete: RequeteSyncCollection = m.message.get_msg().map_contenu()?;
    debug!("requete_confirmer_etat_fuuids cle parsed : {:?}", requete);

    let user_id = {
        match m.message.get_user_id() {
            Some(u) => u,
            None => {
                if m.verifier_exchanges(vec![L3Protege, L4Secure]) {
                    match requete.user_id {
                        Some(u) => u,
                        None => {
                            error!("requete_sync_collection L3Protege/L4Secure user_id manquant");
                            return Ok(None)
                        }
                    }
                } else {
                    error!("requetes.requete_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", uuid_transaction);
                    return Ok(None)
                }
            }
        }
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        .hint(Hint::Name("fichiers_cuuid".into()))
        .build();

    let mut filtre = doc!{"user_id": user_id};
    match requete.cuuid {
        Some(cuuid) => {
            filtre.insert("cuuids", cuuid);
        },
        None => {
            // Requete sur les favoris
            filtre.insert("favoris", true);
        }
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_fichiers(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCollection { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_sync_plusrecent<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let uuid_transaction = m.correlation_id.clone();

    debug!("requete_sync_plusrecent Message : {:?}", & m.message);
    let requete: RequeteSyncIntervalle = m.message.get_msg().map_contenu()?;
    debug!("requete_sync_plusrecent cle parsed : {:?}", requete);

    let user_id = {
        match m.message.get_user_id() {
            Some(u) => u,
            None => {
                if m.verifier_exchanges(vec![L3Protege, L4Secure]) {
                    match requete.user_id {
                        Some(u) => u,
                        None => {
                            error!("requete_sync_plusrecent L3Protege/L4Secure user_id manquant");
                            return Ok(None)
                        }
                    }
                } else {
                    error!("requetes.requete_sync_plusrecent Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", uuid_transaction);
                    return Ok(None)
                }
            }
        }
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_CREATION: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        .hint(Hint::Name("fichiers_cuuid".into()))
        .build();
    let date_debut = requete.debut.get_datetime();
    let mut filtre = {
        match requete.fin {
            Some(f) => {
                let date_fin = f.get_datetime();
                doc!{"user_id": user_id, "$or":[{
                    CHAMP_CREATION: {"$lte": date_fin, "$gte": date_debut},
                    CHAMP_MODIFICATION: {"$lte": date_fin, "$gte": date_debut},
                }]}
            },
            None => {
                doc!{"user_id": user_id, "$or":[{
                    CHAMP_CREATION: {"$gte": date_debut},
                    CHAMP_MODIFICATION: {"$gte": date_debut},
                }]}
            }
        }
    };

    debug!("requete_sync_plusrecent Requete fichiers debut {:?}, filtre : {:?}", date_debut, filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_fichiers(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCollection { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_sync_corbeille<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let uuid_transaction = m.correlation_id.clone();

    debug!("requete_sync_corbeille Message : {:?}", & m.message);
    let requete: RequeteSyncIntervalle = m.message.get_msg().map_contenu()?;
    debug!("requete_sync_corbeille cle parsed : {:?}", requete);

    let user_id = {
        match m.message.get_user_id() {
            Some(u) => u,
            None => {
                if m.verifier_exchanges(vec![L3Protege, L4Secure]) {
                    match requete.user_id {
                        Some(u) => u,
                        None => {
                            error!("requete_sync_corbeille L3Protege/L4Secure user_id manquant");
                            return Ok(None)
                        }
                    }
                } else {
                    error!("requetes.requete_sync_corbeille Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", uuid_transaction);
                    return Ok(None)
                }
            }
        }
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_CREATION: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        .hint(Hint::Name("fichiers_cuuid".into()))
        .build();
    let date_debut = requete.debut.get_datetime();
    let mut filtre = doc! {"user_id": user_id, "supprime": true};

    debug!("requete_sync_corbeille Requete fichiers debut {:?}, filtre : {:?}", date_debut, filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_fichiers(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCollection { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseRequeteSyncCuuids {
    complete: bool,
    liste: Vec<CuuidsSync>
}

async fn requete_sync_cuuids<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let uuid_transaction = m.correlation_id.clone();

    match m.message.certificat.as_ref() {
        Some(inner) => {
            if let Some(domaines) = inner.get_domaines()? {
                if ! domaines.contains(&String::from("GrosFichiers")) {
                    error!("requete_sync_cuuids Permission refusee (domaines cert != GrosFichiers)");
                    return Ok(None)
                }
            } else {
                error!("requete_sync_cuuids Permission refusee (domaines cert None)");
                return Ok(None)
            }
        },
        None => {
            error!("requete_sync_cuuids Permission refusee (certificat non charge)");
            return Ok(None)
        }
    }

    debug!("requete_sync_cuuids Message : {:?}", & m.message);
    let requete: RequeteSyncCuuids = m.message.get_msg().map_contenu()?;
    debug!("requete_sync_cuuids cle parsed : {:?}", requete);

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_CREATION: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
        CHAMP_METADATA: 1,
        CHAMP_USER_ID: 1,
        CHAMP_CUUIDS: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        .build();
    let mut filtre = doc! {"supprime": false, "metadata": {"$exists": true}, "fuuid_v_courante": {"$exists": false}};

    debug!("requete_sync_cuuids filtre : {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_cuuids(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCuuids { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn find_sync_fichiers<M>(middleware: &M, filtre: Document, opts: FindOptions) -> Result<Vec<FichierSync>, Box<dyn Error>>
    where M: MongoDao
{
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let mut curseur = collection.find(filtre, opts).await?;
    let mut fichiers_confirmation = Vec::new();
    while let Some(d) = curseur.next().await {
        let mut record: FichierSync = convertir_bson_deserializable(d?)?;
        record.derniere_modification = Some(DateEpochSeconds::from(record.map_derniere_modification.clone()));
        fichiers_confirmation.push(record);
    }

    Ok(fichiers_confirmation)
}

async fn find_sync_cuuids<M>(middleware: &M, filtre: Document, opts: FindOptions) -> Result<Vec<CuuidsSync>, Box<dyn Error>>
    where M: MongoDao
{
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let mut curseur = collection.find(filtre, opts).await?;
    let mut cuuids_confirmation = Vec::new();
    while let Some(d) = curseur.next().await {
        let mut record: CuuidsSync = convertir_bson_deserializable(d?)?;
        record.derniere_modification = Some(DateEpochSeconds::from(record.map_derniere_modification.clone()));
        cuuids_confirmation.push(record);
    }

    Ok(cuuids_confirmation)
}
