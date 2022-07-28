use std::collections::{HashMap, HashSet};
use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L4Secure};
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, EvenementContenuCollection, GestionnaireGrosFichiers};
use crate::grosfichiers_constantes::*;
use crate::requetes::{mapper_fichier_db, verifier_acces_usager};
use crate::traitement_index::{ElasticSearchDao, emettre_commande_indexation, set_flag_indexe, traiter_index_manquant};
use crate::traitement_media::{emettre_commande_media, traiter_media_batch};
use crate::transactions::*;

const REQUETE_MAITREDESCLES_VERIFIER_PREUVE: &str = "verifierPreuve";

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes standard
        TRANSACTION_NOUVELLE_VERSION => commande_nouvelle_version(middleware, m, gestionnaire).await,
        TRANSACTION_NOUVELLE_COLLECTION => commande_nouvelle_collection(middleware, m, gestionnaire).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => commande_associer_conversions(middleware, m, gestionnaire).await,
        TRANSACTION_ASSOCIER_VIDEO => commande_associer_video(middleware, m, gestionnaire).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => commande_ajouter_fichiers_collection(middleware, m, gestionnaire).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => commande_deplacer_fichiers_collection(middleware, m, gestionnaire).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => commande_retirer_documents_collection(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => commande_supprimer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENTS => commande_recuperer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_CHANGER_FAVORIS => commande_changer_favoris(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_FICHIER => commande_decrire_fichier(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_COLLECTION => commande_decrire_collection(middleware, m, gestionnaire).await,
        TRANSACTION_COPIER_FICHIER_TIERS => commande_copier_fichier_tiers(middleware, m, gestionnaire).await,
        TRANSACTION_FAVORIS_CREERPATH => commande_favoris_creerpath(middleware, m, gestionnaire).await,

        COMMANDE_INDEXER => commande_reindexer(middleware, m, gestionnaire).await,
        COMMANDE_COMPLETER_PREVIEWS => commande_completer_previews(middleware, m, gestionnaire).await,
        COMMANDE_CONFIRMER_FICHIER_INDEXE => commande_confirmer_fichier_indexe(middleware, m, gestionnaire).await,
        COMMANDE_NOUVEAU_FICHIER => commande_nouveau_fichier(middleware, m, gestionnaire).await,

        // Video
        COMMANDE_VIDEO_TRANSCODER => commande_video_convertir(middleware, m, gestionnaire).await,
        COMMANDE_VIDEO_ARRETER_CONVERSION => commande_video_arreter_conversion(middleware, m, gestionnaire).await,
        COMMANDE_VIDEO_GET_JOB => commande_video_get_job(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_nouvelle_version<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_nouvelle_version Consommer commande : {:?}", & m.message);
    let commande: TransactionNouvelleVersion = m.message.get_msg().map_contenu(None)?;
    debug!("Commande nouvelle versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_decrire_fichier<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_decrire_fichier Consommer commande : {:?}", & m.message);
    let commande: TransactionDecrireFichier = m.message.get_msg().map_contenu(None)?;
    debug!("Commande decrire_fichier parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let tuuids = vec![commande.tuuid];
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_nouvelle_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_nouvelle_collection Consommer commande : {:?}", & m.message);
    let commande: TransactionNouvelleCollection = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_nouvelle_collection versions parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let cuuid = commande.cuuid.as_ref();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, None::<&Vec<String>>, cuuid).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_associer_conversions<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_associer_conversions Consommer commande : {:?}", & m.message);
    let commande: TransactionAssocierConversions = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_associer_conversions versions parsed : {:?}", commande);

    if ! m.verifier_exchanges(vec![L4Secure]) {
        Err(format!("grosfichiers.commande_associer_conversions: Autorisation invalide (pas L4Secure) pour message {:?}", m.correlation_id))?
    }
    if ! m.verifier_roles(vec![RolesCertificats::Media]) {
        Err(format!("grosfichiers.commande_associer_conversions: Autorisation invalide (pas media) pour message {:?}", m.correlation_id))?
    }

    // Autorisation - doit etre signe par media



    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_associer_video<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_associer_video Consommer commande : {:?}", & m.message);
    let commande: TransactionAssocierVideo = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_associer_video versions parsed : {:?}", commande);

    // Autorisation
    if ! m.verifier_exchanges(vec![L2Prive]) {
        Err(format!("grosfichiers.commande_associer_video: Autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn verifier_autorisation_usager<M,S,T,U>(middleware: &M, user_id: S, tuuids: Option<&Vec<U>>, cuuid: Option<T>)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
{
    let user_id_str = user_id.as_ref();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    if cuuid.is_some() {
        let cuuid_ref = cuuid.expect("cuuid");

        // Verifier que la collection destination (cuuid) appartient a l'usager
        let filtre = doc!{CHAMP_TUUID: cuuid_ref.as_ref()};
        let doc_collection = collection.find_one(filtre, None).await?;
        match doc_collection {
            Some(d) => {
                let mapping_collection: FichierDetail = mapper_fichier_db(d)?;
                if Some(user_id_str.to_owned()) != mapping_collection.user_id {
                    return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "message": "cuuid n'appartient pas a l'usager"}), None)?))
                }
            },
            None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "message": "cuuid inconnu"}), None)?))
        }
    }

    if tuuids.is_some() {
        let tuuids_vec: Vec<&str> = tuuids.expect("tuuids").iter().map(|t| t.as_ref()).collect();
        let mut tuuids_set: HashSet<&str> = HashSet::new();
        let filtre = doc!{CHAMP_TUUID: {"$in": &tuuids_vec}, CHAMP_USER_ID: user_id_str};
        tuuids_set.extend(&tuuids_vec);

        let mut curseur_docs = collection.find(filtre, None).await?;
        while let Some(fresult) = curseur_docs.next().await {
            let d_result = fresult?;
            let tuuid_doc = d_result.get_str("tuuid")?;
            tuuids_set.remove(tuuid_doc);
        }

        if tuuids_set.len() > 0 {
            // Certains tuuids n'appartiennent pas a l'usager
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "message": "tuuids n'appartiennent pas a l'usager"}), None)?))
        }
    }

    Ok(None)
}

async fn commande_ajouter_fichiers_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_ajouter_fichiers_collection Consommer commande : {:?}", & m.message);
    let commande: TransactionAjouterFichiersCollection = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_ajouter_fichiers_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let cuuid = commande.cuuid.as_str();
        let tuuids: Vec<&str> = commande.inclure_tuuids.iter().map(|t| t.as_str()).collect();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_deplacer_fichiers_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_deplacer_fichiers_collection Consommer commande : {:?}", & m.message);
    let commande: TransactionDeplacerFichiersCollection = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_deplacer_fichiers_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let cuuid = commande.cuuid_origine.as_str();
        let cuuid_destination = commande.cuuid_destination.as_str();
        let mut tuuids: Vec<&str> = commande.inclure_tuuids.iter().map(|t| t.as_str()).collect();
        tuuids.push(cuuid_destination);  // Piggyback pour verifier un des 2 cuuids
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_retirer_documents_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_retirer_documents_collection Consommer commande : {:?}", & m.message);
    let commande: TransactionRetirerDocumentsCollection = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_retirer_documents_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let cuuid = commande.cuuid.as_str();
        let tuuids: Vec<&str> = commande.retirer_tuuids.iter().map(|t| t.as_str()).collect();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_documents<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_supprimer_documents Consommer commande : {:?}", & m.message);
    let commande: TransactionListeDocuments = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_supprimer_documents versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let tuuids: Vec<&str> = commande.tuuids.iter().map(|t| t.as_str()).collect();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_recuperer_documents<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_recuperer_documents Consommer commande : {:?}", & m.message);
    let commande: TransactionListeDocuments = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_recuperer_documents versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let tuuids: Vec<&str> = commande.tuuids.iter().map(|t| t.as_str()).collect();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_changer_favoris<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_changer_favoris Consommer commande : {:?}", & m.message);
    let commande: TransactionChangerFavoris = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_changer_favoris versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let keys: Vec<String> = commande.favoris.keys().cloned().collect();
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&keys), None::<String>).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_decrire_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_decrire_collection Consommer commande : {:?}", & m.message);
    let commande: TransactionDecrireCollection = m.message.get_msg().map_contenu(None)?;
    debug!("Commande decrire_collection parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let tuuids = vec![commande.tuuid];
        let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if err_reponse.is_some() {
            return Ok(err_reponse)
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_copier_fichier_tiers<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_decrire_collection Consommer commande : {:?}", & m.message);
    let commande: CommandeCopierFichierTiers = m.message.get_msg().map_contenu(None)?;
    debug!("Commande decrire_collection parsed : {:?}", commande);
    // debug!("Commande en json (DEBUG) : \n{:?}", serde_json::to_string(&commande));

    // Verifier aupres du maitredescles si les cles sont valides
    let preuve = commande.preuve;
    let preuve_value: Value = m.message.get_msg().map_contenu(Some("preuve"))?;
    let routage_maitrecles = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, REQUETE_MAITREDESCLES_VERIFIER_PREUVE)
        .partition(&preuve.partition)
        .build();
    let reponse_preuve = match middleware.transmettre_requete(routage_maitrecles, &preuve_value).await? {
        TypeMessage::Valide(m) => {
            match m.message.certificat.as_ref() {
                Some(c) => {
                    if c.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
                        debug!("commande_copier_fichier_tiers Reponse preuve : {:?}", m);
                        let preuve_value: ReponsePreuvePossessionCles = m.message.get_msg().map_contenu(None)?;
                        Ok(preuve_value)
                    } else {
                        Err(format!("commandes.commande_copier_fichier_tiers Erreur chargement certificat de reponse verification preuve, certificat n'est pas de role maitre des cles"))
                    }
                },
                None => Err(format!("commandes.commande_copier_fichier_tiers Erreur chargement certificat de reponse verification preuve, certificat inconnu"))
            }
        },
        m => Err(format!("commandes.commande_copier_fichier_tiers Erreur reponse message verification cles, mauvais type : {:?}", m))
    }?;
    debug!("Reponse verification preuve : {:?}", reponse_preuve);

    // S'assurer que tous les fuuids de la transaction sont verifies
    let transaction_copier = commande.transaction;
    let mut fuuids = Vec::new();
    fuuids.push(transaction_copier.fuuid.as_str());
    if let Some(i) = &transaction_copier.images {
        let fuuids_image: Vec<&str> = i.values().map(|info| info.hachage.as_str()).collect();
        fuuids.extend(fuuids_image);
    }
    if let Some(v) = &transaction_copier.video {
        let fuuids_videos: Vec<&str> = v.values().map(|info| info.fuuid_video.as_str()).collect();
        fuuids.extend(fuuids_videos);
    }

    debug!("Fuuids fichier : {:?}", fuuids);
    for fuuid in fuuids {
        if let Some(confirme) = reponse_preuve.verification.get(fuuid.into()) {
            if(!confirme) {
                debug!("Au moins une des cles n'est pas confirmee, on abandonne la transaction");
                return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cles invalides ou manquantes"}), None)?));
            }
        }
    }

    // Traiter la transaction, generer nouveau MVA pour transmettre uniquement la transaction
    // La preuve n'est plus necessaire
    let transaction_copier: Value = m.message.get_msg().map_contenu(Some("transaction"))?;
    let transaction_copier_str = serde_json::to_string(&transaction_copier)?;
    debug!("Transaction copier str : {:?}", transaction_copier_str);
    let mut transaction_copier_message = MessageSerialise::from_str(transaction_copier_str.as_str())?;
    transaction_copier_message.certificat = m.message.certificat.clone();
    let mva = MessageValideAction::new(transaction_copier_message, m.q, "transaction.GrosFichiers.copierFichierTiers".into(), m.domaine, m.action, m.type_message);
    Ok(sauvegarder_traiter_transaction(middleware, mva, gestionnaire).await?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeCopierFichierTiers {
    pub preuve: PreuvePossessionCles,
    pub transaction: TransactionCopierFichierTiers,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreuvePossessionCles {
    pub cles: HashMap<String, String>,
    pub partition: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponsePreuvePossessionCles {
    pub verification: HashMap<String, bool>,
}

async fn commande_reindexer<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_reindexer Consommer commande : {:?}", & m.message);
    let commande: CommandeIndexerContenu = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_reindexer parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec delegation globale
    // Verifier si on a un certificat delegation globale
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("commandes.commande_reindexer: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    if let Some(r) = commande.reset {
        if r == true {
            info!("Reset flag indexe sur tous les documents");
            let filtre = doc! { CHAMP_FLAG_INDEXE: true };
            let ops = doc! { "$set": { CHAMP_FLAG_INDEXE: false } };
            let resultat = collection.update_many(filtre, ops, None).await?;
            debug!("commande_reindexer Reset flag indexes, resultat {:?}", resultat);

            // Delete index, recreer
            gestionnaire.es_reset_index().await?;
        }
    }

    let limite = match commande.limit {
        Some(inner) => inner,
        None => 1000,
    };

    let tuuids = traiter_index_manquant(middleware, gestionnaire, limite).await?;

    let reponse = ReponseCommandeReindexer {tuuids: Some(tuuids)};
    Ok(Some(middleware.formatter_reponse(reponse, None)?))
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeIndexerContenu {
    reset: Option<bool>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct ReponseCommandeReindexer {
    tuuids: Option<Vec<String>>,
}

async fn commande_completer_previews<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_completer_previews Consommer commande : {:?}", & m.message);
    let commande: CommandeIndexerContenu = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_completer_previews parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("commandes.commande_completer_previews: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    let limite = match commande.limit {
        Some(inner) => inner,
        None => 1000,
    };

    let tuuids = traiter_media_batch(middleware, limite).await?;

    // Reponse generer preview
    let reponse = ReponseCommandeReindexer {tuuids: Some(tuuids)};
    Ok(Some(middleware.formatter_reponse(reponse, None)?))
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeCompleterPreviews {
    reset: Option<bool>,
}

async fn commande_confirmer_fichier_indexe<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_confirmer_fichier_indexe Consommer commande : {:?}", & m.message);
    let commande: CommandeConfirmerFichierIndexe = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_confirmer_fichier_indexe parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un composant protege
    match m.verifier_exchanges(vec![Securite::L3Protege]) {
        true => Ok(()),
        false => Err(format!("commandes.commande_completer_previews: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    set_flag_indexe(middleware, &commande.fuuid).await?;

    // Traiter la commande
    Ok(None)
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeConfirmerFichierIndexe {
    fuuid: String,
}

/// Commande qui indique la creation _en cours_ d'un nouveau fichier. Permet de creer un
/// placeholder a l'ecran en attendant le traitement du fichier.
async fn commande_nouveau_fichier<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_nouveau_fichier Consommer commande : {:?}", & m.message);
    let commande: TransactionNouvelleVersion = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_nouveau_fichier parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    let delegation_proprietaire = m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);
    if ! (role_prive || delegation_proprietaire) && user_id.is_none() {
        let reponse = json!({"ok": false, "err": "Non autorise"});
        return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
    }

    let fuuid = commande.fuuid;
    let mimetype = commande.mimetype;
    let tuuid = match commande.tuuid {
        Some(t) => t,
        None => {
            let reponse = json!({"ok": false, "err": "tuuid manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };
    let cuuid = commande.cuuid;
    let nom_fichier = commande.nom;

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": &fuuid};
    // Ajouter collection au besoin
    if let Some(c) = cuuid.as_ref() {
        add_to_set.insert("cuuids", c);
    }

    let ops = doc! {
        "$set": {
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
            CHAMP_USER_ID: &user_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    debug!("commande_nouveau_fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("commande_nouveau_fichier.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("commande_nouveau_fichier Resultat transaction update : {:?}", resultat);

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, tuuid.as_str(), EVENEMENT_AJOUTER_FICHIER).await?;
    if let Some(c) = cuuid.as_ref() {
        let mut event = EvenementContenuCollection::new();
        let fichiers_ajoutes = vec![tuuid.to_owned()];
        event.cuuid = cuuid.clone();
        event.fichiers_ajoutes = Some(fichiers_ajoutes);
        emettre_evenement_contenu_collection(middleware, event).await?;
    }

    Ok(middleware.reponse_ok()?)
}

async fn commande_favoris_creerpath<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_favoris_creerpath Consommer commande : {:?}", & m.message);
    let commande: TransactionFavorisCreerpath = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_favoris_creerpath parsed : {:?}", commande);

    // Autorisation : si user_id fourni dans la commande, on verifie que le certificat est 4.secure ou delegation globale
    let user_id = {
        match commande.user_id {
            Some(user_id) => {
                // S'assurer que le certificat permet d'utiliser un user_id fourni (4.secure ou delegation globale)
                match m.verifier_exchanges(vec![Securite::L4Secure]) {
                    true => Ok(user_id),
                    false => {
                        match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                            true => Ok(user_id),
                            false => Err(format!("commandes.commande_completer_previews: Utilisation user_id refusee pour message {:?}", m.correlation_id))
                        }
                    },
                }
            },
            None => {
                // Utiliser le user_id du certificat
                match &m.message.certificat {
                    Some(c) => match c.get_user_id()? {
                        Some(u) => Ok(u.to_owned()),
                        None => Err(format!("commandes.commande_favoris_creerpath: user_id manquant du certificat pour message {:?}", m.correlation_id))
                    },
                    None => Err(format!("commandes.commande_favoris_creerpath: Certificat non charge pour message {:?}", m.correlation_id))
                }
            }
        }
    }?;

    debug!("commande_favoris_creerpath Utiliser user_id {}", user_id);

    // Verifier si le path existe deja
    let tuuid_favoris = format!("{}_{}", user_id, commande.favoris_id);
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let filtre_favoris = doc!{
        CHAMP_USER_ID: &user_id,
        CHAMP_TUUID: &tuuid_favoris,
        CHAMP_SUPPRIME: false,
        CHAMP_FAVORIS: true
    };
    debug!("commande_favoris_creerpath Filtre doc favoris : {:?}", filtre_favoris);
    let doc_favoris_opt = collection.find_one(filtre_favoris, None).await?;
    let mut tuuid_leaf = None;

    debug!("commande_favoris_creerpath Doc_favoris_opt trouve : {:?}", doc_favoris_opt);
    match doc_favoris_opt {
        Some(doc_favoris) => {
            match commande.path_collections {
                Some(path_collections) => {
                    let mut trouve = true;
                    let mut cuuid_courant = tuuid_favoris.clone();
                    for path_col in path_collections {
                        let filtre_info_collection = doc!{
                            CHAMP_USER_ID: &user_id,
                            CHAMP_CUUIDS: &cuuid_courant,
                            CHAMP_NOM: &path_col,
                            CHAMP_SUPPRIME: false,
                        };
                        let doc_info_collection = collection.find_one(filtre_info_collection, None).await?;
                        match doc_info_collection {
                            Some(inner_doc) => {
                                let collection_info: InformationCollection = match convertir_bson_deserializable(inner_doc) {
                                    Ok(inner_collection) => Ok(inner_collection),
                                    Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion bson path {} : {:?}", path_col, e))
                                }?;
                                cuuid_courant = collection_info.tuuid.clone();
                            },
                            None => {
                                // Collection manquante, executer la transaction
                                trouve = false;
                                break
                            }
                        }
                        debug!("transaction_favoris_creerpath Path tuuid : {:?}", cuuid_courant);
                    }

                    if trouve {
                        tuuid_leaf = Some(cuuid_courant)
                    }
                },
                None => {
                    tuuid_leaf = Some(tuuid_favoris)
                }
            }
        },
        None => ()
    }

    if tuuid_leaf.is_some() {
        // Retourner le tuuid comme reponse, aucune transaction necessaire
        debug!("commande_favoris_creerpath Path trouve, tuuid {:?}", tuuid_leaf);
        let reponse = json!({CHAMP_TUUID: &tuuid_leaf});
        Ok(Some(middleware.formatter_reponse(reponse, None)?))
    } else {
        // Poursuivre le traitement sous forme de transaction
        debug!("commande_favoris_creerpath Path incomplet, poursuivre avec la transaction");
        Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
    }
}

async fn commande_video_convertir<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commande_video_convertir Consommer commande : {:?}", & m.message);
    let commande: CommandeVideoConvertir = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_video_convertir parsed : {:?}", commande);

    let fuuid = commande.fuuid.as_str();

    {   // Verifier acces
        let user_id = m.get_user_id();
        let delegation_globale = m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);
        if delegation_globale || m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
            // Ok
        } else if user_id.is_some() {
            let u = user_id.expect("commande_video_convertir user_id");
            let resultat = verifier_acces_usager(middleware, &u, vec![fuuid]).await?;
            if ! resultat.contains(&commande.fuuid) {
                debug!("commande_video_convertir verifier_exchanges : Usager n'a pas acces a fuuid {}", fuuid);;
                return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
            }
        } else {
            debug!("commande_video_convertir verifier_exchanges : Certificat n'a pas l'acces requis (securite 2,3,4 ou user_id avec acces fuuid)");
            return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
        }
    }

    // Verifier si le fichier a deja un video correspondant
    let bitrate_quality = match &commande.quality_video {
        Some(q) => q.to_owned(),
        None => match &commande.bitrate_video {
            Some(b) => b.to_owned() as i32,
            None => 0,
        }
    };
    let cle_video = format!("{};{};{}p;{}", commande.mimetype, commande.codec_video, commande.resolution_video, bitrate_quality);
    let filtre_fichier = doc!{CHAMP_FUUIDS: fuuid};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let info_fichier: FichierDetail = match collection.find_one(filtre_fichier, None).await? {
        Some(f) => convertir_bson_deserializable(f)?,
        None => {
            info!("commande_video_convertir verifier_exchanges : Fichier inconnu {}", fuuid);
            return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichier inconnu"}), None)?))
        }
    };

    let version_courante = match info_fichier.version_courante {
        Some(v) => v,
        None => {
            info!("commande_video_convertir Fichier video en etat incorrect (version_courante manquant) {}", fuuid);
            return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Information fichier corrompue"}), None)?))
        }
    };

    match version_courante.video {
        Some(v) => {
            // Verifier si le video existe deja
            match v.get(cle_video.as_str()) {
                Some(v) => {
                    info!("commande_video_convertir Fichier video existe deja {} pour {}", cle_video, fuuid);
                    return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Video dans ce format existe deja"}), None)?))
                },
                None => ()  // Ok, le video n'existe pas
            }
        },
        None => ()  // Ok, aucuns videos existant
    };

    // Conserver l'information de conversion, emettre nouveau message de job
    // Note : job lock fait plus tard avant conversion, duplication de messages est OK
    let insert_ops = doc! {
        "tuuid": commande.tuuid,
        CHAMP_FUUID: fuuid,
        CHAMP_MIMETYPE: commande.mimetype,
        "codecVideo": commande.codec_video,
        "codecAudio": commande.codec_audio,
        "qualityVideo": commande.quality_video,
        "resolutionVideo": commande.resolution_video,
        "bitrateVideo": commande.bitrate_video,
        "bitrateAudio": commande.bitrate_audio,
        "preset": commande.preset,
        "etat": 1,  // Pending
    };
    let set_ops = doc! {
        CHAMP_FLAG_MEDIA_RETRY: 0,  // Reset le retry count automatique
    };
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": insert_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre_video = doc! {CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video};
    let collection_video = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let emettre_job = match collection_video.find_one_and_update(filtre_video, ops, options).await? {
        Some(d) => {
            debug!("commande_video_convertir Etat precedent : {:?}", d);
            // Verifier l'etat du document precedent (e.g. pending, erreur, en cours, etc)

            true  // Emettre la job
        },
        None => true  // Nouvelle entree, emettre la nouvelle job.
    };

    if emettre_job {
        let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS, COMMANDE_VIDEO_DISPONIBLE)
            .exchanges(vec![Securite::L2Prive])
            .build();
        let commande = json!({CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video});
        middleware.transmettre_commande(routage, &commande, false).await?;
    }

    Ok(middleware.reponse_ok()?)
}

async fn commande_video_arreter_conversion<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_video_arreter_conversion Consommer commande : {:?}", & m.message);
    let commande: CommandeVideoArreterConversion = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_video_arreter_conversion parsed : {:?}", commande);

    todo!("fix me")
}

async fn commande_video_get_job<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_video_get_job Consommer commande : {:?}", & m.message);
    let commande: CommandeVideoGetJob = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_video_get_job parsed : {:?}", commande);

    // Verifier autorisation
    if ! m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        info!("commande_video_get_job Exchange n'est pas de niveau 2,3,4");
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
    }
    if ! m.verifier_roles(vec![RolesCertificats::Media]) {
        info!("commande_video_get_job Role n'est pas media");
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre media)"}), None)?))
    }

    let prochaine_job = match commande.fuuid {
        Some(fuuid) => match commande.cle_conversion {
            Some(cle) => trouver_prochaine_job(middleware, Some(fuuid), Some(cle)).await?,
            None => trouver_prochaine_job(middleware, None::<&str>, None::<&str>).await?
        },
        None => trouver_prochaine_job(middleware, None::<&str>, None::<&str>).await?
    };

    debug!("commande_video_get_job Prochaine job : {:?}", prochaine_job);

    match prochaine_job {
        Some(job) => {
            let reponse_job = middleware.formatter_reponse(&job, None)?;
            debug!("Reponse job : {:?}", reponse_job);
            Ok(Some(reponse_job))
        },
        None => {
            Ok(Some(middleware.formatter_reponse(&json!({"ok": true, "message": "Aucune job disponible"}), None)?))
        }
    }
}

async fn trouver_prochaine_job<M,S,T>(middleware: &M, fuuid: Option<S>, cle: Option<T>)
    -> Result<Option<JobVideo>, Box<dyn Error>>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        S: AsRef<str>,
        T: AsRef<str>
{
    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;

    // Verifier si la job qui correspond au parametres est diponible
    let job: Option<JobVideo> = match fuuid {
        Some(f) => match cle {
            Some(c) => {
                let fuuid_ = f.as_ref();
                let cle_ = c.as_ref();
                debug!("trouver_prochaine_job Utiliser fuuid: {}, cle: {}", fuuid_, cle_);
                let filtre = doc!{CHAMP_FUUID: fuuid_, CHAMP_CLE_CONVERSION: cle_};
                match collection.find_one(filtre, None).await? {
                    Some(r) => {
                        debug!("trouver_prochaine_job (1) Charger job : {:?}", r);
                        let job: JobVideo = convertir_bson_deserializable(r)?;
                        // Verifier si la job est disponible
                        if job.etat == VIDEO_CONVERSION_ETAT_PENDING {
                            Some(job)
                        } else {
                            debug!("Job demandee ({}, {}) n'est pas pending", fuuid_, cle_);
                            None
                        }
                    },
                    None => None
                }
            },
            None => None
        },
        None => None
    };

    let job: Option<JobVideo> = match job {
        Some(j) => Some(j),
        None => {
            // Tenter de trouver la prochaine job disponible
            let filtre = doc! {"etat": VIDEO_CONVERSION_ETAT_PENDING};
            let hint = Some(Hint::Name("etat_jobs".into()));
            let options = FindOneOptions::builder().hint(hint).build();
            match collection.find_one(filtre, options).await? {
                Some(d) => {
                    debug!("trouver_prochaine_job (2) Charger job : {:?}", d);
                    Some(convertir_bson_deserializable(d)?)
                },
                None => None
            }
        }
    };

    match &job {
        Some(j) => {
            // Marquer la job comme running
            let filtre = doc!{CHAMP_FUUID: &j.fuuid, CHAMP_CLE_CONVERSION: &j.cle_conversion};
            let ops = doc! {
                "$set": {"etat": VIDEO_CONVERSION_ETAT_RUNNING},
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            collection.update_one(filtre, ops, None).await?;
        },
        None => ()
    }

    Ok(job)
}