use std::collections::{HashMap, HashSet};
use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::grosfichiers_constantes::*;
use crate::requetes::mapper_fichier_db;
use crate::traitement_index::{ElasticSearchDao, emettre_commande_indexation, set_flag_indexe, traiter_index_manquant};
use crate::traitement_media::{emettre_commande_media, traiter_media_batch};
use crate::transactions::*;

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
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => commande_ajouter_fichiers_collection(middleware, m, gestionnaire).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => commande_retirer_documents_collection(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => commande_supprimer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENTS => commande_recuperer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_CHANGER_FAVORIS => commande_changer_favoris(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_FICHIER => commande_decrire_fichier(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_COLLECTION => commande_decrire_collection(middleware, m, gestionnaire).await,
        COMMANDE_INDEXER => commande_reindexer(middleware, m, gestionnaire).await,
        COMMANDE_COMPLETER_PREVIEWS => commande_completer_previews(middleware, m, gestionnaire).await,
        COMMANDE_CONFIRMER_FICHIER_INDEXE => commande_confirmer_fichier_indexe(middleware, m, gestionnaire).await,
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

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_ajouter_fichiers_collection: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

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

async fn commande_reindexer<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_reindexer Consommer commande : {:?}", & m.message);
    let commande: CommandeIndexerContenu = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_reindexer parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
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
