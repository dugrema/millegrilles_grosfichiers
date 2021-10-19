use std::collections::HashMap;
use std::error::Error;

use log::{debug, error, warn};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::transactions::*;
use crate::grosfichiers_constantes::*;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.message);

    // Autorisation : doit etre un message via exchange
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

    match m.action.as_str() {
        // Commandes standard
        TRANSACTION_NOUVELLE_VERSION => commande_nouvelle_version(middleware, m, gestionnaire).await,
        TRANSACTION_NOUVELLE_COLLECTION => commande_nouvelle_collection(middleware, m, gestionnaire).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => commande_ajouter_fichiers_collection(middleware, m, gestionnaire).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => commande_retirer_documents_collection(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => commande_supprimer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENTS => commande_recuperer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_CHANGER_FAVORIS => commande_changer_favoris(middleware, m, gestionnaire).await,
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

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

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
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_nouvelle_collection: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_retirer_documents_collection: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_documents<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_supprimer_documents Consommer commande : {:?}", & m.message);
    let commande: TransactionSupprimerDocuments = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_supprimer_documents versions parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_supprimer_documents: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_recuperer_documents<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_recuperer_documents Consommer commande : {:?}", & m.message);
    let commande: TransactionSupprimerDocuments = m.message.get_msg().map_contenu(None)?;
    debug!("Commande commande_recuperer_documents versions parsed : {:?}", commande);

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_recuperer_documents: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

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

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale
    // todo Ajouter usager acces prive
    match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => Ok(()),
        false => Err(format!("grosfichiers.commande_changer_favoris: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}