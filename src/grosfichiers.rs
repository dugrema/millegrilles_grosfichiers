use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

const DOMAINE_NOM: &str = "GrosFichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "GrosFichiers";
const NOM_COLLECTION_FICHIERS_REP: &str = "GrosFichiers/fichiersRep";
const NOM_COLLECTION_VERSIONS: &str = "GrosFichiers/versionsFichiers";
const NOM_COLLECTION_DOCUMENTS: &str = "GrosFichiers/documents";

const NOM_Q_TRANSACTIONS: &str = "GrosFichiers/transactions";
const NOM_Q_VOLATILS: &str = "GrosFichiers/volatils";
const NOM_Q_TRIGGERS: &str = "GrosFichiers/triggers";

const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";
const REQUETE_FAVORIS: &str = "favoris";
const REQUETE_DOCUMENTS_PAR_TUUID: &str = "documentsParTuuid";
const REQUETE_CONTENU_COLLECTION: &str = "contenuCollection";
const REQUETE_GET_CORBEILLE: &str = "getCorbeille";

const TRANSACTION_NOUVELLE_VERSION: &str = "nouvelleVersion";
const TRANSACTION_NOUVELLE_COLLECTION: &str = "nouvelleCollection";
const TRANSACTION_AJOUTER_FICHIERS_COLLECTION: &str = "ajouterFichiersCollection";
const TRANSACTION_RETIRER_DOCUMENTS_COLLECTION: &str = "retirerDocumentsCollection";
const TRANSACTION_SUPPRIMER_DOCUMENTS: &str = "supprimerDocuments";
const TRANSACTION_RECUPERER_DOCUMENTS: &str = "recupererDocuments";
const TRANSACTION_CHANGER_FAVORIS: &str = "changerFavoris";

const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
const CHAMP_SUPPRIME: &str = "supprime";
const CHAMP_NOM: &str = "nom";
const CHAMP_TITRE: &str = "titre";
const CHAMP_MIMETYPE: &str = "mimetype";
const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
const CHAMP_FAVORIS: &str = "favoris";

#[derive(Clone, Debug)]
pub struct GestionnaireGrosFichiers {
    // pub consignation: String,
}

#[async_trait]
impl TraiterTransaction for GestionnaireGrosFichiers {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireGrosFichiers {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> String { String::from(NOM_COLLECTION_TRANSACTIONS) }

    fn get_collections_documents(&self) -> Vec<String> { vec![
        String::from(NOM_COLLECTION_VERSIONS),
        String::from(NOM_COLLECTION_FICHIERS_REP),
        String::from(NOM_COLLECTION_DOCUMENTS),
    ] }

    fn get_q_transactions(&self) -> String { String::from(NOM_Q_TRANSACTIONS) }

    fn get_q_volatils(&self) -> String { String::from(NOM_Q_VOLATILS) }

    fn get_q_triggers(&self) -> String { String::from(NOM_Q_TRIGGERS) }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        preparer_index_mongodb_custom(middleware).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_evenement(middleware, message).await
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 2.prive, 3.protege et 4.secure
    let requetes_protegees: Vec<&str> = vec![
        REQUETE_ACTIVITE_RECENTE,
        REQUETE_FAVORIS,
        REQUETE_DOCUMENTS_PAR_TUUID,
        REQUETE_CONTENU_COLLECTION,
        REQUETE_GET_CORBEILLE,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    // let evenements_proteges: Vec<&str> = vec![
    //     EVENEMENT_CLES_MANQUANTES_PARTITION,
    // ];
    // for evnt in evenements_proteges {
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L3Protege});
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L4Secure});
    // }

    let commandes_privees: Vec<&str> = vec![
        TRANSACTION_NOUVELLE_VERSION,
        TRANSACTION_NOUVELLE_COLLECTION,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION,
        TRANSACTION_SUPPRIMER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS,
        TRANSACTION_CHANGER_FAVORIS,
    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L3Protege});
    }

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
        }
    ));

    let mut rk_transactions = Vec::new();
    let transactions_secures = vec![
        TRANSACTION_NOUVELLE_VERSION,
        TRANSACTION_NOUVELLE_COLLECTION,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION,
        TRANSACTION_SUPPRIMER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS,
        TRANSACTION_CHANGER_FAVORIS,
    ];
    for ts in transactions_secures {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, ts).into(),
            exchange: Securite::L4Secure
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into()));

    queues
}

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
    where M: MongoDao
{
    // Index fuuids pour fichiers (liste par tuuid)
    let options_unique_fuuid = IndexOptions {
        nom_index: Some(format!("fichiers_fuuid")),
        unique: false
    };
    let champs_index_fuuid = vec!(
        ChampIndex {nom_champ: String::from("fuuids"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_fuuid,
        Some(options_unique_fuuid)
    ).await?;

    // Index cuuids pour collections de fichiers (liste par cuuid)
    let options_unique_cuuid = IndexOptions {
        nom_index: Some(format!("fichiers_cuuid")),
        unique: false
    };
    let champs_index_cuuid = vec!(
        ChampIndex {nom_champ: String::from("cuuids"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_cuuid,
        Some(options_unique_cuuid)
    ).await?;

    // tuuids (serie de fichiers)
    let options_unique_tuuid = IndexOptions {
        nom_index: Some(format!("fichiers_tuuid")),
        unique: true
    };
    let champs_index_tuuid = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_tuuid,
        Some(options_unique_tuuid)
    ).await?;

    // Activite recente des fichiers
    let options_recents = IndexOptions {
        nom_index: Some(format!("fichiers_activite_recente")),
        unique: true
    };
    let champs_recents = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_SUPPRIME), direction: -1},  // pour filtre
        ChampIndex {nom_champ: String::from(CHAMP_MODIFICATION), direction: -1},
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},  // Tri stable
    );
    middleware.create_index(
        NOM_COLLECTION_FICHIERS_REP,
        champs_recents,
        Some(options_recents)
    ).await?;

    // Favoris
    let options_favoris = IndexOptions {
        nom_index: Some(format!("collections_favoris")),
        unique: false
    };
    let champs_favoris = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_SUPPRIME), direction: -1},
        ChampIndex {nom_champ: String::from(CHAMP_FAVORIS), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_FICHIERS_REP,
        champs_favoris,
        Some(options_favoris)
    ).await?;

    // Index cuuid pour collections
    let options_unique_versions_fuuid = IndexOptions {
        nom_index: Some(format!("versions_fuuid")),
        unique: true
    };
    let champs_index_versions_fuuid = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FUUID), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VERSIONS,
        champs_index_versions_fuuid,
        Some(options_unique_versions_fuuid)
    ).await?;
    // Index fuuids pour fichiers (liste par fsuuid)
    let options_unique_fuuid = IndexOptions {
        nom_index: Some(format!("Versions_fuuids")),
        unique: false
    };
    let champs_index_fuuid = vec!(
        ChampIndex {nom_champ: String::from("fuuids"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VERSIONS,
        champs_index_fuuid,
        Some(options_unique_fuuid)
    ).await?;
    Ok(())
}

pub async fn entretien<M>(_middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    match message.verifier_exchanges(vec![Securite::L3Protege]) {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))
            }
        }
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
                REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
                REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
                REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
                REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("grosfichiers.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // EVENEMENT_CLES_MANQUANTES_PARTITION => {
        //     evenement_cle_manquante(middleware, &m).await?;
        //     Ok(None)
        // },
        _ => Err(format!("grosfichiers.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}


async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("grosfichiers.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        // TRANSACTION_CLE  => {
        //     sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
        //     Ok(None)
        // },
        _ => Err(format!("grosfichiers.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionNouvelleVersion {
    fuuid: String,
    cuuid: Option<String>,
    tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    nom_fichier: String,
    mimetype: String,
    taille: u64,
    #[serde(rename="dateFichier")]
    date_fichier: DateEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionNouvelleCollection {
    nom: String,
    cuuid: Option<String>,  // Insertion dans collection destination
    securite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionAjouterFichiersCollection {
    cuuid: String,  // Collection qui recoit les documents
    inclure_tuuids: Vec<String>,  // Fichiers/rep a ajouter a la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionRetirerDocumentsCollection {
    cuuid: String,  // Collection qui recoit les documents
    retirer_tuuids: Vec<String>,  // Fichiers/rep a retirer de la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSupprimerDocuments {
    tuuids: Vec<String>,  // Fichiers/rep a supprimer
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionChangerFavoris {
    favoris: HashMap<String, bool>,
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(middleware, transaction).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, transaction).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, transaction).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => transaction_retirer_documents_collection(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, transaction).await,
        TRANSACTION_CHANGER_FAVORIS => transaction_changer_favoris(middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn transaction_nouvelle_version<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_nouvelle_version Consommer transaction : {:?}", &transaction);
    let transaction_fichier: TransactionNouvelleVersion = match transaction.clone().convertir::<TransactionNouvelleVersion>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction : {:?}", e))?
    };

    // Determiner tuuid - si non fourni, c'est l'uuid-transaction (implique un nouveau fichier)
    let tuuid = match &transaction_fichier.tuuid {
        Some(t) => t.clone(),
        None => String::from(transaction.get_uuid_transaction())
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    };

    let fuuid = transaction_fichier.fuuid;
    let cuuid = transaction_fichier.cuuid;
    let nom_fichier = transaction_fichier.nom_fichier;
    let mimetype = transaction_fichier.mimetype;

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert("tuuid", &tuuid);
        doc_version.insert("fuuids", vec![&fuuid]);
        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            doc_version.insert("flag_media", "image");
            doc_version.insert("flag_media_traite", false);
        } else if mimetype.starts_with("video") {
            doc_version.insert("flag_media", "video");
            doc_version.insert("flag_media_traite", false);
        } else if mimetype =="application/pdf" {
            doc_version.insert("flag_indexe", false);
        }
        match collection.insert_one(doc_version, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur insertion nouvelle version {} : {:?}", fuuid, e))?
        }
    }

    // Retirer champs cles - ils sont inutiles dans la version
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": &fuuid};
    // Ajouter collection au besoin
    if let Some(c) = cuuid {
        add_to_set.insert("cuuids", c);
    }

    let ops = doc! {
        "$set": {
            "version_courante": doc_bson_transaction,
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    debug!("nouveau fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("nouveau fichier Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_nouvelle_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_nouvelle_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionNouvelleCollection = match transaction.clone().convertir::<TransactionNouvelleCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_collection) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction en bson : {:?}", e))?
    };

    let tuuid = transaction.get_uuid_transaction().to_owned();
    let cuuid = transaction_collection.cuuid;
    let nom_collection = transaction_collection.nom;
    let date_courante = millegrilles_common_rust::bson::DateTime::now();
    let securite = match transaction_collection.securite {
        Some(s) => s,
        None => SECURITE_3_PROTEGE.to_owned()
    };

    // Creer document de collection (fichiersRep)
    let mut doc_collection = doc! {
        CHAMP_TUUID: &tuuid,
        CHAMP_NOM: nom_collection,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        CHAMP_SECURITE: &securite,
        CHAMP_SUPPRIME: false,
    };
    debug!("grosfichiers.transaction_nouvelle_collection Ajouter nouvelle collection doc : {:?}", doc_collection);

    // Ajouter collection parent au besoin
    if let Some(c) = cuuid {
        let mut arr = millegrilles_common_rust::bson::Array::new();
        arr.push(millegrilles_common_rust::bson::Bson::String(c));
        doc_collection.insert("cuuids", arr);
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.insert_one(doc_collection, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_nouvelle_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_ajouter_fichiers_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_ajouter_fichiers_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionAjouterFichiersCollection = match transaction.clone().convertir::<TransactionAjouterFichiersCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let add_to_set = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid};
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.inclure_tuuids}};
    let ops = doc! {
        "$addToSet": add_to_set,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_ajouter_fichiers_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_retirer_documents_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_retirer_documents_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionRetirerDocumentsCollection = match transaction.clone().convertir::<TransactionRetirerDocumentsCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let pull_from_array = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid};
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.retirer_tuuids}};
    let ops = doc! {
        "$pull": pull_from_array,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_retirer_documents_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_supprimer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerDocuments = match transaction.clone().convertir::<TransactionSupprimerDocuments>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_supprimer_documents Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_recuperer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_recuperer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerDocuments = match transaction.clone().convertir::<TransactionSupprimerDocuments>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: false},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_recuperer_documents Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_changer_favoris<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_changer_favoris Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionChangerFavoris = match transaction.clone().convertir::<TransactionChangerFavoris>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur conversion transaction : {:?}", e))?
    };

    let (tuuids_set, tuuids_reset) = {
        let mut tuuids_set = Vec::new();
        let mut tuuids_reset = Vec::new();

        // Split en deux requetes - une pour favoris = true, l'autre pour false
        for (key, value) in transaction_collection.favoris.iter() {
            if *value == true {
                tuuids_set.push(key.to_owned());
            } else {
                tuuids_reset.push(key.to_owned());
            }
        }
        (tuuids_set, tuuids_reset)
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    // Faire 2 requetes, une pour favoris=true, l'autre false
    if ! tuuids_reset.is_empty() {
        let filtre_reset = doc! {CHAMP_TUUID: {"$in": &tuuids_reset}};
        let ops_reset = doc! { "$set": {CHAMP_FAVORIS: false}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_reset, ops_reset, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many reset sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update reset : {:?}", resultat);
    }

    if ! tuuids_set.is_empty() {
        let filtre_set = doc! {CHAMP_TUUID: {"$in": &tuuids_set}};
        let ops_set = doc! { "$set": {CHAMP_FAVORIS: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_set, ops_set, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many set sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update set : {:?}", resultat);
    }

    middleware.reponse_ok()
}

async fn requete_activite_recente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_activite_recente Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu(None)?;
    debug!("requete_activite_recente cle parsed : {:?}", requete);
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
    let filtre = doc!{CHAMP_SUPPRIME: false};

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
        let fichier_mappe: FichierVersionCourante = fichier_db.try_into()?;
        fichiers_mappes.push(fichier_mappe);
    }

    // Convertir fichiers en Value (serde pour reponse json)
    Ok(serde_json::to_value(fichiers_mappes)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequetePlusRecente {
    limit: Option<i64>,
    skip: Option<u64>,
}

fn mapper_fichier_db(fichier: Document) -> Result<FichierVersionCourante, Box<dyn Error>> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    let mut fichier_mappe: FichierVersionCourante = convertir_bson_deserializable(fichier)?;
    fichier_mappe.date_creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
    fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichierVersionCourante {
    tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    cuuids: Option<Vec<String>>,
    nom: String,
    titre: Option<HashMap<String, String>>,

    fuuid_v_courante: Option<String>,
    version_courante: Option<DBFichierVersion>,

    favoris: Option<bool>,

    date_creation: Option<DateEpochSeconds>,
    derniere_modification: Option<DateEpochSeconds>,
}

// impl TryFrom<DBFichier> for FichierVersionCourante {
//     type Error = String;
//
//     fn try_from(mut value: DBFichier) -> Result<Self, Self::Error> {
//         let fuuid = value.fuuid_v_courante;
//         let vc = match value.versions.remove(&fuuid) {
//             Some(v) => v,
//             None => Err(format!("Mapping version {} manquant", &fuuid))?
//         };
//
//         Ok(FichierVersionCourante {
//             tuuid: value.tuuid,
//             cuuids: value.cuuids,
//             nom_fichier: value.nom_fichier,
//
//             fuuid: fuuid.clone(),
//             fuuid_v_courante: fuuid,
//             version_courante: vc,
//
//             date_creation: value.creation,
//             derniere_modification: value.derniere_modification,
//         })
//     }
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct DBFichier {
//     tuuid: String,
//     cuuids: Option<Vec<String>>,
//     fuuids: Vec<String>,
//     nom_fichier: String,
//     fuuid_v_courante: String,
//     versions: HashMap<String, DBFichierVersion>,
//
//     // Champs mappes indirectement
//     creation: Option<DateEpochSeconds>,
//     derniere_modification: Option<DateEpochSeconds>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DBFichierVersion {
    nom_fichier: String,
    mimetype: String,
    taille: usize,
    #[serde(rename="dateFichier")]
    date_fichier: DateEpochSeconds,
}

async fn requete_favoris<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_favoris Message : {:?}", & m.message);
    //let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let projection = doc! {CHAMP_NOM: true, CHAMP_TITRE: true, CHAMP_SECURITE: true, CHAMP_TUUID: true};
    let filtre = doc! { CHAMP_FAVORIS: true };
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
    // titre: Option<HashMap<String, String>>,
}

async fn requete_documents_par_tuuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.message);
    let requete: RequeteDocumentsParTuuids = m.message.get_msg().map_contenu(None)?;
    debug!("requete_documents_par_tuuid cle parsed : {:?}", requete);

    let filtre = doc! { CHAMP_TUUID: {"$in": &requete.tuuids_documents} };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let curseur = collection.find(filtre, None).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers":  fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_contenu_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_contenu_collection Message : {:?}", & m.message);
    let requete: RequeteContenuCollection = m.message.get_msg().map_contenu(None)?;
    debug!("requete_contenu_collection cle parsed : {:?}", requete);

    let skip = match requete.skip { Some(s) => s, None => 0 };
    let limit = match requete.limit { Some(l) => l, None => 50 };
    let filtre_collection = doc! { CHAMP_TUUID: &requete.tuuid_collection, CHAMP_SUPPRIME: false };

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
                doc_sort.insert(k, 1);
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

    // if permission is not None:
    //     permission[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES] = extra_out[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS]
    //     permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)
    //     reponse['permission'] = permission

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_get_corbeille<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_corbeille Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_corbeille cle parsed : {:?}", requete);
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
    let filtre = doc!{CHAMP_SUPPRIME: true};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParTuuids {
    tuuids_documents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteContenuCollection {
    tuuid_collection: String,
    limit: Option<i64>,
    skip: Option<u64>,
    sort_keys: Option<Vec<String>>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct RequeteClesNonDechiffrable {
//     limite: Option<u64>,
//     page: Option<u64>,
// }

// async fn evenement_cle_manquante<M>(middleware: &M, m: &MessageValideAction) -> Result<(), Box<dyn Error>>
//     where M: ValidateurX509 + GenerateurMessages + MongoDao,
// {
//     debug!("evenement_cle_manquante Marquer cles comme non dechiffrables {:?}", &m.message);
//     let event_non_dechiffrables: ReponseSynchroniserCles = m.message.get_msg().map_contenu(None)?;
//
//     let filtre = doc! { CHAMP_HACHAGE_BYTES: { "$in": event_non_dechiffrables.liste_hachage_bytes }};
//     let ops = doc! {
//         "$set": { CHAMP_NON_DECHIFFRABLE: true },
//         "$currentDate": { CHAMP_MODIFICATION: true },
//     };
//     let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
//     let resultat_update = collection.update_many(filtre, ops, None).await?;
//     debug!("evenement_cle_manquante Resultat update : {:?}", resultat_update);
//
//     Ok(())
// }

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::backup::CatalogueHoraire;
    use millegrilles_common_rust::formatteur_messages::MessageSerialise;
    use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
    use millegrilles_common_rust::middleware::IsConfigurationPki;
    use millegrilles_common_rust::middleware_db::preparer_middleware_db;
    use millegrilles_common_rust::mongo_dao::convertir_to_bson;
    use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
    use millegrilles_common_rust::recepteur_messages::TypeMessage;
    use millegrilles_common_rust::tokio as tokio;

    use crate::test_setup::setup;

    use super::*;

    // #[tokio::test]
    // async fn test_requete_compte_non_dechiffrable() {
    //     setup("test_requete_compte_non_dechiffrable");
    //     let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
    //     let enveloppe_privee = middleware.get_enveloppe_privee();
    //     let fingerprint = enveloppe_privee.fingerprint().as_str();
    //
    //     let gestionnaire = GestionnaireGrosFichiers {fingerprint: fingerprint.into()};
    //     futures.push(tokio::spawn(async move {
    //
    //         let contenu = json!({});
    //         let message_mg = MessageMilleGrille::new_signer(
    //             enveloppe_privee.as_ref(),
    //             &contenu,
    //             DOMAINE_NOM.into(),
    //             REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
    //             None::<&str>,
    //             None
    //         ).expect("message");
    //         let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
    //
    //         // Injecter certificat utilise pour signer
    //         message.certificat = Some(enveloppe_privee.enveloppe.clone());
    //
    //         let mva = MessageValideAction::new(
    //             message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
    //
    //         let reponse = requete_compter_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
    //         debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }

}

