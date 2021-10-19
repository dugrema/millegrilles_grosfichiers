use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
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
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::commandes::consommer_commande;
use crate::grosfichiers_constantes::*;
use crate::requetes::consommer_requete;
use crate::transactions::*;

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

