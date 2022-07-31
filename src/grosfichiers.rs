use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::CommandeSauvegarderCle;
use millegrilles_common_rust::{chrono, chrono::{DateTime, Utc}};
use millegrilles_common_rust::chrono::Timelike;
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
use crate::evenements::consommer_evenement;
use crate::grosfichiers_constantes::*;
use crate::requetes::{consommer_requete, mapper_fichier_db};
use crate::traitement_index::{ElasticSearchDao, ElasticSearchDaoImpl, InfoDocumentIndexation, ParametresIndex, ParametresRecherche, ResultatRecherche, traiter_index_manquant};
use crate::traitement_media::{entretien_video_jobs, traiter_media_batch};
use crate::transactions::*;

#[derive(Clone, Debug)]
pub struct GestionnaireGrosFichiers {
    // pub consignation: String,
    pub index_dao: Arc<ElasticSearchDaoImpl>,
}

#[async_trait]
impl TraiterTransaction for GestionnaireGrosFichiers {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
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
        true
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
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
        entretien(self, middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        traiter_cedule(self, middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl ElasticSearchDao for GestionnaireGrosFichiers {
    async fn es_preparer(&self) -> Result<(), String> {
        self.index_dao.es_preparer().await
    }

    fn es_est_pret(&self) -> bool {
        self.index_dao.es_est_pret()
    }

    async fn es_indexer<S, T>(&self, nom_index: S, id_doc: T, info_doc: InfoDocumentIndexation)
        -> Result<(), String>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        self.index_dao.es_indexer(nom_index, id_doc, info_doc).await
    }

    async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresRecherche)
        -> Result<ResultatRecherche, String>
        where S: AsRef<str> + Send
    {
        self.index_dao.es_rechercher(nom_index, params).await
    }

    async fn es_reset_index(&self) -> Result<(), String> { self.index_dao.es_reset_index().await }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 2.prive
    let requetes_privees: Vec<&str> = vec![
        REQUETE_ACTIVITE_RECENTE,
        REQUETE_FAVORIS,
        REQUETE_DOCUMENTS_PAR_TUUID,
        REQUETE_DOCUMENTS_PAR_FUUID,
        REQUETE_CONTENU_COLLECTION,
        REQUETE_GET_CORBEILLE,
        REQUETE_RECHERCHE_INDEX,
        REQUETE_GET_CLES_FICHIERS,
        REQUETE_CONFIRMER_ETAT_FUUIDS,
        REQUETE_VERIFIER_ACCES_FUUIDS,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes_privees: Vec<&str> = vec![
        TRANSACTION_NOUVELLE_VERSION,  // Emise par consignationfichiers
        TRANSACTION_NOUVELLE_COLLECTION,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION,
        TRANSACTION_SUPPRIMER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS,
        TRANSACTION_CHANGER_FAVORIS,
        TRANSACTION_DECRIRE_FICHIER,
        TRANSACTION_DECRIRE_COLLECTION,
        TRANSACTION_COPIER_FICHIER_TIERS,
        TRANSACTION_FAVORIS_CREERPATH,
        TRANSACTION_ASSOCIER_CONVERSIONS,
        TRANSACTION_ASSOCIER_VIDEO,
        TRANSACTION_SUPPRIMER_VIDEO,
        COMMANDE_NOUVEAU_FICHIER,
        COMMANDE_INDEXER,
        COMMANDE_VIDEO_TRANSCODER,
        COMMANDE_VIDEO_ARRETER_CONVERSION,
        COMMANDE_VIDEO_GET_JOB,
    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    let commandes_protegees: Vec<&str> = vec![
        COMMANDE_INDEXER,
        COMMANDE_COMPLETER_PREVIEWS,
        COMMANDE_CONFIRMER_FICHIER_INDEXE,
    ];
    for cmd in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L3Protege});
    }

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_CONFIRMER_ETAT_FUUIDS), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.*.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_TRANSCODAGE_PROGRES), exchange: Securite::L2Prive});

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
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION,
        TRANSACTION_SUPPRIMER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS,
        TRANSACTION_CHANGER_FAVORIS,
        TRANSACTION_ASSOCIER_CONVERSIONS,
        TRANSACTION_ASSOCIER_VIDEO,
        TRANSACTION_DECRIRE_FICHIER,
        TRANSACTION_DECRIRE_COLLECTION,
        TRANSACTION_COPIER_FICHIER_TIERS,
        TRANSACTION_FAVORIS_CREERPATH,
        TRANSACTION_SUPPRIMER_VIDEO,

        // Transaction emise par media
        TRANSACTION_ASSOCIER_CONVERSIONS,
        TRANSACTION_ASSOCIER_VIDEO,
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
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

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

    // Index flag indexe
    let options_index_indexe = IndexOptions {
        nom_index: Some(format!("flag_indexe")),
        unique: false
    };
    let champs_index_indexe = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FLAG_INDEXE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VERSIONS,
        champs_index_indexe,
        Some(options_index_indexe)
    ).await?;

    // Index flag image_traitees
    let options_index_media_traite = IndexOptions {
        nom_index: Some(format!("flag_media_traite")),
        unique: false
    };
    let champs_index_media_traite = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FLAG_MEDIA_TRAITE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VERSIONS,
        champs_index_media_traite,
        Some(options_index_media_traite)
    ).await?;

    // Index conversion video cles
    let options_fuuids_params = IndexOptions {
        nom_index: Some(format!("fuuid_params")),
        unique: true
    };
    let champs_fuuids_params = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CLE_CONVERSION), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VIDEO_JOBS,
        champs_fuuids_params,
        Some(options_fuuids_params)
    ).await?;

    // Index conversion video getJob
    let options_jobs_params = IndexOptions {
        nom_index: Some(format!("etat_jobs")),
        unique: false
    };
    let champs_jobs_params = vec!(
        ChampIndex {nom_champ: String::from("etat"), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_MODIFICATION), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_VIDEO_JOBS,
        champs_jobs_params,
        Some(options_jobs_params)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(_gestionnaire: &GestionnaireGrosFichiers, _middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, trigger: &MessageCedule)
    -> Result<(), Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Traiter cedule {}", DOMAINE_NOM);

    let mut prochain_entretien_index_media = chrono::Utc::now();
    let intervalle_entretien_index_media = chrono::Duration::minutes(5);

    let date_epoch = trigger.get_date();
    let minutes = date_epoch.get_datetime().minute();

    // Executer a toutes les 5 minutes
    if minutes % 5 == 0 {
        debug!("Generer index et media manquants");
        if let Err(e) = traiter_media_batch(middleware, MEDIA_IMAGE_BACTH_DEFAULT).await {
            warn!("Erreur traitement media batch : {:?}", e);
        }
        if let Err(e) = entretien_video_jobs(middleware).await {
            warn!("Erreur traitement media entretien_video_jobs : {:?}", e);
        }
        if let Err(e) = traiter_index_manquant(middleware, gestionnaire, 1000).await {
            warn!("Erreur traitement index manquant batch : {:?}", e);
        }
    }

    Ok(())
}

pub async fn emettre_evenement_maj_fichier<M, S, T>(middleware: &M, tuuid: S, action: T) -> Result<(), String>
where
    M: GenerateurMessages + MongoDao,
    S: AsRef<str>,
    T: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let action_str = action.as_ref();
    debug!("grosfichiers.emettre_evenement_maj_fichier Emettre evenement maj pour fichier {}", tuuid_str);

    // Charger fichier
    let filtre = doc! {CHAMP_TUUID: tuuid_str};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(filtre, None).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.emettre_evenement_maj_fichier Erreur collection.find_one pour {} : {:?}", tuuid_str, e))?
    };
    match doc_fichier {
        Some(inner) => {
            // Extraire liste de fuuids directement
            let routage_action = RoutageMessageAction::builder("grosfichiers", action_str)
                .exchanges(vec![Securite::L2Prive])
                .build();

            match inner.get_array("fuuids") {
                Ok(fuuids) => {
                    middleware.emettre_evenement(routage_action.clone(), &json!({CHAMP_FUUIDS: fuuids})).await?;
                },
                Err(_) => ()
            };

            let fichier_mappe = match mapper_fichier_db(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("grosfichiers.emettre_evenement_maj_fichier Erreur mapper_fichier_db : {:?}", e))?
            };
            let routage = RoutageMessageAction::builder("grosfichiers", EVENEMENT_MAJ_FICHIER)
                .exchanges(vec![Securite::L2Prive])
                .build();
            middleware.emettre_evenement(routage, &fichier_mappe).await?;
        },
        None => Err(format!("grosfichiers.emettre_evenement_maj_fichier Fichier {} introuvable", tuuid_str))?
    };

    Ok(())
}

pub async fn emettre_evenement_maj_collection<M, S>(middleware: &M, tuuid: S) -> Result<(), String>
where
    M: GenerateurMessages + MongoDao,
    S: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    debug!("grosfichiers.emettre_evenement_maj_collection Emettre evenement maj pour collection {}", tuuid_str);

    // Charger fichier
    let filtre = doc! {CHAMP_TUUID: tuuid_str};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(filtre, None).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.where Erreur collection.find_one pour {} : {:?}", tuuid_str, e))?
    };
    match doc_fichier {
        Some(inner) => {
            let fichier_mappe = match mapper_fichier_db(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("grosfichiers.emettre_evenement_maj_collection Erreur mapper_fichier_db : {:?}", e))?
            };
            let routage = RoutageMessageAction::builder("grosfichiers", "majCollection")
                .exchanges(vec![Securite::L2Prive])
                .build();
            middleware.emettre_evenement(routage, &fichier_mappe).await?;
        },
        None => Err(format!("grosfichiers.emettre_evenement_maj_collection Collection {} introuvable", tuuid_str))?
    };

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementContenuCollection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fichiers_ajoutes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fichiers_modifies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collections_ajoutees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collections_modifiees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retires: Option<Vec<String>>,
}

impl EvenementContenuCollection {
    pub fn new() -> Self {
        Self {
            cuuid: None,
            fichiers_ajoutes: None,
            fichiers_modifies: None,
            collections_ajoutees: None,
            collections_modifiees: None,
            retires: None,
        }
    }
}

pub async fn emettre_evenement_contenu_collection<M,E>(middleware: &M, evenement: E)
    -> Result<(), String>
where
    M: GenerateurMessages + MongoDao,
    E: Borrow<EvenementContenuCollection> + Debug
{
    debug!("grosfichiers.emettre_evenement_contenu_collection Emettre evenement maj pour collection {:?}", evenement);

    let evenement_ref = evenement.borrow();

    let routage = {
        let mut routage_builder = RoutageMessageAction::builder("grosfichiers", "majContenuCollection")
            .exchanges(vec![Securite::L2Prive]);
        if let Some(cuuid) = evenement_ref.cuuid.as_ref() {
            routage_builder = routage_builder.partition(cuuid.clone());
        }
        routage_builder.build()
    };

    // let contenu = json!({
    //     "cuuid": tuuid_str,
    //     "fichiers_ajoutes": fichiers_ajoutes,
    //     "collections_ajoutees": collections_ajoutees,
    //     "tuuids_retires": tuuids_retires,
    // });
    middleware.emettre_evenement(routage, evenement_ref).await?;

    Ok(())
}

// #[cfg(test)]
// mod test_integration {
//     use millegrilles_common_rust::backup::CatalogueHoraire;
//     use millegrilles_common_rust::formatteur_messages::MessageSerialise;
//     use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
//     use millegrilles_common_rust::middleware::IsConfigurationPki;
//     use millegrilles_common_rust::middleware_db::preparer_middleware_db;
//     use millegrilles_common_rust::mongo_dao::convertir_to_bson;
//     use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
//     use millegrilles_common_rust::recepteur_messages::TypeMessage;
//     use millegrilles_common_rust::tokio as tokio;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
// // #[tokio::test]
//     // async fn test_requete_compte_non_dechiffrable() {
//     //     setup("test_requete_compte_non_dechiffrable");
//     //     let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//     //     let enveloppe_privee = middleware.get_enveloppe_privee();
//     //     let fingerprint = enveloppe_privee.fingerprint().as_str();
//     //
//     //     let gestionnaire = GestionnaireGrosFichiers {fingerprint: fingerprint.into()};
//     //     futures.push(tokio::spawn(async move {
//     //
//     //         let contenu = json!({});
//     //         let message_mg = MessageMilleGrille::new_signer(
//     //             enveloppe_privee.as_ref(),
//     //             &contenu,
//     //             DOMAINE_NOM.into(),
//     //             REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
//     //             None::<&str>,
//     //             None
//     //         ).expect("message");
//     //         let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//     //
//     //         // Injecter certificat utilise pour signer
//     //         message.certificat = Some(enveloppe_privee.enveloppe.clone());
//     //
//     //         let mva = MessageValideAction::new(
//     //             message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//     //
//     //         let reponse = requete_compter_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//     //         debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);
//     //
//     //     }));
//     //     // Execution async du test
//     //     futures.next().await.expect("resultat").expect("ok");
//     // }
//
// }

