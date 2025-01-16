use std::sync::Arc;
use std::thread::sleep;
use log::{debug, error, info};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::{Duration, Timelike, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, DEFAULT_Q_TTL, TOPOLOGIE_NOM_DOMAINE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::time::{Duration as DurationTokio, timeout};

use crate::grosfichiers_constantes::*;
use crate::commandes::consommer_commande;
use crate::requetes::consommer_requete;
use crate::evenements::{consommer_evenement, HandlerEvenements};
use crate::traitement_entretien::{calculer_quotas, reclamer_fichiers};
use crate::traitement_index::IndexationJobHandler;
use crate::traitement_jobs::{creer_jobs_manquantes, entretien_jobs_expirees, maintenance_impossible_jobs};
// use crate::traitement_media::{ImageJobHandler, VideoJobHandler};
use crate::transactions::aiguillage_transaction;

const INTERVALLE_THREAD_EVENEMENTS_SECS: u64 = 1;

#[derive(Clone)]
pub struct GrosFichiersDomainManager {
    pub instance_id: String,
    // pub image_job_handler: ImageJobHandler,
    // pub video_job_handler: VideoJobHandler,
    // pub indexation_job_handler: IndexationJobHandler,
    pub evenements_handler: HandlerEvenements
}

impl GrosFichiersDomainManager {
    pub fn new(instance_id: String) -> GrosFichiersDomainManager {

        // let image_job_handler = ImageJobHandler {};
        // let video_job_handler = VideoJobHandler {};
        let indexation_job_handler = IndexationJobHandler {};
        let evenements_handler = HandlerEvenements::new();

        GrosFichiersDomainManager {
            instance_id,
            // image_job_handler, video_job_handler, indexation_job_handler,
            evenements_handler
        }
    }
}

impl GestionnaireDomaineV2 for GrosFichiersDomainManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(NOM_COLLECTION_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_VERSIONS),
            String::from(NOM_COLLECTION_FICHIERS_REP),
            String::from(NOM_COLLECTION_DOCUMENTS),
            String::from(NOM_COLLECTION_PARTAGE_CONTACT),
            String::from(NOM_COLLECTION_MEDIA),
        ])
    }

    fn reclame_fuuids(&self) -> bool {
        true
    }

    fn get_rebuild_transaction_batch_size(&self) -> u64 { 50 }
}

impl GestionnaireBusMillegrilles for GrosFichiersDomainManager {
    fn get_nom_domaine(&self) -> String {
        DOMAINE_NOM.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAINE_NOM)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAINE_NOM)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues(self)
    }
}

#[async_trait]
impl ConsommateurMessagesBus for GrosFichiersDomainManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement(middleware, self, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for GrosFichiersDomainManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for GrosFichiersDomainManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        if ! middleware.get_mode_regeneration() {  // Only when not rebuilding
            traiter_cedule(self, middleware, trigger).await?;
        }
        Ok(())
    }

    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), Error>
    where
        M: MongoDao + ConfigMessages
    {
        // Handle transaction collection init being overridden
        if let Some(collection_name) = self.get_collection_transactions() {
            prepare_mongodb_domain_indexes(middleware, collection_name).await?;
        }
        preparer_index_mongodb(middleware).await?;  // Specialised indexes for domain collections
        Ok(())
    }
}

pub fn preparer_queues(manager: &GrosFichiersDomainManager) -> Vec<QueueType> {
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
        REQUETE_GET_CLES_FICHIERS,
        REQUETE_GET_CLES_STREAM,
        REQUETE_CONFIRMER_ETAT_FUUIDS,
        REQUETE_VERIFIER_ACCES_FUUIDS,
        REQUETE_VERIFIER_ACCES_TUUIDS,
        REQUETE_SYNC_COLLECTION,
        REQUETE_SYNC_RECENTS,
        REQUETE_SYNC_CORBEILLE,
        REQUETE_SYNC_CUUIDS,
        REQUETE_JOBS_VIDEO,
        REQUETE_CHARGER_CONTACTS,
        REQUETE_PARTAGES_USAGER,
        REQUETE_PARTAGES_CONTACT,
        REQUETE_INFO_STATISTIQUES,
        REQUETE_STRUCTURE_REPERTOIRE,
        REQUETE_JWT_STREAMING,
        REQUETE_SOUS_REPERTOIRES,
        REQUETE_RECHERCHE_INDEX,
        REQUETE_SEARCH_INDEX_V2,
        REQUETE_INFO_VIDEO,
        REQUEST_SYNC_DIRECTORY,
        REQUEST_FILES_BY_TUUID,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes_privees: Vec<&str> = vec![
        TRANSACTION_NOUVELLE_VERSION,  // Emise par consignationfichiers
        TRANSACTION_NOUVELLE_COLLECTION,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION,
        // TRANSACTION_RETIRER_DOCUMENTS_COLLECTION,
        TRANSACTION_SUPPRIMER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS,
        TRANSACTION_RECUPERER_DOCUMENTS_V2,
        TRANSACTION_ARCHIVER_DOCUMENTS,
        // TRANSACTION_CHANGER_FAVORIS,
        TRANSACTION_DECRIRE_FICHIER,
        TRANSACTION_DECRIRE_COLLECTION,
        TRANSACTION_COPIER_FICHIER_TIERS,
        // TRANSACTION_FAVORIS_CREERPATH,
        TRANSACTION_SUPPRIMER_VIDEO,
        TRANSACTION_VIDEO_SUPPRIMER_JOB_V2,
        TRANSACTION_AJOUTER_CONTACT_LOCAL,
        TRANSACTION_SUPPRIMER_CONTACTS,
        TRANSACTION_PARTAGER_COLLECTIONS,
        TRANSACTION_SUPPRIMER_PARTAGE_USAGER,
        TRANSACTION_SUPPRIMER_ORPHELINS,

        COMMANDE_RECLAMER_FUUIDS,

        COMMANDE_NOUVEAU_FICHIER,
        COMMANDE_VIDEO_TRANSCODER,
        // COMMANDE_VIDEO_ARRETER_CONVERSION,
        // COMMANDE_VIDEO_GET_JOB,
        COMMANDE_COMPLETER_PREVIEWS,
    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    let commandes_protegees: Vec<&str> = vec![
        COMMANDE_REINDEXER,
        COMMANDE_GET_CLE_JOB_CONVERSION,
        COMMANDE_JOB_GET_KEY,
        TRANSACTION_ASSOCIER_CONVERSIONS,
        TRANSACTION_ASSOCIER_VIDEO,
        TRANSACTION_IMAGE_SUPPRIMER_JOB_V2,
        TRANSACTION_VIDEO_SUPPRIMER_JOB_V2,
        TRANSACTION_CONFIRMER_FICHIER_INDEXE,
    ];
    for cmd in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L3Protege});
    }

    // RK 2.prive
    let requetes_protegees: Vec<&str> = vec![
        REQUETE_SYNC_COLLECTION,
        REQUETE_SYNC_RECENTS,
        REQUETE_SYNC_CORBEILLE,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L4Secure});
    }

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_FICHIERS_SYNCPRET), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_FICHIERS_VISITER_FUUIDS), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_FICHIERS_CONSIGNE), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.*.{}", DOMAINE_MEDIA_NOM, EVENEMENT_TRANSCODAGE_PROGRES), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_FICHIERS_SYNC_PRIMAIRE), exchange: Securite::L2Prive});

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FILECONTROLER_NOM, EVENEMENT_FILEHOST_NEWFUUID), exchange: Securite::L1Public});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", TOPOLOGIE_NOM_DOMAINE, EVENEMENT_RESET_VISITS_CLAIMS), exchange: Securite::L1Public});


    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues

}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    // Index fuuids pour fichiers (liste par tuuid)
    let options_unique_fuuids_versions = IndexOptions {
        nom_index: Some(format!("fuuids_versions_user_id")),
        unique: false
    };
    let champs_index_fuuids_version = vec!(
        ChampIndex {nom_champ: String::from("fuuids_versions"), direction: 1},
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_fuuids_version,
        Some(options_unique_fuuids_versions)
    ).await?;

    // Index cuuids pour collections de fichiers (liste par cuuid)
    let options_unique_cuuid = IndexOptions {
        nom_index: Some(format!("path_cuuids")),
        unique: false
    };
    let champs_index_cuuid = vec!(
        ChampIndex {nom_champ: String::from("path_cuuids"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_cuuid,
        Some(options_unique_cuuid)
    ).await?;

    // Index user_id_type_node pour collections de fichiers (liste par cuuid)
    let options_user_id_type_node = IndexOptions {
        nom_index: Some(format!("user_id_type_node")),
        unique: false
    };
    let champs_index_user_id_type_node = vec!(
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
        ChampIndex {nom_champ: String::from("type_node"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_user_id_type_node,
        Some(options_user_id_type_node)
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
        middleware,
        NOM_COLLECTION_FICHIERS_REP,
        champs_index_tuuid,
        Some(options_unique_tuuid)
    ).await?;

    // Activite recente des fichiers
    let options_recents = IndexOptions {
        nom_index: Some(format!("fichiers_activite_recente_2")),
        unique: true
    };
    let champs_recents = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_SUPPRIME), direction: -1},  // pour filtre
        ChampIndex {nom_champ: String::from(CHAMP_SUPPRIME_INDIRECT), direction: -1},  // pour filtre
        ChampIndex {nom_champ: String::from(CHAMP_MODIFICATION), direction: -1},
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},  // Tri stable
    );
    middleware.create_index(
        middleware,
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
        middleware,
        NOM_COLLECTION_FICHIERS_REP,
        champs_favoris,
        Some(options_favoris)
    ).await?;

    // Index fuuid pour versions
    let options_unique_versions_fuuid = IndexOptions {nom_index: Some(CHAMP_FUUID.to_string()), unique: true};
    let champs_index_versions_fuuid = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FUUID), direction: 1}
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_versions_fuuid,
        Some(options_unique_versions_fuuid)
    ).await?;

    // Index fuuids_reclames pour versions
    let options_unique_versions_fuuids_reclames = IndexOptions {nom_index: Some("fuuids_reclames".to_string()), unique: false};
    let champs_index_versions_fuuids_reclames = vec!(
        ChampIndex {nom_champ: String::from("fuuids_reclames"), direction: 1}
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_versions_fuuids_reclames,
        Some(options_unique_versions_fuuids_reclames)
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
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_media_traite,
        Some(options_index_media_traite)
    ).await?;

    let options_index_video_traite = IndexOptions {
        nom_index: Some(format!("flag_video_traite")),
        unique: false
    };
    let champs_index_video_traite = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FLAG_VIDEO_TRAITE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_video_traite,
        Some(options_index_video_traite)
    ).await?;

    let options_index_last_visits = IndexOptions {
        nom_index: Some("last_visits".to_string()),
        unique: false
    };
    let champs_index_last_visits = vec!(
        ChampIndex {nom_champ: String::from(CONST_FIELD_LAST_VISIT_VERIFICATION), direction: 1},
        ChampIndex {nom_champ: String::from("visites.nouveau"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_last_visits,
        Some(options_index_last_visits)
    ).await?;

    let options_index_tuuids = IndexOptions {
        nom_index: Some("tuuids".to_string()),
        unique: false
    };
    let champs_index_tuuids = vec!(
        ChampIndex {nom_champ: String::from("tuuids"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VERSIONS,
        champs_index_tuuids,
        Some(options_index_tuuids)
    ).await?;

    // Index conversion unique tuuid/params
    let options_tuuids_params = IndexOptions {
        nom_index: Some(format!("tuuid_params")),
        unique: true
    };
    let champs_tuuids_params = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CLE_CONVERSION), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VIDEO_JOBS,
        champs_tuuids_params,
        Some(options_tuuids_params)
    ).await?;

    let options_job_id = IndexOptions {nom_index: Some("job_id".to_string()), unique: true};
    let champs_job_id_params = vec!(
        ChampIndex {nom_champ: String::from("job_id"), direction: 1},
    );
    middleware.create_index(middleware, NOM_COLLECTION_VIDEO_JOBS, champs_job_id_params, Some(options_job_id)).await?;

    // Index conversion images getJob
    let options_images_jobs = IndexOptions {
        nom_index: Some(NOM_INDEX_ETAT_JOBS.to_string()),
        unique: false
    };
    let champs_images_jobs = vec!(
        ChampIndex {nom_champ: String::from("etat"), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_MODIFICATION), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_INSTANCES), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_IMAGES_JOBS,
        champs_images_jobs,
        Some(options_images_jobs)
    ).await?;

    let options_images_user_id_tuuids = IndexOptions {
        nom_index: Some(NOM_INDEX_USER_ID_TUUIDS.to_string()),
        unique: false
    };
    let champs_images_user_id_tuuids = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_IMAGES_JOBS,
        champs_images_user_id_tuuids,
        Some(options_images_user_id_tuuids)
    ).await?;

    let options_job_id = IndexOptions {nom_index: Some("job_id".to_string()), unique: true};
    let champs_job_id_params = vec!(
        ChampIndex {nom_champ: String::from("job_id"), direction: 1},
    );
    middleware.create_index(middleware, NOM_COLLECTION_IMAGES_JOBS, champs_job_id_params, Some(options_job_id)).await?;

    // Index conversion video getJob
    let options_jobs_params = IndexOptions {
        nom_index: Some(NOM_INDEX_ETAT_JOBS.to_string()),
        unique: false
    };
    let champs_jobs_params = vec!(
        ChampIndex {nom_champ: String::from("etat"), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_MODIFICATION), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_INSTANCES), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VIDEO_JOBS,
        champs_jobs_params,
        Some(options_jobs_params)
    ).await?;

    let options_video_user_id_tuuids = IndexOptions {
        nom_index: Some(NOM_INDEX_USER_ID_TUUIDS.to_string()),
        unique: false
    };
    let champs_video_user_id_tuuids = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_VIDEO_JOBS,
        champs_video_user_id_tuuids,
        Some(options_video_user_id_tuuids)
    ).await?;

    // Index indexation contenu
    let options_indexation_jobs = IndexOptions {
        nom_index: Some(NOM_INDEX_ETAT_JOBS.to_string()),
        unique: false
    };
    let champs_indexation_jobs = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_ETAT_JOB), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_FLAG_DB_RETRY), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_INSTANCES), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INDEXATION_JOBS,
        champs_indexation_jobs,
        Some(options_indexation_jobs)
    ).await?;

    let options_job_id = IndexOptions {nom_index: Some("job_id".to_string()), unique: true};
    let champs_job_id_params = vec!(
        ChampIndex {nom_champ: String::from("job_id"), direction: 1},
    );
    middleware.create_index(middleware, NOM_COLLECTION_INDEXATION_JOBS, champs_job_id_params, Some(options_job_id)).await?;

    let options_indexation_user_id_tuuids = IndexOptions {
        nom_index: Some(NOM_INDEX_USER_ID_TUUIDS.to_string()),
        unique: false
    };
    let champs_indexation_user_id_tuuids = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INDEXATION_JOBS,
        champs_indexation_user_id_tuuids,
        Some(options_indexation_user_id_tuuids)
    ).await?;

    let options_indexation_quotas_user_id = IndexOptions {
        nom_index: Some(NOM_INDEX_USER_ID.to_string()),
        unique: true
    };
    let champs_indexation_user_id_quotas = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_QUOTAS_USAGERS,
        champs_indexation_user_id_quotas,
        Some(options_indexation_quotas_user_id)
    ).await?;

    // Index fuuid pour media
    let options_unique_media = IndexOptions {nom_index: Some("fuuid_userid".to_string()), unique: true};
    let champs_index_media = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_FUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1}
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_MEDIA,
        champs_index_media,
        Some(options_unique_media)
    ).await?;

    // Unique index for contacts
    let options_unique_contact = IndexOptions {nom_index: Some("contact_id".to_string()), unique: true};
    let champs_index_contact = vec!(
        ChampIndex {nom_champ: String::from("contact_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_PARTAGE_CONTACT,
        champs_index_contact,
        Some(options_unique_contact)
    ).await?;

    // Unique index for shared collections
    let options_unique_shared_collections = IndexOptions {nom_index: Some("user_collection".to_string()), unique: true};
    let champs_index_shared_collections = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_TUUID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_PARTAGE_COLLECTIONS,
        champs_index_shared_collections,
        Some(options_unique_shared_collections)
    ).await?;

    Ok(())
}

pub async fn traiter_cedule<M>(gestionnaire: &GrosFichiersDomainManager, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), CommonError>
where M: MiddlewareMessages + BackupStarter + MongoDao
{
    debug!("Traiter cedule {}", DOMAINE_NOM);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip");
        return Ok(());
    }

    let date_epoch = trigger.get_date();

    if date_epoch < Utc::now() - Duration::seconds(90) {
        return Ok(())  // Trigger too old, ignore
    }

    let minutes = date_epoch.minute();
    let hours = date_epoch.hour();

    if hours % 3 == 0 && minutes == 21
    {
        info!("creer_jobs_manquantes STARTING");
        if let Err(e) = creer_jobs_manquantes(middleware).await {  // Creer jobs media/indexation manquantes (recovery)
            info!("creer_jobs_manquantes Error: {:?}", e);
        }
        info!("creer_jobs_manquantes DONE");
    }
    // if minutes % 4 == 2
    {
        // Restart expired media jobs
        info!("entretien_jobs_expirees STARTING");
        let fetch_filehosts = minutes == 2;  // Once an hour
        if let Err(e) = entretien_jobs_expirees(middleware, fetch_filehosts).await {
            error!("entretien_jobs_expirees Error: {:?}", e);
        }
        info!("entretien_jobs_expirees DONE");
    }
    // if hours % 3 == 2 && minutes == 27
    {
        // Remove media/indexation jobs that will never complete
        info!("maintenance_impossible_jobs STARTING");
        if let Err(e) = maintenance_impossible_jobs(middleware, gestionnaire).await {
            error!("maintenance_impossible_jobs Error: {:?}", e);
        }
        info!("maintenance_impossible_jobs DONE");
    }

    // Recalculer les quotas a toutes les 3 heures
    if hours % 3 == 1 && minutes == 14
    {
        info!("calculer_quotas STARTING");
        if let Err(e) = calculer_quotas(middleware).await {
            error!("calculer_quotas Error: {:?}", e);
        };
        info!("calculer_quotas DONE");
    }

    // Reclamer les fichiers pour eviter qu'ils soient supprimes. Execute des petites batch toutes
    // les 3 minutes pour s'assurer que tous les fichiers sont identifies aux 3 jours.
    {
        let nouveaux = minutes % 3 != 0;  // Check fichiers presents nul part toutes les minutes
        info!("reclamer_fichiers STARTING");
        if let Err(e) = reclamer_fichiers(middleware, gestionnaire, nouveaux).await {
            error!("reclamer_fichiers Error: {:?}", e);
        }
        info!("reclamer_fichiers DONE");
    }

    Ok(())
}

pub async fn thread_entretien_evenements<M>(middleware: &M, gestionnaire: &'static GrosFichiersDomainManager)
where M: Middleware + 'static
{
    let handler_evenements = &gestionnaire.evenements_handler;

    loop {
        if let Err(e) = handler_evenements.emettre_cuuid_content_expires(middleware, gestionnaire).await {
            error!("thread_entretien_evenements Erreur emettre_cuuid_content_expires : {}", e);
        }
        tokio::time::sleep(DurationTokio::new(INTERVALLE_THREAD_EVENEMENTS_SECS, 0)).await;
    }
}
