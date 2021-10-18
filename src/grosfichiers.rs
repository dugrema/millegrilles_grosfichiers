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
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_to_bson, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

const DOMAINE_NOM: &str = "GrosFichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "GrosFichiers";
const NOM_COLLECTION_FICHIERS: &str = "GrosFichiers/fichiers";
const NOM_COLLECTION_COLLECTIONS: &str = "GrosFichiers/collections";
const NOM_COLLECTION_DOCUMENTS: &str = "GrosFichiers/documents";

const NOM_Q_TRANSACTIONS: &str = "GrosFichiers/transactions";
const NOM_Q_VOLATILS: &str = "GrosFichiers/volatils";
const NOM_Q_TRIGGERS: &str = "GrosFichiers/triggers";

const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";
const REQUETE_FAVORIS: &str = "favoris";

const TRANSACTION_NOUVELLE_VERSION: &str = "nouvelleVersion";

const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale, serie de fuuids
const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
const CHAMP_SUPPRIME: &str = "supprime";
const CHAMP_MIMETYPE: &str = "mimetype";
const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";

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
        String::from(NOM_COLLECTION_COLLECTIONS),
        String::from(NOM_COLLECTION_FICHIERS),
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

    let commandes_privees: Vec<&str> = vec![TRANSACTION_NOUVELLE_VERSION];
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
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_NOUVELLE_VERSION).into(),
        exchange: Securite::L4Secure
    });

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
        NOM_COLLECTION_FICHIERS,
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
        NOM_COLLECTION_FICHIERS,
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
        NOM_COLLECTION_FICHIERS,
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
        NOM_COLLECTION_FICHIERS,
        champs_recents,
        Some(options_recents)
    ).await?;

    // Index cuuid pour collections
    let options_unique_cuuid = IndexOptions {
        nom_index: Some(format!("collections_cuuid")),
        unique: true
    };
    let champs_index_cuuid = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_CUUID), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_COLLECTIONS,
        champs_index_cuuid,
        Some(options_unique_cuuid)
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
    match message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas d'un exchange reconnu)")),
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
                REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
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

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(middleware, transaction).await,
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
    // Retirer champs cles - ils sont inutiles dans la version
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);
    doc_bson_transaction.remove(CHAMP_CUUID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": &fuuid};
    // Ajouter collection au besoin
    if let Some(c) = cuuid {
        add_to_set.insert("cuuids", c);
    }

    let mut doc_set = doc!{
        format!("versions.{}", fuuid): doc_bson_transaction,
        CHAMP_FUUID_V_COURANTE: &fuuid,
        CHAMP_MIMETYPE: &mimetype,
        CHAMP_SUPPRIME: false,
    };

    // Information optionnelle pour accelerer indexation/traitement media
    if mimetype.starts_with("image") {
        doc_set.insert("flag_media", "image");
        doc_set.insert("flag_media_traite", false);
    } else if mimetype.starts_with("video") {
        doc_set.insert("flag_media", "video");
        doc_set.insert("flag_media_traite", false);
    } else if mimetype =="application/pdf" {
        doc_set.insert("flag_indexe", false);
    }

    let ops = doc! {
        "$set": doc_set,
        "$addToSet": add_to_set,
        "$setOnInsert": {
            "nom_fichier": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
    debug!("nouveau fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("nouveau fichier Resultat transaction update : {:?}", resultat);

    Ok(None)
}

async fn requete_activite_recente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_activite_recente Message : {:?}", & m.message);
    // let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
        .limit(100)
        .skip(0)
        .build();
    let filtre = doc!{CHAMP_SUPPRIME: false};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = {
        let mut fichiers_mappes = Vec::new();
        while let Some(fresult) = curseur.next().await {
            let fcurseur = fresult?;
            let fichier_db = mapper_fichier_db(fcurseur)?;
            let fichier_mappe: FichierVersionCourante = fichier_db.try_into()?;
            fichiers_mappes.push(fichier_mappe);
        }
        // Convertir fichiers en Value (serde pour reponse json)
        serde_json::to_value(fichiers_mappes)
    }?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

fn mapper_fichier_db(fichier: Document) -> Result<DBFichier, Box<dyn Error>> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    let mut fichier_mappe: DBFichier = convertir_bson_deserializable(fichier)?;
    fichier_mappe.creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
    fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichierVersionCourante {
    tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    cuuids: Option<Vec<String>>,
    nom_fichier: String,

    fuuid: String,
    fuuid_v_courante: String,
    version_courante: DBFichierVersion,

    date_creation: Option<DateEpochSeconds>,
    derniere_modification: Option<DateEpochSeconds>,
}

impl TryFrom<DBFichier> for FichierVersionCourante {
    type Error = String;

    fn try_from(mut value: DBFichier) -> Result<Self, Self::Error> {
        let fuuid = value.fuuid_v_courante;
        let vc = match value.versions.remove(&fuuid) {
            Some(v) => v,
            None => Err(format!("Mapping version {} manquant", &fuuid))?
        };

        Ok(FichierVersionCourante {
            tuuid: value.tuuid,
            cuuids: value.cuuids,
            nom_fichier: value.nom_fichier,

            fuuid: fuuid.clone(),
            fuuid_v_courante: fuuid,
            version_courante: vc,

            date_creation: value.creation,
            derniere_modification: value.derniere_modification,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DBFichier {
    tuuid: String,
    cuuids: Option<Vec<String>>,
    fuuids: Vec<String>,
    nom_fichier: String,
    fuuid_v_courante: String,
    versions: HashMap<String, DBFichierVersion>,

    // Champs mappes indirectement
    creation: Option<DateEpochSeconds>,
    derniere_modification: Option<DateEpochSeconds>,
}

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
    // let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    // let filtre = doc! { CHAMP_NON_DECHIFFRABLE: true };
    // let hint = Hint::Name(INDEX_NON_DECHIFFRABLES.into());
    // // let sort_doc = doc! {
    // //     CHAMP_NON_DECHIFFRABLE: 1,
    // //     CHAMP_CREATION: 1,
    // // };
    // let opts = CountOptions::builder().hint(hint).build();
    // let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    // let compte = collection.count_documents(filtre, opts).await?;

    let reponse = json!({ "favoris": [] });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
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
