use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use log::{debug, info, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Bson, bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::fichiers::is_mimetype_video;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{get_user_effectif, Transaction};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::millegrilles_cryptographie::serde_dates::mapstringepochseconds;

use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, EvenementContenuCollection, GestionnaireGrosFichiers};

use crate::grosfichiers_constantes::*;
use crate::requetes::{ContactRow, verifier_acces_usager, verifier_acces_usager_tuuids};
use crate::traitement_jobs::{JobHandler, JobHandlerFichiersRep, JobHandlerVersions};
// use crate::traitement_media::emettre_commande_media;
// use crate::traitement_index::emettre_commande_indexation;

pub async fn consommer_transaction<M>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.type_message);

    let action = match &m.type_message {
        TypeMessageOut::Commande(r) |
        TypeMessageOut::Transaction(r) => r.action.clone(),
        _ => Err(CommonError::Str("consommer_transaction Mauvais type de message (doit etre Commande ou Transaction)"))?
    };

    // Autorisation
    match action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_NOUVELLE_VERSION |
        TRANSACTION_NOUVELLE_COLLECTION |
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION |
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION |
        // TRANSACTION_RETIRER_DOCUMENTS_COLLECTION |
        TRANSACTION_SUPPRIMER_DOCUMENTS |
        TRANSACTION_RECUPERER_DOCUMENTS |
        TRANSACTION_RECUPERER_DOCUMENTS_V2 |
        TRANSACTION_ARCHIVER_DOCUMENTS |
        // TRANSACTION_CHANGER_FAVORIS |
        TRANSACTION_DECRIRE_FICHIER |
        TRANSACTION_DECRIRE_COLLECTION |
        TRANSACTION_COPIER_FICHIER_TIERS |
        // TRANSACTION_FAVORIS_CREERPATH |
        TRANSACTION_SUPPRIMER_VIDEO |
        TRANSACTION_ASSOCIER_CONVERSIONS |
        TRANSACTION_ASSOCIER_VIDEO |
        TRANSACTION_IMAGE_SUPPRIMER_JOB |
        TRANSACTION_VIDEO_SUPPRIMER_JOB |
        TRANSACTION_SUPPRIMER_ORPHELINS => {
            match m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
                true => Ok(()),
                false => Err(CommonError::Str("transactions.consommer_transaction: pas 4.secure"))
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {:?}", m.type_message))?,
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: TryInto<TransactionValide> + Send
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(CommonError::Str("aiguillage_transaction Erreur try_into TransactionValide"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.aiguillage_transaction Transaction sans action : {}", transaction.transaction.id))?
        },
        None => Err(format!("transactions.aiguillage_transaction Transaction sans routage : {}", transaction.transaction.id))?
    };

    match action.as_str() {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(gestionnaire, middleware, transaction).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, gestionnaire, transaction).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, gestionnaire, transaction).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => transaction_deplacer_fichiers_collection(middleware, gestionnaire, transaction).await,
        // TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => transaction_retirer_documents_collection(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, gestionnaire, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, gestionnaire, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS_V2 => transaction_recuperer_documents_v2(middleware, transaction).await,
        TRANSACTION_ARCHIVER_DOCUMENTS => transaction_archiver_documents(middleware, gestionnaire, transaction).await,
        // TRANSACTION_CHANGER_FAVORIS => transaction_changer_favoris(middleware, transaction).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => transaction_associer_conversions(middleware, gestionnaire, transaction).await,
        TRANSACTION_ASSOCIER_VIDEO => transaction_associer_video(middleware, gestionnaire, transaction).await,
        TRANSACTION_DECRIRE_FICHIER => transaction_decrire_fichier(middleware, gestionnaire, transaction).await,
        TRANSACTION_DECRIRE_COLLECTION => transaction_decire_collection(middleware, gestionnaire, transaction).await,
        TRANSACTION_COPIER_FICHIER_TIERS => transaction_copier_fichier_tiers(gestionnaire, middleware, transaction).await,
        // TRANSACTION_FAVORIS_CREERPATH => transaction_favoris_creerpath(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_VIDEO => transaction_supprimer_video(middleware, gestionnaire, transaction).await,
        TRANSACTION_IMAGE_SUPPRIMER_JOB => transaction_supprimer_job_image(middleware, gestionnaire, transaction).await,
        TRANSACTION_VIDEO_SUPPRIMER_JOB => transaction_supprimer_job_video(middleware, gestionnaire, transaction).await,
        TRANSACTION_AJOUTER_CONTACT_LOCAL => transaction_ajouter_contact_local(middleware, gestionnaire, transaction).await,
        TRANSACTION_SUPPRIMER_CONTACTS => transaction_supprimer_contacts(middleware, gestionnaire, transaction).await,
        TRANSACTION_PARTAGER_COLLECTIONS => transaction_partager_collections(middleware, gestionnaire, transaction).await,
        TRANSACTION_SUPPRIMER_PARTAGE_USAGER => transaction_supprimer_partage_usager(middleware, gestionnaire, transaction).await,
        TRANSACTION_SUPPRIMER_ORPHELINS => transaction_supprimer_orphelins(middleware, gestionnaire, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleVersion {
    pub fuuid: String,
    // #[serde(skip_serializing_if="Option::is_none")]
    // pub cuuid: Option<String>,
    pub cuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    //#[serde(skip_serializing_if="Option::is_none")]
    //pub nom: Option<String>,
    pub mimetype: String,
    //#[serde(skip_serializing_if="Option::is_none")]
    //pub metadata: Option<DataChiffre>,
    pub metadata: DataChiffre,
    pub taille: u64,
    //#[serde(rename="dateFichier", skip_serializing_if="Option::is_none")]
    //pub date_fichier: Option<DateEpochSeconds>,
    // #[serde(rename = "_cle", skip_serializing_if = "Option::is_none")]
    // pub cle: Option<MessageMilleGrille>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireFichier {
    pub tuuid: String,
    // nom: Option<String>,
    // titre: Option<HashMap<String, CommonError>>,
    metadata: Option<DataChiffre>,
    // description: Option<HashMap<String, CommonError>>,
    pub mimetype: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireCollection {
    pub tuuid: String,
    // nom: Option<String>,
    metadata: Option<DataChiffre>,
    // titre: Option<HashMap<String, CommonError>>,
    // description: Option<HashMap<String, CommonError>>,
    // securite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleCollection {
    // nom: Option<String>,
    pub metadata: DataChiffre,
    pub cuuid: Option<String>,  // Insertion dans collection destination
    // securite: Option<String>,
    favoris: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterFichiersCollection {
    pub cuuid: String,                  // Collection qui recoit les documents
    pub inclure_tuuids: Vec<String>,    // Fichiers/rep a ajouter a la collection
    pub contact_id: Option<String>,     // Permission de copie a partir d'un partage
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDeplacerFichiersCollection {
    pub cuuid_origine: String,          // Collection avec les documents (source)
    pub cuuid_destination: String,      // Collection qui recoit les documents
    pub inclure_tuuids: Vec<String>,    // Fichiers/rep a ajouter a la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRetirerDocumentsCollection {
    pub cuuid: String,  // Collection qui recoit les documents
    pub retirer_tuuids: Vec<String>,  // Fichiers/rep a retirer de la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionListeDocuments {
    pub tuuids: Vec<String>,  // Fichiers/rep a supprimer, archiver, etc
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerDocuments {
    pub tuuids: Vec<String>,    // Fichiers/rep a supprimer
    pub cuuid: Option<String>,  // Collection a retirer des documents (suppression conditionnelle)
    // pub cuuids_path: Option<Vec<String>>,  // Path du fichier lors de la suppression (breadcrumb)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionChangerFavoris {
    pub favoris: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCopierFichierTiers {
    pub fuuid: String,
    pub cuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    pub mimetype: String,
    pub user_id: Option<String>,
    pub taille: u64,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, VideoInfo>>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub hachage: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resolution: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub taille: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub data_chiffre: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoInfo {
    pub fuuid: String,
    pub tuuid: String,
    pub fuuid_video: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resolution: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub taille_fichier: Option<u64>,
    pub mimetype: String,
    pub codec: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub bitrate: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub quality: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionFavorisCreerpath {
    pub favoris_id: String,
    pub user_id: Option<String>,
    pub path_collections: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierRepBorrowed<'a> {
    /// Identificateur unique d'un node pour l'usager
    #[serde(borrow)]
    pub tuuid: &'a str,
    #[serde(borrow)]
    pub user_id: &'a str,
    #[serde(borrow)]
    pub type_node: &'a str,
    pub supprime: bool,
    pub supprime_indirect: bool,
    #[serde(borrow)]
    pub metadata: DataChiffreBorrow<'a>,

    // Champs pour type_node Fichier
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub mimetype: Option<&'a str>,
    /// Fuuids des versions en ordre (plus recent en dernier)
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub fuuids_versions: Option<Vec<&'a str>>,

    // Champs pour type_node Fichiers/Repertoires
    /// Path des cuuids parents (inverse, parent immediat est index 0)
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub path_cuuids: Option<Vec<&'a str>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierRepOwned {
    /// Identificateur unique d'un node pour l'usager
    pub tuuid: String,
    pub user_id: String,
    pub type_node: String,
    pub supprime: bool,
    pub supprime_indirect: bool,
    pub metadata: DataChiffre,

    // Champs pour type_node Fichier
    pub mimetype: Option<String>,
    /// Fuuids des versions en ordre (plus recent en dernier)
    pub fuuids_versions: Option<Vec<String>>,

    // Champs pour type_node Fichiers/Repertoires
    /// Path des cuuids parents (inverse, parent immediat est index 0)
    pub path_cuuids: Option<Vec<String>>,

    // Mapping date - requis pour sync
    // #[serde(deserialize_with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification")]
    // map_derniere_modification: DateTime<Utc>,
    #[serde(default, rename(deserialize="_mg-derniere-modification"), skip_serializing_if = "Option::is_none",
    serialize_with="optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub derniere_modification: Option<DateTime<Utc>>,
}

impl NodeFichierRepOwned {
    pub async fn from_nouvelle_version<M,U,S>(middleware: &M, value: &TransactionNouvelleVersion, uuid_transaction: S, user_id: U)
        -> Result<Self, CommonError>
        where M: MongoDao, S: ToString, U: ToString
    {
        let user_id = user_id.to_string();

        let tuuid = match &value.tuuid {
            Some(t) => t.to_owned(),
            None => uuid_transaction.to_string(),
        };

        let cuuid = value.cuuid.as_str();
        //     match value.cuuid.as_ref() {
        //     Some(inner) => inner.as_str(),
        //     None => Err(format!("transactions.transaction_nouvelle_version Cuuid absent de transaction nouvelle_version"))?
        // };

        let mut cuuids = vec![cuuid.to_owned()];

        // Inserer l'information du path (cuuids parents)
        let filtre = doc!{ CHAMP_TUUID: &cuuid, CHAMP_USER_ID: &user_id };
        let collection_nodes = middleware.get_collection_typed::<NodeFichiersRepBorrow>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection_nodes.find(filtre, None).await?;
        if curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            if let Some(path_parent) = row.path_cuuids {
                // Inserer les cuuids du parent
                cuuids.extend(path_parent.into_iter().map(|c|c.to_owned()));
            }
        } else {
            Err(format!("transactions.transaction_nouvelle_version Cuuid {} inconnu", cuuid))?;
        };

        Ok(Self {
            tuuid: tuuid.to_owned(),
            user_id,
            type_node: TypeNode::Fichier.to_str().to_owned(),
            supprime: false,
            supprime_indirect: false,
            metadata: value.metadata.clone(),
            mimetype: Some(value.mimetype.clone()),
            fuuids_versions: Some(vec![value.fuuid.clone()]),
            path_cuuids: Some(cuuids),
            // map_derniere_modification: Default::default(),
            derniere_modification: None,
        })
    }
    
    // pub fn map_date_modification(&mut self) {
    //     self.derniere_modification = Some(self.map_derniere_modification.clone());
    // }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierVersionOwned {
    pub fuuid: String,
    pub tuuid: String,
    pub user_id: String,
    pub mimetype: String,
    pub metadata: DataChiffre,
    pub taille: u64,

    pub fuuids: Vec<String>,
    pub fuuids_reclames: Vec<String>,

    pub supprime: bool,
    #[serde(with="mapstringepochseconds")]
    pub visites: HashMap<String, DateTime<Utc>>,

    // Mapping date
    // #[serde(with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification", skip_serializing)]
    // map_derniere_modification: DateTime<Utc>,
    #[serde(default, rename(deserialize = "_mg-derniere-modification"),
    serialize_with = "optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    derniere_modification: Option<DateTime<Utc>>,

    // Champs optionnels media
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageConversion>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, TransactionAssocierVideoVersionDetail>>,

    #[serde(skip_serializing_if="Option::is_none")]
    flag_media: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_retry: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_traite: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_video_traite: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_index: Option<bool>,
}

impl NodeFichierVersionOwned {
    pub async fn from_nouvelle_version<U, S>(value: &TransactionNouvelleVersion, tuuid: S, user_id: U)
        -> Result<Self, CommonError>
        where S: ToString, U: ToString
    {
        let user_id = user_id.to_string();

        let mimetype = value.mimetype.as_str();

        let (flag_media_traite, flag_video_traite, flag_media) = Self::get_flags_media(mimetype);

        Ok(Self {
            fuuid: value.fuuid.clone(),
            tuuid: tuuid.to_string(),
            user_id: user_id.to_string(),
            mimetype: value.mimetype.clone(),
            metadata: value.metadata.clone(),
            taille: value.taille.clone(),
            fuuids: vec![value.fuuid.clone()],
            fuuids_reclames: vec![value.fuuid.clone()],
            supprime: false,
            visites: Default::default(),
            // map_derniere_modification: Default::default(),
            derniere_modification: None,
            height: None,
            width: None,
            duration: None,
            video_codec: None,
            anime: None,
            images: None,
            video: None,
            flag_media,
            flag_media_retry: None,
            flag_media_traite: Some(flag_media_traite),
            flag_video_traite: Some(flag_video_traite),
            flag_index: Some(false),
        })
    }

    pub fn get_flags_media(mimetype: &str) -> (bool, bool, Option<String>) {
        let mut flag_media_traite = true;
        let mut flag_video_traite = true;
        let mut flag_media = None;

        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            flag_media_traite = false;
            flag_media = Some("image".to_string());
        } else if is_mimetype_video(mimetype) {
            flag_media_traite = false;
            flag_video_traite = false;
            flag_media = Some("video".to_string());
        } else if mimetype == "application/pdf" {
            flag_media_traite = false;
            flag_media = Some("poster".to_string());
        }
        (flag_media_traite, flag_video_traite, flag_media)
    }

    // pub fn map_date_modification(&mut self) {
    //     self.derniere_modification = Some(self.map_derniere_modification.clone());
    // }
}

async fn transaction_nouvelle_version<M>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_nouvelle_version Consommer transaction : {}", transaction.transaction.id);
    let transaction_fichier: TransactionNouvelleVersion = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_fichier: TransactionNouvelleVersion = match transaction.clone().convertir::<TransactionNouvelleVersion>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction : {:?}", e))?
    // };

    // let enveloppe = match transaction.get_enveloppe_certificat() {
    //     Some(inner) => inner,
    //     None => Err(format!("grosfichiers.transaction_nouvelle_version Certificat absent (enveloppe)"))?
    // };

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err(format!("grosfichiers.transaction_nouvelle_version User_id absent du certificat"))?
        },
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur get_user_id() : {:?}", e))?
    };

    // let cuuid = match transaction_fichier.cuuid {
    //     Some(inner) => inner,
    //     None => Err(format!("transactions.transaction_nouvelle_version Fichier sans cuuid, SKIP"))?
    // };
    // let cuuid = transaction_fichier.cuuid;

    // Determiner tuuid - si non fourni, c'est l'uuid-transaction (implique un nouveau fichier)
    // let tuuid = match &transaction_fichier.tuuid {
    //     Some(t) => t.clone(),
    //     None => String::from(&transaction.transaction.id)
    // };

    // Conserver champs transaction uniquement (filtrer champs meta)
    // let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
    //     Ok(d) => d,
    //     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    // };

    let fichier_rep = match NodeFichierRepOwned::from_nouvelle_version(
        middleware, &transaction_fichier, &transaction.transaction.id, &user_id).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.NodeFichierRepOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
    };

    let tuuid = fichier_rep.tuuid.clone();

    let fichier_version = match NodeFichierVersionOwned::from_nouvelle_version(
        &transaction_fichier, &tuuid, &user_id).await {
        Ok(mut inner) => {
            inner.visites.insert("nouveau".to_string(), Utc::now());
            inner
        },
        Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
    };

    let fuuid = transaction_fichier.fuuid;
    let cuuid = transaction_fichier.cuuid;
    let mimetype = transaction_fichier.mimetype;

    // Retirer champ CUUID, pas utile dans l'information de version
    // doc_bson_transaction.remove(CHAMP_CUUID);

    // let mut flag_media = false;
    let mut flag_duplication = false;

    // Inserer document de version
    {
        let visites = {
            let mut visites = doc!();
            for (k, v) in &fichier_version.visites {
                visites.insert(k.to_owned(), v.timestamp());
            }
            visites
        };

        // Utiliser la struct fichier_version comme contenu initial
        let mut doc_version_bson = match convertir_to_bson(fichier_version) {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur convertir_to_bson fichier_version : {:?}", e))?
        };

        // Ajouter date creation
        doc_version_bson.insert(CHAMP_CREATION, Utc::now());
        doc_version_bson.insert(CHAMP_MODIFICATION, Utc::now());  // Remplacer champ
        doc_version_bson.insert(CHAMP_VISITES, visites);  // Override visites avec date i64

        let ops = doc!{
            "$setOnInsert": doc_version_bson,
            // "$currentDate": { CHAMP_MODIFICATION: true }
        };

        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc! { CHAMP_FUUID: &fuuid, CHAMP_TUUID: &tuuid, CHAMP_USER_ID: &user_id };
        let options = UpdateOptions::builder().upsert(true).build();
        match collection.update_one(filtre, ops, options).await {
            Ok(inner) => {
                if inner.upserted_id.is_none() {
                    // Row pas inseree, on a une duplication
                    flag_duplication = true;
                }
            },
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur update_one fichier_version : {:?}", e))?
        };
    }

    // Inserer document FichierRep
    {
        // Utiliser la struct fichier_version comme contenu initial
        let mut doc_rep_bson = match convertir_to_bson(fichier_rep) {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur convertir_to_bson fichier_rep : {:?}", e))?
        };

        // Ajouter date creation
        doc_rep_bson.insert(CHAMP_CREATION, Utc::now());
        doc_rep_bson.insert(CHAMP_MODIFICATION, Utc::now());  // Remplacer champ modification
        doc_rep_bson.insert(CHAMP_FLAG_INDEX, false);

        let ops = doc!{
            "$setOnInsert": doc_rep_bson,
            // "$currentDate": { CHAMP_MODIFICATION: true }
        };

        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let filtre = doc! { CHAMP_TUUID: &tuuid, CHAMP_USER_ID: &user_id };
        let options = UpdateOptions::builder().upsert(true).build();
        match collection.update_one(filtre, ops, options).await {
            Ok(inner) => (),
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur update_one fichier_version : {:?}", e))?
        };
    }

    if flag_duplication == false {
        // On emet les messages de traitement uniquement si la transaction est nouvelle
        // Conserver information pour indexer le fichier
        // let mut parametres = HashMap::new();
        // parametres.insert("mimetype".to_string(), Bson::String(mimetype.clone()));
        // if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
        //     middleware, &fuuid, &user_id, None,
        //     None, Some(parametres), false).await {
        //     error!("transaction_nouvelle_version Erreur ajout_job_indexation : {:?}", e);
        // }
        // if let Err(e) = ajout_job_indexation(middleware, &tuuid, &fuuid, &user_id, &mimetype).await {
        //     error!("transaction_nouvelle_version Erreur ajout_job_indexation : {:?}", e);
        // }

        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await {
            warn!("transaction_nouvelle_version Erreur emettre_evenement_maj_fichier : {:?}", e);
        }

        // if let Some(cuuid) = cuuid.as_ref() {
            let mut evenement_contenu = EvenementContenuCollection::new(cuuid.clone());
            // evenement_contenu.cuuid = Some(cuuid.clone());
            evenement_contenu.fichiers_ajoutes = Some(vec![tuuid.clone()]);
            emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;
        // }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_nouvelle_collection<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_nouvelle_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionNouvelleCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionNouvelleCollection = match transaction.clone().convertir::<TransactionNouvelleCollection>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction : {:?}", e))?
    // };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_collection) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction en bson : {:?}", e))?
    };

    let user_id = transaction.certificat.get_user_id()?;

    let tuuid = &transaction.transaction.id.to_owned();
    let cuuid = transaction_collection.cuuid;
    // let nom_collection = transaction_collection.nom;
    let metadata = match convertir_to_bson(&transaction_collection.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion metadata chiffre en bson {:?}", e))?
    };

    let date_courante = millegrilles_common_rust::bson::DateTime::now();
    // let securite = match transaction_collection.securite {
    //     Some(s) => s,
    //     None => SECURITE_3_PROTEGE.to_owned()
    // };
    let favoris = match transaction_collection.favoris {
        Some(f) => f,
        None => false
    };
    let type_node: &str = match favoris {
        true => TypeNode::Collection.into(),
        false => TypeNode::Repertoire.into(),
    };

    // Creer document de collection (fichiersRep)
    let mut doc_collection = doc! {
        CHAMP_TUUID: &tuuid,
        // CHAMP_NOM: nom_collection,
        CHAMP_METADATA: metadata,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        // CHAMP_SECURITE: &securite,
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: false,
        CHAMP_SUPPRIME_INDIRECT: false,
        CHAMP_FAVORIS: favoris,
        CHAMP_TYPE_NODE: type_node,
        CHAMP_FLAG_INDEX: false,
    };
    debug!("grosfichiers.transaction_nouvelle_collection Ajouter nouvelle collection doc : {:?}", doc_collection);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    // Ajouter collection parent au besoin
    if let Some(c) = cuuid.as_ref() {
        //let mut arr = millegrilles_common_rust::bson::Array::new();
        //arr.push(millegrilles_common_rust::bson::Bson::String(c.clone()));
        doc_collection.insert("cuuid", c.clone());

        // Charger le cuuid pour ajouter path vers root
        match get_path_cuuid(middleware, c).await {
            Ok(inner) => {
                if let Some(path_cuuids) = inner {
                    let mut path_cuuids_modifie: Vec<Bson> = path_cuuids.iter().map(|c| Bson::String(c.to_owned())).collect();
                    doc_collection.insert("path_cuuids", path_cuuids_modifie);
                }
            },
            Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection get_path_cuuid : {:?}", e))?
        }

        // let filtre = doc! { CHAMP_TUUID: c };
        // match collection.find_one(filtre, None).await {
        //     Ok(inner) => {
        //         match inner {
        //             Some(doc_parent) => {
        //                 match convertir_bson_deserializable::<FichierDetail>(doc_parent) {
        //                     Ok(inner) => {
        //                         match inner.path_cuuids.clone() {
        //                             Some(mut path_cuuids) => {
        //                                 // Inserer le nouveau parent
        //                                 let mut path_cuuids_modifie: Vec<Bson> = path_cuuids.iter().map(|c| Bson::String(c.to_owned())).collect();
        //                                 path_cuuids_modifie.insert(0, Bson::String(c.to_owned()));
        //                                 doc_collection.insert("path_cuuids", path_cuuids_modifie);
        //                             },
        //                             None => {
        //                                 doc_collection.insert("path_cuuids", vec![Bson::String(c.to_owned())]);
        //                             }
        //                         }
        //                     },
        //                     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection convertir_bson_deserializable : {:?}", e))?
        //                 }
        //             },
        //             None => {
        //                 doc_collection.insert("path_cuuids", vec![Bson::String(c.to_owned())]);
        //             }
        //         }
        //     },
        //     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection find_one : {:?}", e))?
        // }
    }

    let resultat = match collection.insert_one(doc_collection, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_nouvelle_collection Resultat transaction update : {:?}", resultat);

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid).await?;
    {
        // let mut evenement_contenu = EvenementContenuCollection::new();
        let mut evenement_contenu = match cuuid.as_ref() {
            Some(cuuid) => Ok(EvenementContenuCollection::new(cuuid.clone())),
            None => match user_id {
                Some(inner) => Ok(EvenementContenuCollection::new(inner.clone())),
                None => Err(format!("cuuid et user_id sont None, erreur event emettre_evenement_contenu_collection"))
            }
        };
        match evenement_contenu {
            Ok(mut inner) => {
                inner.collections_ajoutees = Some(vec![tuuid.clone()]);
                emettre_evenement_contenu_collection(middleware, gestionnaire, inner).await?;
            },
            Err(e) => error!("transaction_nouvelle_collection {}", e)
        }
    }

    let reponse = json!({"ok": true, "tuuid": tuuid});
    Ok(Some(middleware.build_reponse(reponse)?.0))
    // match middleware.formatter_reponse(&reponse, None) {
    //     Ok(inner) => Ok(Some(inner)),
    //     Err(e) => Err(format!("transaction_nouvelle_collection Erreur formattage reponse : {:?}", e))?
    // }

    // middleware.reponse_ok()
}

#[derive(Deserialize)]
struct RowRepertoirePaths {
    tuuid: String,
    cuuid: Option<String>,
    path_cuuids: Option<Vec<String>>,
}

async fn get_path_cuuid<M,S>(middleware: &M, cuuid: S)
    -> Result<Option<Vec<String>>, CommonError>
    where M: MongoDao, S: AsRef<str>
{
    let cuuid = cuuid.as_ref();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc! { CHAMP_TUUID: cuuid };
    let options = FindOneOptions::builder().projection(doc!{CHAMP_TUUID: 1, CHAMP_CUUID: 1, CHAMP_PATH_CUUIDS: 1}).build();
    let doc_parent: RowRepertoirePaths = match collection.find_one(filtre, options).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            return Ok(None)
        }
    };

    let path_cuuids = match doc_parent.path_cuuids {
        Some(mut inner) => {
            inner.insert(0, cuuid.to_owned());
            inner
        },
        None => vec![cuuid.to_owned()]
    };

    Ok(Some(path_cuuids))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowFichiersRepCuuidNode {
    tuuid: String,
    cuuids: Option<Vec<String>>,
    cuuids_paths: Option<HashMap<String, Vec<String>>>,
    ancetres: Option<Vec<String>>,  // Liste (set) de tous les cuuids ancetres
}

// async fn recalculer_cuuids_fichiers<M,S,T>(middleware: &M, cuuids: Vec<S>, tuuids: Option<Vec<T>>) -> Result<(), CommonError>
//     where
//         M: MongoDao,
//         S: AsRef<str>,
//         T: ToString
// {
//     let cuuids: Vec<&str> = cuuids.iter().map(|s| s.as_ref()).collect();
//     let tuuids: Option<Vec<Bson>> = match tuuids {
//         Some(inner) => Some(inner.iter().map(|s| Bson::String(s.to_string())).collect()),
//         None => None
//     };
//     debug!("recalculer_cuuids_fichiers Cuuids : {:?}", &cuuids);
//
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
//
//     // Conserver les cuuids dans un cache - utiliser pour mapping des fichiers
//     let mut cache_cuuids = HashMap::new();
//
//     let type_node_fichier: &str = TypeNode::Fichier.into();
//
//     // Recalculer le path de tous les fichiers affectes par au moins un cuuid modifie
//     let mut filtre = doc! {
//         CHAMP_CUUIDS: {"$in": &cuuids},
//         CHAMP_TYPE_NODE: type_node_fichier,
//     };
//     if let Some(tuuids) = tuuids {
//         filtre.insert("tuuid", doc!{"$in": tuuids});
//     };
//     let options = FindOptions::builder()
//         .projection(doc!{ CHAMP_TUUID: 1, CHAMP_CUUIDS: 1})
//         .build();
//     let mut curseur = collection.find(filtre, options).await?;
//     while let Some(r) = curseur.next().await {
//         let row: RowFichiersRepCuuidNode = convertir_bson_deserializable(r?)?;
//
//         let mut ancetres = HashSet::new();
//         let mut map_path_cuuids = HashMap::new();
//         if let Some(cuuids) = row.cuuids {
//             debug!("recalculer_cuuids_fichiers Recalculer paths pour fichier {} avec cuuids {:?}", row.tuuid, cuuids);
//             for cuuid in cuuids {
//                 let row_cuuid = match cache_cuuids.get(&cuuid) {
//                     Some(inner) => inner,
//                     None => {
//                         // Charger le cuuid
//                         let filtre = doc! { CHAMP_TUUID: &cuuid };
//                         let doc_cuuid: RowRepertoirePaths = match collection.find_one(filtre, None).await? {
//                             Some(inner) => match convertir_bson_deserializable(inner) {
//                                 Ok(inner) => inner,
//                                 Err(e) => {
//                                     warn!("recalculer_cuuids_fichiers Erreur convertir_bson_deserializable pour cuuid {} vers RowRepertoirePaths (SKIP) : {:?}", cuuid, e);
//                                     continue;
//                                 },
//                             },
//                             None => {
//                                 warn!("recalculer_cuuids_fichiers Cuuid manquant {}, SKIP", cuuid);
//                                 continue;
//                             }
//                         };
//                         cache_cuuids.insert(cuuid.clone(), doc_cuuid);
//                         cache_cuuids.get(&cuuid).expect("get cuuid")
//                     }
//                 };
//
//                 match row_cuuid.path_cuuids.clone() {
//                     Some(mut path_cuuids) => {
//                         // Repertoire
//                         // Ajouter le tuuid du repertoire a son path
//                         path_cuuids.insert(0, row_cuuid.tuuid.clone());
//
//                         for cuuid in &path_cuuids {
//                             ancetres.insert(cuuid.clone());
//                         }
//                         map_path_cuuids.insert(row_cuuid.tuuid.clone(), path_cuuids);
//                     },
//                     None => {
//                         // Collection (root)
//                         ancetres.insert(row_cuuid.tuuid.clone());
//                         map_path_cuuids.insert(row_cuuid.tuuid.clone(), vec![row_cuuid.tuuid.clone()]);
//                     }
//                 }
//             }
//         }
//
//         let filtre = doc! { CHAMP_TUUID: row.tuuid };
//         let ancetres: Vec<String> = ancetres.into_iter().collect();
//         let ops = doc! {
//             "$set": {
//                 CHAMP_MAP_PATH_CUUIDS: convertir_to_bson(map_path_cuuids)?,
//                 CHAMP_CUUIDS_ANCETRES: ancetres,
//             },
//             "$currentDate": { CHAMP_MODIFICATION: true }
//         };
//         collection.update_one(filtre, ops, None).await?;
//     }
//
//     Ok(())
// }

async fn transaction_ajouter_fichiers_collection<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let uuid_transaction = &transaction.transaction.id;

    debug!("transaction_ajouter_fichiers_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionAjouterFichiersCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionAjouterFichiersCollection = match transaction.clone().convertir::<TransactionAjouterFichiersCollection>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("transaction.transaction_ajouter_fichiers_collection Certificat sans user_id"))?
    };

    let (user_id_origine, user_id_destination) = match transaction_collection.contact_id.as_ref() {
        Some(contact_id) => {
            debug!("transaction_ajouter_fichiers_collection Verifier que le contact_id est valide (correspond aux tuuids)");
            let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let filtre = doc! {CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id};
            let contact = match collection.find_one(filtre, None).await {
                Ok(inner) => match inner {
                    Some(inner) => inner,
                    None => {
                        let reponse = json!({"ok": false, "err": "Contact_id invalide"});
                        return Ok(Some(middleware.build_reponse(reponse)?.0))
                        // match middleware.formatter_reponse(&reponse, None) {
                        //     Ok(inner) => return Ok(Some(inner)),
                        //     Err(e) => Err(format!("transactions.transaction_ajouter_fichiers_collection Erreur formattage reponse (err) pour contact_id invalide : {:?}", e))?
                        // }
                    }
                },
                Err(e) => Err(format!("transactions.transaction_ajouter_fichiers_collection Erreur traitement contact_id : {:?}", e))?
            };

            match verifier_acces_usager_tuuids(middleware, &contact.user_id, &transaction_collection.inclure_tuuids).await {
                Ok(inner) => {
                    if inner.len() != transaction_collection.inclure_tuuids.len() {
                        let reponse = json!({"ok": false, "err": "Acces refuse"});
                        return Ok(Some(middleware.build_reponse(reponse)?.0))
                        // match middleware.formatter_reponse(&reponse, None) {
                        //     Ok(inner) => return Ok(Some(inner)),
                        //     Err(e) => Err(format!("transactions.transaction_ajouter_fichiers_collection Erreur formattage reponse (err) pour verifier_acces_usager_tuuids : {:?}", e))?
                        // }
                    }
                },
                Err(e) => Err(format!("transactions.transaction_ajouter_fichiers_collection Erreur verifier_acces_usager_tuuids : {:?}", e))?
            }

            // Retourner le user_id d'origine et destination
            (contact.user_id, Some(user_id))
        },
        None => (user_id, None)  // Origine et destination est le meme user
    };

    debug!("transaction_ajouter_fichiers_collection Copier fichiers user_id {} (vers {:?})", user_id_origine, user_id_destination);

    // Dupliquer la structure de repertoires
    if let Err(e) = dupliquer_structure_repertoires(
        middleware, uuid_transaction, &transaction_collection.cuuid, &transaction_collection.inclure_tuuids, user_id_origine.as_str(), user_id_destination).await {
        Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur dupliquer_structure_repertoires sur transcation : {:?}", e))?
    }

    for tuuid in &transaction_collection.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_AJOUTER_FICHIER_COLLECTION).await {
            warn!("transaction_ajouter_fichiers_collection Erreur emettre_evenement_maj_fichier : {:?}", e)
        }

        // {
        //     let mut parametres = HashMap::new();
        //     parametres.insert("mimetype".to_string(), Bson::String(mimetype.clone()));
        //     parametres.insert("fuuid".to_string(), Bson::String(fuuid.clone()));
        //     if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
        //         middleware, &tuuid, &user_id, None,
        //         None, Some(parametres), true).await {
        //         error!("transaction_decire_fichier Erreur ajout_job_indexation : {:?}", e);
        //     }
        // }
    }

    {
        let mut evenement_contenu = EvenementContenuCollection::new(transaction_collection.cuuid.clone());
        // evenement_contenu.cuuid = Some(transaction_collection.cuuid.clone());
        evenement_contenu.fichiers_ajoutes = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug)]
struct CopieTuuidVersCuuid {
    tuuid_original: String,
    cuuid_destination: String,
}

/// Duplique la structure des repertoires listes dans tuuids.
/// Les fichiers des sous-repertoires sont linkes (pas copies).
async fn dupliquer_structure_repertoires<M,U,C,T,S,D>(middleware: &M, uuid_transaction: U, cuuid: C, tuuids: &Vec<T>, user_id: S, user_id_destination: Option<D>)
    -> Result<(), CommonError>
    where M: MongoDao, U: AsRef<str>, C: AsRef<str>, T: ToString, S: AsRef<str>, D: AsRef<str>
{
    let uuid_transaction = uuid_transaction.as_ref();
    let user_id = user_id.as_ref();
    let cuuid = cuuid.as_ref();
    let user_id_destination = match user_id_destination.as_ref() {
        Some(inner) => inner.as_ref(),
        None => user_id
    };
    let mut tuuids_remaining: Vec<CopieTuuidVersCuuid> = tuuids.iter().map(|t| {
        CopieTuuidVersCuuid { tuuid_original: t.to_string(), cuuid_destination: cuuid.to_owned() }
    }).collect();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_nodes = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_FICHIERS_REP)?;

    loop {
        let fichier_rep_tuuid = match tuuids_remaining.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let filtre = doc! {
            CHAMP_TUUID: &fichier_rep_tuuid.tuuid_original,
            CHAMP_USER_ID: user_id,
        };
        let mut curseur = collection_nodes.find(filtre, None).await?;
        if curseur.advance().await? {
            let mut fichier_rep = curseur.deserialize_current()?;
            let type_node = TypeNode::try_from(fichier_rep.type_node)?;
            let tuuid_src = fichier_rep.tuuid.to_owned();

            debug!("dupliquer_structure_repertoires Copier fichier_rep {} vers {}", fichier_rep_tuuid.tuuid_original, fichier_rep_tuuid.cuuid_destination);

            // Creer nouveau tuuid unique pour le fichier/repertoire a dupliquer
            let nouveau_tuuid_str = format!("{}/{}/{}", uuid_transaction, &fichier_rep_tuuid.cuuid_destination, fichier_rep.tuuid);
            let nouveau_tuuid_multihash = hacher_bytes(nouveau_tuuid_str.into_bytes().as_slice(), Some(Code::Blake2s256), Some(Base::Base16Lower));
            let nouveau_tuuid = (&nouveau_tuuid_multihash[9..]).to_string();
            debug!("dupliquer_structure_repertoires Nouveau tuuid : {:?}", nouveau_tuuid);

            // Remplacer le tuuid
            fichier_rep.tuuid = nouveau_tuuid.as_str();

            // Recuperer le path du cuuid destination, remplacer path_cuuids
            let path_cuuids_option = match get_path_cuuid(middleware, &fichier_rep_tuuid.cuuid_destination).await {
                Ok(inner) => inner,
                Err(e) => Err(format!("transactions.dupliquer_structure_repertoires get_path_cuuid : {:?}", e))?
            };

            match path_cuuids_option.as_ref() {
                Some(inner) => {
                    fichier_rep.path_cuuids = Some(inner.iter().map(|s| s.as_str()).collect());
                },
                None => {
                    fichier_rep.path_cuuids = None;
                }
            };

            // collection.insert_one(doc_repertoire, None).await?;
            let filtre = doc! {
                CHAMP_TUUID: &fichier_rep.tuuid, CHAMP_USER_ID: &user_id_destination,
                // CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false,
            };
            let mut set_ops = convertir_to_bson(&fichier_rep)?;
            set_ops.insert(CHAMP_CREATION, Utc::now());
            if user_id_destination != user_id {
                // Changer le user_id (copie de repertoire partage)
                set_ops.insert(CHAMP_USER_ID, user_id_destination);
            }

            let ops = doc! {
                "$set": {CHAMP_FLAG_INDEX: false},
                "$setOnInsert": set_ops,
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            let options = UpdateOptions::builder().upsert(true).build();
            let result = collection.update_one(filtre, ops, options).await?;
            if result.upserted_id.is_none() {
                info!("dupliquer_structure_repertoires Erreur, aucune valeur upserted pour tuuid {}", tuuid_src);
            }

            match type_node {
                TypeNode::Fichier => {
                    if user_id_destination != user_id {
                        // Copier les versions des fichiers vers le user_id destination
                        let filtre = doc!{ CHAMP_TUUID: &tuuid_src, CHAMP_USER_ID: &user_id };
                        let collection_versions = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
                            NOM_COLLECTION_VERSIONS)?;
                        let mut curseur = collection_versions.find(filtre, None).await?;
                        if curseur.advance().await? {
                            let mut row = curseur.deserialize_current()?;
                            row.user_id = user_id_destination;
                            row.tuuid = nouveau_tuuid.as_str();

                            let filtre = doc! {
                                // Utiliser le fuuid pour eviter duplication dans la destination
                                CHAMP_FUUID: &row.fuuid,
                                CHAMP_USER_ID: user_id_destination
                            };
                            let mut set_ops = convertir_to_bson(row)?;
                            set_ops.insert(CHAMP_CREATION, Utc::now());

                            let ops = doc!{
                                "$setOnInsert": set_ops,
                                "$currentDate": {CHAMP_MODIFICATION: true}
                            };
                            let options = UpdateOptions::builder().upsert(true).build();
                            collection_versions.update_one(filtre, ops, options).await?;
                        } else {
                            warn!{"dupliquer_structure_repertoires Version fichier src tuuid {} introuvable, skip", tuuid_src};
                        }
                    }
                },
                TypeNode::Collection | TypeNode::Repertoire => {
                    // Trouver les sous-repertoires, traiter individuellement
                    let filtre_ajout_cuuid = doc! { format!("{}.0", CHAMP_PATH_CUUIDS): &tuuid_src };
                    debug!("dupliquer_structure_repertoires filtre_ajout_cuuid : {:?}", filtre_ajout_cuuid);
                    let mut curseur = collection_nodes.find(filtre_ajout_cuuid, None).await?;
                    while curseur.advance().await? {
                        let sous_document = curseur.deserialize_current()?;
                        let copie_tuuid = CopieTuuidVersCuuid {
                            tuuid_original: sous_document.tuuid.to_owned(),
                            cuuid_destination: nouveau_tuuid.clone()
                        };
                        debug!("dupliquer_structure_repertoires Parcourir sous-fichier/rep {:?}", copie_tuuid);
                        tuuids_remaining.push(copie_tuuid);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Recalcule les path de cuuids de tous les sous-repertoires et fichiers sous un cuuid
async fn recalculer_path_cuuids<M,C>(middleware: &M, cuuid: C)
    -> Result<(), CommonError>
    where M: MongoDao, C: ToString
{
    let cuuid = cuuid.to_string();
    let mut tuuids_remaining: Vec<String> = vec![cuuid.to_owned()];

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_typed = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_FICHIERS_REP)?;

    loop {
        let tuuid = match tuuids_remaining.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let path_cuuids = {
            match get_path_cuuid(middleware, &tuuid).await? {
                Some(inner) => Some(inner),
                None => Some(vec![tuuid.clone()])
            }
        };

        let filtre = doc! { format!("{}.0", CHAMP_PATH_CUUIDS): &tuuid };
        let mut curseur = collection_typed.find(filtre, None).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            let type_node = TypeNode::try_from(row.type_node)?;

            // Mettre a jour path_cuuids
            let filtre = doc! { CHAMP_TUUID: row.tuuid };
            let ops = doc! {
                "$set": { CHAMP_PATH_CUUIDS: &path_cuuids },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            collection.update_one(filtre, ops, None).await?;

            match type_node {
                TypeNode::Fichier => {
                    // Rien a faire
                },
                TypeNode::Collection | TypeNode::Repertoire => {
                    // Ajouter aux tuuids remaining pour sous-reps/fichiers
                    tuuids_remaining.push(row.tuuid.to_owned());
                }
            }
        }
    }

    Ok(())
}

async fn transaction_deplacer_fichiers_collection<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_deplacer_fichiers_collection Consommer transaction : {}", transaction.transaction.id);
    let user_id = transaction.certificat.get_user_id()?;
    // let user_id = match transaction.get_enveloppe_certificat() {
    //     Some(e) => e.get_user_id()?.to_owned(),
    //     None => None
    // };

    let transaction_collection: TransactionDeplacerFichiersCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionDeplacerFichiersCollection = match transaction.convertir::<TransactionDeplacerFichiersCollection>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur conversion transaction : {:?}", e))?
    // };

    let path_cuuids_destination = match get_path_cuuid(middleware, transaction_collection.cuuid_destination.as_str()).await {
        Ok(inner) => match inner {
            Some(inner) => inner,
            None => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Path cuuids None - SKIP"))?
        },
        Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur get_path_cuuid : {:?}", e))?
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    {
        let filtre = doc! {
            CHAMP_TUUID: {"$in": &transaction_collection.inclure_tuuids},
            "path_cuuids.0": &transaction_collection.cuuid_origine,
            CHAMP_USER_ID: &user_id,
        };

        // Deplacer fichiers/repertoires en remplacant path_cuuids_destination
        let ops = doc! {
            "$set": { CHAMP_PATH_CUUIDS: &path_cuuids_destination },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let resultat = match collection.update_many(filtre.clone(), ops, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur update_one sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_deplacer_fichiers_collection Resultat transaction update : {:?}", resultat);
    }

    // Recalculer les paths des sous-repertoires et fichiers
    debug!("transaction_deplacer_fichiers_collection Recalculer path fuuids sous {}", transaction_collection.cuuid_destination);
    if let Err(e) = recalculer_path_cuuids(middleware, &transaction_collection.cuuid_destination).await {
        error!("transaction_deplacer_fichiers_collection Erreur recalculer_cuuids_fichiers : {:?}", e);
    }

    for tuuid in &transaction_collection.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_DEPLACER_FICHIER_COLLECTION).await {
            warn!("transaction_deplacer_fichiers_collection Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    {
        let mut evenement_source = EvenementContenuCollection::new(transaction_collection.cuuid_origine.clone());
        // evenement_source.cuuid = Some(transaction_collection.cuuid_origine.clone());
        evenement_source.retires = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_source).await?;

        let mut evenement_destination = EvenementContenuCollection::new(transaction_collection.cuuid_destination.clone());
        // evenement_destination.cuuid = Some(transaction_collection.cuuid_destination.clone());
        evenement_destination.fichiers_ajoutes = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_destination).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

/// Obsolete - conserver pour support legacy
async fn transaction_retirer_documents_collection<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
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
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_retirer_documents_collection Resultat transaction update : {:?}", resultat);

    // Recalculer les paths des sous-repertoires et fichiers
    todo!("fonction obsolete, doit supporter quand meme - fix me");
    // if let Err(e) = recalculer_path_cuuids(middleware, &transaction_collection.cuuid).await {
    //     error!("grosfichiers.transaction_nouvelle_version Erreur recalculer_cuuids_fichiers : {:?}", e);
    // }

    for tuuid in &transaction_collection.retirer_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_RETIRER_COLLECTION).await {
            warn!("transaction_retirer_documents_collection Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    {
        let mut evenement_contenu = EvenementContenuCollection::new(transaction_collection.cuuid.clone());
        // evenement_contenu.cuuid = Some(transaction_collection.cuuid.clone());
        evenement_contenu.retires = Some(transaction_collection.retirer_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn find_tuuids_retires<M,U,S>(middleware: &M, user_id: U, tuuids_in: Vec<S>)
    -> Result<HashMap<String, Vec<String>>, CommonError>
    where M: MongoDao, U: AsRef<str>, S: AsRef<str>
{
    let tuuids: Vec<&str> = tuuids_in.iter().map(|c| c.as_ref()).collect();
    let mut tuuids_retires_par_cuuid: HashMap<String, Vec<String>> = HashMap::new();
    let user_id = user_id.as_ref();

    let collection_nodes = middleware.get_collection_typed::<NodeFichiersRepBorrow>(
            NOM_COLLECTION_FICHIERS_REP)?;
    // Note : le filtre va potentiellement recuperer des rows qui ont ete supprimes indirectement
    //        precedemment.
    let filtre = doc! {
        "$or": [
            {
                CHAMP_PATH_CUUIDS: { "$in": &tuuids },
                CHAMP_SUPPRIME_INDIRECT: true,
            },
            { CHAMP_TUUID: { "$in": &tuuids } }
        ],
        CHAMP_USER_ID: user_id,
    };
    let projection_node_row = doc! {
        CHAMP_TUUID: true, CHAMP_USER_ID: true,
        CHAMP_TYPE_NODE: true, CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: true,
        CHAMP_PATH_CUUIDS: true,
        // CHAMP_CUUID: true, CHAMP_CUUIDS: true,
        // CHAMP_CUUIDS_SUPPRIMES: true, CHAMP_CUUIDS_SUPPRIMES_INDIRECT: true,
        // CHAMP_MAP_PATH_CUUIDS: true,
    };
    let options = FindOptions::builder().projection(projection_node_row.clone()).build();
    debug!("grosfichiers.transaction_supprimer_documents Filtre charger collections/repertoires pour traitement arborescence : {:?}", filtre);
    let mut curseur = match collection_nodes.find(filtre, options).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur find collections/repertoires changement arborescence : {:?}", e))?
    };

    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        let type_node = TypeNode::try_from(row.type_node)?;
        let cuuid = match row.path_cuuids {
            Some(inner) => match inner.get(0) {
                Some(inner) => *inner,
                None => user_id,
            },
            None => user_id
        };

        let liste = match tuuids_retires_par_cuuid.get_mut(cuuid) {
            Some(inner) => inner,
            None => {
                tuuids_retires_par_cuuid.insert(cuuid.to_owned(), Vec::new());
                tuuids_retires_par_cuuid.get_mut(cuuid).expect("tuuids_retires_par_cuuid.get_mut")
            }
        };
        liste.push(row.tuuid.to_owned());
    }

    Ok(tuuids_retires_par_cuuid)
}

async fn supprimer_versions_conditionnel<M,T,U>(middleware: &M, user_id: U, fuuids_in: &Vec<T>)
    -> Result<(), CommonError>
    where M: MongoDao, U: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id.as_ref();
    let fuuids: Vec<&str> = fuuids_in.iter().map(|s| s.as_ref()).collect();
    let mut fuuids_inconnus: HashSet<&str> = HashSet::new();
    fuuids_inconnus.extend(fuuids.iter());

    // Charger les fichiers non supprimes par user_id/fuuid
    // Ces fichiers sont connus et non supprimes, on les retire de la liste d'inconnus
    {
        let filtre = doc! {
            CHAMP_USER_ID: user_id,
            CHAMP_FUUIDS_VERSIONS: { "$in": fuuids },
            CHAMP_SUPPRIME: false,
        };
        let options = FindOptions::builder().hint(Hint::Name("fuuids_versions_user_id".to_string())).build();
        let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection.find(filtre, options).await?;
        if curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            if let Some(row_fuuids) = &row.fuuids_versions {
                for row_fuuid in row_fuuids {
                    fuuids_inconnus.remove(*row_fuuid);
                }
            }
        }
    }

    debug!("supprimer_versions_conditionnel Fuuids inconnus ou supprimes pour user_id {} : {:?}", user_id, fuuids_inconnus);
    let fuuids_inconnus: Vec<&str> = fuuids_inconnus.into_iter().collect();
    let filtre = doc! {
        CHAMP_USER_ID: user_id,
        CHAMP_FUUID: {"$in": fuuids_inconnus}
    };
    let ops = doc! {
        "$set": { CHAMP_SUPPRIME: true },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = UpdateOptions::builder().hint(Hint::Name("fuuid_user_id".to_string())).build();
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    collection.update_many(filtre, ops, options).await?;

    Ok(())
}

async fn supprimer_tuuids<M,U,T>(middleware: &M, user_id_in: U, tuuids_in: Vec<T>)
    -> Result<HashMap<String, Vec<String>>, CommonError>
    where M: MongoDao, U: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id_in.as_ref();
    let tuuids: Vec<&str> = tuuids_in.iter().map(|s| s.as_ref()).collect();

    // let mut tuuids_retires_par_cuuid: HashMap<String, Vec<String>> = HashMap::new();

    // Determiner tous les fichiers a supprimer - requis pour fichiersVersions
    let fuuids_a_supprimer= {
        let mut fuuids_a_supprimer = HashSet::new();
        let filtre = doc! {
            CHAMP_USER_ID: &user_id,
            CHAMP_TYPE_NODE: TypeNode::Fichier.to_str(),
            CHAMP_SUPPRIME: false,
            "$or": [
                { CHAMP_TUUID: {"$in": &tuuids} },
                { CHAMP_PATH_CUUIDS: {"$in": &tuuids} },
            ]
        };
        let collection_fichierrep = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection_fichierrep.find(filtre, None).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            if let Some(fuuids) = row.fuuids_versions {
                if let Some(fuuid) = fuuids.first() {
                    fuuids_a_supprimer.insert(fuuid.to_string());
                }
            }
        }
        fuuids_a_supprimer
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    // Marquer les collections, repertoires et fichiers supprimes directement.
    {
        let filtre = doc! {
            CHAMP_TUUID: {"$in": &tuuids},
            CHAMP_USER_ID: &user_id,
        };
        debug!("grosfichiers.transaction_supprimer_documents Filtre marquer tuuids supprimes : {:?}", filtre);
        let ops = doc! {
            "$set": { CHAMP_SUPPRIME: true },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        collection.update_many(filtre, ops, None).await?;
    }

    // Marquer les sous-repertoires et fichiers supprimes indirectement (via arborescence)
    {
        let filtre = doc! {
            CHAMP_PATH_CUUIDS: {"$in": &tuuids},
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
        };
        debug!("grosfichiers.transaction_supprimer_documents Filtre marquer tuuids supprimes : {:?}", filtre);
        let ops = doc! {
            "$set": { CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: true },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        collection.update_many(filtre, ops, None).await?;
    }

    let fuuids_a_supprimer: Vec<String> = fuuids_a_supprimer.into_iter().collect();
    supprimer_versions_conditionnel(middleware, &user_id, &fuuids_a_supprimer).await?;

    // Parcourir les elements pour recuperer les tuuids qui viennent d'etre supprimes (indirect)
    // let tuuids: Vec<&str> = transaction_collection.tuuids.iter().map(|c| c.as_str()).collect();
    let tuuids_retires_par_cuuid = find_tuuids_retires(middleware, user_id, tuuids).await?;

    Ok(tuuids_retires_par_cuuid)
}

async fn transaction_supprimer_documents<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_documents Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionSupprimerDocuments = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionSupprimerDocuments = match transaction.clone().convertir::<TransactionSupprimerDocuments>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_documents Erreur user_id absent du certificat"))?
    };

    // Conserver liste de tuuids par cuuid, utilise pour evenement
    // let mut tuuids_retires_par_cuuid: HashMap<String, Vec<String>> = HashMap::new();

    let mut tuuids_retires_par_cuuid: HashMap<String, Vec<String>> = match supprimer_tuuids(
        middleware, &user_id, transaction_collection.tuuids).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur supprimer_tuuids : {:?}", e))?
    };

    debug!("transaction_supprimer_documents Emettre messages pour tuuids retires : {:?}", tuuids_retires_par_cuuid);

    // Emettre evenements supprime par cuuid
    for (cuuid, liste) in tuuids_retires_par_cuuid {
        let mut evenement = EvenementContenuCollection::new(cuuid);
        // evenement.cuuid = Some(cuuid);
        evenement.retires = Some(liste);
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_recuperer_documents<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_recuperer_documents Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionListeDocuments = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionListeDocuments = match transaction.clone().convertir::<TransactionListeDocuments>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur conversion transaction : {:?}", e))?
    // };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: false, CHAMP_ARCHIVE: false},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_recuperer_documents Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_RECUPERER).await {
            warn!("transaction_recuperer_documents Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecupererDocumentsV2 {
    /// Items a recuperer par { cuuid: [tuuid, ...] }
    pub items: HashMap<String, Option<Vec<String>>>
}

async fn recuperer_parents<M,C,U>(middleware: &M, user_id: U, tuuid: C) -> Result<(), CommonError>
    where M: MongoDao, C: AsRef<str>, U: AsRef<str>
{
    let tuuid = tuuid.as_ref();
    let filtre = doc!{ CHAMP_TUUID: tuuid, CHAMP_USER_ID: user_id.as_ref() };
    let collection = middleware.get_collection_typed::<FichierDetail>(NOM_COLLECTION_FICHIERS_REP)?;
    let repertoire = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => Err(format!("recuperer_parents Tuuid inconnu {}", tuuid))?
    };

    let type_node = match repertoire.type_node {
        Some(inner) => TypeNode::try_from(inner.as_str())?,
        None => Err(format!("recuperer_parents Node sans information de type {}", tuuid))?
    };

    let cuuids = match type_node {
        TypeNode::Fichier => Err(format!("recuperer_parents Node {} de type Fichier, invalide pour reactiver parents", tuuid))?,
        TypeNode::Collection => {
            // Ok, aucuns parents a reactiver
            vec![tuuid.to_owned()]
        },
        TypeNode::Repertoire => {
            match repertoire.path_cuuids {
                Some(mut inner) => {
                    inner.push(tuuid.to_owned());  // Ajouter le repertoire lui-meme
                    inner
                },
                None => Err(format!("recuperer_parents Node {} est un Repertoire sans path_cuuids, invalide pour reactiver parents", tuuid))?,
            }
        }
    };

    let filtre = doc! { CHAMP_TUUID: {"$in": cuuids} };
    let ops = doc! {
        "$set": {
            CHAMP_SUPPRIME: false,
            CHAMP_SUPPRIME_INDIRECT: false,
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    collection.update_many(filtre, ops, None).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowRecupererFichierDb {
    tuuid: String,
    cuuid: Option<String>,
    cuuids_supprimes: Option<Vec<String>>,
    cuuids_supprimes_indirect: Option<Vec<String>>,
    type_node: String,
    supprime: bool,
    supprime_indirect: Option<bool>,
}

async fn recuperer_tuuids<M,T,C,U>(middleware: &M, user_id: U, cuuid: C, tuuids_params: Option<Vec<T>>) -> Result<(), CommonError>
    where
        M: MongoDao,
        T: AsRef<str>,
        C: AsRef<str>,
        U: AsRef<str>
{
    let user_id = user_id.as_ref();
    let mut tuuids: Vec<&str> = match tuuids_params.as_ref() {
        Some(inner) => inner.iter().map(|c| c.as_ref()).collect(),
        None => vec![cuuid.as_ref()]  // Recuperer une collection
    };

    debug!("recuperer_tuuids Recuperer tuuids {:?}", tuuids);
    let mut nodes_restants = Vec::new();

    // Charger liste initiale de nodes
    let collection_nodes = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    {
        let filtre = doc! {
            CHAMP_TUUID: { "$in": tuuids },
            CHAMP_USER_ID: user_id
        };
        let mut curseur = collection_nodes.find(filtre, None).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            nodes_restants.push(row);
        }
    }

    // Parcourir les nodes. Recuperer recursivement les Repertoires avec supprime_indirect: true.
    let mut tuuids_a_recuperer = Vec::new();
    let mut fuuids_a_recuperer = Vec::new();
    loop {
        let node_courant = match nodes_restants.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let type_node = TypeNode::try_from(node_courant.type_node.as_str())?;

        match type_node {
            TypeNode::Fichier => {
                if let Some(fuuids) = node_courant.fuuids_versions {
                    fuuids_a_recuperer.extend(fuuids);
                }
            },
            TypeNode::Collection | TypeNode::Repertoire => {
                // Charger la liste des nodes supprimes indirectement sous ce repertoire
                let filtre = doc! {
                    CHAMP_USER_ID: user_id,
                    "path_cuuids.0": &node_courant.tuuid,
                    CHAMP_SUPPRIME_INDIRECT: true
                };
                let mut curseur = collection_nodes.find(filtre, None).await?;
                while curseur.advance().await? {
                    let row = curseur.deserialize_current()?;
                    nodes_restants.push(row);
                }
            }
        }

        tuuids_a_recuperer.push(node_courant.tuuid);
    }

    {
        debug!("recuperer_tuuids Recuperer {} tuuids", tuuids_a_recuperer.len());
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_TUUID: {"$in": tuuids_a_recuperer}};
        let ops = doc! {
            "$set": {CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false, CHAMP_ARCHIVE: false },
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        collection_nodes.update_many(filtre, ops, None).await?;
    }

    {
        debug!("recuperer_tuuids Recuperer {} fuuids", fuuids_a_recuperer.len());
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUID: {"$in": fuuids_a_recuperer}};
        let ops = doc! {
            "$set": { CHAMP_SUPPRIME: false },
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        collection.update_many(filtre, ops, None).await?;
    }

    // let mut curseur = {
    //     let filtre = doc! {
    //         CHAMP_TUUID: {"$in": tuuids},
    //         CHAMP_USER_ID: user_id
    //     };
    //     let collection_nodes = middleware.get_collection_typed::<NodeFichiersRepBorrow>(NOM_COLLECTION_FICHIERS_REP)?;
    //     collection_nodes.find(filtre, None).await?
    // };
    //
    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    // // Conserver la liste de fuuids pour les marquer comme supprime: false dans versions.
    // let mut fuuids_recuperer = Vec::new();
    //
    // while curseur.advance().await? {
    //     let row = curseur.deserialize_current()?;
    //     let type_node = TypeNode::try_from(row.type_node)?;
    //     match type_node {
    //         TypeNode::Fichier => {
    //             // Recuperer le fichier nomme directement (peu importe son etat)
    //             let filtre = doc!{ CHAMP_TUUID: row.tuuid, CHAMP_USER_ID: user_id };
    //             let ops = doc! {
    //                 "$set": { CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false, CHAMP_ARCHIVE: false },
    //                 "$currentDate": { CHAMP_MODIFICATION: true },
    //             };
    //             collection.update_one(filtre, ops, None).await?;
    //
    //             // S'assurer que le fichier est marque supprime: false dans versions
    //             if let Some(fuuids) = row.fuuids_versions {
    //                 fuuids_recuperer.extend(fuuids.into_iter().map(|s| s.to_owned()));
    //             }
    //         },
    //         TypeNode::Repertoire | TypeNode::Collection => {
    //             // Recupere le repertoire, ses sous-repertoires et fichiers
    //             // Va ignorer les sous-repertoires qui n'ont pas le flag supprime_indirect: true
    //             let cuuid = row.tuuid;
    //
    //             let filtre = doc! {
    //                 CHAMP_USER_ID: user_id,
    //                 "$or": [
    //                     { CHAMP_TUUID: cuuid },
    //                     { CHAMP_PATH_CUUIDS: cuuid, CHAMP_SUPPRIME_INDIRECT: true }
    //                 ]
    //             };
    //             let ops = doc! {
    //                 "$set": { CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false },
    //                 "$currentDate": { CHAMP_MODIFICATION: true },
    //             };
    //             collection.update_many(filtre, ops, None).await?;
    //         }
    //     }
    // }
    //
    // debug!("recuperer_tuuids Recuperer fuuids : {:?}", fuuids_recuperer);
    // if ! fuuids_recuperer.is_empty() {
    //     // Marquer les fuuids comme supprime: false dans la table de versions
    //     // Note : un message de recuperation a deja ete emis vers consignation fichiers pour
    //     //        verifier que les originaux existente.
    //     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUID: {"$in": fuuids_recuperer} };
    //     let ops = doc! {
    //         "$set": { CHAMP_SUPPRIME: false },
    //         "$currentDate": { CHAMP_MODIFICATION: true }
    //     };
    //     collection.update_many(filtre, ops, None).await?;
    // }

    Ok(())
}

async fn transaction_recuperer_documents_v2<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_recuperer_documents_v2 Consommer transaction : {}", transaction.transaction.id);

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_recuperer_documents_v2 Erreur user_id absent du certificat"))?
    };

    let transaction: TransactionRecupererDocumentsV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction: TransactionRecupererDocumentsV2 = match transaction.clone().convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents_v2 Erreur conversion transaction : {:?}", e))?
    // };

    for (cuuid, paths) in transaction.items {
        // Recuperer le cuuid (parent) jusqu'a la racine au besoin
        debug!("transaction_recuperer_documents_v2 Recuperer cuuid {} et parents", cuuid);
        if let Err(e) = recuperer_parents(middleware, &user_id, &cuuid).await {
            Err(format!("grosfichiers.transaction_recuperer_documents_v2 Erreur recuperer_parents : {:?}", e))?
        }

        // Reactiver les fichiers avec le cuuid courant sous cuuids_supprimes.
        debug!("transaction_recuperer_documents_v2 Recuperer tuuids {:?} sous cuuid {}", paths, cuuid);
        if let Err(e) = recuperer_tuuids(middleware, &user_id, cuuid, paths).await {
            Err(format!("grosfichiers.transaction_recuperer_documents_v2 Erreur recuperer_tuuids : {:?}", e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_archiver_documents<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_archiver_documents Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionListeDocuments = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionListeDocuments = match transaction.clone().convertir::<TransactionListeDocuments>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transactions.transaction_archiver_documents Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = transaction.certificat.get_user_id()?;
    // let user_id = match transaction.get_enveloppe_certificat() {
    //     Some(e) => e.get_user_id()?.to_owned(),
    //     None => None
    // };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = match user_id.as_ref() {
        Some(u) => doc! {CHAMP_USER_ID: u, CHAMP_TUUID: {"$in": &transaction_collection.tuuids}},
        None => doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}}
    };
    let ops = doc! {
        "$set": {CHAMP_ARCHIVE: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transactions.transaction_archiver_documents Erreur update_many sur transcation : {:?}", e))?
    };
    debug!("transaction_archiver_documents Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_ARCHIVER).await {
            warn!("transaction_archiver_documents Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_changer_favoris<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    todo!("obsolete?");

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

        for tuuid in &tuuids_reset {
            // Emettre fichier pour que tous les clients recoivent la mise a jour
            emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid).await?;
        }

    }

    if ! tuuids_set.is_empty() {
        let filtre_set = doc! {CHAMP_TUUID: {"$in": &tuuids_set}};
        let ops_set = doc! { "$set": {CHAMP_FAVORIS: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_set, ops_set, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many set sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update set : {:?}", resultat);

        for tuuid in &tuuids_set {
            // Emettre fichier pour que tous les clients recoivent la mise a jour
            emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid).await?;
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

/// Fait un touch sur les fichiers_rep identifies. User_id optionnel (e.g. pour ops systeme comme visites)
async fn touch_fichiers_rep<M,U,S,V>(middleware: &M, user_id: Option<U>, fuuids_in: V) -> Result<(), CommonError>
    where
        M: GenerateurMessages + MongoDao,
        U: AsRef<str>,
        S: AsRef<str>,
        V: Borrow<Vec<S>>,
{
    let fuuids_in = fuuids_in.borrow();
    let fuuids: Vec<&str> = fuuids_in.iter().map(|s| s.as_ref()).collect();

    let filtre = match user_id {
        Some(user_id) => {
            doc! {
                CHAMP_USER_ID: user_id.as_ref(),
                CHAMP_FUUIDS_VERSIONS: {"$in": fuuids},
            }
        },
        None => {
            doc! { CHAMP_FUUIDS_VERSIONS: {"$in": fuuids } }
        }
    };

    let ops = doc! {
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    collection.update_many(filtre, ops, None).await?;

    Ok(())
}

async fn transaction_associer_conversions<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_associer_conversions Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionAssocierConversions = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionAssocierConversions = match transaction.clone().convertir::<TransactionAssocierConversions>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_associer_conversions Erreur conversion transaction : {:?}", e))?
    // };

    let tuuid = transaction_mappee.tuuid.clone();
    let user_id = match transaction_mappee.user_id.as_ref() {
        Some(inner) => Some(inner.as_str()),
        None => None
    };
    let fuuid = transaction_mappee.fuuid.as_str();

    let doc_images = match convertir_to_bson(transaction_mappee.images.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur conversion images en bson : {:?}", e))?
    };

    // Mapper tous les fuuids avec leur mimetype
    let (fuuids, fuuids_reclames) = {
        let mut fuuids = Vec::new();
        let mut fuuids_reclames = Vec::new();
        fuuids.push(transaction_mappee.fuuid.clone());
        for (_, image) in transaction_mappee.images.iter() {
            fuuids.push(image.hachage.to_owned());
            if image.data_chiffre.is_none() {
                fuuids_reclames.push(image.hachage.to_owned());
            }
        }
        (fuuids, fuuids_reclames)
    };

    // MAJ de la version du fichier
    {
        let mut filtre = doc! { CHAMP_FUUID: &transaction_mappee.fuuid };
        if let Some(inner) = user_id {
            // Note : legacy, supporte ancienne transaction (pre 2023.6) qui n'avait pas le user_id
            filtre.insert(CHAMP_USER_ID, inner);
        }
        let mut set_ops = doc! {};

        // Si on a le thumbnail, on va marquer media_traite
        debug!("Traiter images : {:?}", transaction_mappee.images);
        set_ops.insert(CHAMP_FLAG_MEDIA_TRAITE, true);

        // Inserer images par cle dans set_ops
        for (k, v) in &doc_images {
            debug!("Traiter image {} : {:?}", k, v);
            let cle_image = format!("images.{}", k);
            set_ops.insert(cle_image, v.to_owned());
        };

        if let Some(inner) = transaction_mappee.anime {
            set_ops.insert("anime", inner);
        }
        if let Some(inner) = &transaction_mappee.mimetype {
            set_ops.insert("mimetype", inner);
        }
        if let Some(inner) = transaction_mappee.width {
            set_ops.insert("width", inner);
        }
        if let Some(inner) = transaction_mappee.height {
            set_ops.insert("height", inner);
        }
        if let Some(inner) = transaction_mappee.video_codec.as_ref() {
            set_ops.insert("videoCodec", inner);
        }
        if let Some(inner) = transaction_mappee.duration.as_ref() {
            set_ops.insert("duration", inner);
        }
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }

        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids_reclames},
        };

        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        debug!("transactions.transaction_associer_conversions set ops versions : {:?}", ops);
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }

        if let Err(e) = gestionnaire.image_job_handler.set_flag(middleware, fuuid, user_id, None, true).await {
            error!("transaction_associer_conversions Erreur set flag true pour traitement job images {:?}/{} : {:?}", user_id, fuuid, e);
        }
    }

    // S'assurer d'appliquer le fitre sur la version courante
    {
        if let Err(e) = touch_fichiers_rep(middleware, user_id.as_ref(), &fuuids).await {
            error!("transaction_associer_conversions Erreur touch_fichiers_rep {:?}/{} : {:?}", user_id, fuuid, e);
        }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Some(tuuid) = tuuid {
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_ASSOCIER_CONVERSION).await {
            warn!("transaction_associer_conversions Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_associer_video<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_associer_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionAssocierVideo = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionAssocierVideo = match transaction.clone().convertir::<TransactionAssocierVideo>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion transaction : {:?}", e))?
    // };

    let tuuid = transaction_mappee.tuuid.clone();

    let doc_video = match convertir_to_bson(transaction_mappee.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion images en bson : {:?}", e))?
    };

    // Mapper tous les fuuids avec leur mimetype
    let (fuuids, fuuid_mimetypes) = {
        let mut fuuids = Vec::new();
        let mut fuuid_mimetypes = HashMap::new();
        fuuids.push(transaction_mappee.fuuid_video.clone());
        fuuid_mimetypes.insert(transaction_mappee.fuuid_video.clone(), transaction_mappee.mimetype.clone());

        (fuuids, fuuid_mimetypes)
    };

    let cle_video = match transaction_mappee.cle_conversion {
        Some(inner) => inner,  // Nouveau avec 2023.7.4
        None => {
            // Note : avant 2023.7.4 (et media 2023.7.4), la cle_video n'etait pas fournie
            //        cause un probleme avec les videos verticaux.
            let resolution = match transaction_mappee.height {
                Some(height) => match transaction_mappee.width {
                    Some(width) => {
                        // La resolution est le plus petit des deux nombres
                        if width < height {
                            width
                        } else {
                            height
                        }
                    },
                    None => height,
                },
                None => 0
            };
            let bitrate_quality = {
                match &transaction_mappee.quality {
                    Some(q) => q.to_owned(),
                    None => match &transaction_mappee.bitrate {
                        Some(b) => b.to_owned() as i32,
                        None => 0
                    }
                }
            };
            format!("{};{};{}p;{}", &transaction_mappee.mimetype, &transaction_mappee.codec, resolution, bitrate_quality)
        }
    };

    // Appliquer le filtre sur la version courante (pour l'usager si applicable)
    // Note : obsolete depuis 2023.9 (refact structure fichiersRep). fuuid_v_courante n'est pas dans fichierRep
    let mut fuuid_video_existant = None;
    {
        let mut filtre = doc! {
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_FUUID_V_COURANTE: &transaction_mappee.fuuid,
            CHAMP_USER_ID: &transaction_mappee.user_id,
        };

        // if let Some(user_id) = transaction_mappee.user_id.as_ref() {
        //     // Utiliser un filtre pour un usager
        //     filtre.insert(CHAMP_USER_ID, user_id.to_owned());
        // }

        // Verifier si le video existe deja - retirer le fuuid_video si c'est le cas
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        {
            let doc_existant: Option<FichierDetail> = match collection.find_one(filtre.clone(), None).await {
                Ok(d) => match d {
                    Some(d) => match convertir_bson_deserializable(d) {
                        Ok(d) => d,
                        Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion bson fichier (video) : {:?}", e))?
                    },
                    None => None
                },
                Err(e) => Err(format!("transaction_associer_video Erreur chargement fichier (video) : {:?}", e))?
            };
            if let Some(d) = doc_existant {
                if let Some(version_courante) = d.version_courante {
                    if let Some(v) = version_courante.video {
                        if let Some(video) = v.get(cle_video.as_str()) {
                            fuuid_video_existant = Some(video.fuuid_video.to_owned());
                        }
                    }
                }
            }
        }

        if let Some(fuuid_video) = fuuid_video_existant.as_ref() {
            let ops = doc! {
                "$pull": {
                    CHAMP_FUUIDS: &fuuid_video,
                    CHAMP_FUUIDS_RECLAMES: &fuuid_video
                },
                // "$unset": {format!("version_courante.fuuidMimetypes.{}", fuuid_video): true},
            };
            match collection.update_many(filtre.clone(), ops, None).await {
                Ok(inner) => debug!("transaction_associer_video Suppression video : {:?}", inner),
                Err(e) => Err(format!("transactions.transaction_associer_video Erreur suppression video existant : {:?}", e))?
            }
        }

        let mut set_ops = doc! {
            format!("version_courante.video.{}", &cle_video): &doc_video,
        };
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("version_courante.{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }

        // Combiner les fuuids hors de l'info de version
        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids},
        };

        let mut ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };

        match collection.update_many(filtre, ops, None).await {
            Ok(inner) => debug!("transaction_associer_video Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_video Erreur maj versions : {:?}", e))?
        }
    }
    // Fin obsolete depuis 2023.9

    // MAJ de la version du fichier
    {
        let filtre = doc! {
            CHAMP_FUUID: &transaction_mappee.fuuid,
            // CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_USER_ID: &transaction_mappee.user_id,
        };

        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

        if let Some(fuuid_video) = fuuid_video_existant.as_ref() {
            let ops = doc! {
                "$pull": {
                    CHAMP_FUUIDS: &fuuid_video,
                    CHAMP_FUUIDS_RECLAMES: &fuuid_video,
                },
                // "$unset": {format!("fuuidMimetypes.{}", fuuid_video): true},
            };
            match collection.update_many(filtre.clone(), ops, None).await {
                Ok(inner) => debug!("transaction_associer_video Suppression video : {:?}", inner),
                Err(e) => Err(format!("transactions.transaction_associer_video Erreur suppression video existant : {:?}", e))?
            }
        }

        let mut set_ops = doc! {
            CHAMP_FLAG_VIDEO_TRAITE: true,
            format!("video.{}", &cle_video): &doc_video,
        };
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }
        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids},
        };
        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transaction_associer_video Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_video Erreur maj versions : {:?}", e))?
        }
    }

    {   // Supprimer job dans table videos
        // Traiter la commande
        let mut cles_supplementaires = HashMap::new();
        cles_supplementaires.insert(CHAMP_CLE_CONVERSION.to_string(), cle_video.clone());
        if let Err(e) = gestionnaire.video_job_handler.set_flag(
            middleware, &transaction_mappee.fuuid, Some(&transaction_mappee.user_id), Some(cles_supplementaires), true).await {
            error!("transaction_associer_video Erreur traitement flag : {:?}", e);
        }

        // let collection_video = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
        // let filtre = doc! {CHAMP_FUUID: &transaction_mappee.fuuid, CHAMP_CLE_CONVERSION: &cle_video};
        // if let Err(e) = collection_video.delete_one(filtre, None).await {
        //     error!("transactions.transaction_associer_conversions Erreur suppression job video fuuid {:?} cle {} : {:?}",
        //         &transaction_mappee.fuuid, &cle_video, e);
        // }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Some(t) = tuuid.as_ref() {
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, t, EVENEMENT_FUUID_ASSOCIER_VIDEO).await {
            warn!("transaction_associer_video Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    if let Err(e) = touch_fichiers_rep(middleware, Some(&transaction_mappee.user_id), &fuuids).await {
        error!("transaction_associer_video Erreur touch_fichiers_rep {:?}/{:?} : {:?}", transaction_mappee.user_id, fuuids, e);
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_decrire_fichier<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_decire_fichier Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionDecrireFichier = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionDecrireFichier = match transaction.clone().convertir::<TransactionDecrireFichier>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = transaction.certificat.get_user_id()?;

    let tuuid = transaction_mappee.tuuid.as_str();
    let mut filtre = doc! { CHAMP_TUUID: tuuid };
    if let Some(inner) = &user_id {
        filtre.insert("user_id", inner);
    }

    // {
    //     // Reset flag indexe
    //     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let ops = doc! {
    //         "$set": { CHAMP_FLAG_INDEX: false },
    //         "$unset": { CHAMP_FLAG_INDEX_ERREUR: true },
    //         "$currentDate": { CHAMP_MODIFICATION: true },
    //     };
    //     if let Err(e) = collection_versions.update_one(filtre.clone(), ops, None).await {
    //         Err(format!("transactions.transaction_decire_collection Erreur maj versions fichiers tuuid {} : {:?}", tuuid, e))?
    //     }
    // }

    let mut set_ops = doc! {
        CHAMP_FLAG_INDEX: false,
    };

    // Modifier metadata
    if let Some(metadata) = transaction_mappee.metadata {
        let metadata_bson = match bson::to_bson(&metadata) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion metadata vers bson : {:?}", e))?
        };
        set_ops.insert("metadata", metadata_bson);
    }

    if let Some(mimetype) = transaction_mappee.mimetype {
        set_ops.insert("mimetype", &mimetype);
    }

    // Creer job indexation
    let ops = doc! {
        "$set": set_ops,
        "$unset": {CHAMP_FLAG_INDEX_RETRY: true, CHAMP_FLAG_INDEX_ERREUR: true},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => {
            debug!("transaction_decire_fichier Update description : {:?}", inner);
            if let Some(doc_fichier) = inner {
                let user_id = doc_fichier.user_id;
                let fuuid = match doc_fichier.fuuids_versions.as_ref() {
                    Some(inner) => match inner.get(0) {
                        Some(inner) => Some(inner),
                        None => None
                    },
                    None => None
                };
                if let Some(fuuid) = fuuid {
                    if let Some(mimetype) = doc_fichier.mimetype {
                        let mut parametres = HashMap::new();
                        parametres.insert("mimetype".to_string(), Bson::String(mimetype.to_string()));
                        parametres.insert("fuuid".to_string(), Bson::String(fuuid.to_string()));
                        if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
                            middleware, tuuid, user_id, None,
                            None, Some(parametres), true).await {
                            error!("transaction_decire_fichier Erreur ajout_job_indexation : {:?}", e);
                        }
                    }
                }
            }
        },
        Err(e) => Err(format!("transaction_decire_fichier Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_DECRIRE_FICHIER).await {
        warn!("transaction_decire_fichier Erreur emettre_evenement_maj_fichier : {:?}", e);
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_decire_collection<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_decire_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionDecrireCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionDecrireCollection = match transaction.clone().convertir::<TransactionDecrireCollection>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = transaction.certificat.get_user_id()?;

    let tuuid = transaction_mappee.tuuid.as_str();
    let filtre = doc! { CHAMP_TUUID: tuuid };

    let doc_metadata = match convertir_to_bson(&transaction_mappee.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion transaction : {:?}", e))?
    };

    let mut set_ops = doc! {
        "metadata": doc_metadata,
        CHAMP_FLAG_INDEX: false,
    };

    let ops = doc! {
        "$set": set_ops,
        "$unset": {CHAMP_FLAG_INDEX_RETRY: true, CHAMP_FLAG_INDEX_ERREUR: true},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => {
            debug!("transactions.transaction_decire_collection Update description : {:?}", inner);
            if let Some(d) = inner {
                // Emettre evenement de maj contenu sur chaque cuuid
                match convertir_bson_deserializable::<FichierDetail>(d) {
                    Ok(fichier) => {
                        if let Some(favoris) = fichier.favoris {
                            if let Some(u) = user_id {
                                if favoris {
                                    let mut evenement = EvenementContenuCollection::new(u);
                                    // evenement.cuuid = Some(u);
                                    evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                                }
                            }
                        }
                        if let Some(cuuids) = fichier.cuuids {
                            for cuuid in cuuids {
                                let mut evenement = EvenementContenuCollection::new(cuuid);
                                // evenement.cuuid = Some(cuuid);
                                evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                            }
                        }
                    },
                    Err(e) => warn!("transaction_decire_collection Erreur conversion a FichierDetail : {:?}", e)
                }
            }
        },
        Err(e) => Err(format!("transactions.transaction_decire_collection Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_copier_fichier_tiers<M>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    warn!("transaction_copier_fichier_tiers Transaction OBSOLETE - SKIP");
    Ok(None)
    // debug!("transaction_copier_fichier_tiers Consommer transaction : {:?}", &transaction);
    // let transaction_fichier: TransactionCopierFichierTiers = match transaction.clone().convertir::<TransactionCopierFichierTiers>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur conversion transaction : {:?}", e))?
    // };
    //
    // let user_id = match transaction_fichier.user_id.as_ref() {
    //     Some(inner) => inner,
    //     None => Err(format!("transactions.transaction_copier_fichier_tiers user_id manquant"))?
    // };
    //
    // // Detecter si le fichier existe deja pour l'usager (par fuuid)
    // let tuuid = {
    //     let filtre = doc!{CHAMP_USER_ID: &user_id, CHAMP_FUUIDS: &transaction_fichier.fuuid};
    //     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    //     match collection.find_one(filtre, None).await {
    //         Ok(inner) => {
    //             match inner {
    //                 Some(doc) => {
    //                     // Le document existe deja, reutiliser le tuuid et ajouter au nouveau cuuid
    //                     let fichier: FichierDetail = match convertir_bson_deserializable(doc) {
    //                         Ok(inner) => inner,
    //                         Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur mapping a FichierDetail : {:?}", e))?
    //                     };
    //                     fichier.tuuid
    //                 },
    //                 None => {
    //                     // Nouveau fichier, utiliser uuid_transaction pour le tuuid
    //                     &transaction.transaction.id.to_string()
    //                 }
    //             }
    //         },
    //         Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur verification fuuid existant : {:?}", e))?
    //     }
    // };
    //
    // // Conserver champs transaction uniquement (filtrer champs meta)
    // let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
    //     Ok(d) => d,
    //     Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    // };
    //
    // debug!("transaction_copier_fichier_tiers Tuuid {} Doc bson : {:?}", tuuid, doc_bson_transaction);
    //
    // let fuuid = transaction_fichier.fuuid;
    // let cuuid = transaction_fichier.cuuid;
    // let metadata = transaction_fichier.metadata;
    // let mimetype = transaction_fichier.mimetype;
    //
    // let mut fuuids = HashSet::new();
    // let mut fuuids_reclames = HashSet::new();
    // fuuids.insert(fuuid.as_str());
    // fuuids_reclames.insert(fuuid.as_str());
    // let images_presentes = match &transaction_fichier.images {
    //     Some(images) => {
    //         let presentes = ! images.is_empty();
    //         for image in images.values() {
    //             fuuids.insert(image.hachage.as_str());
    //             if image.data_chiffre.is_none() {
    //                 fuuids_reclames.insert(image.hachage.as_str());
    //             }
    //         }
    //         presentes
    //     },
    //     None => false
    // };
    // let videos_presents = match &transaction_fichier.video {
    //     Some(videos) => {
    //         let presents = ! videos.is_empty();
    //         for video in videos.values() {
    //             fuuids.insert(video.fuuid_video.as_str());
    //             fuuids_reclames.insert(video.fuuid_video.as_str());
    //         }
    //         presents
    //     },
    //     None => false
    // };
    //
    // let fuuids: Vec<&str> = fuuids.into_iter().collect();  // Convertir en vec
    // let fuuids_reclames: Vec<&str> = fuuids_reclames.into_iter().collect();  // Convertir en vec
    //
    // debug!("transaction_copier_fichier_tiers Fuuids fichier : {:?}", fuuids);
    // doc_bson_transaction.insert(CHAMP_FUUIDS, &fuuids);
    // doc_bson_transaction.insert(CHAMP_FUUIDS_RECLAMES, &fuuids_reclames);
    //
    // // Retirer champ CUUID, pas utile dans l'information de version
    // doc_bson_transaction.remove(CHAMP_CUUID);
    //
    // // Inserer document de version
    // {
    //     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let mut doc_version = doc_bson_transaction.clone();
    //     doc_version.insert(CHAMP_TUUID, &tuuid);
    //     doc_version.insert(CHAMP_FUUIDS, &fuuids);
    //     doc_version.insert(CHAMP_FUUIDS_RECLAMES, &fuuids_reclames);
    //
    //     // Information optionnelle pour accelerer indexation/traitement media
    //     if mimetype.starts_with("image") {
    //         doc_version.insert(CHAMP_FLAG_MEDIA, "image");
    //
    //         // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
    //         doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);
    //     } else if mimetype.starts_with("video") {
    //         doc_version.insert(CHAMP_FLAG_MEDIA, "video");
    //
    //         // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
    //         doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);
    //
    //         // Si au moins 1 video est present dans l'entree, on ne fait pas de traitements supplementaires
    //         doc_version.insert(CHAMP_FLAG_VIDEO_TRAITE, videos_presents);
    //     } else if mimetype =="application/pdf" {
    //         doc_version.insert(CHAMP_FLAG_MEDIA, "poster");
    //
    //         // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
    //         doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);
    //     }
    //     doc_version.insert(CHAMP_FLAG_INDEX, false);
    //
    //     // Champs date
    //     doc_version.insert(CHAMP_CREATION, Utc::now());
    //
    //     let ops = doc! {
    //         "$setOnInsert": doc_version,
    //         "$currentDate": {CHAMP_MODIFICATION: true}
    //     };
    //
    //     let filtre = doc! { "fuuid": &fuuid, "tuuid": &tuuid };
    //     let options = UpdateOptions::builder()
    //         .upsert(true)
    //         .build();
    //
    //     match collection.update_one(filtre, ops, options).await {
    //         Ok(resultat_update) => {
    //             if resultat_update.upserted_id.is_none() && resultat_update.matched_count != 1 {
    //                Err(format!("transactions.transaction_copier_fichier_tiers Erreur mise a jour versionsFichiers, echec insertion document (updated count == 0)"))?;
    //             }
    //         },
    //         Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur update versionFichiers : {:?}", e))?
    //     }
    // }
    //
    // // Retirer champs cles - ils sont inutiles dans la version_courante
    // doc_bson_transaction.remove(CHAMP_TUUID);
    // doc_bson_transaction.remove(CHAMP_FUUID);
    // doc_bson_transaction.remove(CHAMP_METADATA);
    // doc_bson_transaction.remove(CHAMP_FUUIDS);
    // doc_bson_transaction.remove(CHAMP_FUUIDS_RECLAMES);
    // doc_bson_transaction.remove(CHAMP_USER_ID);
    //
    // let filtre = doc! {CHAMP_TUUID: &tuuid};
    // let mut add_to_set = doc!{
    //     "fuuids": {"$each": &fuuids},
    //     "fuuids_reclames": {"$each": &fuuids_reclames},
    // };
    //
    // // Ajouter collection
    // add_to_set.insert("cuuids", &cuuid);
    //
    // let metadata = match metadata {
    //     Some(inner) => match convertir_to_bson(inner) {
    //         Ok(metadata) => Some(metadata),
    //         Err(e) => Err(format!("Erreur conversion metadata a bson : {:?}", e))?
    //     },
    //     None => None
    // };
    //
    // let ops = doc! {
    //     "$set": {
    //         // "version_courante": doc_bson_transaction,
    //         CHAMP_FUUIDS_VERSIONS: vec![&fuuid],
    //         CHAMP_MIMETYPE: &mimetype,
    //         CHAMP_SUPPRIME: false,
    //         CHAMP_FLAG_INDEX: false,
    //     },
    //     "$addToSet": add_to_set,
    //     "$setOnInsert": {
    //         CHAMP_TUUID: &tuuid,
    //         CHAMP_CREATION: Utc::now(),
    //         CHAMP_USER_ID: &user_id,
    //         CHAMP_METADATA: metadata,
    //         CHAMP_TYPE_NODE: TypeNode::Fichier.to_str(),
    //     },
    //     "$currentDate": {CHAMP_MODIFICATION: true}
    // };
    // let opts = UpdateOptions::builder().upsert(true).build();
    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    // debug!("nouveau fichier update ops : {:?}", ops);
    // let resultat = match collection.update_one(filtre, ops, opts).await {
    //     Ok(r) => r,
    //     Err(e) => Err(format!("grosfichiers.transaction_copier_fichier_tiers Erreur update_one sur transcation : {:?}", e))?
    // };
    // debug!("transaction_copier_fichier_tiers nouveau fichier Resultat transaction update : {:?}", resultat);
    //
    // if let Err(e) = recalculer_path_cuuids(middleware, cuuid).await {
    //     Err(format!("grosfichiers.transaction_copier_fichier_tiers Erreur update_one sur transcation : {:?}", e))?
    // }
    //
    // {
    //     let mut parametres = HashMap::new();
    //     parametres.insert("mimetype".to_string(), Bson::String(mimetype.clone()));
    //     parametres.insert("fuuid".to_string(), Bson::String(fuuid.clone()));
    //     if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
    //         middleware, &tuuid, user_id, None,
    //         None, Some(parametres), true).await {
    //         error!("transaction_decire_fichier Erreur ajout_job_indexation : {:?}", e);
    //     }
    // }
    //
    // // Emettre fichier pour que tous les clients recoivent la mise a jour
    // if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_COPIER_FICHIER_TIERS).await {
    //     warn!("transaction_copier_fichier_tiers Erreur emettre_evenement_maj_fichier : {:?}", e);
    // }
    //
    // middleware.reponse_ok()
}

async fn transaction_favoris_creerpath<M>(middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_favoris_creerpath Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionFavorisCreerpath = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionFavorisCreerpath = match transaction.clone().convertir::<TransactionFavorisCreerpath>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion transaction : {:?}", e))?
    // };
    let uuid_transaction = &transaction.transaction.id;

    let user_id = match &transaction_collection.user_id {
        Some(u) => u.to_owned(),
        None => {
            match transaction.certificat.get_user_id()? {
                Some(inner) => inner,
                None => Err(CommonError::Str("grosfichiers.transaction_favoris_creerpath Erreur user_id absent du certificat"))?
            }
            // match transaction.get_enveloppe_certificat() {
            //     Some(c) => {
            //         match c.get_user_id()? {
            //             Some(u) => Ok(u.to_owned()),
            //             None => Err(format!("grosfichiers.transaction_favoris_creerpath user_id manquant"))
            //         }
            //     },
            //     None => Err(format!("grosfichiers.transaction_favoris_creerpath Certificat non charge"))
            // }
        }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let date_courante = Utc::now();
    let tuuid_favoris = format!("{}_{}", &user_id, &transaction_collection.favoris_id);

    {
        let ops_favoris = doc! {
            "$setOnInsert": {
                CHAMP_TUUID: &tuuid_favoris,
                CHAMP_NOM: &transaction_collection.favoris_id,
                CHAMP_CREATION: &date_courante,
                CHAMP_MODIFICATION: &date_courante,
                CHAMP_SECURITE: SECURITE_3_PROTEGE,
                CHAMP_USER_ID: &user_id,
            },
            "$set": {
                CHAMP_SUPPRIME: false,
                CHAMP_FAVORIS: true,
            }
        };
        let filtre_favoris = doc! {CHAMP_TUUID: &tuuid_favoris};
        let options_favoris = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let doc_favoris_opt = match collection.find_one_and_update(
            filtre_favoris, ops_favoris, Some(options_favoris)).await {
            Ok(f) => Ok(f),
            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur find_one_and_update doc favoris : {:?}", e))
        }?;

        if doc_favoris_opt.is_none() {
            Err(format!("grosfichiers.transaction_favoris_creerpath Erreur creation document favoris"))?;
        }
    }

    let mut cuuid_courant = tuuid_favoris.clone();
    let mut idx = 0;
    let tuuid_leaf = match transaction_collection.path_collections {
        Some(path_collections) => {
            for path_col in path_collections {
                idx = idx+1;
                // Trouver ou creer favoris
                let filtre = doc!{
                    CHAMP_CUUIDS: &cuuid_courant,
                    CHAMP_USER_ID: &user_id,
                    CHAMP_NOM: &path_col,
                };
                let doc_path = match collection.find_one(filtre, None).await {
                    Ok(d) => Ok(d),
                    Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur creation doc collection path {} : {:?}", path_col, e))
                }?;
                match doc_path {
                    Some(d) => {
                        debug!("grosfichiers.transaction_favoris_creerpath Mapper info collection : {:?}", d);
                        let collection_info: InformationCollection = match convertir_bson_deserializable(d) {
                            Ok(inner_collection) => Ok(inner_collection),
                            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion bson path {} : {:?}", path_col, e))
                        }?;
                        cuuid_courant = collection_info.tuuid.clone();

                        let flag_supprime = match collection_info.supprime {
                            Some(f) => f,
                            None => true
                        };

                        if flag_supprime {
                            // MAj collection, flip flags
                            let filtre = doc!{CHAMP_TUUID: &collection_info.tuuid};
                            let ops = doc!{
                                "$set": {CHAMP_SUPPRIME: false},
                                "$currentDate": {CHAMP_MODIFICATION: true}
                            };
                            match collection.update_one(filtre, ops, None).await {
                                Ok(_) => (),
                                Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur flip flag supprime de tuuid={} : {:?}", &collection_info.tuuid, e))?
                            }
                        }
                    },
                    None => {
                        // Creer la nouvelle collection
                        let tuuid = format!("{}_{}", uuid_transaction, idx);
                        let collection_info = doc!{
                            CHAMP_TUUID: &tuuid,
                            CHAMP_NOM: &path_col,
                            CHAMP_CREATION: &date_courante,
                            CHAMP_MODIFICATION: &date_courante,
                            CHAMP_SECURITE: SECURITE_3_PROTEGE,
                            CHAMP_USER_ID: &user_id,
                            CHAMP_SUPPRIME: false,
                            CHAMP_FAVORIS: false,
                            CHAMP_CUUIDS: vec![cuuid_courant]
                        };
                        match collection.insert_one(collection_info, None).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur insertion collection path {} : {:?}", path_col, e))
                        }?;
                        cuuid_courant = tuuid.clone();
                    }
                }
            }

            // Retourner le dernier identifcateur de collection (c'est le tuuid)
            cuuid_courant
        },
        None => tuuid_favoris.clone()
    };

    if let Err(e) = recalculer_path_cuuids(middleware, tuuid_favoris).await {
        Err(format!("grosfichiers.transaction_favoris_creerpath Erreur recalculer_path_cuuids : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    Ok(Some(middleware.build_reponse(json!({CHAMP_TUUID: &tuuid_leaf}))?.0))
    // let reponse = match middleware.formatter_reponse(json!({CHAMP_TUUID: &tuuid_leaf}), None) {
    //     Ok(r) => Ok(r),
    //     Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    // }?;
    //
    // Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationCollection {
    pub tuuid: String,
    pub nom: String,
    pub cuuids: Option<Vec<String>>,
    pub user_id: String,
    pub supprime: Option<bool>,
    pub favoris: Option<bool>,
}

async fn transaction_supprimer_video<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionSupprimerVideo = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_collection: TransactionSupprimerVideo = match transaction.clone().convertir::<TransactionSupprimerVideo>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion transaction : {:?}", e))?
    // };

    let fuuid = &transaction_collection.fuuid_video;

    // let enveloppe = match transaction.get_enveloppe_certificat() {
    //     Some(e) => e,
    //     None => Err(format!("transaction_supprimer_video Certificat inconnu, transaction ignoree"))?
    // };
    let user_id = transaction.certificat.get_user_id()?;

    let mut labels_videos = Vec::new();
    let filtre = doc!{CHAMP_FUUIDS: fuuid, CHAMP_USER_ID: user_id.as_ref()};
    let collection_fichier_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let doc_video = match collection_fichier_versions.find_one(filtre.clone(), None).await {
        Ok(d) => match d {
            Some(d) => d,
            None => Err(format!("transaction_supprimer_video Erreur chargement info document, aucun match"))?
        },
        Err(e) => Err(format!("transaction_supprimer_video Erreur chargement info document : {:?}", e))?
    };

    let tuuid = doc_video.tuuid;

    let mut ops_unset = doc!{};
    if let Some(map_video) = doc_video.video.as_ref() {
        for (label, video) in map_video {
            if &video.fuuid_video == fuuid {
                ops_unset.insert(format!("video.{}", label), true);
                labels_videos.push(label);
            }
        }
    }

    {
        let filtre = doc!{CHAMP_FUUIDS: fuuid};
        let mut ops_unset = doc!{format!("fuuidMimetypes.{}", fuuid): true};
        for label in labels_videos {
            ops_unset.insert(format!("video.{}", label), true);
        }

        let ops = doc! {
            "$pull": {CHAMP_FUUIDS: fuuid, CHAMP_FUUIDS_RECLAMES: fuuid},
            "$unset": ops_unset,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let collection_version_fichier = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

        debug!("transaction_supprimer_video Supprimer video {:?} ops {:?}", filtre, ops);

        match collection_version_fichier.update_one(filtre, ops, None).await {
            Ok(_r) => (),
            Err(e) => Err(format!("transaction_supprimer_video Erreur update_one collection fichiers rep : {:?}", e))?
        }
    }

    if let Err(e) = touch_fichiers_rep(middleware, user_id.as_ref(), vec![fuuid]).await {
        error!("transaction_favoris_creerpath Erreur touch_fichiers_rep {:?}/{:?} : {:?}", user_id, fuuid, e);
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_ASSOCIER_VIDEO).await {
        warn!("transaction_favoris_creerpath Erreur emettre_evenement_maj_fichier : {:?}", e);
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(CommonError::Str("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}


async fn transaction_supprimer_job_image<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_job_image Consommer transaction : {}", transaction.transaction.id);
    let transaction_supprimer_job: TransactionSupprimerJobImage = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_supprimer_job: TransactionSupprimerJobImage = match transaction.clone().convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(CommonError::String(format!("grosfichiers.transaction_supprimer_job_video Erreur conversion transaction : {:?}", e)))?
    // };

    let user_id = get_user_effectif(&transaction, &transaction_supprimer_job)?;

    let fuuid = &transaction_supprimer_job.fuuid;

    // let enveloppe = match transaction.get_enveloppe_certificat() {
    //     Some(e) => e,
    //     None => Err(format!("transaction_supprimer_video Certificat inconnu, transaction ignoree"))?
    // };
    //
    // let user_id = enveloppe.get_user_id()?;

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = gestionnaire.image_job_handler.set_flag(middleware, fuuid, Some(user_id),None, true).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag image : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(CommonError::Str("transactions.transaction_supprimer_job_image Erreur formattage reponse"))
    }
}

async fn transaction_supprimer_job_video<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_job_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_supprimer: TransactionSupprimerJobVideo = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_supprimer: TransactionSupprimerJobVideo = match transaction.clone().convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_supprimer_job_image Erreur conversion transaction : {:?}", e))?
    // };

    let user_id = get_user_effectif(&transaction, &transaction_supprimer)?;

    let fuuid = &transaction_supprimer.fuuid;
    // let user_id = &transaction_supprimer.user_id;
    let mut cles_supplementaires = HashMap::new();
    cles_supplementaires.insert("cle_conversion".to_string(), transaction_supprimer.cle_conversion.clone());

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = gestionnaire.video_job_handler.set_flag(middleware, fuuid, Some(user_id),Some(cles_supplementaires), true).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag video : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(CommonError::Str("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterContactLocal {
    /// Usager du carnet
    pub user_id: String,
    /// Contact local ajoute
    pub contact_user_id: String,
}

async fn transaction_ajouter_contact_local<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_ajouter_contact_local Consommer transaction : {}", transaction.transaction.id);
    let uuid_transaction = transaction.transaction.id.clone();

    let transaction_mappee: TransactionAjouterContactLocal = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionAjouterContactLocal = match transaction.convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur conversion transaction : {:?}", e))?
    // };

    let filtre = doc! {
        CHAMP_CONTACT_ID: uuid_transaction,
        CHAMP_USER_ID: &transaction_mappee.user_id,
        "contact_user_id": &transaction_mappee.contact_user_id,
    };
    let ops = doc! {
        "$setOnInsert": {
            CHAMP_USER_ID: transaction_mappee.user_id,
            "contact_user_id": transaction_mappee.contact_user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    if let Err(e) = collection.update_one(filtre, ops, options).await {
        Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur sauvegarde contact : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(CommonError::Str("grosfichiers.transaction_ajouter_contact_local Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerContacts {
    pub contact_ids: Vec<String>,
}

async fn transaction_supprimer_contacts<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_contacts Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_contacts Erreur user_id absent du certificat"))?
    };
    // let user_id = match transaction.get_enveloppe_certificat() {
    //     Some(inner) => match inner.get_user_id()? {
    //         Some(inner) => inner.to_owned(),
    //         None => Err(format!("grosfichiers.transaction_supprimer_contacts User_id manquant du certificat"))?
    //     },
    //     None => Err(format!("grosfichiers.transaction_supprimer_contacts Erreur enveloppe manquante"))?
    // };

    let transaction_mappee: TransactionSupprimerContacts = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionSupprimerContacts = match transaction.convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_supprimer_contacts Erreur conversion transaction : {:?}", e))?
    // };

    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_CONTACT_ID: {"$in": transaction_mappee.contact_ids},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    if let Err(e) = collection.delete_many(filtre, None).await {
        Err(format!("grosfichiers.transaction_supprimer_contacts Erreur suppression contacts : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(CommonError::Str("grosfichiers.transaction_supprimer_contacts Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPartagerCollections {
    pub cuuids: Vec<String>,
    pub contact_ids: Vec<String>,
}

async fn transaction_partager_collections<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_partager_collections Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_partager_collections Erreur user_id absent du certificat"))?
    };
    // let user_id = match transaction.get_enveloppe_certificat() {
    //     Some(inner) => match inner.get_user_id()? {
    //         Some(inner) => inner.to_owned(),
    //         None => Err(format!("grosfichiers.transaction_partager_collections User_id manquant du certificat"))?
    //     },
    //     None => Err(format!("grosfichiers.transaction_partager_collections Erreur enveloppe manquante"))?
    // };

    let transaction_mappee: TransactionPartagerCollections = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionPartagerCollections = match transaction.convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_partager_collections Erreur conversion transaction : {:?}", e))?
    // };

    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    for contact_id in transaction_mappee.contact_ids {
        for cuuid in &transaction_mappee.cuuids {
            let filtre = doc! {
                CHAMP_USER_ID: &user_id,
                CHAMP_CONTACT_ID: &contact_id,
                CHAMP_TUUID: cuuid,
            };
            let options = UpdateOptions::builder().upsert(true).build();
            let ops = doc! {
                "$setOnInsert": {
                    CHAMP_USER_ID: &user_id,
                    CHAMP_CONTACT_ID: &contact_id,
                    CHAMP_TUUID: cuuid,
                    CHAMP_CREATION: Utc::now(),
                },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            if let Err(e) = collection.update_one(filtre, ops, options).await {
                Err(format!("grosfichiers.transaction_partager_collections Erreur sauvegarde partage : {:?}", e))?
            }
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerPartageUsager {
    pub contact_id: String,
    pub tuuid: String,
}

async fn transaction_supprimer_partage_usager<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_partage_usager Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_partage_usager Erreur user_id absent du certificat"))?
    };
    // let user_id = match transaction.get_enveloppe_certificat() {
    //     Some(inner) => match inner.get_user_id()? {
    //         Some(inner) => inner.to_owned(),
    //         None => Err(format!("grosfichiers.transaction_supprimer_partage_usager User_id manquant du certificat"))?
    //     },
    //     None => Err(format!("grosfichiers.transaction_supprimer_partage_usager Erreur enveloppe manquante"))?
    // };

    let transaction_mappee: TransactionSupprimerPartageUsager = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionSupprimerPartageUsager = match transaction.convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_supprimer_partage_usager Erreur conversion transaction : {:?}", e))?
    // };

    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_CONTACT_ID: transaction_mappee.contact_id,
        CHAMP_TUUID: transaction_mappee.tuuid,
    };
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    if let Err(e) = collection.delete_one(filtre, None).await {
        Err(format!("transactions.transaction_supprimer_partage_usager Erreur delete_one : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerOrphelins {
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseSupprimerOrphelins {
    pub ok: bool,
    pub err: Option<String>,
    pub fuuids_a_conserver: Vec<String>,
}

pub struct ResultatVerifierOrphelins {
    pub versions_supprimees: HashMap<String, bool>,
    pub fuuids_a_conserver: Vec<String>
}

pub async fn trouver_orphelins_supprimer<M>(middleware: &M, commande: &TransactionSupprimerOrphelins)
    -> Result<ResultatVerifierOrphelins, CommonError>
    where M: MongoDao
{
    let mut versions_supprimees = HashMap::new();
    let mut fuuids_a_conserver = Vec::new();

    let fuuids_commande = {
        let mut set_fuuids = HashSet::new();
        for fuuid in &commande.fuuids { set_fuuids.insert(fuuid.as_str()); }
        set_fuuids
    };

    // S'assurer qu'au moins un fuuid peut etre supprime.
    // Extraire les fuuids qui doivent etre conserves
    let filtre = doc! {
        CHAMP_FUUIDS: {"$in": &commande.fuuids},
    };
    let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
        NOM_COLLECTION_VERSIONS)?;
    debug!("trouver_orphelins_supprimer Filtre requete orphelins : {:?}", filtre);
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let doc_mappe = curseur.deserialize_current()?;
        let fuuids_version = &doc_mappe.fuuids;
        let fuuid_fichier = doc_mappe.fuuid;
        let supprime = doc_mappe.supprime;

        if supprime {
            // Verifier si l'original est l'orphelin a supprimer
            if fuuids_commande.contains(fuuid_fichier) {
                if !versions_supprimees.contains_key(fuuid_fichier) {
                    // S'assurer de ne pas faire d'override si le fuuid est deja present avec false
                    versions_supprimees.insert(fuuid_fichier.to_string(), true);
                }
            }
        } else {
            if fuuids_commande.contains(fuuid_fichier) {
                // Override, s'assurer de ne pas supprimer le fichier si au moins 1 usager le conserve
                versions_supprimees.insert(fuuid_fichier.to_string(), false);
            }

            // Pas supprime localement, ajouter tous les fuuids qui sont identifies comme orphelins
            for fuuid in fuuids_version {
                if fuuids_commande.contains(*fuuid) {
                    fuuids_a_conserver.push(fuuid.to_string());
                }
            }
        }
    }

    debug!("trouver_orphelins_supprimer Versions supprimees : {:?}, fuuids a conserver : {:?}", versions_supprimees, fuuids_a_conserver);
    let resultat = ResultatVerifierOrphelins { versions_supprimees, fuuids_a_conserver };
    Ok(resultat)
}

async fn transaction_supprimer_orphelins<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_partage_usager Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionSupprimerOrphelins = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    // let transaction_mappee: TransactionSupprimerOrphelins = match transaction.convertir() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("grosfichiers.transaction_supprimer_orphelins Erreur conversion transaction : {:?}", e))?
    // };
    match traiter_transaction_supprimer_orphelins(middleware, transaction_mappee).await {
        Ok(inner) => Ok(inner),
        Err(e) => Err(format!("transaction_supprimer_orphelins Erreur traitement {:?}", e))?
    }
}

async fn traiter_transaction_supprimer_orphelins<M>(middleware: &M, transaction: TransactionSupprimerOrphelins)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: GenerateurMessages + MongoDao
{
    let resultat = trouver_orphelins_supprimer(middleware, &transaction).await?;

    let collection_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    for (fuuid, supprimer) in resultat.versions_supprimees {
        if supprimer {
            info!("traiter_transaction_supprimer_orphelins Supprimer fuuid {}", fuuid);
            let filtre_rep = doc! { CHAMP_FUUIDS_VERSIONS: &fuuid };
            let ops = doc! {
                "$pull": { CHAMP_FUUIDS_VERSIONS: &fuuid },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            collection_rep.update_many(filtre_rep, ops, None).await?;

            let filtre_version = doc! { CHAMP_FUUID: &fuuid, CHAMP_SUPPRIME: true };
            collection_versions.delete_many(filtre_version, None).await?;

            // Nettoyage fichiers sans versions
            let filtre_rep_vide = doc! {
                CHAMP_TYPE_NODE: TypeNode::Fichier.to_str(),
                format!("{}.0", CHAMP_FUUIDS_VERSIONS): {"$exists": false}
            };
            collection_rep.delete_many(filtre_rep_vide, None).await?;
        }
    }

    let reponse = ReponseSupprimerOrphelins { ok: true, err: None, fuuids_a_conserver: resultat.fuuids_a_conserver };
    Ok(Some(middleware.build_reponse(reponse)?.0))
    // Ok(Some(middleware.formatter_reponse(reponse, None)?))
}