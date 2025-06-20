use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use crate::data_structs::{FileComment, ImageDetail, MediaOwnedRow, VideoDetail};
use crate::domain_manager::GrosFichiersDomainManager;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::bson::Bson;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::dechiffrage::{DataChiffre, DataChiffreBorrow};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::fichiers::is_mimetype_video;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::hachages::{hacher_bytes, hacher_bytes_vu8};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::optionformatchiffragestr;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{optionepochseconds, MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::millegrilles_cryptographie::serde_dates::mapstringepochseconds;
use millegrilles_common_rust::mongo_dao::{opt_chrono_datetime_as_bson_datetime, map_chrono_datetime_as_bson_datetime};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, convertir_to_bson_array, start_transaction_regeneration, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::mongodb::{ClientSession, Collection, Cursor, SessionCursor};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::{bson, bson::doc};
use millegrilles_common_rust::{hex, serde_json, serde_json::json};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use crate::grosfichiers_constantes::*;
use crate::requetes::{verifier_acces_usager_tuuids, ContactRow};
use crate::traitement_media::{set_flag_image_traitee, set_flag_video_traite};

pub async fn aiguillage_transaction<M, T>(_gestionnaire: &GrosFichiersDomainManager, middleware: &M, transaction: T, session: &mut ClientSession)
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
        // Adding, updating files
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(middleware, transaction, session).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, transaction, session).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => transaction_associer_conversions(middleware, transaction, session).await,
        TRANSACTION_ASSOCIER_VIDEO => transaction_associer_video(middleware, transaction, session).await,
        TRANSACTION_DECRIRE_FICHIER => transaction_decrire_fichier(middleware, transaction, session).await,
        TRANSACTION_DECRIRE_COLLECTION => transaction_decrire_collection(middleware, transaction, session).await,
        TRANSACTION_UPDATE_FILE_TEXT_CONTENT =>  transaction_update_file_text_content(middleware, transaction, session).await,
        TRANSACTION_FILE_SUMMARY => transaction_set_file_summary(middleware, transaction, session).await,

        // Moving files
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => transaction_deplacer_fichiers_collection(middleware, transaction, session).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, transaction, session).await,
        TRANSACTION_RECUPERER_DOCUMENTS_V2 => transaction_recuperer_documents_v2(middleware, transaction, session).await,
        TRANSACTION_RECYCLE_ITEMS_V3 => transaction_recycle_items_v3(middleware, transaction, session).await,
        TRANSACTION_SUPPRIMER_ORPHELINS => transaction_supprimer_orphelins(middleware, transaction, session).await,
        TRANSACTION_DELETE_V2 => transaction_delete_v2(middleware, transaction, session).await,
        TRANSACTION_MOVE_V2 => transaction_move_v2(middleware, transaction, session).await,
        TRANSACTION_COPY_V2 => transaction_copy_v2(middleware, transaction, session).await,
        TRANSACTION_PERMANENTLY_DELETE_FILES => transaction_permanently_delete_files(middleware, transaction, session).await,

        // Media
        TRANSACTION_SUPPRIMER_VIDEO => transaction_supprimer_video(middleware, transaction, session).await,
        TRANSACTION_IMAGE_SUPPRIMER_JOB_V2 => transaction_supprimer_job_image_v2(middleware, transaction, session).await,
        TRANSACTION_VIDEO_SUPPRIMER_JOB_V2 => transaction_supprimer_job_video_v2(middleware, transaction, session).await,

        // Sharing
        TRANSACTION_AJOUTER_CONTACT_LOCAL => transaction_ajouter_contact_local(middleware, transaction, session).await,
        TRANSACTION_SUPPRIMER_CONTACTS => transaction_supprimer_contacts(middleware,  transaction, session).await,
        TRANSACTION_PARTAGER_COLLECTIONS => transaction_partager_collections(middleware, transaction, session).await,
        TRANSACTION_SUPPRIMER_PARTAGE_USAGER => transaction_supprimer_partage_usager(middleware,  transaction, session).await,

        // Legacy but still required (no command associated)
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, transaction, session).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, transaction, session).await,

        // Obsolete transactions - keep to avoid getting an error on rebuild
        TRANSACTION_IMAGE_SUPPRIMER_JOB => obsolete(),
        TRANSACTION_VIDEO_SUPPRIMER_JOB => obsolete(),
        TRANSACTION_COPIER_FICHIER_TIERS => obsolete(),
        TRANSACTION_ARCHIVER_DOCUMENTS => obsolete(),

        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleVersion {
    pub fuuid: String,
    pub cuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    pub mimetype: String,
    pub metadata: DataChiffre,
    pub taille: u64,

    // Valeurs de chiffrage symmetrique (depuis 2024.3)
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireFichier {
    pub tuuid: String,
    pub metadata: Option<DataChiffre>,
    pub mimetype: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireCollection {
    pub tuuid: String,
    pub metadata: Option<DataChiffre>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleCollection {
    pub metadata: DataChiffre,
    pub cuuid: Option<String>,  // Insertion dans collection destination
    favoris: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterFichiersCollection {
    pub cuuid: String,                  // Collection qui recoit les documents
    pub inclure_tuuids: Vec<String>,    // Fichiers/rep a ajouter a la collection
    pub contact_id: Option<String>,     // Permission de copie a partir d'un partage
    pub include_deleted: Option<bool>,  // Allows copying from trash to new section
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionChangerFavoris {
    pub favoris: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionUpdateFileTextContent {
    pub tuuid: String,
    pub file_language: Option<String>,
    pub tags: Option<EncryptedDocument>,
    pub comment: Option<EncryptedDocument>,
    /// Comment_id allows to replace an existing comment
    pub comment_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionFileSummary {
    pub fuuid: String,
    /// Tuuid provided only if operation is for a single user
    pub tuuids: Option<Vec<String>>,
    /// Detected file language
    pub file_language: Option<String>,
    /// Generated tags
    pub tags: Option<EncryptedDocument>,
    /// The comment contains the summary
    pub comment: Option<EncryptedDocument>,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeFichierRepRow<'a> {
    /// Identificateur unique d'un node pour l'usager
    pub tuuid: String,
    pub user_id: String,
    pub type_node: &'a str,
    #[serde(default, rename="_mg-derniere-modification", with="chrono_datetime_as_bson_datetime")]
    pub derniere_modification: DateTime<Utc>,
    #[serde(default, rename="_mg-creation", with="chrono_datetime_as_bson_datetime")]
    pub date_creation: DateTime<Utc>,
    pub flag_index: bool,
    pub flag_rag: Option<bool>,
    pub supprime: bool,
    pub supprime_indirect: bool,
    pub metadata: DataChiffreBorrow<'a>,

    // Champs pour type_node Fichier
    pub mimetype: Option<&'a str>,
    /// Fuuids des versions en ordre (plus recent en dernier)
    pub fuuids_versions: Option<Vec<&'a str>>,

    // Champs pour type_node Fichiers/Repertoires
    /// Path des cuuids parents (inverse, parent immediat est index 0)
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

    pub flag_index: bool,
    pub flag_rag: Option<bool>,

    // Champs pour type_node Fichier
    pub mimetype: Option<String>,
    /// Fuuids des versions en ordre (plus recent en dernier)
    pub fuuids_versions: Option<Vec<String>>,

    // Champs pour type_node Fichiers/Repertoires
    /// Path des cuuids parents (inverse, parent immediat est index 0)
    pub path_cuuids: Option<Vec<String>>,

    // pub language: Option<String>,
    // pub comments: Option<Vec<FileComment>>,
    // pub tags: Option<Vec<EncryptedDocument>>,

    // Mapping date - requis pour sync
    #[serde(default, rename(deserialize="_mg-derniere-modification"), skip_serializing_if = "Option::is_none",
    serialize_with="optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub derniere_modification: Option<DateTime<Utc>>,
    #[serde(default, rename(deserialize="_mg-creation"), skip_serializing_if = "Option::is_none",
        serialize_with="optionepochseconds::serialize",
        deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub date_creation: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierVersionAudioOwned {
    index: u32,
    title: Option<String>,
    language: Option<String>,
    codec_name: Option<String>,
    bit_rate: Option<u32>,
    default: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierVersionSubtitlesOwned {
    index: u32,
    language: Option<String>,
    title: Option<String>,
    codec_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeFichierVersionRow<'a> {
    pub fuuid: String,
    pub mimetype: &'a str,
    pub taille: u64,

    pub tuuids: Vec<&'a str>,
    pub fuuids_reclames: Vec<&'a str>,

    // #[serde(with="mapstringepochseconds")]
    #[serde(with="map_chrono_datetime_as_bson_datetime")]
    pub visites: HashMap<String, DateTime<Utc>>,
    #[serde(with="chrono_datetime_as_bson_datetime")]
    pub last_visit_verification: DateTime<Utc>,

    // Mapping date
    #[serde(rename="_mg-creation", with="chrono_datetime_as_bson_datetime")]
    creation: DateTime<Utc>,
    #[serde(rename="_mg-derniere-modification", with="chrono_datetime_as_bson_datetime")]
    derniere_modification: DateTime<Utc>,

    #[serde(skip_serializing_if="Option::is_none")]
    flag_media: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_retry: Option<i32>,
    pub flag_media_traite: bool,
    pub flag_video_traite: bool,
    pub flag_summary: Option<bool>,

    // Information de chiffrage symmetrique (depuis 2024.3.0)
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<&'a str>,
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<&'a str>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<&'a str>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierVersionOwned {
    pub fuuid: String,
    pub mimetype: String,
    pub taille: u64,

    pub tuuids: Vec<String>,
    pub fuuids_reclames: Vec<String>,

    pub language: Option<String>,

    #[serde(
        serialize_with="mapstringepochseconds::serialize",
        deserialize_with="map_chrono_datetime_as_bson_datetime::deserialize"
    )]
    pub visites: HashMap<String, DateTime<Utc>>,

    // Mapping date
    #[serde(default, rename(deserialize = "_mg-derniere-modification"),
    serialize_with = "optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub derniere_modification: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if="Option::is_none")]
    flag_media: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_retry: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_traite: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_video_traite: Option<bool>,

    // Information de chiffrage symmetrique (depuis 2024.3.0)
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<String>,
}

pub fn get_flags_media(mimetype: &str) -> (bool, bool, Option<String>, bool) {
    let mut flag_media_traite = true;
    let mut flag_video_traite = true;
    let mut flag_media = None;
    let mut flag_summary = true;

    // Information optionnelle pour accelerer indexation/traitement media
    if mimetype.starts_with("image/") {
        flag_media_traite = false;
        flag_media = Some("image".to_string());
        flag_summary = false;
    } else if is_mimetype_video(mimetype) {
        flag_media_traite = true;  // Thumbnails generes avec le video depuis 2024.9
        flag_video_traite = false;
        flag_media = Some("video".to_string());
    } else if mimetype == "application/pdf" {
        flag_media_traite = false;
        flag_media = Some("poster".to_string());
        flag_summary = false;
    } else if mimetype.starts_with("text/") {
        flag_summary = true;
    }
    (flag_media_traite, flag_video_traite, flag_media, flag_summary)
}

async fn transaction_nouvelle_version<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_nouvelle_version Consommer transaction : {}", transaction.transaction.id);
    let transaction_fichier: TransactionNouvelleVersion = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err(format!("grosfichiers.transaction_nouvelle_version User_id absent du certificat"))?
        },
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur get_user_id() : {:?}", e))?
    };

    let tuuid = match &transaction_fichier.tuuid {
        Some(t) => t.to_owned(),
        None => transaction.transaction.id.clone(),
    };

    let cuuid = transaction_fichier.cuuid.as_str();
    let mut cuuids = vec![cuuid.to_owned()];

    // Inserer l'information du path (cuuids parents)
    let filtre = doc!{ CHAMP_TUUID: &cuuid, CHAMP_USER_ID: &user_id };
    let collection_nodes = middleware.get_collection_typed::<NodeFichiersRepBorrow>(
        NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection_nodes.find_with_session(filtre, None, session).await?;
    if curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        if let Some(path_parent) = row.path_cuuids {
            // Inserer les cuuids du parent
            cuuids.extend(path_parent.into_iter().map(|c|c.to_owned()));
        }
    } else {
        Err(format!("transactions.transaction_nouvelle_version Cuuid {} inconnu", cuuid))?;
    };

    let fuuid = transaction_fichier.fuuid;
    let mut flag_duplication = false;
    let taille_fichier = transaction_fichier.taille as i64;

    // Inserer document de version
    {
        let (flag_media_traite, flag_video_traite, flag_media, flag_summary) = get_flags_media(transaction_fichier.mimetype.as_str());

        let mut visites = HashMap::new();
        visites.insert("nouveau".to_string(), Utc::now());

        // Creer date de verification anterieure pour forcer reclamation initiale
        let last_visit_verification = DateTime::from_timestamp(1704085200, 0).expect("from_timestamp");

        let row_version = NodeFichierVersionRow {
            fuuid: fuuid.clone(),
            mimetype: transaction_fichier.mimetype.as_str(),
            taille: transaction_fichier.taille,
            tuuids: vec![tuuid.as_str()],
            fuuids_reclames: vec![fuuid.as_str()],
            visites,
            last_visit_verification,
            creation: Utc::now(),
            derniere_modification: Utc::now(),
            flag_media,
            flag_media_retry: None,
            flag_media_traite,
            flag_video_traite,
            flag_summary: Some(flag_summary),
            cle_id: transaction_fichier.cle_id.as_ref().map(|x|x.as_str()),
            format: transaction_fichier.format,
            nonce: transaction_fichier.nonce.as_ref().map(|x|x.as_str()),
            verification: transaction_fichier.verification.as_ref().map(|x|x.as_str()),
        };

        let collection = middleware.get_collection_typed::<NodeFichierVersionRow>(NOM_COLLECTION_VERSIONS)?;
        if let Err(e) = collection.insert_one_with_session(&row_version, None, session).await {
            Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur update_one fichier_version : {:?}", e))?
        }
    }

    // Inserer document FichierRep
    {
        let row_rep = NodeFichierRepRow {
            tuuid,
            user_id: user_id.clone(),
            type_node: TypeNode::Fichier.to_str(),
            derniere_modification: Utc::now(),
            date_creation: Utc::now(),
            flag_index: false,
            flag_rag: Some(false),
            supprime: false,
            supprime_indirect: false,
            metadata: transaction_fichier.metadata.borrow(),
            mimetype: Some(transaction_fichier.mimetype.as_str()),
            fuuids_versions: Some(vec![fuuid.as_str()]),
            path_cuuids: Some(cuuids.iter().map(|x|x.as_str()).collect()),
        };

        let collection = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
        if let Err(e) = collection.insert_one_with_session(&row_rep, None, session).await {
            Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur update_one fichier_version : {:?}", e))?
        }
    }

    if flag_duplication == false {

        // Mettre a jour le quota usager (ou inserer au besoin)
        {
            let collection_quotas = middleware.get_collection(NOM_COLLECTION_QUOTAS_USAGERS)?;
            let filtre = doc!{"user_id": &user_id};
            let ops = doc!{
                "$setOnInsert": {CHAMP_CREATION: Utc::now()},
                "$inc": {"bytes_total_versions": taille_fichier, "nombre_total_versions": 1},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            if let Err(e) = collection_quotas.update_one_with_session(filtre, ops, options, session).await {
                error!("transaction_nouvelle_version Erreur mise a jour quota usager : {:?}", e);
            }
        }

    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_nouvelle_collection<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_nouvelle_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionNouvelleCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = transaction.certificat.get_user_id()?;

    let tuuid = &transaction.transaction.id.to_owned();
    let cuuid = transaction_collection.cuuid;
    let metadata = match convertir_to_bson(&transaction_collection.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion metadata chiffre en bson {:?}", e))?
    };

    let date_courante = millegrilles_common_rust::bson::DateTime::now();
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
        CHAMP_METADATA: metadata,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: false,
        CHAMP_SUPPRIME_INDIRECT: false,
        CHAMP_FAVORIS: favoris,
        CHAMP_TYPE_NODE: type_node,
        CHAMP_FLAG_INDEX: false,
        CHAMP_FLAG_RAG: false,
    };
    debug!("grosfichiers.transaction_nouvelle_collection Ajouter nouvelle collection doc : {:?}", doc_collection);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    // Ajouter collection parent au besoin
    if let Some(c) = cuuid.as_ref() {
        doc_collection.insert("cuuid", c.clone());

        // Charger le cuuid pour ajouter path vers root
        match get_path_cuuid(middleware, c, session).await {
            Ok(inner) => {
                if let Some(path_cuuids) = inner {
                    let path_cuuids_modifie: Vec<Bson> = path_cuuids.iter().map(|c| Bson::String(c.to_owned())).collect();
                    doc_collection.insert("path_cuuids", path_cuuids_modifie);
                }
            },
            Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection get_path_cuuid : {:?}", e))?
        }
    }

    let resultat = match collection.insert_one_with_session(doc_collection, None, session).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_nouvelle_collection Resultat transaction update : {:?}", resultat);

    let reponse = json!({"ok": true, "tuuid": tuuid});
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RowRepertoirePaths {
    // tuuid: String,
    // cuuid: Option<String>,
    path_cuuids: Option<Vec<String>>,
}

async fn get_path_cuuid<M,S>(middleware: &M, cuuid: S, session: &mut ClientSession)
    -> Result<Option<Vec<String>>, CommonError>
    where M: MongoDao, S: AsRef<str>
{
    let cuuid = cuuid.as_ref();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc! { CHAMP_TUUID: cuuid };
    let options = FindOneOptions::builder().projection(doc!{CHAMP_PATH_CUUIDS: 1}).build();
    let doc_parent: RowRepertoirePaths = match collection.find_one_with_session(filtre, options, session).await? {
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

async fn get_path_cuuid_no_session<M,S>(middleware: &M, cuuid: S)
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

/// The transaction_ajouter_fichiers_collection transaction is deprecated since 2024.9 - replaced by transaction_copy_v2.
/// The command is still used (has been refactored)
async fn transaction_ajouter_fichiers_collection<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let uuid_transaction = &transaction.transaction.id;

    debug!("transaction_ajouter_fichiers_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionAjouterFichiersCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("transaction.transaction_ajouter_fichiers_collection Certificat sans user_id"))?
    };

    let (user_id_origine, user_id_destination) = match transaction_collection.contact_id.as_ref() {
        Some(contact_id) => {
            debug!("transaction_ajouter_fichiers_collection Verifier que le contact_id est valide (correspond aux tuuids)");
            let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let filtre = doc! {CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id};
            let contact = match collection.find_one_with_session(filtre, None, session).await {
                Ok(inner) => match inner {
                    Some(inner) => inner,
                    None => {
                        let reponse = json!({"ok": false, "err": "Contact_id invalide"});
                        return Ok(Some(middleware.build_reponse(reponse)?.0))
                    }
                },
                Err(e) => Err(format!("transactions.transaction_ajouter_fichiers_collection Erreur traitement contact_id : {:?}", e))?
            };

            match verifier_acces_usager_tuuids(middleware, &contact.user_id, &transaction_collection.inclure_tuuids).await {
                Ok(inner) => {
                    if inner.len() != transaction_collection.inclure_tuuids.len() {
                        let reponse = json!({"ok": false, "err": "Acces refuse"});
                        return Ok(Some(middleware.build_reponse(reponse)?.0))
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
        middleware, uuid_transaction, &transaction_collection.cuuid, &transaction_collection.inclure_tuuids, user_id_origine.as_str(), user_id_destination, session).await {
        Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur dupliquer_structure_repertoires sur transaction : {:?}", e))?
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
async fn dupliquer_structure_repertoires<M,U,C,T,S,D>(
    middleware: &M, uuid_transaction: U, cuuid: C, tuuids: &Vec<T>, user_id: S, user_id_destination: Option<D>, session: &mut ClientSession)
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

    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_reps =
        middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions =
        middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;

    loop {
        let fichier_rep_tuuid = match tuuids_remaining.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let filtre = doc! {
            CHAMP_TUUID: &fichier_rep_tuuid.tuuid_original,
            CHAMP_USER_ID: user_id,
        };
        let mut curseur = collection_reps.find(filtre, None).await?;
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

            // Set as not deleted
            fichier_rep.supprime = false;
            fichier_rep.supprime_indirect = false;

            // Recuperer le path du cuuid destination, remplacer path_cuuids
            let path_cuuids_option = match get_path_cuuid(middleware, &fichier_rep_tuuid.cuuid_destination, session).await {
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

            // collection.insert_one_with_session(doc_repertoire, None).await?;
            let filtre = doc! {
                CHAMP_TUUID: &fichier_rep.tuuid, CHAMP_USER_ID: &user_id_destination,
                // CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false,
            };
            let mut set_ops = convertir_to_bson(&fichier_rep)?;
            // Ensure the file/directory is not deleted in the destination (allows copying from Trash)
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
            debug!("dupliquer_structure_repertoires Upsert entry: {:?}", ops);
            let options = UpdateOptions::builder().upsert(true).build();
            let result = collection_reps.update_one_with_session(filtre, ops, options, session).await?;
            if result.upserted_id.is_none() {
                info!("dupliquer_structure_repertoires Erreur, aucune valeur upserted pour tuuid {}", tuuid_src);
            }

            match type_node {
                TypeNode::Fichier => {
                    if user_id_destination != user_id {
                        // Copier les versions des fichiers vers le user_id destination
                        let filtre = doc!{CHAMP_TUUIDS: &tuuid_src};
                        let ops = doc!{"$addToSet": {"tuuids": &nouveau_tuuid}, "$currentDate": {CHAMP_MODIFICATION: true}};
                        collection_versions.update_many_with_session(filtre, ops, None, session).await?;

                        if let Some(fuuids_versions) = fichier_rep.fuuids_versions.clone() {
                            copy_media_file(middleware, session, user_id_destination, user_id, fuuids_versions).await?;
                        }
                    }
                },
                TypeNode::Collection | TypeNode::Repertoire => {
                    // Trouver les sous-repertoires, traiter individuellement
                    let filtre_ajout_cuuid = doc! {
                        format!("{}.0", CHAMP_PATH_CUUIDS): &tuuid_src,
                        "$or": [
                            {CHAMP_SUPPRIME: false},
                            {CHAMP_SUPPRIME_INDIRECT: true},  // Implies indirectly deleted. Used to copy out of Trash.
                        ],
                    };
                    debug!("dupliquer_structure_repertoires filtre_ajout_cuuid : {:?}", filtre_ajout_cuuid);
                    let mut curseur = collection_reps.find_with_session(filtre_ajout_cuuid, None, session).await?;
                    while curseur.advance(session).await? {
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
async fn recalculer_path_cuuids<M,C>(middleware: &M, cuuid: C, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao, C: ToString
{
    let cuuid = cuuid.to_string();
    let mut tuuids_remaining: Vec<String> = vec![cuuid.to_owned()];

    let collection_typed = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_FICHIERS_REP)?;

    loop {
        let tuuid = match tuuids_remaining.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let path_cuuids = {
            match get_path_cuuid(middleware, &tuuid, session).await? {
                Some(inner) => Some(inner),
                None => Some(vec![tuuid.clone()])
            }
        };

        let filtre = doc! { format!("{}.0", CHAMP_PATH_CUUIDS): &tuuid };
        let mut curseur = collection_typed.find_with_session(filtre, None, session).await?;
        while curseur.advance(session).await? {
            let row = curseur.deserialize_current()?;
            let type_node = TypeNode::try_from(row.type_node)?;

            // Mettre a jour path_cuuids
            let filtre = doc! { CHAMP_TUUID: row.tuuid };
            let ops = doc! {
                "$set": { CHAMP_PATH_CUUIDS: &path_cuuids },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };
            collection_typed.update_one_with_session(filtre, ops, None, session).await?;

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

async fn recalculer_path_cuuids_no_session<M,C>(middleware: &M, cuuid: C,)
    -> Result<(), CommonError>
    where M: MongoDao, C: ToString
{
    let cuuid = cuuid.to_string();
    let mut tuuids_remaining: Vec<String> = vec![cuuid.to_owned()];

    let collection_typed = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_FICHIERS_REP)?;

    loop {
        let tuuid = match tuuids_remaining.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let path_cuuids = {
            match get_path_cuuid_no_session(middleware, &tuuid).await? {
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
            collection_typed.update_one(filtre, ops, None).await?;

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

async fn transaction_deplacer_fichiers_collection<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_deplacer_fichiers_collection Consommer transaction : {}", transaction.transaction.id);
    let user_id = transaction.certificat.get_user_id()?;

    let transaction_collection: TransactionDeplacerFichiersCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let path_cuuids_destination = match get_path_cuuid(middleware, transaction_collection.cuuid_destination.as_str(), session).await {
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
        let resultat = match collection.update_many_with_session(filtre.clone(), ops, None, session).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur update_one sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_deplacer_fichiers_collection Resultat transaction update : {:?}", resultat);
    }

    // Recalculer les paths des sous-repertoires et fichiers
    if middleware.get_mode_regeneration() {
        // Troubleshooting rebuilding
        session.commit_transaction().await?;
        if let Err(e) = recalculer_path_cuuids_no_session(middleware, &transaction_collection.cuuid_destination).await {
            error!("transaction_deplacer_fichiers_collection Erreur recalculer_cuuids_fichiers : {:?}", e);
        }
        // Restart transaction after to get access to all data just modified
        start_transaction_regeneration(session).await?;
    } else {
        debug!("transaction_deplacer_fichiers_collection Recalculer path fuuids sous {}", transaction_collection.cuuid_destination);
        if let Err(e) = recalculer_path_cuuids(middleware, &transaction_collection.cuuid_destination, session).await {
            error!("transaction_deplacer_fichiers_collection Erreur recalculer_cuuids_fichiers : {:?}", e);
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn supprimer_versions_conditionnel<M,T,U>(middleware: &M, user_id: U, fuuids_in: &Vec<T>, session: &mut ClientSession)
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
        let mut curseur = collection.find_with_session(filtre, options, session).await?;
        if curseur.advance(session).await? {
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
        // CHAMP_USER_ID: user_id,
        CHAMP_FUUID: {"$in": fuuids_inconnus}
    };
    let ops = doc! {
        "$pullAll": { "tuuids": {} },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = UpdateOptions::builder().hint(Hint::Name("fuuid".to_string())).build();
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    collection.update_many_with_session(filtre, ops, options, session).await?;

    Ok(())
}

/// Deprecated since 2024.9
async fn _supprimer_tuuids<M,U,T>(middleware: &M, user_id_in: U, tuuids_in: Vec<T>, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao, U: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id_in.as_ref();
    let tuuids: Vec<&str> = tuuids_in.iter().map(|s| s.as_ref()).collect();

    let collection_reps =
        middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions =
        middleware.get_collection_typed::<NodeFichierVersionRow>(NOM_COLLECTION_VERSIONS)?;

    // Marquer les collections, repertoires et fichiers supprimes directement.
    {
        let filtre = doc! {
            CHAMP_TUUID: {"$in": &tuuids},
            CHAMP_USER_ID: &user_id,
        };
        debug!("grosfichiers.transaction_supprimer_documents Filtre marquer tuuids supprimes : {:?}", filtre);
        let ops = doc! {
            "$set": { CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: false },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        collection_reps.update_many_with_session(filtre, ops, None, session).await?;

        // Retrirer tous les tuuids de versions
        let filtre = doc! {"tuuids": {"$in": &tuuids}};
        let ops = doc!{"$pullAll": {"tuuids": &tuuids}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_versions.update_many_with_session(filtre, ops, None, session).await?;
    }

    // Marquer les sous-repertoires et fichiers supprimes indirectement (via arborescence)
    {
        let filtre = doc! {
            CHAMP_PATH_CUUIDS: {"$in": &tuuids},
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
        };

        let mut cursor = collection_reps.find_with_session(filtre.clone(), None, session).await?;
        let mut sub_tuuids = Vec::new();
        while cursor.advance(session).await? {
            let row = cursor.deserialize_current()?;
            sub_tuuids.push(row.tuuid);
        }

        debug!("grosfichiers.transaction_supprimer_documents Filtre marquer tuuids supprimes : {:?}", filtre);
        let ops = doc! {
            "$set": { CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: true },
            "$currentDate": { CHAMP_MODIFICATION: true },
        };
        collection_reps.update_many_with_session(filtre, ops, None, session).await?;

        // Retrirer tous les tuuids de versions
        let filtre = doc! {"tuuids": {"$in": &sub_tuuids}};
        let ops = doc!{"$pullAll": {"tuuids": sub_tuuids}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_versions.update_many_with_session(filtre, ops, None, session).await?;
    }

    Ok(())
}

/// The transaction_supprimer_documents transaction is deprecated since 2024.9. Replaced by transaction_delete_v2.
async fn transaction_supprimer_documents<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_documents Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionSupprimerDocuments = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_documents Erreur user_id absent du certificat"))?
    };

    match _supprimer_tuuids(
        middleware, &user_id, transaction_collection.tuuids, session).await {
        Ok(_) => (),
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur supprimer_tuuids : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_recuperer_documents<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    // LEGACY
    debug!("transaction_recuperer_documents Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionListeDocuments = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: false},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection_reps = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection_reps.update_many_with_session(filtre, ops, None, session).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur update_one sur transaction : {:?}", e))?
    };
    debug!("grosfichiers.transaction_recuperer_documents Resultat transaction update : {:?}", resultat);

    // Put the tuuid back in versions
    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionRow>(NOM_COLLECTION_VERSIONS)?;
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}, "type_node": TypeNode::Fichier.to_str()};
    let mut cursor = collection_reps.find_with_session(filtre.clone(), None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if let Some(fuuids) = row.fuuids_versions {
            let filtre_versions = doc! {"fuuid": {"$in": fuuids}};
            let ops = doc! {"$addToSet": {"tuuids": row.tuuid}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection_versions.update_many_with_session(filtre_versions, ops, None, session).await?;
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecupererDocumentsV2 {
    /// Items a recuperer par { cuuid: [tuuid, ...] }
    pub items: HashMap<String, Option<Vec<String>>>
}

async fn recuperer_parents<M,C,U>(middleware: &M, user_id: U, tuuid: C, session: &mut ClientSession) -> Result<(), CommonError>
    where M: MongoDao, C: AsRef<str>, U: AsRef<str>
{
    let tuuid = tuuid.as_ref();
    let filtre = doc!{ CHAMP_TUUID: tuuid, CHAMP_USER_ID: user_id.as_ref() };
    let collection = middleware.get_collection_typed::<FichierDetail>(NOM_COLLECTION_FICHIERS_REP)?;
    let repertoire = match collection.find_one_with_session(filtre, None, session).await? {
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
    collection.update_many_with_session(filtre, ops, None, session).await?;

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

async fn recuperer_tuuids<M,T,C,U>(middleware: &M, user_id: U, cuuid: C, tuuids_params: Option<Vec<T>>, session: &mut ClientSession) -> Result<(), CommonError>
    where
        M: MongoDao,
        T: AsRef<str>,
        C: AsRef<str>,
        U: AsRef<str>
{
    let user_id = user_id.as_ref();
    let tuuids: Vec<&str> = match tuuids_params.as_ref() {
        Some(inner) => inner.iter().map(|c| c.as_ref()).collect(),
        None => vec![cuuid.as_ref()]  // Recuperer une collection
    };

    debug!("recuperer_tuuids Recuperer tuuids {:?}", tuuids);
    let mut nodes_restants = Vec::new();

    // Charger liste initiale de nodes
    let collection_reps = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    {
        let filtre = doc! {
            CHAMP_TUUID: { "$in": tuuids },
            CHAMP_USER_ID: user_id
        };
        let mut curseur = collection_reps.find_with_session(filtre, None, session).await?;
        while curseur.advance(session).await? {
            let row = curseur.deserialize_current()?;
            nodes_restants.push(row);
        }
    }

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

    // Parcourir les nodes. Recuperer recursivement les Repertoires avec supprime_indirect: true.
    let mut tuuids_a_recuperer = Vec::new();
    // let mut fuuids_a_recuperer = Vec::new();
    loop {
        let node_courant = match nodes_restants.pop() {
            Some(inner) => inner,
            None => { break; }  // Termine
        };

        let type_node = TypeNode::try_from(node_courant.type_node.as_str())?;

        match type_node {
            TypeNode::Fichier => {
                if let Some(fuuids) = node_courant.fuuids_versions {
                    // fuuids_a_recuperer.extend(fuuids);
                    debug!("recuperer_tuuids Recuperer {} fuuids", fuuids.len());
                    let filtre = doc! {CHAMP_FUUID: {"$in": fuuids}};
                    let ops = doc! {
                        // "$set": { CHAMP_SUPPRIME: false },
                        "$addToSet": {"tuuids": &node_courant.tuuid},
                        "$currentDate": {CHAMP_MODIFICATION: true}
                    };
                    collection_versions.update_many_with_session(filtre, ops, None, session).await?;
                }
            },
            TypeNode::Collection | TypeNode::Repertoire => {
                // Charger la liste des nodes supprimes indirectement sous ce repertoire
                let filtre = doc! {
                    CHAMP_USER_ID: user_id,
                    "path_cuuids.0": &node_courant.tuuid,
                    CHAMP_SUPPRIME_INDIRECT: true
                };
                let mut curseur = collection_reps.find_with_session(filtre, None, session).await?;
                while curseur.advance(session).await? {
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
            "$set": {CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false },
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        collection_reps.update_many_with_session(filtre, ops, None, session).await?;
    }

    Ok(())
}

async fn transaction_recuperer_documents_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_recuperer_documents_v2 Consommer transaction : {}", transaction.transaction.id);

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_recuperer_documents_v2 Erreur user_id absent du certificat"))?
    };

    let transaction: TransactionRecupererDocumentsV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    for (cuuid, paths) in transaction.items {
        // Recuperer le cuuid (parent) jusqu'a la racine au besoin
        debug!("transaction_recuperer_documents_v2 Recuperer cuuid {} et parents", cuuid);
        if let Err(e) = recuperer_parents(middleware, &user_id, &cuuid, session).await {
            Err(format!("grosfichiers.transaction_recuperer_documents_v2 Erreur recuperer_parents : {:?}", e))?
        }

        // Reactiver les fichiers avec le cuuid courant sous cuuids_supprimes.
        debug!("transaction_recuperer_documents_v2 Recuperer tuuids {:?} sous cuuid {}", paths, cuuid);
        if let Err(e) = recuperer_tuuids(middleware, &user_id, cuuid, paths, session).await {
            Err(format!("grosfichiers.transaction_recuperer_documents_v2 Erreur recuperer_tuuids : {:?}", e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

fn obsolete() -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError> {
    // Obsolete - no effect
    Ok(None)
}

/// Fait un touch sur les fichiers_rep identifies. User_id optionnel (e.g. pour ops systeme comme visites)
pub async fn touch_fichiers_rep<M,S,V>(middleware: &M, fuuids_in: V, session: &mut ClientSession) -> Result<(), CommonError>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>,
        V: Borrow<Vec<S>>,
{
    let fuuids_in = fuuids_in.borrow();
    let fuuids: Vec<&str> = fuuids_in.iter().map(|s| s.as_ref()).collect();

    // let filtre = match user_id {
    //     Some(user_id) => {
    //         doc! {
    //             CHAMP_USER_ID: user_id.as_ref(),
    //             CHAMP_FUUIDS_VERSIONS: {"$in": fuuids},
    //         }
    //     },
    //     None => {
    //         doc! { CHAMP_FUUIDS_VERSIONS: {"$in": fuuids } }
    //     }
    // };

    let filtre = doc! { CHAMP_FUUIDS_VERSIONS: {"$in": fuuids } };

    let ops = doc! {
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    collection.update_many_with_session(filtre, ops, None, session).await?;

    Ok(())
}

async fn transaction_associer_conversions<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_associer_conversions Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionAssocierConversions = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    // let tuuid = transaction_mappee.tuuid.clone();
    // let user_id = match transaction_mappee.user_id.as_ref() {
    //     Some(inner) => Some(inner.as_str()),
    //     None => None
    // };
    let fuuid = transaction_mappee.fuuid.as_str();

    // Mapper tous les fuuids avec leur mimetype
    let fuuids_reclames = {
        let mut fuuids_reclames = Vec::new();
        for (_, image) in transaction_mappee.images.iter() {
            if image.data_chiffre.is_none() {  // Ignore content with data: no file to manage
                fuuids_reclames.push(image.hachage.to_owned());
            }
        }
        fuuids_reclames
    };

    {
        // let user_id = match user_id {
        //     Some(inner) => inner.to_string(),
        //     None => {
        //         // Find the user id
        //         let filtre_reps = match tuuid.as_ref() {
        //             // Best approach with tuuid (unique index)
        //             Some(tuuid) => doc! { CHAMP_TUUID: tuuid },
        //             // Legacy support
        //             None => {
        //                 match user_id {
        //                     Some(user_id) => doc! { "fuuids_versions": fuuid, CHAMP_USER_ID: user_id },
        //                     // Note : legacy, supporte ancienne transaction (pre 2023.6) qui n'avait pas le user_id
        //                     None => doc! { "fuuids_versions": fuuid }
        //                 }
        //             },
        //         };
        //         let collection_reps = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
        //         let mut cursor = collection_reps.find_with_session(filtre_reps, None, session).await?;
        //         if cursor.advance(session).await? {
        //             let row = cursor.deserialize_current()?;
        //             row.user_id
        //         } else {
        //             Err(format!("transaction_associer_conversions No match for fuuid {}", fuuid))?
        //         }
        //     }
        // };

        // Fetch matching user_ids for this fuuid
        let user_ids = {
            let filtre_reps = doc! {CHAMP_FUUIDS_VERSIONS: fuuid};
            let collection_reps = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
            let mut cursor = collection_reps.find_with_session(filtre_reps, None, session).await?;
            let mut user_ids = HashSet::with_capacity(20);
            if cursor.advance(session).await? {
                let row = cursor.deserialize_current()?;
                user_ids.insert(row.user_id);
            } else {
                Err(format!("transaction_associer_conversions No match for fuuid {}", fuuid))?
            }
            user_ids
        };

        for user_id in user_ids {
            // Map with the struct (acts as data validation)
            let media_row = MediaOwnedRow {
                fuuid: transaction_mappee.fuuid.clone(),
                user_id,
                creation: Utc::now(),
                derniere_modification: Utc::now(),
                // mimetype: transaction_mappee.mimetype,
                height: transaction_mappee.height,
                width: transaction_mappee.width,
                duration: transaction_mappee.duration,
                video_codec: transaction_mappee.video_codec.clone(),
                anime: transaction_mappee.anime.unwrap_or(false),
                images: None,
                video: None,
                audio: None,
                subtitles: None,
            };

            let mut set_ops = doc! {
                // "mimetype": media_row.mimetype,
                "height": media_row.height,
                "width": media_row.width,
                "duration": media_row.duration,
                "videoCodec": media_row.video_codec,
                "anime": media_row.anime,
                // "images": convertir_to_bson(transaction_mappee.images)?,
            };

            if transaction_mappee.images.len() > 0 {
                for (key, value) in &transaction_mappee.images {
                    set_ops.insert(format!("images.{}", key), convertir_to_bson(value)?);
                }
            };

            if let Some(audio) = transaction_mappee.audio.as_ref() {
                set_ops.insert("audio", convertir_to_bson_array(audio)?);
            }
            if let Some(subtitles) = transaction_mappee.subtitles.as_ref() {
                set_ops.insert("subtitles", convertir_to_bson_array(subtitles)?);
            }

            // Insert into the media table.
            let collection_media = middleware.get_collection(NOM_COLLECTION_MEDIA)?;
            let filtre_media = doc! {"fuuid": media_row.fuuid, "user_id": media_row.user_id};
            let ops = doc! {
                "$set": set_ops,
                "$setOnInsert": {CHAMP_CREATION: Utc::now()},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            collection_media.update_one_with_session(filtre_media, ops, options, session).await?;
        }

        // Update the versions table
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let ops = doc! {
            "$set": {CHAMP_FLAG_MEDIA_TRAITE: true},
            "$addToSet": {CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids_reclames}},
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let filtre_versions = doc!{"fuuid": fuuid};
        match collection.update_one_with_session(filtre_versions, ops, None, session).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_associer_video<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_associer_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionAssocierVideo = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let fuuid = transaction_mappee.fuuid.as_str();
    let fuuid_video = transaction_mappee.fuuid_video.as_str();
    let user_id = transaction_mappee.user_id.as_str();

    let video_detail = VideoDetail {
        fuuid: fuuid.to_owned(),
        fuuid_video: transaction_mappee.fuuid_video.clone(),
        taille_fichier: transaction_mappee.taille_fichier,
        mimetype: transaction_mappee.mimetype.clone(),
        codec: transaction_mappee.codec.clone(),
        cle_conversion: transaction_mappee.cle_conversion.clone(),
        width: transaction_mappee.width,
        height: transaction_mappee.height,
        bitrate: transaction_mappee.bitrate,
        quality: transaction_mappee.quality,
        audio_stream_idx: transaction_mappee.audio_stream_idx,
        subtitle_stream_idx: transaction_mappee.subtitle_stream_idx,
        header: transaction_mappee.header,
        format: transaction_mappee.format,
        nonce: transaction_mappee.nonce,
        cle_id: transaction_mappee.cle_id,
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

    let filtre = doc!{ "fuuid": fuuid, "user_id": user_id };
    let collection_media = middleware.get_collection(NOM_COLLECTION_MEDIA)?;
    let ops = doc!{
        "$set": {"anime": true, format!("video.{}", cle_video): convertir_to_bson(video_detail)?},
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection_media.update_one_with_session(filtre, ops, options, session).await?;

    // MAJ de la version du fichier
    {
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc!{"fuuid": fuuid};
        let ops = doc! {
            "$set": {CHAMP_FLAG_VIDEO_TRAITE: true},
            "$addToSet": {CHAMP_FUUIDS_RECLAMES: fuuid_video},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        if let Err(e) = collection_versions.update_one_with_session(filtre, ops, None, session).await {
            Err(format!("transactions.transaction_associer_video Erreur maj versions : {:?}", e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_decrire_fichier<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_decire_fichier Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionDecrireFichier = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = transaction.certificat.get_user_id()?;

    let tuuid = transaction_mappee.tuuid.as_str();
    let mut filtre = doc! { CHAMP_TUUID: tuuid };
    if let Some(inner) = &user_id {
        filtre.insert("user_id", inner);
    }

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

    if let Some(mimetype) = transaction_mappee.mimetype.as_ref() {
        set_ops.insert("mimetype", mimetype);

        // Update versions
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc!{"tuuids": tuuid};
        let ops = doc!{"$set": {"mimetype": mimetype}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_versions.update_many_with_session(filtre, ops, None, session).await?;
    }

    // Creer job indexation
    let ops = doc! {
        "$set": set_ops,
        "$unset": {CHAMP_FLAG_INDEX_RETRY: true, CHAMP_FLAG_INDEX_ERREUR: true},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    if let Err(e) = collection.find_one_and_update_with_session(filtre, ops, None, session).await {
        Err(format!("transaction_decire_fichier Erreur update description : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_decrire_collection<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_decrire_collection Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionDecrireCollection = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let tuuid = transaction_mappee.tuuid.as_str();
    let filtre = doc! { CHAMP_TUUID: tuuid };

    let doc_metadata = match convertir_to_bson(&transaction_mappee.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.transaction_decrire_collection Erreur conversion transaction : {:?}", e))?
    };

    let set_ops = doc! {
        "metadata": doc_metadata,
        CHAMP_FLAG_INDEX: false,
    };

    let ops = doc! {
        "$set": set_ops,
        "$unset": {CHAMP_FLAG_INDEX_RETRY: true, CHAMP_FLAG_INDEX_ERREUR: true},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    collection.update_one_with_session(filtre, ops, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
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

async fn transaction_supprimer_video<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_collection: TransactionSupprimerVideo = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let fuuid = &transaction_collection.fuuid_video;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err("transaction_supprimer_video No user_id in certificate")?
    };

    // Find the original fuuid for the video
    let filtre_versions = doc!{"fuuids_reclames": fuuid};
    let collection_versions =
        middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let file_version = match collection_versions.find_one_with_session(filtre_versions.clone(), None, session).await? {
        Some(inner) => inner,
        None => Err(format!("transaction_supprimer_video No matching file version found with fuuid {}", fuuid))?
    };
    let fuuid_original = file_version.fuuid.as_str();

    // Load media information for original fuuid/user_id
    let filtre_media = doc!{CHAMP_FUUID: fuuid_original, CHAMP_USER_ID: &user_id};
    let collection_media = middleware.get_collection_typed::<MediaOwnedRow>(NOM_COLLECTION_MEDIA)?;
    let doc_video = match collection_media.find_one_with_session(filtre_media.clone(), None, session).await {
        Ok(d) => match d {
            Some(d) => d,
            None => Err(format!("transaction_supprimer_video No document match on user_id:{}/fuuid:{}", user_id, fuuid))?
        },
        Err(e) => Err(format!("transaction_supprimer_video Erreur chargement info document : {:?}", e))?
    };

    // Find video label matching video fuuid to remove
    let mut ops_unset_video = doc!{};
    if let Some(map_video) = doc_video.video.as_ref() {
        for (label, video) in map_video {
            if &video.fuuid_video == fuuid {
                ops_unset_video.insert(format!("video.{}", label), true);
            }
        }
    }

    // Ensure there is a video with that fuuid
    if ops_unset_video.len() == 0 {
        return Ok(None)  // Nothing to do
    }

    // Remove video with matching fuuid
    let ops_media = doc!{"$unset": ops_unset_video, "$currentDate": {CHAMP_MODIFICATION: true}};
    collection_media.update_one_with_session(filtre_media, ops_media, None, session).await?;

    // Cleanup file version (claimed fuuids)
    {
        let ops = doc! {
            "$pull": {CHAMP_FUUIDS_RECLAMES: fuuid},
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let collection_version_fichier = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

        debug!("transaction_supprimer_video Supprimer video {:?} ops {:?}", filtre_versions, ops);
        match collection_version_fichier.update_one_with_session(filtre_versions, ops, None, session).await {
            Ok(_r) => (),
            Err(e) => Err(format!("transaction_supprimer_video Erreur update_one collection fichiers rep : {:?}", e))?
        }
    }

    if let Err(e) = touch_fichiers_rep(middleware, vec![fuuid], session).await {
        error!("transaction_favoris_creerpath Erreur touch_fichiers_rep {:?}/{:?} : {:?}", user_id, fuuid, e);
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(_) => Err(CommonError::Str("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}

async fn transaction_supprimer_job_image_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                            -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_job_image Consommer transaction : {}", transaction.transaction.id);
    let transaction_supprimer_job: TransactionSupprimerJobImageV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let fuuid = &transaction_supprimer_job.fuuid;
    // let tuuid = &transaction_supprimer_job.tuuid;

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = set_flag_image_traitee(middleware, fuuid, session).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag image : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(_) => Err(CommonError::Str("transactions.transaction_supprimer_job_image Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerJobVideoV2 {
    pub tuuid: String,
    pub fuuid: String,
    pub job_id: String,
}

async fn transaction_supprimer_job_video_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                            -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_job_video Consommer transaction : {}", transaction.transaction.id);
    let transaction_supprimer: TransactionSupprimerJobVideoV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let job_id = &transaction_supprimer.job_id;
    let fuuid = &transaction_supprimer.fuuid;
    let tuuid = &transaction_supprimer.tuuid;

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = set_flag_video_traite(middleware, Some(tuuid), fuuid, Some(job_id.as_str()), session).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag video : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(_) => Err(CommonError::Str("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterContactLocal {
    /// Usager du carnet
    pub user_id: String,
    /// Contact local ajoute
    pub contact_user_id: String,
}

async fn transaction_ajouter_contact_local<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_ajouter_contact_local Consommer transaction : {}", transaction.transaction.id);
    let uuid_transaction = transaction.transaction.id.clone();

    let transaction_mappee: TransactionAjouterContactLocal = serde_json::from_str(transaction.transaction.contenu.as_str())?;

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
    if let Err(e) = collection.update_one_with_session(filtre, ops, options, session).await {
        Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur sauvegarde contact : {:?}", e))?
    }

    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(_) => Err(CommonError::Str("grosfichiers.transaction_ajouter_contact_local Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerContacts {
    pub contact_ids: Vec<String>,
}

async fn transaction_supprimer_contacts<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_contacts Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_contacts Erreur user_id absent du certificat"))?
    };

    let transaction_mappee: TransactionSupprimerContacts = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_CONTACT_ID: {"$in": transaction_mappee.contact_ids},
    };
    let collection_contacts = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    if let Err(e) = collection_contacts.delete_many_with_session(filtre.clone(), None, session).await {
        Err(format!("grosfichiers.transaction_supprimer_contacts Erreur suppression contacts : {:?}", e))?
    }

    // Remove all shared collections associated to deleted contacts
    let collection_shared_collections = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    if let Err(e) = collection_shared_collections.delete_many_with_session(filtre, None, session).await {
        Err(format!("grosfichiers.transaction_supprimer_contacts Erreur suppression contacts : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok(None, None) {
        Ok(r) => Ok(Some(r)),
        Err(_) => Err(CommonError::Str("grosfichiers.transaction_supprimer_contacts Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPartagerCollections {
    pub cuuids: Vec<String>,
    pub contact_ids: Vec<String>,
}

async fn transaction_partager_collections<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_partager_collections Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_partager_collections Erreur user_id absent du certificat"))?
    };

    let transaction_mappee: TransactionPartagerCollections = serde_json::from_str(transaction.transaction.contenu.as_str())?;

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
            if let Err(e) = collection.update_one_with_session(filtre, ops, options, session).await {
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

async fn transaction_supprimer_partage_usager<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_partage_usager Consommer transaction : {}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("grosfichiers.transaction_supprimer_partage_usager Erreur user_id absent du certificat"))?
    };

    let transaction_mappee: TransactionSupprimerPartageUsager = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_CONTACT_ID: transaction_mappee.contact_id,
        CHAMP_TUUID: transaction_mappee.tuuid,
    };
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    if let Err(e) = collection.delete_one_with_session(filtre, None, session).await {
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

async fn transaction_supprimer_orphelins<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_partage_usager Consommer transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionSupprimerOrphelins = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    match traiter_transaction_supprimer_orphelins(middleware, transaction_mappee, session).await {
        Ok(inner) => Ok(inner),
        Err(e) => Err(format!("transaction_supprimer_orphelins Erreur traitement {:?}", e))?
    }
}

async fn traiter_transaction_supprimer_orphelins<M>(middleware: &M, transaction: TransactionSupprimerOrphelins, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: GenerateurMessages + MongoDao
{
    let collection_reps = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection_media = middleware.get_collection(NOM_COLLECTION_MEDIA)?;

    // Delete all matching media
    let filtre_versions = doc!{"fuuid": {"$in": &transaction.fuuids}};
    collection_media.delete_many_with_session(filtre_versions, None, session).await?;

    // Delete all matching versions
    let filtre_versions = doc!{"fuuid": {"$in": &transaction.fuuids}};
    collection_versions.delete_many_with_session(filtre_versions, None, session).await?;

    // Remove versions from all filereps
    let filtre_reps = doc!{"fuuids_versions": {"$in": &transaction.fuuids}};
    let ops_reps = doc! {
        "$pullAll": {"fuuids_versions": &transaction.fuuids},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection_reps.update_many_with_session(filtre_reps, ops_reps, None, session).await?;

    // Final cleanup for all filereps that are deleted and with no fileversions left.
    let filtre_delete_reps = doc!{"supprime": true, "fuuids_versions.0": {"exists": false}, "type_node": TypeNode::Fichier.to_str()};
    collection_reps.delete_many_with_session(filtre_delete_reps, None, session).await?;

    if middleware.get_mode_regeneration() {
        session.commit_transaction().await?;
        start_transaction_regeneration(session).await?;
    }

    let reponse = ReponseSupprimerOrphelins { ok: true, err: None, fuuids_a_conserver: vec![] };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Serialize, Deserialize)]
pub struct TransactionDeleteV2 {
    pub command: MessageMilleGrillesOwned,
    pub directories: Option<Vec<String>>,
    pub subdirectories: Option<Vec<String>>,
    pub files: Option<Vec<String>>,
    pub user_id: Option<String>,
}

async fn transaction_delete_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_delete_v2 Consume transaction : {}", transaction.transaction.id);
    let transaction_content: TransactionDeleteV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection_fichiersrep =
        middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_fichiersversion =
        middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;

    // Handle subdirectories first
    if let Some(subdirectories) = transaction_content.subdirectories {
        debug!("transaction_delete_v2 Delete subdirectories: {:?}", subdirectories);
        delete_file_versions_from_directories(middleware, session, &subdirectories).await?;

        // Mark all the files as indirectly deleted in the rep collection
        let filtre_rep = doc! { "path_cuuids.0": {"$in": &subdirectories}, "supprime": false, "type_node": TypeNode::Fichier.to_str() };
        let ops = doc!{"$set": {"supprime": true, "supprime_indirect": true}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_fichiersrep.update_many_with_session(filtre_rep, ops, None, session).await?;

        // Mark all listed subdirectories as deleted indirectly.
        let directory_filtre = doc!{ "tuuid": {"$in": subdirectories} };
        let directory_ops = doc!{"$set": {"supprime": true, "supprime_indirect": true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection_fichiersrep.update_many_with_session(directory_filtre, directory_ops, None, session).await?;
    }

    // Directories being directly targeted by the delete command
    if let Some(directories) = transaction_content.directories {
        debug!("transaction_delete_v2 Delete directories: {:?}", directories);
        delete_file_versions_from_directories(middleware, session, &directories).await?;

        // Mark all the files as indirectly deleted in the rep collection
        let filtre_rep = doc! { "path_cuuids.0": {"$in": &directories}, "supprime": false, "type_node": TypeNode::Fichier.to_str() };
        let ops = doc!{"$set": {"supprime": true, "supprime_indirect": true}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_fichiersrep.update_many_with_session(filtre_rep, ops, None, session).await?;

        // Mark all listed directories as deleted directly.
        let directory_filtre = doc!{ "tuuid": {"$in": directories} };
        let directory_ops = doc!{"$set": {"supprime": true, "supprime_indirect": false}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection_fichiersrep.update_many_with_session(directory_filtre, directory_ops, None, session).await?;
    }

    if let Some(files) = transaction_content.files {
        debug!("transaction_delete_v2 Delete files: {:?}", files);
        // Mark all listed files as deleted.

        let version_filtre = doc!{ "tuuids": {"$in": &files} };
        let version_ops = doc!{"$pullAll": {"tuuids": &files}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection_fichiersversion.update_many_with_session(version_filtre.clone(), version_ops, None, session).await?;

        let file_filtre = doc!{ "tuuid": {"$in": &files} };
        let rep_ops = doc!{"$set": {"supprime": true, "supprime_indirect": false}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection_fichiersrep.update_many_with_session(file_filtre, rep_ops, None, session).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn delete_file_versions_from_directories<M>(middleware: &M, session: &mut ClientSession, subdirectories: &Vec<String>)
    -> Result<(), CommonError>
    where M: MongoDao
{
    // Iterate through all directories in fichiers rep to find matching files. The recursive
    // work of finding subdirectories has already been done in the command.

    let collection_fichiersrep =
        middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_fichiersversion =
        middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;

    for cuuid in subdirectories {
        // List all files directly under the cuuid (and not already deleted)
        let filtre_files = doc! {
            "path_cuuids.0": cuuid,
            "supprime": false,
            "type_node": TypeNode::Fichier.to_str()
        };
        let mut cursor = collection_fichiersrep.find_with_session(filtre_files.clone(), None, session).await?;
        let mut file_tuuids = Vec::new();
        while cursor.advance(session).await? {
            let row = cursor.deserialize_current()?;
            file_tuuids.push(row.tuuid.to_owned());
        }

        // Mark all files in the version collection as deleted
        let filtre_tuuids = doc! {"tuuids": {"$in": &file_tuuids}};
        let version_ops = doc!{"$pullAll": {"tuuids": file_tuuids}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection_fichiersversion.update_many_with_session(filtre_tuuids, version_ops, None, session).await?;
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct TransactionMoveV2Directory {
    /// Reverse hierarchy of destination (cuuids)
    pub path: Vec<String>,
    /// List of individual cuuids to move
    pub directories: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionMoveV2 {
    pub command: MessageMilleGrillesOwned,
    pub destination: Vec<String>,
    pub directories: Option<Vec<TransactionMoveV2Directory>>,
    pub files: Option<Vec<String>>,
    pub user_id: Option<String>,
}

async fn transaction_move_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let transaction_content: TransactionMoveV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection_reps = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    if let Some(files) = transaction_content.files {
        let filtre = doc!{ "tuuid": {"$in": files}, "type_node": TypeNode::Fichier.to_str() };
        let ops = doc! {
            "$set": {"path_cuuids": &transaction_content.destination},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        collection_reps.update_many_with_session(filtre, ops, None, session).await?;
    }

    if let Some(directories) = transaction_content.directories {
        for move_command in directories {
            // Move everything directly under the directories (including deleted files/subdirectory)
            for directory in move_command.directories {
                // Move the directory itself
                let filtre = doc! { "tuuid": &directory };
                // Change type_node to Repertoire if it is Collection. It is possible to move a top-level Collection under another.
                let ops = doc! {
                    "$set": {"path_cuuids": &move_command.path, "type_node": TypeNode::Repertoire.to_str()},
                    "$currentDate": {CHAMP_MODIFICATION: true}
                };
                collection_reps.update_one_with_session(filtre, ops, None, session).await?;

                // Move files under directory
                let mut new_path = vec![&directory];
                new_path.extend(&move_command.path);
                let filtre = doc! { "path_cuuids.0": &directory, "type_node": TypeNode::Fichier.to_str() };
                let ops = doc! {
                    "$set": {"path_cuuids": new_path},
                    "$currentDate": {CHAMP_MODIFICATION: true}
                };
                collection_reps.update_many_with_session(filtre, ops, None, session).await?;
            }
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Serialize, Deserialize)]
pub struct TransactionCopyV2 {
    pub command: MessageMilleGrillesOwned,
    pub destination: Vec<String>,
    pub directories: Option<Vec<TransactionMoveV2Directory>>,
    pub files: Option<Vec<String>>,
    pub user_id: String,
    pub include_deleted: Option<bool>,
    // pub source_user_id: Option<String>,
}

fn digest_new_tuuid(transaction_id_bytes: &Vec<u8>, old_tuuid: &str) -> String {
    let mut bytes_to_hash = old_tuuid.as_bytes().to_vec();
    bytes_to_hash.extend(transaction_id_bytes);
    let digest_value = hacher_bytes_vu8(&bytes_to_hash[..], Some(Code::Blake2s256));
    hex::encode(digest_value)
}

async fn transaction_copy_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let transaction_content: TransactionCopyV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let user_id = &transaction_content.user_id;
    let include_deleted = transaction_content.include_deleted.unwrap_or(false);

    let collection_reps =
        middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;

    let transaction_id = &transaction.transaction.id;
    let transaction_id_bytes = hex::decode(transaction_id)?;

    if let Some(files) = transaction_content.files {
        let destination: Vec<&str> = transaction_content.destination.iter().map(|s| s.as_str()).collect();
        let filtre = doc!{"tuuid": {"$in": &files}};
        let cursor_reps = collection_reps.find_with_session(filtre.clone(), None, session).await?;
        copy_files_to_directory(middleware, session, user_id.as_str(), cursor_reps, &destination, &transaction_id_bytes).await?;
    }

    if let Some(directories) = transaction_content.directories {
        // Prepare a mapping for all the new directory tuuids - will be used to adjust the new path_cuuids.
        let mut new_cuuid_map = HashMap::new();
        for copy_directories in &directories {
            for directory in &copy_directories.directories {
                let new_directory_tuuid = digest_new_tuuid(&transaction_id_bytes, directory.as_str());
                new_cuuid_map.insert(directory, new_directory_tuuid);
            }
        }

        // Copy files and directories
        for copy_directories in &directories {
            for directory in &copy_directories.directories {
                let mut destination: Vec<&str> = copy_directories.path.iter()
                    .map(|s| {
                        match new_cuuid_map.get(s) {
                            Some(inner) => inner.as_str(),  // New cuuid
                            None => s.as_str()  // Keep old cuuid (part of destination parent hierarchy)
                        }
                    })
                    .collect();
                // Copy the directory entry
                let filtre = doc!{"tuuid": &directory};
                let mut cursor_reps = collection_reps.find_with_session(filtre.clone(), None, session).await?;
                let new_tuuid = new_cuuid_map.get(&directory).expect("get new tuuid");
                if cursor_reps.advance(session).await? {
                    let mut row = cursor_reps.deserialize_current()?;
                    row.tuuid = new_tuuid.clone();
                    row.user_id = user_id.clone();  // In case this is a copy from shared collections
                    row.path_cuuids = Some(destination.clone());
                    row.type_node = TypeNode::Repertoire.to_str();  // It is possible to copy a Collection to another one
                    row.flag_index = false;  // Need to index new path
                    row.date_creation = Utc::now();
                    row.derniere_modification = row.date_creation.clone();

                    // Remove deleted flags if present. Allows copying out of Trash.
                    row.supprime = false;
                    row.supprime_indirect = false;

                    // Insert the directory with the updated identifiers
                    debug!("transaction_copy_v2 Copy (directories) tuuid {} to {}", directory, row.tuuid);
                    collection_reps.insert_one_with_session(row, None, session).await?;
                } else {
                    error!("transaction_copy_v2 Directory {} not found during copy, skipping", directory);
                    continue
                }

                // Copy all files
                destination.insert(0, new_tuuid.as_str());  // Prepend parent directory for files
                let mut filtre = doc!{
                    "path_cuuids.0": &directory,
                    "type_node": TypeNode::Fichier.to_str(),
                };
                if include_deleted {
                    // Include files that have been indirectly deleted (deleted with the directory)
                    filtre.insert("$or", vec![
                        doc!{CHAMP_SUPPRIME: false},
                        doc!{CHAMP_SUPPRIME_INDIRECT: true},
                    ]);
                } else {
                    // Exclude all deleted files
                    filtre.insert("supprime", false);
                }
                let cursor_reps = collection_reps.find_with_session(filtre.clone(), None, session).await?;
                copy_files_to_directory(middleware, session, user_id.as_str(), cursor_reps, &destination, &transaction_id_bytes).await?;
            }
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn copy_files_to_directory<'a, M>(
    middleware: &M, session: &mut ClientSession, user_id: &str, mut cursor_reps: SessionCursor<NodeFichierRepRow<'a>>,
    destination: &Vec<&str>, transaction_id_bytes: &Vec<u8>) -> Result<(), CommonError>
    where M: MongoDao
{
    let collection_reps =
        middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions =
        middleware.get_collection_typed::<NodeFichierVersionRow>(NOM_COLLECTION_VERSIONS)?;

    let now = Utc::now();

    while cursor_reps.advance(session).await? {
        let mut row = cursor_reps.deserialize_current()?;
        let original_user_id = row.user_id.clone();
        let change_user = original_user_id.as_str() != user_id;

        #[cfg(debug_assertions)]
        let old_tuuid = row.tuuid.clone();

        // Update path_cuuids and identifier. Then re-insert.
        // Hash the old tuuid and the current transaction id with blake2s to get a new unique tuuid.
        let new_tuuid = digest_new_tuuid(transaction_id_bytes, row.tuuid.as_str());
        row.tuuid = new_tuuid.clone();
        row.user_id = user_id.to_string();  // We may be copying from shared collections
        row.path_cuuids = Some(destination.clone());
        row.flag_index = false;  // Need to index new path
        row.date_creation = now.clone();
        row.derniere_modification = now.clone();

        // Remove deleted flags. Allows copying out of the Trash area.
        row.supprime = false;
        row.supprime_indirect = false;

        let fuuids_versions = row.fuuids_versions.clone();

        // Insert the row with the updated identifiers
        #[cfg(debug_assertions)]
        debug!("transaction_copy_v2 Copy (files-1) tuuid {} to {}", old_tuuid, row.tuuid);
        collection_reps.insert_one_with_session(row, None, session).await?;

        // Add tuuid to versions
        if let Some(fuuids_versions) = fuuids_versions {
            let filtre_versions = doc! {"fuuid": {"$in": &fuuids_versions}};
            let ops = doc! {"$addToSet": {"tuuids": &new_tuuid}, "$currentDate": {CHAMP_MODIFICATION: true}};
            debug!("transaction_copy_v2 Filtre {:?}, ops: {:?}", filtre_versions, ops);
            collection_versions.update_many_with_session(filtre_versions, ops, None, session).await?;

            if change_user {
                copy_media_file(middleware, session, user_id, original_user_id, fuuids_versions).await?;
            }
        }
    }

    Ok(())
}

async fn copy_media_file<M,S,T>(middleware: &M, session: &mut ClientSession, user_id: S, original_user_id: T, fuuids_versions: Vec<&str>)
    -> Result<(), CommonError>
    where M: MongoDao, S: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id.as_ref();
    let original_user_id = original_user_id.as_ref();

    debug!("copy_media_file fuuids_versions: {:?}, user_id: {:?}", fuuids_versions, user_id);
    let collection_media = middleware.get_collection_typed::<MediaOwnedRow>(NOM_COLLECTION_MEDIA)?;

    let filtre_media = doc! {"fuuid": {"$in": &fuuids_versions}, "user_id": original_user_id};
    let mut cursor = collection_media.find_with_session(filtre_media, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        let filtre = doc! {"fuuid": &row.fuuid, "user_id": user_id};

        let mut set_on_insert = doc! {
            CHAMP_CREATION: Utc::now(),
            // "mimetype": row.mimetype,
            "height": row.height,
            "width": row.width,
            "duration": row.duration,
            "videoCodec": row.video_codec,
            "anime": row.anime,
        };
        if let Some(images) = row.images {
            set_on_insert.insert("images", convertir_to_bson(images)?);
        }
        if let Some(audio) = row.audio {
            set_on_insert.insert("audio", convertir_to_bson_array(audio)?);
        }
        if let Some(subtitles) = row.subtitles {
            set_on_insert.insert("subtitles", convertir_to_bson_array(subtitles)?);
        }

        let mut ops = doc! {
            "$setOnInsert": set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        // Copy videos individually to merge to merge the entries.
        if let Some(video) = row.video {
            let mut set_ops = doc! {};
            for (key, value) in video {
                set_ops.insert(format!("video.{}", key), convertir_to_bson(value)?);
            }
            if !set_ops.is_empty() {
                ops.insert("$set", set_ops);
            }
        }
        debug!("copy_media_file ops {:?}", ops);
        let options = UpdateOptions::builder().upsert(true).build();
        collection_media.update_one_with_session(filtre, ops, options, session).await?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct TransactionRecycleItemsV3 {
    /// Original command
    pub command: MessageMilleGrillesOwned,

    /// User Id
    pub user_id: String,

    /// Files to restore.
    pub file_tuuids: Vec<String>,

    /// Directories to restore.
    /// All files with supprime_indirect == true in those directories will be restored.
    pub directory_tuuids: Vec<String>
}


async fn transaction_recycle_items_v3<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_recuperer_documents_v2 Consommer transaction : {}", transaction.transaction.id);

    let transaction: TransactionRecycleItemsV3 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = transaction.user_id;

    let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;

    if transaction.file_tuuids.len() > 0 {
        recycle_files(middleware, session, user_id.as_str(), &transaction.file_tuuids).await?;
    }

    if transaction.directory_tuuids.len() > 0 {
        // Recover directories
        let filtre_directory = doc!{CHAMP_TUUID: {"$in": &transaction.directory_tuuids}, CHAMP_USER_ID: &user_id};
        let ops = doc!{
            "$set": {CHAMP_SUPPRIME: false, CHAMP_SUPPRIME_INDIRECT: false},
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        collection.update_many_with_session(filtre_directory, ops, None, session).await?;

        // Recover files directly under each directory (indirectly deleted)
        let filtre_files = doc!{
            format!("{}.0", CHAMP_PATH_CUUIDS): {"$in": &transaction.directory_tuuids},
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: true,
            CHAMP_SUPPRIME_INDIRECT: true,
        };
        let mut cursor = collection.find(filtre_files, None).await?;
        let mut file_tuuids = Vec::new();
        while cursor.advance().await? {
            let mut row = cursor.deserialize_current()?;
            file_tuuids.push(row.tuuid.to_string());
        }

        // Process files in batches
        for file_batch in file_tuuids.chunks(100) {
            recycle_files(middleware, session, user_id.as_str(), file_batch).await?;
        }
    }

    Ok(None)
}

async fn recycle_files<M>(middleware: &M, session: &mut ClientSession, user_id: &str, files: &[String]) -> Result<(), CommonError>
    where M: MongoDao
{
    let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

    // Rebuild the link from version to file.
    let filtre_filerep = doc!{CHAMP_TUUID: {"$in": files}, CHAMP_USER_ID: &user_id};
    let mut cursor = collection.find_with_session(filtre_filerep.clone(), None, session).await?;
    while cursor.advance(session).await? {
        let mut row = cursor.deserialize_current()?;
        if let Some(fuuids) = row.fuuids_versions {
            let filtre = doc! {
                CHAMP_FUUID: {"$in": fuuids},
            };
            let ops = doc!{
                "$addToSet": {CHAMP_TUUIDS: row.tuuid},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            collection_versions.update_many_with_session(filtre, ops, None, session).await?;
        }
    }

    // Mark all files as no longer deleted.
    let ops = doc! {
        "$set": {
            CHAMP_SUPPRIME: false,
            CHAMP_SUPPRIME_INDIRECT: false
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_many_with_session(filtre_filerep, ops, None, session).await?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PermanentlyDeleteFilesTransaction {
    pub tuuids: Vec<String>,
    pub fuuids: Option<Vec<String>>,
}

async fn transaction_permanently_delete_files<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_permanently_delete_files Run transaction id:{}", transaction.transaction.id);
    if ! transaction.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Err(format!("transaction_permanently_delete_files Transaction id:{} unauthorized, not L3Protege", transaction.transaction.id))?;
    } else if ! transaction.certificat.verifier_domaines(vec![DOMAINE_NOM_GROSFICHIERS.to_string()])? {
        Err(format!("transaction_permanently_delete_files Transaction id:{} unauthorized, not from domain GrosFichiers", transaction.transaction.id))?;
    }

    let content: PermanentlyDeleteFilesTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    // Delete from fichierrep
    let filtre_tuuids = doc!{"tuuid": {"$in": content.tuuids}};
    let collection_fichiersrep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    collection_fichiersrep.delete_many_with_session(filtre_tuuids, None, session).await?;

    if let Some(fuuids) = content.fuuids {
        let filtre_fuuids = doc! {"fuuid": {"$in": fuuids}};

        // Delete from the media collection
        let collection_media = middleware.get_collection(NOM_COLLECTION_MEDIA)?;
        collection_media.delete_many_with_session(filtre_fuuids.clone(), None, session).await?;

        // Delete from the versions collection
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        collection_versions.delete_many_with_session(filtre_fuuids, None, session).await?;
    }

    Ok(None)
}

async fn transaction_update_file_text_content<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                                 -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_update_file_text_content Transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionUpdateFileTextContent = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("transaction_update_file_text_content Missing user_id from certificate for id:{}", transaction.transaction.id))?
    };

    let tuuid = transaction_mappee.tuuid.as_str();

    // Modifier metadata
    if let Some(inner) = transaction_mappee.file_language {
        todo!("Put in versions");
        // set_ops.insert("language", inner);
    }

    if let Some(inner) = transaction_mappee.tags {
        todo!("Where do they go?")
        // let inner_bson = match bson::to_bson(&inner) {
        //     Ok(inner) => inner,
        //     Err(e) => Err(format!("transaction_update_file_text_content Error converting file_language to bson : {:?}", e))?
        // };
        // set_ops.insert("tags", inner_bson);
    }

    if let Some(comment) = transaction_mappee.comment {
        let collection_comments = middleware.get_collection_typed::<FileComment>(NOM_COLLECTION_FILE_COMMENTS)?;
        match transaction_mappee.comment_id {
            Some(comment_id) => {
                // Update
                todo!("Update comment");
            }
            None => {
                // Insert
                let comment_entry = FileComment {
                    tuuid: tuuid.to_string(),
                    comment_id: transaction.transaction.id.clone(),
                    encrypted_data: comment,
                    date: transaction.transaction.estampille,
                    user_id: Some(user_id),
                };
                collection_comments.insert_one(comment_entry, None).await?;
            }
        }
    }

    // let mut push_to_array_ops = doc!{};
    //
    // if let Some(comment) = transaction_mappee.comment {
    //     let comment_entry = FileComment {
    //         encrypted_data: comment,
    //         date: transaction.transaction.estampille,
    //         user_id: Some(user_id),
    //     };
    //     let comment_bson = match bson::to_bson(&comment_entry) {
    //         Ok(inner) => inner,
    //         Err(e) => Err(format!("transaction_update_file_text_content Error converting comment to bson : {:?}", e))?
    //     };
    //     match transaction_mappee.comment_idx {
    //         Some(idx) => {
    //             set_ops.insert(format!("comments.{}", idx), comment_bson);
    //         }
    //         None => {
    //             push_to_array_ops.insert("comments".to_string(), comment_bson);
    //         }
    //     }
    // }
    //
    // let mut ops = doc! {
    //     "$set": set_ops,
    //     "$currentDate": { CHAMP_MODIFICATION: true }
    // };
    // if push_to_array_ops.len() > 0 {
    //     ops.insert("$push", push_to_array_ops);
    // }
    //
    // let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    // if let Err(e) = collection.find_one_and_update_with_session(filtre, ops, None, session).await {
    //     Err(format!("transaction_update_file_text_content Erreur update description : {:?}", e))?
    // }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_set_file_summary<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                         -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_update_file_text_content Transaction : {}", transaction.transaction.id);
    let transaction_mappee: TransactionFileSummary = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let fuuid = transaction_mappee.fuuid.as_str();

    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;

    // Modify version
    if let Some(inner) = transaction_mappee.file_language {
        let filtre = doc!{"fuuid": fuuid};
        let ops = doc!{"$set": {"language": inner}, "$currentDate": {CHAMP_MODIFICATION: true}};
        collection_versions.update_one(filtre, ops, None).await?;
    }

    if let Some(comment) = transaction_mappee.comment {
        let tuuids = match transaction_mappee.tuuids {
            Some(tuuids) => tuuids,
            None => {
                // Apply to all tuuids that match the file
                let filtre = doc!{"fuuid": fuuid};
                let mut cursor = collection_versions.find_with_session(filtre, None, session).await?;
                let mut tuuids = Vec::new();
                while cursor.advance(session).await? {
                    let row = cursor.deserialize_current()?;
                    tuuids.extend(row.tuuids);
                }
                tuuids
            }
        };

        let collection_comments = middleware.get_collection_typed::<FileComment>(NOM_COLLECTION_FILE_COMMENTS)?;
        // Insert
        let tag_options = UpdateOptions::builder().upsert(true).build();
        for tuuid in tuuids {
            let comment_entry = FileComment {
                tuuid: tuuid.to_string(),
                comment_id: transaction.transaction.id.clone(),
                encrypted_data: comment.clone(),
                date: transaction.transaction.estampille,
                user_id: None,
            };
            collection_comments.insert_one_with_session(comment_entry, None, session).await?;

            // Insert tags when appropriate
            if let Some(tags) = &transaction_mappee.tags {
                let filtre = doc!{"tuuid": &tuuid, "comment_id": CONST_COMMENT_TAGS};
                let ops = doc!{
                    "$set": {
                        "date": transaction.transaction.estampille,
                        "encrypted_data": convertir_to_bson(tags)?,
                    }
                };
                collection_comments.update_one_with_session(filtre, ops, tag_options.clone(), session).await?;
            }
        }
    }

    let filtre = doc!{"fuuid": fuuid};
    let ops = doc!{
        "$set": {CHAMP_FLAG_SUMMARY: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection_versions.update_one(filtre, ops, None).await?;

    Ok(None)
}
