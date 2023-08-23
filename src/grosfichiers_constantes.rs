use std::collections::HashMap;
use millegrilles_common_rust::bson::{Bson, DateTime, Document};
use millegrilles_common_rust::chiffrage_cle::InformationCle;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use crate::requetes::mapper_fichier_db;

pub const DOMAINE_NOM: &str = "GrosFichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "GrosFichiers";
pub const NOM_COLLECTION_FICHIERS_REP: &str = "GrosFichiers/fichiersRep";
pub const NOM_COLLECTION_VERSIONS: &str = "GrosFichiers/versionsFichiers";
pub const NOM_COLLECTION_DOCUMENTS: &str = "GrosFichiers/documents";
pub const NOM_COLLECTION_IMAGES_JOBS: &str = "GrosFichiers/jobs/images";
pub const NOM_COLLECTION_VIDEO_JOBS: &str = "GrosFichiers/jobs/video";
pub const NOM_COLLECTION_INDEXATION_JOBS: &str = "GrosFichiers/jobs/indexation";
pub const NOM_COLLECTION_PARTAGE_CONTACT: &str = "GrosFichiers/partage/contacts";
pub const NOM_COLLECTION_PARTAGE_COLLECTIONS: &str = "GrosFichiers/partage/collections";

pub const DOMAINE_FICHIERS_NOM: &str = "fichiers";
pub const DOMAINE_MEDIA_NOM: &str = "media";

pub const NOM_Q_TRANSACTIONS: &str = "GrosFichiers/transactions";
pub const NOM_Q_VOLATILS: &str = "GrosFichiers/volatils";
pub const NOM_Q_TRIGGERS: &str = "GrosFichiers/triggers";

pub const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";
pub const REQUETE_FAVORIS: &str = "favoris";
pub const REQUETE_DOCUMENTS_PAR_TUUID: &str = "documentsParTuuid";
pub const REQUETE_DOCUMENTS_PAR_FUUID: &str = "documentsParFuuid";
pub const REQUETE_CONTENU_COLLECTION: &str = "contenuCollection";
pub const REQUETE_GET_CORBEILLE: &str = "getCorbeille";
pub const REQUETE_GET_CLES_FICHIERS: &str = "getClesFichiers";
pub const REQUETE_GET_CLES_STREAM: &str = "getClesStream";
pub const REQUETE_CONFIRMER_ETAT_FUUIDS: &str = "confirmerEtatFuuids";
pub const REQUETE_VERIFIER_ACCES_FUUIDS: &str = "verifierAccesFuuids";
pub const REQUETE_SYNC_COLLECTION: &str = "syncCollection";
pub const REQUETE_SYNC_RECENTS: &str = "syncRecents";
pub const REQUETE_SYNC_CORBEILLE: &str = "syncCorbeille";
pub const REQUETE_SYNC_CUUIDS: &str = "syncCuuids";
pub const REQUETE_JOBS_VIDEO: &str = "requeteJobsVideo";
pub const REQUETE_CHARGER_CONTACTS: &str = "chargerContacts";
pub const REQUETE_PARTAGES_USAGER: &str = "getPartagesUsager";
pub const REQUETE_PARTAGES_CONTACT: &str = "getPartagesContact";
pub const REQUETE_INFO_STATISTIQUES: &str = "getInfoStatistiques";
pub const REQUETE_STRUCTURE_REPERTOIRE: &str = "getStructureRepertoire";

pub const TRANSACTION_NOUVELLE_VERSION: &str = "nouvelleVersion";
pub const TRANSACTION_NOUVELLE_COLLECTION: &str = "nouvelleCollection";
pub const TRANSACTION_AJOUTER_FICHIERS_COLLECTION: &str = "ajouterFichiersCollection";
pub const TRANSACTION_DEPLACER_FICHIERS_COLLECTION: &str = "deplacerFichiersCollection";
// pub const TRANSACTION_RETIRER_DOCUMENTS_COLLECTION: &str = "retirerDocumentsCollection";
pub const TRANSACTION_SUPPRIMER_DOCUMENTS: &str = "supprimerDocuments";
pub const TRANSACTION_RECUPERER_DOCUMENTS: &str = "recupererDocuments";
pub const TRANSACTION_RECUPERER_DOCUMENTS_V2: &str = "recupererDocumentsV2";
pub const TRANSACTION_ARCHIVER_DOCUMENTS: &str = "archiverDocuments";
// pub const TRANSACTION_CHANGER_FAVORIS: &str = "changerFavoris";
pub const TRANSACTION_ASSOCIER_CONVERSIONS: &str = "associerConversions";
pub const TRANSACTION_ASSOCIER_VIDEO: &str = "associerVideo";
pub const TRANSACTION_DECRIRE_FICHIER: &str = "decrireFichier";
pub const TRANSACTION_DECRIRE_COLLECTION: &str = "decrireCollection";
pub const TRANSACTION_COPIER_FICHIER_TIERS: &str = "copierFichierTiers";
// pub const TRANSACTION_FAVORIS_CREERPATH: &str = "favorisCreerPath";
pub const TRANSACTION_SUPPRIMER_VIDEO: &str = "supprimerVideo";
pub const TRANSACTION_IMAGE_SUPPRIMER_JOB: &str = "supprimerJobImage";
pub const TRANSACTION_VIDEO_SUPPRIMER_JOB: &str = "supprimerJobVideo";
pub const TRANSACTION_CONFIRMER_FICHIER_INDEXE: &str = "confirmerFichierIndexe";
pub const TRANSACTION_AJOUTER_CONTACT_LOCAL: &str = "ajouterContactLocal";
pub const TRANSACTION_SUPPRIMER_CONTACTS: &str = "supprimerContacts";
pub const TRANSACTION_PARTAGER_COLLECTIONS: &str = "partagerCollections";
pub const TRANSACTION_SUPPRIMER_PARTAGE_USAGER: &str = "supprimerPartageUsager";

pub const COMMANDE_REINDEXER: &str = "reindexerConsignation";
pub const COMMANDE_COMPLETER_PREVIEWS: &str = "completerPreviews";
pub const COMMANDE_NOUVEAU_FICHIER: &str = "commandeNouveauFichier";
pub const COMMANDE_ACTIVITE_FUUIDS: &str = "confirmerActiviteFuuids";
pub const COMMANDE_IMAGE_GET_JOB: &str = "getJobImage";
pub const COMMANDE_VIDEO_TRANSCODER: &str = "transcoderVideo";
pub const COMMANDE_VIDEO_ARRETER_CONVERSION: &str = "arreterVideo";
pub const COMMANDE_VIDEO_DISPONIBLE: &str = "jobConversionVideoDisponible";
pub const COMMANDE_VIDEO_GET_JOB: &str = "getJobVideo";
pub const COMMANDE_FUUIDS_DOMAINE_LISTE: &str = "fuuidsDomaineListe";
pub const COMMANDE_GET_CLE_JOB_CONVERSION: &str = "getCleJobConversion";
pub const COMMANDE_INDEXATION_GET_JOB: &str = "getJobIndexation";
pub const COMMANDE_RECLAMER_FUUIDS: &str = "reclamerFuuids";

pub const EVENEMENT_MAJ_FICHIER: &str = "majFichier";
pub const EVENEMENT_FUUID_AJOUTER_FICHIER_COLLECTION: &str = "fuuidAjouterFichierCollection";
pub const EVENEMENT_FUUID_ASSOCIER_CONVERSION: &str = "fuuidAssocierConversion";
pub const EVENEMENT_FUUID_ASSOCIER_VIDEO: &str = "fuuidAssocierVideo";
pub const EVENEMENT_FUUID_COPIER_FICHIER_TIERS: &str = "fuuidCopierFichierTiers";
pub const EVENEMENT_FUUID_DECRIRE_FICHIER: &str = "fuuidDecrireFichier";
pub const EVENEMENT_FUUID_DEPLACER_FICHIER_COLLECTION: &str = "fuuidDeplacerFichierCollection";
pub const EVENEMENT_FUUID_NOUVELLE_VERSION: &str = "fuuidNouvelleVersion";
pub const EVENEMENT_FUUID_CONSIGNE: &str = "fuuidConsigne";
pub const EVENEMENT_FUUID_RECUPERER: &str = "fuuidRecuperer";
pub const EVENEMENT_FUUID_ARCHIVER: &str = "fuuidArchiver";
pub const EVENEMENT_FUUID_RETIRER_COLLECTION: &str = "fuuidRetirerCollection";
pub const EVENEMENT_FUUID_SUPPRIMER_DOCUMENT: &str = "fuuidSupprimerDocument";
pub const EVENEMENT_AJOUTER_FICHIER: &str = "fuuidNouvelleVersion";
pub const EVENEMENT_CONFIRMER_ETAT_FUUIDS: &str = "confirmerEtatFuuids";
pub const EVENEMENT_TRANSCODAGE_PROGRES: &str = "transcodageProgres";
pub const EVENEMENT_FICHIERS_SYNCPRET: &str = "syncPret";
pub const EVENEMENT_FICHIERS_VISITER_FUUIDS: &str = "visiterFuuids";
pub const EVENEMENT_FICHIERS_CONSIGNE: &str = "consigne";
pub const EVENEMENT_REINDEXER_CONSIGNATION: &str = "reindexerConsignation";
pub const EVENEMENT_ANNULER_JOB_VIDEO: &str = "annulerJobVideo";

pub const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
pub const CHAMP_FUUIDS: &str = "fuuids";
pub const CHAMP_FUUIDS_RECLAMES: &str = "fuuids_reclames";
pub const CHAMP_FUUIDS_VERSIONS: &str = "fuuids_versions";
pub const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
pub const CHAMP_TUUIDS: &str = "tuuids";
pub const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
pub const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_CUUIDS_SUPPRIMES: &str = "cuuids_supprimes";  /// Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_CUUIDS_SUPPRIMES_INDIRECT: &str = "cuuids_supprimes_indirect";  /// Liste de cuuids supprimes via parent
pub const CHAMP_SUPPRIME: &str = "supprime";
pub const CHAMP_SUPPRIME_INDIRECT: &str = "supprime_indirect";
pub const CHAMP_SUPPRIME_PATH: &str = "supprime_cuuids_path";
pub const CHAMP_ARCHIVE: &str = "archive";
pub const CHAMP_NOM: &str = "nom";
pub const CHAMP_METADATA: &str = "metadata";
pub const CHAMP_TITRE: &str = "titre";
pub const CHAMP_MIMETYPE: &str = "mimetype";
pub const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
pub const CHAMP_FAVORIS: &str = "favoris";
pub const CHAMP_TYPE_NODE: &str = "type_node";
// pub const CHAMP_FUUID_MIMETYPES: &str = "fuuidMimetypes";
pub const CHAMP_FLAG_INDEX: &str = "flag_index";
pub const CHAMP_FLAG_INDEX_RETRY: &str = "index_retry";
pub const CHAMP_FLAG_INDEX_ERREUR: &str = "flag_index_erreur";
pub const CHAMP_INDEX_START: &str = "index_start";
pub const CHAMP_FLAG_INDEX_ETAT: &str = "etat";
pub const CHAMP_FLAG_MEDIA: &str = "flag_media";
pub const CHAMP_FLAG_MEDIA_TRAITE: &str = "flag_media_traite";
pub const CHAMP_FLAG_VIDEO_TRAITE: &str = "flag_video_traite";
pub const CHAMP_FLAG_MEDIA_RETRY: &str = "flag_media_retry";
pub const CHAMP_FLAG_MEDIA_ERREUR: &str = "flag_media_erreur";
pub const CHAMP_FLAG_DB_RETRY: &str = "retry";
pub const CHAMP_USER_ID: &str = "user_id";
pub const CHAMP_CLE_CONVERSION: &str = "cle_conversion";
pub const CHAMP_CONTACT_ID: &str = "contact_id";
pub const CHAMP_CONTACT_USER_ID: &str = "contact_user_id";
pub const CHAMP_PATH_CUUIDS: &str = "path_cuuids";
// pub const CHAMP_MAP_PATH_CUUIDS: &str = "map_path_cuuids";
// pub const CHAMP_CUUIDS_ANCETRES: &str = "cuuids_ancetres";
pub const CHAMP_TAILLE: &str = "taille";
pub const CHAMP_ETAT_JOB: &str = "etat";
pub const CHAMP_INSTANCES: &str = "instances";

pub const ERREUR_MEDIA_TOOMANYRETRIES: i32 = 1;

pub const MEDIA_RETRY_LIMIT: i32 = 5;
pub const MEDIA_IMAGE_BACTH_DEFAULT: i64 = 50;
pub const LIMITE_INDEXATION_BATCH: i64 = 1000;

pub const VIDEO_CONVERSION_ETAT_PENDING: i32 = 1;
pub const VIDEO_CONVERSION_ETAT_RUNNING: i32 = 2;
pub const VIDEO_CONVERSION_ETAT_PERSISTING: i32 = 3;
pub const VIDEO_CONVERSION_ETAT_ERROR: i32 = 4;
pub const VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES: i32 = 5;

pub const VIDEO_CONVERSION_TIMEOUT_RUNNING: i32 = 10 * 60;  // Secondes
pub const VIDEO_CONVERSION_TIMEOUT_PERSISTING: i32 = 60 * 60;  // Secondes

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TypeNode {
    Collection,
    Repertoire,
    Fichier,
}

impl TypeNode {
    pub fn to_str(&self) -> &'static str {
        match self {
            TypeNode::Collection => "Collection",
            TypeNode::Repertoire => "Repertoire",
            TypeNode::Fichier => "Fichier",
        }
    }
}

impl Into<&str> for TypeNode {
    fn into(self) -> &'static str {
        self.to_str()
    }
}

// impl From<TypeNode> for Bson {
//     fn from(value: TypeNode) -> Self {
//         value.into()
//     }
// }

impl TryFrom<&str> for TypeNode {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let resultat = match value {
            "Collection" => TypeNode::Collection,
            "Repertoire" => TypeNode::Repertoire,
            "Fichier" => TypeNode::Fichier,
            _ => Err(format!("TypeNode {} non supporte", value))?
        };
        Ok(resultat)
    }
}

impl Into<Bson> for TypeNode {
    fn into(self) -> Bson {
        let into_str: &str = self.into();
        Bson::String(into_str.to_owned())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FichierDetail {
    pub tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuids: Option<Vec<String>>,
    pub type_node: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_cuuids: Option<Vec<String>>,
    pub nom: Option<String>,
    pub titre: Option<HashMap<String, String>>,
    pub description: Option<HashMap<String, String>>,
    pub securite: Option<String>,  // Collection seulement
    pub user_id: Option<String>,
    pub mimetype: Option<String>,

    pub fuuid_v_courante: Option<String>,
    pub version_courante: Option<DBFichierVersionDetail>,
    pub favoris: Option<bool>,
    pub date_creation: Option<DateEpochSeconds>,
    pub derniere_modification: Option<DateEpochSeconds>,
    pub supprime: Option<bool>,
    pub archive: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    // #[serde(skip_serializing_if="Option::is_none")]
    // pub supprime_cuuids_path: Option<Vec<String>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub visites: Option<HashMap<String, DateEpochSeconds>>,

    /// Breadcrumbs pour chaque cuuid du fichier
    #[serde(skip_serializing_if="Option::is_none")]
    pub map_path_cuuids: Option<HashMap<String, Vec<String>>>,

    /// Liste de collections ou le fichier a ete supprime
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuids_supprimes: Option<Vec<String>>,
}

impl TryFrom<Document> for FichierDetail {
    type Error = String;

    fn try_from(value: Document) -> Result<Self, Self::Error> {
        match mapper_fichier_db(value) {
            Ok(d) => Ok(d),
            Err(e) => Err(format!("FichierDetail::try_from {:?}", e))?
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DBFichierVersionDetail {
    #[serde(skip_serializing_if="Option::is_none")]
    pub nom: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub fuuid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tuuid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<String>,
    pub mimetype: String,
    pub taille: usize,
    #[serde(rename="dateFichier")]
    pub date_fichier: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageConversion>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, TransactionAssocierVideoVersionDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_retry: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_traite: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_video_traite: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_index: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAssocierConversions {
    pub tuuid: String,
    pub fuuid: String,
    pub user_id: Option<String>,  // Option = legacy, nouvelle version c'est obligatoire
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mimetype: Option<String>,
    pub images: HashMap<String, ImageConversion>,
    pub anime: Option<bool>,
    pub duration: Option<f32>,
    #[serde(rename="videoCodec")]
    pub video_codec: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAssocierVideo {
    pub tuuid: String,
    pub fuuid: String,
    pub user_id: String,
    pub mimetype: String,
    pub codec: String,
    pub fuuid_video: String,

    // Metadata video transcode
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bitrate: Option<u32>,
    pub quality: Option<i32>,
    pub taille_fichier: u64,

    // Information dechiffrage - note : fuuid -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,

    /// Fix bug videas verticaux. Ajoute dans version 2023.7.4
    pub cle_conversion: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAssocierVideoVersionDetail {
    pub tuuid: String,
    pub fuuid: String,
    pub user_id: Option<String>,
    pub mimetype: String,
    pub codec: String,
    pub fuuid_video: String,

    // Metadata video transcode
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bitrate: Option<u32>,
    pub quality: Option<i32>,
    pub taille_fichier: u64,

    // Information dechiffrage - note : fuuid -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,

    /// Fix bug videas verticaux. Ajoute dans version 2023.7.4
    pub cle_conversion: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageConversion {
    pub hachage: String,

    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mimetype: Option<String>,
    pub taille: Option<u64>,
    pub resolution: Option<u32>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub data_chiffre: Option<String>,

    // Information dechiffrage - note : fuuid_v_courante du fichier -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVideoConvertir {
    pub tuuid: String,
    pub fuuid: String,
    pub mimetype: String,
    #[serde(rename="codecVideo")]
    pub codec_video: String,
    #[serde(rename="codecAudio")]
    pub codec_audio: String,
    #[serde(rename="resolutionVideo")]
    pub resolution_video: u32,
    #[serde(rename="qualityVideo")]
    pub quality_video: Option<i32>,
    #[serde(rename="bitrateVideo")]
    pub bitrate_video: Option<u32>,
    #[serde(rename="bitrateAudio")]
    pub bitrate_audio: u32,
    pub preset: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<String>,
    pub fallback: Option<bool>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct CommandeVideoArreterConversion {
//     pub fuuid: String,
//     #[serde(rename="cleConversion")]
//     pub cle_conversion: String,
//     pub user_id: Option<String>,    // Utilise par systeme pour rapporter erreur fatale
//     pub code_erreur: Option<i64>,   // Si Some, toggle flag_video a true sur version fichier
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVideoGetJob {
    pub instance_id: Option<String>,
    // pub fuuid: Option<String>,
    // #[serde(rename="cleConversion")]
    // pub cle_conversion: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerVideo {
    pub fuuid_video: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerJobImage {
    pub fuuid: String,
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerJobVideo {
    pub fuuid: String,
    pub cle_conversion: String,
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeImageArreterTraitement {
    pub fuuid: String,
    pub user_id: Option<String>,    // Utilise par systeme pour rapporter erreur fatale
    pub code_erreur: Option<i64>,   // Si Some, toggle flag_video a true sur version fichier
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeImageGetJob {
    pub instance_id: Option<String>
    // pub fuuid: Option<String>,
    // #[serde(rename="cleConversion")]
    // pub cle_conversion: Option<String>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct JobVideo {
//     pub tuuid: String,
//     pub fuuid: String,
//     pub cle_conversion: String,
//     pub user_id: Option<String>,
//     pub mimetype: String,
//     #[serde(rename="codecVideo")]
//     pub codec_video: String,
//     #[serde(rename="codecAudio")]
//     pub codec_audio: String,
//     #[serde(rename="resolutionVideo")]
//     pub resolution_video: u32,
//     #[serde(rename="qualityVideo")]
//     pub quality_video: Option<i32>,
//     #[serde(rename="bitrateVideo")]
//     pub bitrate_video: Option<u32>,
//     #[serde(rename="bitrateAudio")]
//     pub bitrate_audio: u32,
//     pub preset: Option<String>,
//     pub etat: i32,
//     #[serde(rename="_mg-derniere-modification", skip_serializing)]
//     pub date_modification: Value,
//     pub flag_media_retry: i32,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCle {
    pub ok: Option<bool>
}

// #[derive(Clone, Debug, Deserialize)]
// pub struct CommandeGetCleJobConversion {
//     pub fuuid: String,
//     pub nom_job: String,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeIndexationGetJob {
    pub instance_id: Option<String>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct JobIndexation {
//     pub tuuid: String,
//     pub fuuid: String,
//     pub user_id: String,
//     pub etat: i32,
//     #[serde(rename="_mg-derniere-modification", skip_serializing)]
//     pub date_modification: Value,
//     pub index_start: Option<DateTime>,
//     pub index_retry: i32,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ReponseJobIndexation {
//     pub ok: bool,
//     pub tuuid: String,
//     pub fuuid: String,
//     pub user_id: String,
//     pub mimetype: String,
//     pub metadata: DataChiffre,
//     pub cle: InformationCle,
// }

#[derive(Debug, Deserialize)]
pub struct NodeFichiersRepBorrow<'a> {
    #[serde(borrow)]
    pub tuuid: &'a str,
    // #[serde(borrow)]
    // pub cuuid: Option<&'a str>,
    // #[serde(borrow)]
    // pub cuuids: Option<Vec<&'a str>>,
    #[serde(borrow)]
    pub user_id: &'a str,
    #[serde(borrow)]
    pub type_node: &'a str,
    #[serde(borrow)]
    pub path_cuuids: Option<Vec<&'a str>>,
    // #[serde(borrow)]
    // pub map_path_cuuids: Option<HashMap<&'a str, Vec<&'a str>>>,
    // #[serde(borrow)]
    // pub cuuids_supprimes: Option<Vec<&'a str>>,
    // #[serde(borrow)]
    // pub cuuids_supprimes_indirect: Option<Vec<&'a str>>,
    pub supprime: bool,
    pub supprime_indirect: bool,
    // #[serde(borrow)]
    // pub fuuids_reclames: Option<Vec<&'a str>>,
    #[serde(borrow)]
    pub fuuids_versions: Option<Vec<&'a str>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffreBorrow<'a> {
    #[serde(borrow)]
    pub data_chiffre: &'a str,
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub header: Option<&'a str>,
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub ref_hachage_bytes: Option<&'a str>,
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub hachage_bytes: Option<&'a str>,
    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub format: Option<&'a str>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffre {
    pub data_chiffre: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub ref_hachage_bytes: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub hachage_bytes: Option<String>,
    pub format: Option<String>
}

impl<'a> From<DataChiffreBorrow<'a>> for DataChiffre {
    fn from(value: DataChiffreBorrow) -> Self {
        Self {
            data_chiffre: value.data_chiffre.to_owned(),
            header: match value.header { Some(inner) => Some(inner.to_owned()), None => None},
            ref_hachage_bytes: match value.ref_hachage_bytes { Some(inner) => Some(inner.to_owned()), None => None},
            hachage_bytes: match value.hachage_bytes { Some(inner) => Some(inner.to_owned()), None => None},
            format: match value.format { Some(inner) => Some(inner.to_owned()), None => None},
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeVersionCouranteInlineOwned {
    pub fuuid: String,
    pub taille: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeFichierRepVersionCouranteOwned {
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

    pub versions: Option<Vec<NodeVersionCouranteInlineOwned>>
}
