use std::collections::HashMap;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use crate::requetes::mapper_fichier_db;
use crate::transactions::DataChiffre;

pub const DOMAINE_NOM: &str = "GrosFichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "GrosFichiers";
pub const NOM_COLLECTION_FICHIERS_REP: &str = "GrosFichiers/fichiersRep";
pub const NOM_COLLECTION_VERSIONS: &str = "GrosFichiers/versionsFichiers";
pub const NOM_COLLECTION_DOCUMENTS: &str = "GrosFichiers/documents";
pub const NOM_COLLECTION_VIDEO_JOBS: &str = "GrosFichiers/videoJobs";

pub const DOMAINE_FICHIERS_NOM: &str = "fichiers";

pub const NOM_Q_TRANSACTIONS: &str = "GrosFichiers/transactions";
pub const NOM_Q_VOLATILS: &str = "GrosFichiers/volatils";
pub const NOM_Q_TRIGGERS: &str = "GrosFichiers/triggers";

pub const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";
pub const REQUETE_FAVORIS: &str = "favoris";
pub const REQUETE_DOCUMENTS_PAR_TUUID: &str = "documentsParTuuid";
pub const REQUETE_DOCUMENTS_PAR_FUUID: &str = "documentsParFuuid";
pub const REQUETE_CONTENU_COLLECTION: &str = "contenuCollection";
pub const REQUETE_GET_CORBEILLE: &str = "getCorbeille";
pub const REQUETE_RECHERCHE_INDEX: &str = "rechercheIndex";
pub const REQUETE_GET_CLES_FICHIERS: &str = "getClesFichiers";
pub const REQUETE_GET_CLES_STREAM: &str = "getClesStream";
pub const REQUETE_CONFIRMER_ETAT_FUUIDS: &str = "confirmerEtatFuuids";
pub const REQUETE_VERIFIER_ACCES_FUUIDS: &str = "verifierAccesFuuids";
pub const REQUETE_SYNC_COLLECTION: &str = "syncCollection";
pub const REQUETE_SYNC_RECENTS: &str = "syncRecents";
pub const REQUETE_SYNC_CORBEILLE: &str = "syncCorbeille";
pub const REQUETE_SYNC_CUUIDS: &str = "syncCuuids";
pub const REQUETE_JOBS_VIDEO: &str = "requeteJobsVideo";

pub const TRANSACTION_NOUVELLE_VERSION: &str = "nouvelleVersion";
pub const TRANSACTION_NOUVELLE_COLLECTION: &str = "nouvelleCollection";
pub const TRANSACTION_AJOUTER_FICHIERS_COLLECTION: &str = "ajouterFichiersCollection";
pub const TRANSACTION_DEPLACER_FICHIERS_COLLECTION: &str = "deplacerFichiersCollection";
pub const TRANSACTION_RETIRER_DOCUMENTS_COLLECTION: &str = "retirerDocumentsCollection";
pub const TRANSACTION_SUPPRIMER_DOCUMENTS: &str = "supprimerDocuments";
pub const TRANSACTION_RECUPERER_DOCUMENTS: &str = "recupererDocuments";
pub const TRANSACTION_CHANGER_FAVORIS: &str = "changerFavoris";
pub const TRANSACTION_ASSOCIER_CONVERSIONS: &str = "associerConversions";
pub const TRANSACTION_ASSOCIER_VIDEO: &str = "associerVideo";
pub const TRANSACTION_DECRIRE_FICHIER: &str = "decrireFichier";
pub const TRANSACTION_DECRIRE_COLLECTION: &str = "decrireCollection";
pub const TRANSACTION_COPIER_FICHIER_TIERS: &str = "copierFichierTiers";
pub const TRANSACTION_FAVORIS_CREERPATH: &str = "favorisCreerPath";
pub const TRANSACTION_SUPPRIMER_VIDEO: &str = "supprimerVideo";

pub const COMMANDE_INDEXER: &str = "indexerContenu";
pub const COMMANDE_COMPLETER_PREVIEWS: &str = "completerPreviews";
pub const COMMANDE_CONFIRMER_FICHIER_INDEXE: &str = "confirmerFichierIndexe";
pub const COMMANDE_NOUVEAU_FICHIER: &str = "commandeNouveauFichier";
pub const COMMANDE_ACTIVITE_FUUIDS: &str = "confirmerActiviteFuuids";
pub const COMMANDE_VIDEO_TRANSCODER: &str = "transcoderVideo";
pub const COMMANDE_VIDEO_ARRETER_CONVERSION: &str = "arreterVideo";
pub const COMMANDE_VIDEO_DISPONIBLE: &str = "jobConversionVideoDisponible";
pub const COMMANDE_VIDEO_GET_JOB: &str = "getJobVideo";
pub const COMMANDE_VIDEO_SUPPRIMER_JOB: &str = "supprimerJobVideo";
pub const COMMANDE_FUUIDS_DOMAINE_LISTE: &str = "fuuidsDomaineListe";

pub const EVENEMENT_MAJ_FICHIER: &str = "majFichier";
pub const EVENEMENT_FUUID_AJOUTER_FICHIER_COLLECTION: &str = "fuuidAjouterFichierCollection";
pub const EVENEMENT_FUUID_ASSOCIER_CONVERSION: &str = "fuuidAssocierConversion";
pub const EVENEMENT_FUUID_ASSOCIER_VIDEO: &str = "fuuidAssocierVideo";
pub const EVENEMENT_FUUID_COPIER_FICHIER_TIERS: &str = "fuuidCopierFichierTiers";
pub const EVENEMENT_FUUID_DECRIRE_FICHIER: &str = "fuuidDecrireFichier";
pub const EVENEMENT_FUUID_DEPLACER_FICHIER_COLLECTION: &str = "fuuidDeplacerFichierCollection";
pub const EVENEMENT_FUUID_NOUVELLE_VERSION: &str = "fuuidNouvelleVersion";
pub const EVENEMENT_FUUID_RECUPERER: &str = "fuuidRecuperer";
pub const EVENEMENT_FUUID_RETIRER_COLLECTION: &str = "fuuidRetirerCollection";
pub const EVENEMENT_FUUID_SUPPRIMER_DOCUMENT: &str = "fuuidSupprimerDocument";
pub const EVENEMENT_AJOUTER_FICHIER: &str = "fuuidNouvelleVersion";
pub const EVENEMENT_CONFIRMER_ETAT_FUUIDS: &str = "confirmerEtatFuuids";
pub const EVENEMENT_TRANSCODAGE_PROGRES: &str = "transcodageProgres";
pub const EVENEMENT_FICHIERS_SYNCPRET: &str = "syncPret";

pub const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
pub const CHAMP_FUUIDS: &str = "fuuids";
pub const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
pub const CHAMP_TUUIDS: &str = "tuuids";
pub const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
pub const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_SUPPRIME: &str = "supprime";
pub const CHAMP_SUPPRIME_PATH: &str = "supprime_cuuids_path";
pub const CHAMP_ARCHIVE: &str = "archive";
pub const CHAMP_NOM: &str = "nom";
pub const CHAMP_METADATA: &str = "metadata";
pub const CHAMP_TITRE: &str = "titre";
pub const CHAMP_MIMETYPE: &str = "mimetype";
pub const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
pub const CHAMP_FAVORIS: &str = "favoris";
// pub const CHAMP_FUUID_MIMETYPES: &str = "fuuidMimetypes";
pub const CHAMP_FLAG_INDEXE: &str = "flag_indexe";
pub const CHAMP_FLAG_MEDIA: &str = "flag_media";
pub const CHAMP_FLAG_MEDIA_TRAITE: &str = "flag_media_traite";
pub const CHAMP_FLAG_MEDIA_RETRY: &str = "flag_media_retry";
pub const CHAMP_FLAG_MEDIA_ERREUR: &str = "flag_media_erreur";
pub const CHAMP_USER_ID: &str = "user_id";
pub const CHAMP_CLE_CONVERSION: &str = "cle_conversion";

pub const ERREUR_MEDIA_TOOMANYRETRIES: i32 = 1;

pub const MEDIA_RETRY_LIMIT: i32 = 5;
pub const MEDIA_IMAGE_BACTH_DEFAULT: i64 = 50;

pub const VIDEO_CONVERSION_ETAT_PENDING: i32 = 1;
pub const VIDEO_CONVERSION_ETAT_RUNNING: i32 = 2;
pub const VIDEO_CONVERSION_ETAT_PERSISTING: i32 = 3;
pub const VIDEO_CONVERSION_ETAT_ERROR: i32 = 4;
pub const VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES: i32 = 5;

pub const VIDEO_CONVERSION_TIMEOUT_RUNNING: i32 = 10 * 60;  // Secondes
pub const VIDEO_CONVERSION_TIMEOUT_PERSISTING: i32 = 60 * 60;  // Secondes

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FichierDetail {
    pub tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuids: Option<Vec<String>>,
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
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub supprime_cuuids_path: Option<Vec<String>>,
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
    pub video: Option<HashMap<String, TransactionAssocierVideo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub flag_media_retry: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAssocierConversions {
    pub tuuid: String,
    pub fuuid: String,
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
    pub tuuid: Option<String>,
    pub fuuid: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mimetype: String,
    pub fuuid_video: String,
    pub codec: String,
    pub bitrate: Option<u32>,
    pub quality: Option<i32>,
    pub taille_fichier: u64,
    pub user_id: Option<String>,

    // Information dechiffrage - note : fuuid -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVideoArreterConversion {
    pub fuuid: String,
    #[serde(rename="cleConversion")]
    pub cle_conversion: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVideoGetJob {
    pub fuuid: Option<String>,
    #[serde(rename="cleConversion")]
    pub cle_conversion: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerVideo {
    pub fuuid_video: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobVideo {
    pub tuuid: String,
    pub fuuid: String,
    pub cle_conversion: String,
    pub user_id: Option<String>,
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
    pub etat: i32,
    #[serde(rename="_mg-derniere-modification", skip_serializing)]
    pub date_modification: Value,
    pub flag_media_retry: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCle {
    pub ok: Option<bool>
}
