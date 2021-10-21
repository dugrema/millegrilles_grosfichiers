use std::collections::HashMap;
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

pub const DOMAINE_NOM: &str = "GrosFichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "GrosFichiers";
pub const NOM_COLLECTION_FICHIERS_REP: &str = "GrosFichiers/fichiersRep";
pub const NOM_COLLECTION_VERSIONS: &str = "GrosFichiers/versionsFichiers";
pub const NOM_COLLECTION_DOCUMENTS: &str = "GrosFichiers/documents";

pub const DOMAINE_FICHIERS_NOM: &str = "fichiers";

pub const NOM_Q_TRANSACTIONS: &str = "GrosFichiers/transactions";
pub const NOM_Q_VOLATILS: &str = "GrosFichiers/volatils";
pub const NOM_Q_TRIGGERS: &str = "GrosFichiers/triggers";

pub const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";
pub const REQUETE_FAVORIS: &str = "favoris";
pub const REQUETE_DOCUMENTS_PAR_TUUID: &str = "documentsParTuuid";
pub const REQUETE_CONTENU_COLLECTION: &str = "contenuCollection";
pub const REQUETE_GET_CORBEILLE: &str = "getCorbeille";

pub const TRANSACTION_NOUVELLE_VERSION: &str = "nouvelleVersion";
pub const TRANSACTION_NOUVELLE_COLLECTION: &str = "nouvelleCollection";
pub const TRANSACTION_AJOUTER_FICHIERS_COLLECTION: &str = "ajouterFichiersCollection";
pub const TRANSACTION_RETIRER_DOCUMENTS_COLLECTION: &str = "retirerDocumentsCollection";
pub const TRANSACTION_SUPPRIMER_DOCUMENTS: &str = "supprimerDocuments";
pub const TRANSACTION_RECUPERER_DOCUMENTS: &str = "recupererDocuments";
pub const TRANSACTION_CHANGER_FAVORIS: &str = "changerFavoris";
pub const TRANSACTION_ASSOCIER_CONVERSIONS: &str = "associerConversions";
pub const TRANSACTION_ASSOCIER_VIDEO: &str = "associerVideo";

pub const COMMANDE_INDEXER: &str = "indexerContenu";

pub const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
pub const CHAMP_FUUIDS: &str = "fuuids";
pub const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
pub const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
pub const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_SUPPRIME: &str = "supprime";
pub const CHAMP_NOM: &str = "nom";
pub const CHAMP_TITRE: &str = "titre";
pub const CHAMP_MIMETYPE: &str = "mimetype";
pub const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
pub const CHAMP_FAVORIS: &str = "favoris";
pub const CHAMP_FUUID_MIMETYPES: &str = "fuuidMimetypes";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FichierDetail {
    pub tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuids: Option<Vec<String>>,
    pub nom: String,
    pub titre: Option<HashMap<String, String>>,

    pub fuuid_v_courante: Option<String>,
    pub version_courante: Option<DBFichierVersionDetail>,
    pub favoris: Option<bool>,
    pub date_creation: Option<DateEpochSeconds>,
    pub derniere_modification: Option<DateEpochSeconds>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DBFichierVersionDetail {
    pub nom: String,
    pub mimetype: String,
    pub taille: usize,
    #[serde(rename="dateFichier")]
    pub date_fichier: DateEpochSeconds,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub weight: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageConversion>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, TransactionAssocierVideo>>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAssocierVideo {
    pub tuuid: String,
    pub fuuid: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mimetype: String,
    pub fuuid_video: String,
    pub codec: String,
    pub bitrate: u32,
    pub taille_fichier: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageConversion {
    pub hachage: String,
    width: Option<u32>,
    height: Option<u32>,
    pub mimetype: Option<String>,
    taille: Option<u64>,
    resolution: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    data_chiffre: Option<String>,
}
