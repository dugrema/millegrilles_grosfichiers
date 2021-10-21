use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Mutex;
use log::{debug, error, warn};

use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::serde::{Deserialize, Serialize};

use crate::grosfichiers_constantes::*;

pub async fn emettre_commande_indexation<M, S, U>(middleware: &M, tuuid: U, fuuid: S)
    -> Result<(), String>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>,
        U: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let fuuid_str = fuuid.as_ref();

    // domaine_action = 'commande.fichiers.indexerContenu'
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(doc!{CHAMP_TUUID: tuuid_str}, None).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur chargement fichier : {:?}", e))?
    };
    let fichier = match doc_fichier {
        Some(inner) => {
            match convertir_bson_deserializable::<FichierDetail>(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur conversion vers bson : {:?}", e))?
            }
        },
        None => Err(format!("Aucun fichier avec tuuid {}", tuuid_str))?
    };

    // Verifier si on doit chargement une version different
    let fuuid_v_courante = match fichier.fuuid_v_courante {
        Some(inner) => inner,
        None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Fuuid v courante manquant"))?
    };

    if fuuid_v_courante.as_str() != fuuid_str {
        todo!("Charger version precedente du document")
    }

    let version_courante = match fichier.version_courante {
        Some(inner) => inner,
        None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Version courante manquante"))?
    };

    let mimetype = version_courante.mimetype.clone();

    let document_indexation: DocumentIndexation = version_courante.try_into()?;
    let info_index = InfoDocumentIndexation {
        tuuid: tuuid_str.to_owned(),
        fuuid: fuuid_str.to_owned(),
        doc: document_indexation,

        permission_duree: Some(30 * 60),  // 30 minutes
        permission_hachage_bytes: Some(vec![fuuid_str.to_owned()]),
    };

    match mimetype.as_str().to_ascii_lowercase().as_str() {
        "application/pdf" => {
            debug!("Indexation document contenu pdf : {}", fuuid_str);
            let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_INDEXER)
                .exchanges(vec![Securite::L3Protege])
                .build();
            middleware.transmettre_commande(routage, &info_index, false).await?;
        },
        _ => {
            // Format de document de base, aucun contenu a indexer
            debug!("Indexation document metadata seulement : {}", fuuid_str);
        }
    }

    Ok(())
}

/// Format de document pret a etre indexe
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfoDocumentIndexation {
    tuuid: String,
    fuuid: String,
    doc: DocumentIndexation,

    // Info permission dechiffrage
    permission_duree: Option<u32>,
    permission_hachage_bytes: Option<Vec<String>>,
}

/// Contenu et mots-cles pour l'indexation d'un document
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentIndexation {
    nom: String,    // Nom du fichier
    mimetype: String,
    date_v_courante: DateEpochSeconds,

    // Champs qui proviennent du fichierRep (courant uniquement)
    titre: Option<HashMap<String, String>>,          // Dictionnaire combine
    description: Option<HashMap<String, String>>,    // Dictionnaire combine
    cuuids: Option<Vec<String>>,
}

impl TryFrom<DBFichierVersionDetail> for DocumentIndexation {
    type Error = String;

    fn try_from(value: DBFichierVersionDetail) -> Result<Self, Self::Error> {
        Ok(DocumentIndexation {
            nom: value.nom.clone(),
            mimetype: value.mimetype.clone(),
            date_v_courante: value.date_fichier.clone(),
            titre: None,
            description: None,
            cuuids: None,
        })
    }
}

#[async_trait]
pub trait ElasticSearchDao {
    async fn es_preparer(&self) -> Result<(), String>;

    /// Retourne true si le serveur est pret (accessible, index generes)
    fn es_est_pret(&self) -> bool;

    async fn es_indexer<S, T>(&self, nom_index: S, id_doc: T, info_doc: InfoDocumentIndexation)
        -> Result<(), String>
        where S: AsRef<str> + Send, T: AsRef<str> + Send;

    async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresIndex)
        -> Result<ResultatRecherche, String>
        where S: AsRef<str> + Send;

}

#[derive(Debug)]
pub struct ElasticSearchDaoImpl {
    url: String,
    est_pret: Mutex<bool>,
}

impl ElasticSearchDaoImpl {
    pub fn new<S>(url: S) -> Self
        where S: Into<String>
    {
        ElasticSearchDaoImpl {
            url: url.into(),
            est_pret: Mutex::new(false),
        }
    }
}

#[async_trait]
impl ElasticSearchDao for ElasticSearchDaoImpl {
    async fn es_preparer(&self) -> Result<(), String> {
        debug!("ElasticSearchDaoImpl preparer index");

        let mut guard = match self.est_pret.lock() {
            Ok(inner) => inner,
            Err(e) => Err(format!("traitement_index.ElasticSearchDao Erreur lock est_pret : {:?}", e))?
        };
        *guard = true;

        Ok(())
    }

    fn es_est_pret(&self) -> bool {
        match self.est_pret.lock() {
            Ok(inner) => *inner,
            Err(e) => {
                warn!("traitement_index.ElasticSearchDaoImpl Erreur lecture mutex est_pret : {:?}", e);
                false
            }
        }
    }

    async fn es_indexer<S, T>(&self, nom_index: S, id_doc: T, info_doc: InfoDocumentIndexation)
        -> Result<(), String>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        todo!()
    }

    async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresIndex)
        -> Result<ResultatRecherche, String>
        where S: AsRef<str> + Send
    {
        todo!()
    }
}

pub struct ParametresIndex {

}

pub struct ResultatRecherche {

}