use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Mutex;
use log::{debug, error, info, warn};

use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::serde_json::Value;
use crate::grosfichiers::GestionnaireGrosFichiers;

use crate::grosfichiers_constantes::*;

pub async fn emettre_commande_indexation<M, S, U>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, tuuid: U, fuuid: S)
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
            gestionnaire.es_indexer("grosfichiers", fuuid_str, info_index).await?;
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

    async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresRecherche)
        -> Result<ResultatRecherche, String>
        where S: AsRef<str> + Send;

}

#[derive(Debug)]
pub struct ElasticSearchDaoImpl {
    url: String,
    est_pret: Mutex<bool>,
    client: reqwest::Client,
}

impl ElasticSearchDaoImpl {
    pub fn new<S>(url: S) -> Result<Self, Box<dyn Error>>
        where S: Into<String>
    {
        let client = reqwest::Client::builder()
            .timeout(core::time::Duration::new(20, 0))
            .build()?;

        Ok(ElasticSearchDaoImpl {
            url: url.into(),
            est_pret: Mutex::new(false),
            client,
        })
    }
}

#[async_trait]
impl ElasticSearchDao for ElasticSearchDaoImpl {
    async fn es_preparer(&self) -> Result<(), String> {
        debug!("ElasticSearchDaoImpl preparer index");

        let index_json = index_grosfichiers();
        let url_post = format!("{}/_index_template/grosfichiers", self.url);
        let response = match self.client.put(&url_post).json(&index_json).send().await {
            Ok(inner) => inner,
            Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest : {:?}", e))?
        };

        debug!("ElasticSearchDaoImpl.es_preparer status: {}, {:?}", response.status(), response);
        if response.status().is_client_error() {
            warn!("ElasticSearchDaoImpl.es_preparer Erreur preparation index grosfichiers, contenu invalide. On le reset");
            match self.client.delete(&url_post).send().await {
                Ok(inner) => {
                    if inner.status().is_success() {
                        info!("Reponse reset index : {:?}", inner);
                        Err(format!("Index grosfichiers supprime, va etre recree prochaine fois"))?
                    }
                    Err(format!("Index grosfichiers ne peut pas etre supprimer, code : {:?}", inner))?
                },
                Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest delete index grosfichiers : {:?}", e))?
            }
        }

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
        let id_doc_str = id_doc.as_ref();

        let doc_index = match serde_json::to_value(info_doc.doc) {
            Ok(inner) => inner,
            Err(e) => Err(format!("ElasticSearchDaoImpl.es_indexer Erreur conversion json info_doc : {:?}", e))?
        };

        let url_post = format!("{}/{}/_doc/{}", self.url, nom_index.as_ref(), id_doc_str);
        let response = match self.client.post(&url_post).json(&doc_index).send().await {
            Ok(inner) => inner,
            Err(e) => Err(format!("ElasticSearchDaoImpl.es_indexer Erreur reqwest : {:?}", e))?
        };

        if ! response.status().is_success() {
            Err(format!("ElasticSearchDaoImpl.es_indexer Erreur search index grosfichiers : {:?}", response))?
        }

        debug!("ElasticSearchDaoImpl.es_indexer OK, response : {:?}", response);

        Ok(())
    }

    async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresRecherche)
        -> Result<ResultatRecherche, String>
        where S: AsRef<str> + Send
    {
        let from_idx = match params.from_idx { Some(inner) => inner, None => 0 };
        let size = match params.size { Some(inner) => inner, None => 20 };
        let url_post = format!("{}/{}/_search?from={}&size={}", self.url, nom_index.as_ref(), from_idx, size);

        let query = match &params.mots_cles {
            Some(mots_cles) => {
                json!({
                    "query": {
                        "bool": {
                            "should": [
                                {"match": {"contenu": mots_cles}},
                                {"match": {"nom": mots_cles}},
                                {"match": {"titre._combine": mots_cles}},
                                {"match": {"description._combine": mots_cles}},
                            ]
                        }
                    }
                })
            },
            None => json!({})
        };

        // '%s/%s/_search?from=%d&size=%d' % (self.__url, nom_index, from_idx, size),
        let response = match self.client.get(&url_post).json(&query).send().await {
            Ok(inner) => inner,
            Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest : {:?}", e))?
        };

        if ! response.status().is_success() {
            Err(format!("ElasticSearchDaoImpl.es_preparer Erreur search index grosfichiers : {:?}", response))?
        }

        let resultat: ResultatRecherche = match response.text().await {
            Ok(inner) => {
                debug!("Resultat recherche(str) : {}", inner);
                match serde_json::from_str(inner.as_str()) {
                    Ok(v) => v,
                    Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur conversion json search grosfichiers : {:?}", e))?
                }
            },
            Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur search grosfichiers, conversion text : {:?}", e))?
        };

        debug!("Resultat recherche : {:?}", resultat);

        Ok(resultat)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresIndex {

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultatRecherche {
    pub took: u32,
    pub timed_out: bool,
    pub hits: Option<ResultatHits>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultatHits {
    pub total: ResultatTotal,
    pub max_score: Option<f32>,
    pub hits: Option<Vec<ResultatHitsDetail>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultatTotal {
    pub value: u32,
    pub relation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultatHitsDetail {
    #[serde(rename="_index")]
    pub index: String,
    #[serde(rename="_type")]
    pub type_: String,
    #[serde(rename="_id")]
    pub id_: String,
    #[serde(rename="_score")]
    pub score: f32,
}

pub fn index_grosfichiers() -> Value {
    json!({
        "index_patterns": ["grosfichiers"],
        "template": {
            "settings": {
                "analysis": {
                    "analyzer": {
                        "filename_index": {
                            "tokenizer": "filename_index",
                            "filter": ["asciifolding", "lowercase", "file_edge"]
                        },
                        "filename_search": {
                            "tokenizer": "filename_index",
                            "filter": ["asciifolding", "lowercase"]
                        },
                    },
                    "tokenizer": {
                        "filename_index": {
                            "type": "pattern",
                            "pattern": "[\\W|_]+",
                            "lowercase": true
                        },
                    },
                    "filter": {
                        "file_edge": {
                            "type": "edge_ngram",
                            "min_gram": 3,
                            "max_gram": 16,
                            "token_chars": [
                                "letter",
                                "digit"
                            ]
                        },
                    }
                }
            },
            "mappings": {
                "_source": {
                    "enabled": false
                },
                "properties": {
                    "contenu": {
                        "type": "text",
                    },
                    "nom_fichier": {
                        "type": "text",
                        "search_analyzer": "filename_search",
                        "analyzer": "filename_index"
                    },
                    "titre._combine": {
                        "type": "text",
                        "search_analyzer": "filename_search",
                        "analyzer": "filename_index"
                    },
                    "description._combine": {
                        "type": "text",
                        "search_analyzer": "filename_search",
                        "analyzer": "filename_index"
                    },
                    "mimetype": {"type": "keyword"},
                    // "contenu": {"type": "text"},
                    "date_v_courante": {"type": "date", "format": "strict_date_optional_time||epoch_second"},
                }
            },
        },
        "priority": 500,
        "version": 2,
        "_meta": {
            "description": "Index grosfichiers"
        }
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresRecherche {
    mots_cles: Option<String>,
    from_idx: Option<u32>,
    size: Option<u32>,
}

#[cfg(test)]
mod test_integration_index {
    use millegrilles_common_rust::tokio as tokio;

    use crate::test_setup::setup;

    use super::*;

    #[tokio::test]
    async fn test_creation_index() {
        setup("test_creation_index");
        let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");
        debug!("Test preparer index");
        dao.es_preparer().await.expect("pret");
    }

    #[tokio::test]
    async fn test_indexer() {
        setup("test_indexer");
        let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");
        let document_index = DocumentIndexation {
            nom: String::from("dummy_nom"),
            mimetype: String::from("application/data"),
            date_v_courante: DateEpochSeconds::now(),
            titre: None, description: None, cuuids: None,
        };
        let info_doc = InfoDocumentIndexation {
            tuuid: String::from("tuuid-abcd-1234"),
            fuuid: String::from("fuuid-abcd-1234"),
            doc: document_index,
            permission_hachage_bytes: None, permission_duree: None,
        };
        dao.es_indexer("grosfichiers", info_doc.fuuid.clone(), info_doc).await.expect("indexer");
    }

    #[tokio::test]
    async fn test_search() {
        setup("test_search");
        let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");

        let params = ParametresRecherche {
            mots_cles: Some(String::from("dadada")),
            from_idx: Some(0),
            size: Some(20),
        };
        let resultat = dao.es_rechercher("grosfichiers", &params).await.expect("search");
        debug!("Resultat 1 test_search : {:?}", resultat);
        assert_eq!(0, resultat.hits.expect("hits").total.value);

        let params = ParametresRecherche {
            mots_cles: Some(String::from("dummy_nom")),
            from_idx: Some(0),
            size: Some(20),
        };
        let resultat = dao.es_rechercher("grosfichiers", &params).await.expect("search");
        debug!("Resultat 2 test_search : {:?}", resultat);
        assert_eq!(1, resultat.hits.expect("hits").total.value);

    }

}

