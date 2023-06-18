use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ops::Deref;
use std::sync::Mutex;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint};
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::grosfichiers_constantes::*;

// pub async fn emettre_commande_indexation<M, S, U>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, tuuid: U, fuuid: S)
//     -> Result<(), String>
//     where
//         M: GenerateurMessages + MongoDao,
//         S: AsRef<str>,
//         U: AsRef<str>
// {
//     let tuuid_str = tuuid.as_ref();
//     let fuuid_str = fuuid.as_ref();
//
//     // domaine_action = 'commande.fichiers.indexerContenu'
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
//     let doc_fichier = match collection.find_one(doc!{CHAMP_TUUID: tuuid_str}, None).await {
//         Ok(inner) => inner,
//         Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur chargement fichier : {:?}", e))?
//     };
//     let fichier = match doc_fichier {
//         Some(inner) => {
//             match convertir_bson_deserializable::<FichierDetail>(inner) {
//                 Ok(inner) => inner,
//                 Err(e) => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Erreur conversion vers bson : {:?}", e))?
//             }
//         },
//         None => Err(format!("Aucun fichier avec tuuid {}", tuuid_str))?
//     };
//
//     // Verifier si on doit chargement une version different
//     let fuuid_v_courante = match &fichier.fuuid_v_courante {
//         Some(inner) => inner.as_str(),
//         None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Fuuid v courante manquant"))?
//     };
//
//     if fuuid_v_courante != fuuid_str {
//         todo!("Charger version precedente du document")
//     }
//
//     let mimetype = {
//         let version_courante = match &fichier.version_courante {
//             Some(inner) => inner,
//             None => Err(format!("InfoDocumentIndexation.emettre_commande_indexation Version courante manquante"))?
//         };
//
//         version_courante.mimetype.clone()
//     };
//
//     // let mut document_indexation: DocumentIndexation = version_courante.try_into()?;
//     // document_indexation.merge_fichier(&fichier);
//     let document_indexation: DocumentIndexation = fichier.try_into()?;
//
//     let info_index = InfoDocumentIndexation {
//         tuuid: tuuid_str.to_owned(),
//         fuuid: fuuid_str.to_owned(),
//         doc: document_indexation,
//
//         permission_duree: Some(30 * 60),  // 30 minutes
//         permission_hachage_bytes: Some(vec![fuuid_str.to_owned()]),
//     };
//
//     match mimetype.as_str().to_ascii_lowercase().as_str() {
//         "application/pdf" => {
//             debug!("Indexation document contenu pdf : {}", fuuid_str);
//             let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_INDEXER)
//                 .exchanges(vec![Securite::L3Protege])
//                 .build();
//             middleware.transmettre_commande(routage, &info_index, false).await?;
//         },
//         _ => {
//             // Format de document de base, aucun contenu a indexer
//             debug!("Indexation document metadata seulement : {}", fuuid_str);
//             gestionnaire.es_indexer("grosfichiers", fuuid_str, info_index).await?;
//             set_flag_indexe(middleware, fuuid_str).await?;
//         }
//     }
//
//     Ok(())
// }

// Set le flag indexe a true pour le fuuid (version)
pub async fn set_flag_indexe<M, S>(middleware: &M, fuuid: S) -> Result<(), String>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>
{
    let fuuid_str = fuuid.as_ref();
    let filtre = doc! { CHAMP_FUUID: fuuid_str };
    let ops = doc! {
        "$set": { CHAMP_FLAG_INDEXE: true },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };

    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(_) => (),
        Err(e) => Err(format!("traitement_index.set_flag_indexe Erreur {:?}", e))?
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
    nom: Option<String>,    // Nom du fichier
    mimetype: String,
    date_v_courante: Option<DateEpochSeconds>,

    // Champs qui proviennent du fichierRep (courant uniquement)
    titre: Option<HashMap<String, String>>,          // Dictionnaire combine
    description: Option<HashMap<String, String>>,    // Dictionnaire combine
    cuuids: Option<Vec<String>>,
    userid: Option<String>,
}

impl DocumentIndexation {
    fn merge_fichier(&mut self, fichier: &FichierDetail) {
        self.titre = fichier.titre.clone();
        self.description = fichier.description.clone();
        self.userid = fichier.user_id.clone();
        self.cuuids = fichier.cuuids.clone();
    }
}

impl TryFrom<FichierDetail> for DocumentIndexation {
    type Error = String;

    fn try_from(value: FichierDetail) -> Result<Self, Self::Error> {

        let version_courante = match value.version_courante {
            Some(v) => v,
            None => Err(format!("DocumentIndexation.try_from Erreur mapping fichier, version_courante manquante"))?
        };

        Ok(DocumentIndexation {
            nom: value.nom.clone(),
            mimetype: version_courante.mimetype.clone(),
            date_v_courante: version_courante.date_fichier.clone(),
            titre: value.titre,
            description: value.description,
            cuuids: value.cuuids,
            userid: value.user_id,
        })
    }
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
            userid: None,
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

    async fn es_reset_index(&self) -> Result<(), String>;

}

// #[derive(Debug)]
// pub struct ElasticSearchDaoImpl {
//     url: String,
//     est_pret: Mutex<bool>,
//     client: reqwest::Client,
// }

// impl ElasticSearchDaoImpl {
//     pub fn new<S>(url: S) -> Result<Self, Box<dyn Error>>
//         where S: Into<String>
//     {
//         let client = reqwest::Client::builder()
//             .timeout(core::time::Duration::new(20, 0))
//             .build()?;
//
//         Ok(ElasticSearchDaoImpl {
//             url: url.into(),
//             est_pret: Mutex::new(false),
//             client,
//         })
//     }
// }

// #[async_trait]
// impl ElasticSearchDao for ElasticSearchDaoImpl {
//     async fn es_preparer(&self) -> Result<(), String> {
//         debug!("ElasticSearchDaoImpl preparer index");
//
//         let index_json = index_grosfichiers();
//
//         let mut url_post = match Url::parse(&self.url) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur preparation url template index '{}' : {:?}", self.url, e))?
//         };
//         url_post.set_path("_index_template/grosfichiers");
//
//         // let url_post = format!("{}/_index_template/grosfichiers", self.url);
//         let response = match self.client.put(url_post).json(&index_json).send().await {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest : {:?}", e))?
//         };
//
//         debug!("ElasticSearchDaoImpl.es_preparer status: {}, {:?}", response.status(), response);
//         if response.status().is_client_error() {
//             warn!("ElasticSearchDaoImpl.es_preparer Erreur preparation index grosfichiers, contenu invalide. On le reset");
//             self.es_reset_index().await?;
//             Err(format!("Index grosfichiers supprime, va etre recree prochaine fois"))?
//         }
//
//         let mut guard = match self.est_pret.lock() {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("traitement_index.ElasticSearchDao Erreur lock est_pret : {:?}", e))?
//         };
//         *guard = true;
//
//         Ok(())
//     }
//
//     fn es_est_pret(&self) -> bool {
//         match self.est_pret.lock() {
//             Ok(inner) => *inner,
//             Err(e) => {
//                 warn!("traitement_index.ElasticSearchDaoImpl Erreur lecture mutex est_pret : {:?}", e);
//                 false
//             }
//         }
//     }
//
//     async fn es_indexer<S, T>(&self, nom_index: S, id_doc: T, info_doc: InfoDocumentIndexation)
//         -> Result<(), String>
//         where S: AsRef<str> + Send, T: AsRef<str> + Send
//     {
//         if ! self.es_est_pret() {
//             debug!("es_indexer search n'est pas disponible, rien a faire");
//             return Ok(());
//         }
//
//         let id_doc_str = id_doc.as_ref();
//
//         let doc_index = match serde_json::to_value(info_doc.doc) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_indexer Erreur conversion json info_doc : {:?}", e))?
//         };
//
//         debug!("Indexer document {:?}", doc_index);
//
//         let mut url_post = match Url::parse(&self.url) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_indexer Erreur preparation url indexation '{}' : {:?}", self.url, e))?
//         };
//         url_post.set_path(format!("{}/_doc/{}", nom_index.as_ref(), id_doc_str).as_str());
//
//         // let url_post = format!("{}{}/_doc/{}", self.url, nom_index.as_ref(), id_doc_str);
//         let response = match self.client.post(url_post.clone()).json(&doc_index).send().await {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_indexer Erreur reqwest sur url '{}' : {:?}", url_post, e))?
//         };
//
//         if ! response.status().is_success() {
//             Err(format!("ElasticSearchDaoImpl.es_indexer Erreur indexation (status {}) avec search index grosfichiers : {:?}", response.status(), response))?
//         }
//
//         debug!("ElasticSearchDaoImpl.es_indexer OK, response : {:?}", response);
//
//         Ok(())
//     }
//
//     async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresRecherche)
//         -> Result<ResultatRecherche, String>
//         where S: AsRef<str> + Send
//     {
//         if ! self.es_est_pret() {
//             debug!("es_rechercher search n'est pas disponible, rien a faire");
//             return Err(format!("ElasticSearch n'est pas disponible"));
//         }
//
//         let from_idx = match params.from_idx { Some(inner) => inner, None => 0 };
//         let size = match params.size { Some(inner) => inner, None => 20 };
//
//         let mut url_post = match Url::parse(&self.url) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_rechercher Erreur recherche avec url de base '{}' : {:?}", self.url, e))?
//         };
//         url_post.set_path(format!("{}/_search", nom_index.as_ref()).as_str());
//         url_post.set_query(Some(format!("from={}&size={}", from_idx, size).as_str()));
//
//         // let url_post = format!("{}/{}/_search?from={}&size={}", self.url, nom_index.as_ref(), from_idx, size);
//         let mut bool_params = Map::new();
//
//         let must_params = json!([
//             {"term": {"userid": &params.user_id.as_ref().expect("user_id").to_ascii_lowercase()}},
//             // {"match": {"nom": "p-101_001.1080.jpg"}},
//         ]);
//         bool_params.insert("filter".into(), must_params);
//
//         if params.mots_cles.is_some() {
//             let mots_cles = params.mots_cles.as_ref().expect("mots_cles");
//             let should_params = json!([
//                 {"match": {"contenu": mots_cles}},
//                 {"match": {"nom": mots_cles}},
//                 {"match": {"titre._combine": mots_cles}},
//                 {"match": {"description._combine": mots_cles}},
//             ]);
//             bool_params.insert("should".into(), should_params);
//         }
//
//         bool_params.insert("minimum_should_match".into(), 1.into());
//
//         let query = json!({
//             "query": {
//                 "bool": bool_params,
//             }
//         });
//
//         debug!("es_rechercher Query : {:?}", query);
//
//         // '%s/%s/_search?from=%d&size=%d' % (self.__url, nom_index, from_idx, size),
//         let response = match self.client.get(url_post.clone()).json(&query).send().await {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest '{:?}' : {:?}", url_post, e))?
//         };
//
//         if ! response.status().is_success() {
//             Err(format!("ElasticSearchDaoImpl.es_preparer Erreur search index grosfichiers : {:?}", response))?
//         }
//
//         let resultat: ResultatRecherche = match response.text().await {
//             Ok(inner) => {
//                 debug!("Resultat recherche(str) : {}", inner);
//                 match serde_json::from_str(inner.as_str()) {
//                     Ok(v) => v,
//                     Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur conversion json search grosfichiers : {:?}", e))?
//                 }
//             },
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur search grosfichiers, conversion text : {:?}", e))?
//         };
//
//         debug!("Resultat recherche : {:?}", resultat);
//
//         Ok(resultat)
//     }
//
//     async fn es_reset_index(&self) -> Result<(), String> {
//
//         if ! self.es_est_pret() {
//             debug!("es_reset_index search n'est pas disponible, rien a faire");
//             return Ok(());
//         }
//
//         info!("Reset index fichiers");
//         let url_post = format!("{}/_index_template/grosfichiers", self.url);
//         match self.client.delete(&url_post).send().await {
//             Ok(inner) => {
//                 if inner.status().is_success() {
//                     info!("Reponse reset index : {:?}", inner);
//                     self.es_preparer().await?;
//                 } else {
//                     if inner.status() == 404 {
//                         info!("ElasticSearchDaoImpl.es_reset_index Template index absent (404), on peut le creer");
//                         self.es_preparer().await?;
//                     } else {
//                         Err(format!("Template grosfichiers ne peut pas etre supprimer, code : {:?}", inner))?
//                     }
//                 }
//             },
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest delete template grosfichiers : {:?}", e))?
//         }
//
//         // Supprimer index documents grosfichiers
//         let url_post = format!("{}/grosfichiers", self.url);
//         match self.client.delete(&url_post).send().await {
//             Ok(inner) => {
//                 let status = inner.status();
//                 if status.is_success() {
//                     info!("Reponse reset index : {:?}", inner);
//                 } else {
//                     if status == 404 || status == 405 {
//                         info!("ElasticSearchDaoImpl.es_reset_index Index absent (404/405), on peut le creer");
//                     } else {
//                         Err(format!("Index grosfichiers ne peut pas etre supprimer, code : {:?}", inner))?
//                     }
//                 }
//             },
//             Err(e) => Err(format!("ElasticSearchDaoImpl.es_preparer Erreur reqwest delete index grosfichiers : {:?}", e))?
//         }
//
//         Ok(())
//     }
// }

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
                    "nom": {
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
                    "userid": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 50
                            }
                        }
                    },
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
    pub user_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermission {
    pub tuuids: Option<Vec<String>>,
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetClesStream {
    pub user_id: Option<String>,
    pub fuuids: Vec<String>,
}

// pub async fn traiter_index_manquant<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, limite: i64)
//     -> Result<Vec<String>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + ValidateurX509
// {
//     // if ! gestionnaire.es_est_pret() {
//     //     debug!("traiter_index_manquantElastic search n'est pas disponible, rien a faire");
//     //     return Ok(vec![]);
//     // }
//
//     let opts = FindOptions::builder()
//         .hint(Hint::Name(String::from("flag_indexe")))
//         .sort(doc! {CHAMP_FLAG_INDEXE: 1, CHAMP_CREATION: 1})
//         .limit(limite)
//         .build();
//
//     let filtre = doc! { CHAMP_FLAG_INDEXE: false };
//     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//     let mut curseur = collection.find(filtre, Some(opts)).await?;
//     let mut tuuids = Vec::new();
//
//     while let Some(d) = curseur.next().await {
//         let doc_version = d?;
//         let version_mappe: DBFichierVersionDetail = convertir_bson_deserializable(doc_version)?;
//         let tuuid = version_mappe.tuuid;
//         let fuuid = version_mappe.fuuid;
//         if let Some(t) = tuuid {
//             if let Some(f) = fuuid {
//                 emettre_commande_indexation(gestionnaire, middleware, &t, f).await?;
//                 tuuids.push(t);
//             }
//         }
//     }
//
//     Ok(tuuids)
// }

// #[cfg(test)]
// mod test_integration_index {
//     use millegrilles_common_rust::tokio as tokio;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn test_creation_index() {
//         setup("test_creation_index");
//         let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");
//         debug!("Test preparer index");
//         dao.es_preparer().await.expect("pret");
//     }
//
//     #[tokio::test]
//     async fn test_indexer() {
//         setup("test_indexer");
//         let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");
//         let document_index = DocumentIndexation {
//             nom: String::from("dummy_nom"),
//             mimetype: String::from("application/data"),
//             date_v_courante: DateEpochSeconds::now(),
//             titre: None, description: None, cuuids: None, user_id: None,
//         };
//         let info_doc = InfoDocumentIndexation {
//             tuuid: String::from("tuuid-abcd-1234"),
//             fuuid: String::from("fuuid-abcd-1234"),
//             doc: document_index,
//             permission_hachage_bytes: None, permission_duree: None,
//         };
//         dao.es_indexer("grosfichiers", info_doc.fuuid.clone(), info_doc).await.expect("indexer");
//     }
//
//     #[tokio::test]
//     async fn test_search() {
//         setup("test_search");
//         let dao = ElasticSearchDaoImpl::new("http://192.168.2.131:9200").expect("dao");
//
//         let params = ParametresRecherche {
//             mots_cles: Some(String::from("dadada")),
//             from_idx: Some(0),
//             size: Some(20),
//         };
//         let resultat = dao.es_rechercher("grosfichiers", &params).await.expect("search");
//         debug!("Resultat 1 test_search : {:?}", resultat);
//         assert_eq!(0, resultat.hits.expect("hits").total.value);
//
//         let params = ParametresRecherche {
//             mots_cles: Some(String::from("dummy_nom")),
//             from_idx: Some(0),
//             size: Some(20),
//         };
//         let resultat = dao.es_rechercher("grosfichiers", &params).await.expect("search");
//         debug!("Resultat 2 test_search : {:?}", resultat);
//         assert_eq!(1, resultat.hits.expect("hits").total.value);
//
//     }
//
// }

