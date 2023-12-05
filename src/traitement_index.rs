use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ops::Deref;
use std::sync::Mutex;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{DateTime, doc, Document};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::grosfichiers_constantes::*;
use crate::traitement_jobs::{BackgroundJob, CommandeGetJob, get_prochaine_job_versions, JobHandler, JobHandlerFichiersRep, JobHandlerVersions, ReponseJob};

const EVENEMENT_INDEXATION_DISPONIBLE: &str = "jobIndexationDisponible";


#[derive(Clone, Debug)]
pub struct IndexationJobHandler {}

#[async_trait]
impl JobHandler for IndexationJobHandler {

    fn get_nom_collection(&self) -> &str { NOM_COLLECTION_INDEXATION_JOBS }

    fn get_nom_flag(&self) -> &str { CHAMP_FLAG_INDEX }

    fn get_action_evenement(&self) -> &str { EVENEMENT_INDEXATION_DISPONIBLE }

    async fn marquer_job_erreur<M,G,S>(&self, middleware: &M, gestionnaire_domaine: &G, job: BackgroundJob, erreur: S)
        -> Result<(), Box<dyn Error>>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage,
            G: GestionnaireDomaine,
            S: ToString + Send
    {
        let erreur = erreur.to_string();

        let tuuid = match job.tuuid {
            Some(inner) => inner,
            None => Err(format!("traitement_index.JobHandler Tuuid manquant"))?
        };
        let user_id = job.user_id;

        self.set_flag(middleware, tuuid, Some(user_id), None, true).await?;

        Ok(())
    }
}

impl JobHandlerFichiersRep for IndexationJobHandler {}

// /// Set le flag indexe a true pour le fuuid (version)
// pub async fn set_flag_indexe<M,S,T>(middleware: &M, fuuid: S, user_id: T) -> Result<(), Box<dyn Error>>
//     where
//         M: MongoDao,
//         S: AsRef<str>,
//         T: AsRef<str>
// {
//     let fuuid = fuuid.as_ref();
//     let user_id = user_id.as_ref();
//
//     let filtre = doc! { CHAMP_FUUID: fuuid, CHAMP_USER_ID: user_id };
//     let ops = doc! {
//         "$set": { CHAMP_FLAG_INDEX: true },
//         "$currentDate": { CHAMP_MODIFICATION: true },
//     };
//
//     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//     match collection.update_one(filtre.clone(), ops, None).await {
//         Ok(_) => (),
//         Err(e) => Err(format!("traitement_index.set_flag_indexe Erreur {:?}", e))?
//     }
//
//     // Supprimer job indexation
//     let collection_jobs = middleware.get_collection(NOM_COLLECTION_INDEXATION_JOBS)?;
//     collection_jobs.delete_one(filtre, None).await?;
//
//     Ok(())
// }

pub async fn reset_flag_indexe<M,G>(middleware: &M, gestionnaire: &G, job_handler: &IndexationJobHandler) -> Result<(), Box<dyn Error>>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
        G: GestionnaireDomaine
{
    debug!("reset_flag_indexe Reset flags pour tous les fichiers");

    let filtre = doc! {};
    let ops = doc! {
        "$set": { CHAMP_FLAG_INDEX: false },
        "$unset": { CHAMP_FLAG_INDEX_ERREUR: true },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };

    // let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.update_many(filtre.clone(), ops, None).await {
        Ok(_) => (),
        Err(e) => Err(format!("traitement_index.set_flag_indexe Erreur {:?}", e))?
    }

    // Commencer a creer les jobs d'indexation
    // traiter_indexation_batch(middleware, LIMITE_INDEXATION_BATCH).await?;
    job_handler.entretien(middleware, gestionnaire, Some(LIMITE_INDEXATION_BATCH)).await;

    // Emettre un evenement pour indiquer que de nouvelles jobs sont disponibles
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_REINDEXER_CONSIGNATION)
        .exchanges(vec![Securite::L4Secure])
        .build();
    middleware.emettre_evenement(routage, &json!({})).await?;

    Ok(())
}

// // Set le flag indexe a true pour le fuuid (version)
// pub async fn ajout_job_indexation<M,S,T,U,V>(middleware: &M, tuuid: T, fuuid: S, user_id: U, mimetype: V) -> Result<(), Box<dyn Error>>
//     where
//         M: MongoDao,
//         S: AsRef<str>,
//         T: AsRef<str>,
//         U: AsRef<str>,
//         V: AsRef<str>
// {
//     let tuuid = tuuid.as_ref();
//     let fuuid = fuuid.as_ref();
//     let user_id = user_id.as_ref();
//     let mimetype = mimetype.as_ref();
//
//     let filtre = doc! { CHAMP_FUUID: fuuid, CHAMP_USER_ID: user_id };
//     let ops = doc! {
//         "$set": { CHAMP_FLAG_INDEX: true },
//         "$currentDate": { CHAMP_MODIFICATION: true },
//     };
//
//     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//     match collection.update_one(filtre.clone(), ops, None).await {
//         Ok(_) => (),
//         Err(e) => Err(format!("traitement_index.set_flag_indexe Erreur {:?}", e))?
//     }
//
//     // Supprimer job indexation
//     let collection_jobs = middleware.get_collection(NOM_COLLECTION_INDEXATION_JOBS)?;
//     let now = Utc::now();
//     let ops_job = doc! {
//         "$setOnInsert": {
//             CHAMP_FUUID: fuuid,
//             CHAMP_USER_ID: user_id,
//             CHAMP_CREATION: &now,
//         },
//         "$set": {
//             CHAMP_TUUID: tuuid,
//             CHAMP_MIMETYPE: mimetype,
//             CHAMP_FLAG_INDEX_ETAT: VIDEO_CONVERSION_ETAT_PENDING,
//             CHAMP_FLAG_INDEX_RETRY: 0,
//         },
//         "$currentDate": {
//             CHAMP_MODIFICATION: true,
//         }
//     };
//     let options = UpdateOptions::builder()
//         .upsert(true)
//         .build();
//     collection_jobs.update_one(filtre.clone(), ops_job, options).await?;
//
//     Ok(())
// }

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

// #[async_trait]
// pub trait ElasticSearchDao {
//     async fn es_preparer(&self) -> Result<(), String>;
//
//     /// Retourne true si le serveur est pret (accessible, index generes)
//     fn es_est_pret(&self) -> bool;
//
//     async fn es_indexer<S, T>(&self, nom_index: S, id_doc: T, info_doc: InfoDocumentIndexation)
//         -> Result<(), String>
//         where S: AsRef<str> + Send, T: AsRef<str> + Send;
//
//     async fn es_rechercher<S>(&self, nom_index: S, params: &ParametresRecherche)
//         -> Result<ResultatRecherche, String>
//         where S: AsRef<str> + Send;
//
//     async fn es_reset_index(&self) -> Result<(), String>;
//
// }

// pub async fn traiter_indexation_batch<M>(middleware: &M, limite: i64)
//     -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao
// {
//     debug!("traiter_indexation_batch limite {}", limite);
//
//     // let mut tuuids = Vec::new();
//     // let mut fuuids_media = Vec::new();
//     // let mut fuuids_retry_expire = Vec::new();
//
//     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//     let collection_indexation = middleware.get_collection(NOM_COLLECTION_INDEXATION_JOBS)?;
//
//     // if reset == true {
//     //     // Reset les flags de traitement media de tous les fichiers
//     //     let ops = doc!{
//     //         "$set": { CHAMP_FLAG_INDEX: false },
//     //         "$unset": { CHAMP_FLAG_MEDIA_ERREUR: true },
//     //         "$currentDate": { CHAMP_MODIFICATION: true },
//     //     };
//     //     collection_versions.update_many(doc!{}, ops, None).await?;
//     // }
//
//     // Reset jobs indexation avec start_date expire
//     {
//         let filtre_start_expire = doc! {
//             CHAMP_FLAG_INDEX_ETAT: VIDEO_CONVERSION_ETAT_RUNNING,
//             CHAMP_INDEX_START: { "$lte": Utc::now() - Duration::seconds(300) },
//         };
//         let ops_expire = doc! {
//             "$set": { CHAMP_FLAG_INDEX_ETAT: VIDEO_CONVERSION_ETAT_PENDING },
//             "$unset": { CHAMP_INDEX_START: true },
//             "$currentDate": { CHAMP_MODIFICATION: true },
//         };
//         collection_indexation.update_many(filtre_start_expire, ops_expire, None).await?;
//     }
//
//     let mut curseur = {
//         let opts = FindOptions::builder()
//             // .hint(Hint::Name(String::from("flag_media_traite")))
//             .sort(doc! {CHAMP_FLAG_INDEX: 1, CHAMP_CREATION: 1})
//             .limit(limite)
//             .build();
//         let filtre = doc! { CHAMP_FLAG_INDEX: false };
//         debug!("traiter_indexation_batch filtre {:?}", filtre);
//         collection_versions.find(filtre, Some(opts)).await?
//     };
//     while let Some(d) = curseur.next().await {
//         let doc_version = d?;
//         let version_mappe: DBFichierVersionDetail = convertir_bson_deserializable(doc_version)?;
//
//         if version_mappe.tuuid.is_some() && version_mappe.fuuid.is_some() && version_mappe.user_id.is_some() {
//             let tuuid_ref = version_mappe.tuuid.as_ref().expect("tuuid_ref");
//             let fuuid_ref = version_mappe.fuuid.as_ref().expect("fuuid_ref");
//             let user_id = version_mappe.user_id.as_ref().expect("user_id");
//             let mimetype_ref = version_mappe.mimetype.as_str();
//
//             let filtre = doc!{CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid_ref};
//
//             let job_existante: Option<JobIndexation> = match collection_indexation.find_one(filtre.clone(), None).await? {
//                 Some(inner) => Some(convertir_bson_deserializable(inner)?),
//                 None => None
//             };
//
//             if let Some(job) = job_existante {
//                 if job.index_retry > MEDIA_RETRY_LIMIT {
//                     warn!("traiter_indexation_batch Expirer indexation sur document user_id {} tuuid {} : {} retries",
//                         user_id, tuuid_ref, job.index_retry);
//                     let ops = doc!{
//                         "$set": {
//                             CHAMP_FLAG_INDEX: true,
//                             CHAMP_FLAG_INDEX_ERREUR: ERREUR_MEDIA_TOOMANYRETRIES,
//                         }
//                     };
//                     collection_versions.update_one(filtre.clone(), ops, None).await?;
//                     collection_indexation.delete_one(filtre.clone(), None).await?;
//                     continue;
//                 }
//             }
//
//             // Creer ou mettre a jour la job
//             let now = Utc::now();
//             let ops_job = doc! {
//                 "$setOnInsert": {
//                     CHAMP_TUUID: tuuid_ref,
//                     CHAMP_FUUID: fuuid_ref,
//                     CHAMP_USER_ID: user_id,
//                     CHAMP_MIMETYPE: mimetype_ref,
//                     CHAMP_FLAG_INDEX_ETAT: VIDEO_CONVERSION_ETAT_PENDING,
//                     CHAMP_FLAG_INDEX_RETRY: 0,
//                     CHAMP_CREATION: &now,
//                     CHAMP_MODIFICATION: now,
//                 }
//             };
//             let options = UpdateOptions::builder()
//                 .upsert(true)
//                 .build();
//             collection_indexation.update_one(filtre.clone(), ops_job, options).await?;
//         } else {
//             // Skip, mauvais fichier
//             warn!("traiter_indexation_batch Fichier sans tuuid, fuuid ou user_id - SKIP");
//         }
//     }
//
//     // if fuuids_retry_expire.len() > 0 {
//     //     // Desactiver apres trop d'echecs de retry
//     //     let filtre_retry = doc!{CHAMP_FUUID: {"$in": fuuids_retry_expire}};
//     //     let ops = doc!{
//     //         "$set": {
//     //             CHAMP_FLAG_INDEX: true,
//     //             CHAMP_FLAG_INDEX_ERREUR: ERREUR_MEDIA_TOOMANYRETRIES,
//     //         },
//     //         "$currentDate": {CHAMP_MODIFICATION: true},
//     //     };
//     //     collection_versions.update_many(filtre_retry, ops, None).await?;
//     //
//     //     // Maj le retry count
//     //     if fuuids_media.len() > 0 {
//     //         let filtre_retry = doc!{CHAMP_FUUID: {"$in": fuuids_media}};
//     //         let ops = doc!{
//     //             "$inc": {
//     //                 CHAMP_FLAG_MEDIA_RETRY: 1,
//     //             },
//     //             "$currentDate": {CHAMP_MODIFICATION: true},
//     //         };
//     //         collection_versions.update_many(filtre_retry, ops, None).await?;
//     //     }
//     // } else
//     // if reset == true {
//     //     // Reset les flags de traitement media
//     //     let filtre_retry = doc!{CHAMP_FUUID: {"$in": &fuuids_media}};
//     //     let ops = doc!{
//     //         "$set": {
//     //             CHAMP_FLAG_MEDIA_TRAITE: false,
//     //             CHAMP_FLAG_MEDIA_RETRY: 0,
//     //         },
//     //         "$unset": {CHAMP_FLAG_MEDIA_ERREUR: true},
//     //         "$currentDate": {CHAMP_MODIFICATION: true},
//     //     };
//     //     collection_versions.update_many(filtre_retry, ops, None).await?;
//     // }
//
//     Ok(())
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

pub async fn commande_indexation_get_job<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_indexation_get_job Consommer commande : {:?}", & m.message);
    let commande: CommandeIndexationGetJob = m.message.get_msg().map_contenu()?;

    // Verifier autorisation
    if ! m.verifier_exchanges(vec![Securite::L4Secure]) {
        info!("commande_indexation_get_job Exchange n'est pas de niveau 4");
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
    }

    if ! m.verifier_roles(vec![RolesCertificats::SolrRelai]) {
        info!("commande_indexation_get_job Role n'est pas solrrelai");
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre solrrelai)"}), None)?))
    }

    let certificat = match m.message.certificat {
        Some(inner) => inner,
        None => Err(format!("commandes.commande_indexation_get_job Certificat absent du message"))?
    };

    let commande_get_job = CommandeGetJob { instance_id: commande.instance_id, fallback: None };
    let reponse_prochaine_job = gestionnaire.indexation_job_handler.get_prochaine_job(
        middleware, certificat.as_ref(), commande_get_job).await?;

    debug!("commande_indexation_get_job Prochaine job : {:?}", reponse_prochaine_job);
    Ok(Some(middleware.formatter_reponse(reponse_prochaine_job, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresRecherche {
    pub mots_cles: String,
    pub from_idx: Option<u32>,
    pub size: Option<u32>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermission {
    pub tuuids: Option<Vec<String>>,
    pub fuuids: Vec<String>,
    pub partage: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetClesStream {
    pub user_id: Option<String>,
    pub fuuids: Vec<String>,
    pub jwt: Option<String>,
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

