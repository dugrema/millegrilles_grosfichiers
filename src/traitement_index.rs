use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use std::sync::Mutex;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{DateTime, Duration, Utc};
use millegrilles_common_rust::common_messages::{verifier_reponse_ok, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable, sauvegarder_traiter_transaction_serializable_v2};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, start_transaction_regeneration, start_transaction_regular, verifier_erreur_duplication_mongo, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::tokio::time::timeout;
use crate::data_structs::CompleteFileRow;
use crate::domain_manager::GrosFichiersDomainManager;
use crate::grosfichiers_constantes::*;
use crate::requetes::get_file_keys;
use crate::traitement_jobs::{BackgroundJob, JobHandler, JobHandlerVersions, sauvegarder_job, JobTrigger, reactiver_jobs, create_missing_jobs_indexing};
use crate::transactions::{NodeFichierRepBorrowed, NodeFichierRepOwned, NodeFichierVersionOwned, TransactionSupprimerOrphelins};

const EVENEMENT_INDEXATION_DISPONIBLE: &str = "jobIndexationDisponible";
const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";

#[derive(Clone, Debug)]
pub struct IndexationJobHandler {}

pub async fn reset_flag_indexe<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("reset_flag_indexe Reset flags pour tous les fichiers");

    // Commit transaction or it will timeout. Changing all documents.
    session.commit_transaction().await?;

    let filtre = doc! {};
    let ops = doc! {
        "$set": { CHAMP_FLAG_INDEX: false, "flag_rag": false },
        "$unset": { CHAMP_FLAG_INDEX_ERREUR: true },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };

    // Reset tables rep et versions
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    // collection.update_many_with_session(filtre.clone(), ops.clone(), None, session).await?;
    collection.update_many(filtre.clone(), ops.clone(), None).await?;
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    // collection.update_many_with_session(filtre.clone(), ops, None, session).await?;
    collection.update_many(filtre.clone(), ops, None).await?;

    // // Restart transaction after to get access to all data just modified
    // start_transaction_regular(session).await?;
    //
    // // Index - tables VERSION et FICHIER_REP
    // debug!("Create batch of files to index after reset");
    // create_missing_jobs_indexing(middleware).await?;
    //
    // // Commit changes.
    // session.commit_transaction().await?;

    // Reset le serveur d'indexation
    let routage = RoutageMessageAction::builder("solrrelai", "reindexerConsignation", vec![Securite::L3Protege])
        .timeout_blocking(5_000)
        .build();
    let result = match middleware.transmettre_commande(routage, json!({})).await? {
        Some(inner) => verifier_reponse_ok(&inner),
        None => false
    };

    if ! result {
        warn!("Timeout/error resetting indexing server, will start new index batch anyway");
        // return Ok(Some(middleware.reponse_err(Some(1), None, Some("Error resetting indexing server"))?))
    }

    // Restart transaction after to get access to all data just modified
    start_transaction_regular(session).await?;

    // // Start reindexing.
    // debug!("Create first batch of files to index after reset");
    // reactiver_jobs(middleware, NOM_COLLECTION_INDEXATION_JOBS, 0, 2000, "solrrelai", "processIndex", true, session).await?;
    // debug!("First batch created, reindexing started");

    Ok(Some(middleware.reponse_ok(None, None)?))
}

// /// Format de document pret a etre indexe
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct InfoDocumentIndexation {
//     tuuid: String,
//     fuuid: String,
//     doc: DocumentIndexation,
//
//     // Info permission dechiffrage
//     permission_duree: Option<u32>,
//     permission_hachage_bytes: Option<Vec<String>>,
// }

/// Contenu et mots-cles pour l'indexation d'un document
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DocumentIndexation {
//     nom: Option<String>,    // Nom du fichier
//     mimetype: String,
//     date_v_courante: Option<DateTime<Utc>>,
//
//     // Champs qui proviennent du fichierRep (courant uniquement)
//     titre: Option<HashMap<String, String>>,          // Dictionnaire combine
//     description: Option<HashMap<String, String>>,    // Dictionnaire combine
//     cuuids: Option<Vec<String>>,
//     userid: Option<String>,
// }
//
// impl DocumentIndexation {
//     fn merge_fichier(&mut self, fichier: &FichierDetail) {
//         self.titre = fichier.titre.clone();
//         self.description = fichier.description.clone();
//         self.userid = fichier.user_id.clone();
//         self.cuuids = fichier.path_cuuids.clone();
//     }
// }
//
// impl TryFrom<FichierDetail> for DocumentIndexation {
//     type Error = String;
//
//     fn try_from(value: FichierDetail) -> Result<Self, Self::Error> {
//
//         let version_courante = match value.version_courante {
//             Some(v) => v,
//             None => Err(format!("DocumentIndexation.try_from Erreur mapping fichier, version_courante manquante"))?
//         };
//
//         Ok(DocumentIndexation {
//             nom: value.nom.clone(),
//             mimetype: version_courante.mimetype.clone(),
//             date_v_courante: version_courante.date_fichier.clone(),
//             titre: value.titre,
//             description: value.description,
//             cuuids: value.path_cuuids,
//             userid: value.user_id,
//         })
//     }
// }
//
// impl TryFrom<DBFichierVersionDetail> for DocumentIndexation {
//     type Error = String;
//
//     fn try_from(value: DBFichierVersionDetail) -> Result<Self, Self::Error> {
//         Ok(DocumentIndexation {
//             nom: value.nom.clone(),
//             mimetype: value.mimetype.clone(),
//             date_v_courante: value.date_fichier.clone(),
//             titre: None,
//             description: None,
//             cuuids: None,
//             userid: None,
//         })
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
    pub mots_cles: String,
    pub from_idx: Option<u32>,
    pub size: Option<u32>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermission {
    pub tuuids: Option<Vec<String>>,
    pub fuuids: Option<Vec<String>>,
    pub cle_ids: Option<Vec<String>>,
    pub partage: Option<bool>,
    pub version: Option<i8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetClesStream {
    pub user_id: Option<String>,
    pub fuuids: Vec<String>,
    pub jwt: Option<String>,
}

#[derive(Serialize)]
struct SupprimerIndexTuuids {
    tuuids: Vec<String>,
}

pub async fn entretien_supprimer_fichiersrep<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    debug!("entretien_supprimer_fichiersrep Debut");

    // Emettre retrait de l'index et toggle le flag index de true -> false pour les fichiers supprimes
    if let Err(e) = entretien_supprimer_fichiersrep_index(middleware).await {
        error!("entretien_supprimer_fichiersrep Erreur entretien_supprimer_fichiersrep_index : {:?}", e)
    }

    // Retirer les visites expirees
    if let Err(e) = entretien_supprimer_visites_expirees(middleware).await {
        error!("entretien_supprimer_fichiersrep Erreur entretien_supprimer_visites_expirees : {:?}", e)
    }

    // Retirer les fichiers supprimes et sans visites restantes.
    if let Err(e) = entretien_retirer_supprimes_sans_visites(middleware, gestionnaire).await {
        error!("entretien_supprimer_fichiersrep Erreur entretien_retirer_supprimes_sans_visites : {:?}", e)
    }

    Ok(())
}

#[derive(Deserialize)]
struct InstanceTopologie {
    instance_id: String,
}

#[derive(Deserialize)]
struct ReponseTopologieInstance {
    pub resultats: Vec<InstanceTopologie>,
}

async fn entretien_supprimer_visites_expirees<M>(middleware: &M)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match entretien_supprimer_visites_expirees_session(middleware, &mut session).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn entretien_supprimer_visites_expirees_session<M>(middleware: &M, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    debug!("entretien_supprimer_visites_expirees Debut");

    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, REQUETE_LISTE_NOEUDS, vec![Securite::L3Protege])
        .build();
    let requete = json!({});

    let instances_topologie: ReponseTopologieInstance = match middleware.transmettre_requete(routage, &requete).await? {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let reponse_ref = reponse.message.parse()?;
                reponse_ref.contenu()?.deserialize()?
            },
            _ => Err(format!("Mauvais type reponse pour requete topologie"))?
        },
        None => Err(format!("Aucune reponse pour requete topologie"))?
    };

    let expiration_visite = Utc::now() - Duration::days(3);
    // let expiration_ts = (expiration_visite.timestamp());

    let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_VERSIONS)?;
    for instance in instances_topologie.resultats {
        let filtre = doc! { format!("visites.{}", instance.instance_id): {"$lt": expiration_visite} };
        let ops = doc! {
            "$unset": {format!("visites.{}", instance.instance_id): true},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        debug!("entretien_supprimer_visites_expirees Filtre : {:?}, Ops: {:?}", filtre, ops);
        collection.update_many_with_session(filtre, ops, None, session).await?;
    }

    debug!("entretien_supprimer_visites_expirees Fin");
    Ok(())
}

async fn entretien_supprimer_fichiersrep_index<M>(middleware: &M)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match entretien_supprimer_fichiersrep_index_session(middleware, &mut session).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            // error!("creer_jobs_manquantes_session Error: {:?}", e);
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn entretien_supprimer_fichiersrep_index_session<M>(middleware: &M, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    debug!("entretien_supprimer_fichiersrep_index Debut");

    let filtre = doc!{
        CHAMP_FLAG_INDEX: true,
        "$or": [
            {CHAMP_SUPPRIME: true},
            {CHAMP_SUPPRIME_INDIRECT: true}
        ]
    };
    let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
        NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find_with_session(filtre, None, session).await?;

    let mut tuuids_supprimer = Vec::new();
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        tuuids_supprimer.push(row.tuuid.to_owned());
        if tuuids_supprimer.len() > 1000 {
            // On limite a 1000 suppression a la fois
            break
        }
    }

    if tuuids_supprimer.len() > 0 {
        info!("entretien_supprimer_fichiersrep_index Supprimer indexation sur {} tuuids", tuuids_supprimer.len());
        let domaine: &str = RolesCertificats::SolrRelai.into();
        let routage = RoutageMessageAction::builder(domaine, "supprimerTuuids", vec![Securite::L4Secure])
            .timeout_blocking(30_000)
            .build();
        let commande = SupprimerIndexTuuids { tuuids: tuuids_supprimer.clone() };
        middleware.transmettre_commande(routage, &commande).await?;

        // Marquer tuuids comme non indexes
        let filtre = doc!{ CHAMP_TUUID: {"$in": tuuids_supprimer} };
        let ops = doc!{
            "$set": {CHAMP_FLAG_INDEX: false},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        collection.update_many_with_session(filtre, ops, None, session).await?;
    }

    debug!("entretien_supprimer_fichiersrep_index Fin");
    Ok(())
}

async fn entretien_retirer_supprimes_sans_visites<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match entretien_retirer_supprimes_sans_visites_session(middleware, gestionnaire, &mut session).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            // error!("creer_jobs_manquantes_session Error: {:?}", e);
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn entretien_retirer_supprimes_sans_visites_session<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    warn!("entretien_retirer_supprimes_sans_visites_session Disabled");
    // debug!("entretien_retirer_supprimes_sans_visites Debut");
    //
    // let filtre = doc! {
    //     CHAMP_SUPPRIME: true,  // TODO : fix for new approach tuuids.0
    //     "$or": [
    //         {CHAMP_VISITES: doc!{}},
    //         {CHAMP_VISITES: {"$exists": false}}
    //     ]
    // };
    // let fuuids_supprimes = {
    //     let mut fuuids_supprimes = Vec::new();
    //     let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
    //     let options = FindOptions::builder().limit(1000).build();
    //     let mut curseur = collection.find_with_session(filtre, options, session).await?;
    //     while curseur.advance(session).await? {
    //         let row = curseur.deserialize_current()?;
    //         fuuids_supprimes.push(row.fuuid.to_owned());
    //     }
    //     fuuids_supprimes
    // };
    //
    // debug!("entretien_retirer_supprimes_sans_visites Nouvelle transaction orphelins : {:?}", fuuids_supprimes);
    // let transaction = TransactionSupprimerOrphelins { fuuids: fuuids_supprimes };
    //
    // sauvegarder_traiter_transaction_serializable_v2(
    //     middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_SUPPRIMER_ORPHELINS).await?;

    Ok(())
}

pub async fn set_flag_index_traite<M>(middleware: &M, job_id: &str, tuuid: &str, fuuid: Option<&str>, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao
{
    if let Some(fuuid) = fuuid {
        // Set flag versionFichiers
        let filtre = doc! {"fuuid": fuuid, "tuuid": tuuid};
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let ops = doc! {
            "$set": {CHAMP_FLAG_INDEX: true},
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        collection.update_many_with_session(filtre, ops, None, session).await?;
    }

    // Set flag version reps (si applicable)
    let filtre = doc! {"tuuid": tuuid};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let ops = doc! {
        "$set": {CHAMP_FLAG_INDEX: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_many_with_session(filtre, ops, None, session).await?;

    // Supprimer job image
    let filtre_job = doc!{"job_id": &job_id};
    let collection = middleware.get_collection(NOM_COLLECTION_INDEXATION_JOBS)?;
    collection.delete_many_with_session(filtre_job, None, session).await?;

    Ok(())
}


pub async fn sauvegarder_job_index<M>(middleware: &M, job: &BackgroundJob, session: &mut ClientSession) -> Result<BackgroundJob, CommonError>
where M: MongoDao + GenerateurMessages
{
    // Charger metadata dans le trigger
    let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc!{"tuuid": &job.tuuid};
    let trigger = match collection.find_one_with_session(filtre, None, session).await? {
        Some(fichier) => {
            let mut trigger = JobTrigger::from(job);
            trigger.metadata = Some(fichier.metadata);
            trigger.path_cuuids = fichier.path_cuuids;
            trigger
        },
        None => Err(CommonError::String(format!("sauvegarder_job_index Fichier inconnu tuuid:{}", job.tuuid)))?
    };

    sauvegarder_job(middleware, job, Some(trigger), NOM_COLLECTION_INDEXATION_JOBS, "solrrelai", "processIndex", session).await
}

#[derive(Serialize)]
pub struct LeaseResponse {
    tuuid: String,
    user_id: String,
    metadata: DataChiffre,
    mimetype: Option<String>,
    cuuids: Option<Vec<String>>,
    version: Option<NodeFichierVersionOwned>,  // Option for folders, no file content
}

#[derive(Serialize)]
pub struct LeasesResponse {
    ok: bool,
    leases: Vec<LeaseResponse>,
    secret_keys: Vec<ResponseRequestDechiffrageV2Cle>,
}

/// Lease a batch of files based on a FichiersRep filtre.
pub async fn lease_batch_fichiersrep<M>(middleware: &M, expiry: &DateTime<Utc>, borrower: &str, filtre: Document, batch_size: usize, filehost_id: Option<String>)
    -> Result<Option<LeasesResponse>, CommonError>
where M: MongoDao + GenerateurMessages
{
    let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    // let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    info!("lease_batch_fichiersrep Getting batch for {}, batch size: {}", borrower, batch_size);
    
    // Built aggregation pipeline on fichiers_rep joining on versions for files
    let mut pipeline = vec![doc! {"$match": filtre}]; // Match on fichiers_rep

    // Move all content under fichierrep doc for easier mapping to CompleteFileRow
    pipeline.push(doc!{"$replaceRoot": {"newRoot": {"fichierrep": "$$ROOT"}}});

    // Join version information
    pipeline.push(doc!{"$lookup": {
            "from": NOM_COLLECTION_VERSIONS,
            "localField": "fichierrep.fuuids_versions.0",
            "foreignField": "fuuid",
            "as": "versions",
        }}
    );
    pipeline.push(doc!{"$addFields": {
        "tuuid": "$fichierrep.tuuid",   // Used for troubleshooting deserialization errors
        "current_version": {"$arrayElemAt": ["$versions", 0]},
    }});
    pipeline.push(doc!{"$unset": "versions"});

    let mut leases = Vec::with_capacity(batch_size);

    let mut cursor = collection.aggregate(pipeline, None).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let tuuid = row.get_str("tuuid").unwrap_or("UNKNOWN").to_string();
        let row: CompleteFileRow = match convertir_bson_deserializable(row) {
            Ok(inner) => inner,
            Err(e) => {
                warn!("get_complete_files Deserialization error on tuuid {}: {:?}", tuuid, e);
                continue    // Skip this entry
            }
        };
        
        let file = row.fichierrep;
        let version = row.current_version;

        // Attempt a lease on the file
        if lease_file(middleware, file.user_id.as_str(), file.tuuid.as_str(), borrower, expiry).await? {
            // Add the file to leases
            let cuuids = match file.path_cuuids {
                None => None,
                Some(cuuids) => {
                    Some(cuuids.into_iter().map(|c| c.to_string()).collect())
                }
            };
            leases.push(LeaseResponse {
                tuuid: file.tuuid.to_string(),
                user_id: file.user_id.to_string(),
                metadata: file.metadata.into(),
                cuuids,
                mimetype: match file.mimetype { Some(inner) => Some(inner.to_string()), None => None},
                version,
            });
        }

        if leases.len() >= batch_size {
            break
        }
    }

    info!("lease_batch_fichiersrep Batch for {} ready: {} leases", borrower, leases.len());

    if leases.len() > 0 {
        info!("lease_batch_fichiersrep Fetching decryption keys for {} leases for borrower {}", leases.len(), borrower);
        // Get all decrypted keys for the files
        let mut cle_ids = HashSet::with_capacity(leases.len());
        for lease in &leases {
            if let Some(cle_id) = lease.metadata.cle_id.as_ref() {
                cle_ids.insert(cle_id);
            } else if let Some(ref_hachage_bytes) = lease.metadata.ref_hachage_bytes.as_ref() {
                cle_ids.insert(ref_hachage_bytes);  // Legacy
            }
            if let Some(version) = lease.version.as_ref() {
                if let Some(cle_id) = version.cle_id.as_ref() {
                    cle_ids.insert(cle_id);
                } else {
                    cle_ids.insert(&version.fuuid);  // Legacy
                }
            }
        }
        let secret_keys = get_file_keys(middleware, cle_ids).await?;
        Ok(Some(LeasesResponse { ok: true, leases, secret_keys }))
    } else {
        Ok(None)
    }
}

/// Leases a file. Returns true when successful.
async fn lease_file<M>(middleware: &M, user_id: &str, tuuid: &str, borrower: &str, expiry: &DateTime<Utc>) -> Result<bool, CommonError>
    where M: MongoDao
{
    let filtre = doc!{
        "tuuid": tuuid,
        "user_id": user_id,
        "borrower": borrower,
        "lease_date": {"$lt": expiry},
    };
    let ops = doc!{
        "$currentDate": {"lease_date": true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_JOBS_LEASES)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(inner) => {
            // Returns true when a lease record is added or updated - this means the lease is successful
            Ok(inner.modified_count == 1 || inner.upserted_id.is_some())
        },
        Err(err) => {
            if verifier_erreur_duplication_mongo(&err.kind) {
                // The existing record is not expired - this caused a duplication on upsert
                Ok(false)
            } else {
                Err(err)?
            }
        }
    }
}

async fn lease_file_version<M>(middleware: &M, fuuid: &str, borrower: &str, expiry: &DateTime<Utc>) -> Result<bool, CommonError>
where M: MongoDao
{
    let filtre = doc!{
        "fuuid": fuuid,
        "borrower": borrower,
        "lease_date": {"$lt": expiry},
    };
    let ops = doc!{
        "$currentDate": {"lease_date": true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_JOBS_VERSIONS_LEASES)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(inner) => {
            // Returns true when a lease record is added or updated - this means the lease is successful
            Ok(inner.modified_count == 1 || inner.upserted_id.is_some())
        },
        Err(err) => {
            if verifier_erreur_duplication_mongo(&err.kind) {
                // The existing record is not expired - this caused a duplication on upsert
                Ok(false)
            } else {
                Err(err)?
            }
        }
    }
}

#[derive(Serialize)]
pub struct VersionLeasesResponse {
    ok: bool,
    leases: Vec<NodeFichierVersionOwned>,
    secret_keys: Vec<ResponseRequestDechiffrageV2Cle>,
}

/// Lease a batch of files based on a FichiersRep filtre.
pub async fn lease_batch_fichiersversion<M>(middleware: &M, expiry: &DateTime<Utc>, borrower: &str, filtre: Document, batch_size: usize, filehost_id: Option<String>)
    -> Result<Option<VersionLeasesResponse>, CommonError>
where M: MongoDao + GenerateurMessages
{
    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let mut cursor = collection_versions.find(filtre, None).await?;
    let mut leases = Vec::with_capacity(batch_size);
    while cursor.advance().await? {
        let file = cursor.deserialize_current()?;

        // Attempt a lease on the file
        if lease_file_version(middleware, &file.fuuid, borrower, expiry).await? {
            leases.push(file);
        }

        if leases.len() >= batch_size {
            break
        }
    }

    if leases.len() > 0 {
        info!("lease_batch_fichiersrep Fetching decryption keys for {} leases for borrower {}", leases.len(), borrower);
        // Get all decrypted keys for the files
        let mut cle_ids = HashSet::with_capacity(leases.len());
        for lease in &leases {
            if let Some(cle_id) = lease.cle_id.as_ref() {
                cle_ids.insert(cle_id);
            } else {
                cle_ids.insert(&lease.fuuid);  // Legacy
            }
        }
        let secret_keys = get_file_keys(middleware, cle_ids).await?;
        Ok(Some(VersionLeasesResponse { ok: true, leases, secret_keys }))
    } else {
        Ok(None)
    }
}
