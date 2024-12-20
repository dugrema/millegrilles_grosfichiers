use std::collections::HashMap;
use std::str::from_utf8;
use log::{debug, error, info, warn};

use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{Bson, DateTime, doc}, serde_json};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage_cle::{InformationCle, ReponseDechiffrageCles};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::{InformationDechiffrageV2, ReponseRequeteDechiffrageV2, RequeteDechiffrage};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao, opt_chrono_datetime_as_bson_datetime, start_transaction_regular};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::{chrono, millegrilles_cryptographie, uuid};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleSecreteSerialisee;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::uuid::{uuid, Uuid};
use serde::{Deserialize, Serialize};
use crate::domain_manager::GrosFichiersDomainManager;
use crate::grosfichiers_constantes::*;
use crate::requetes::get_decrypted_keys;
use crate::traitement_entretien::sauvegarder_visites;
use crate::traitement_index::set_flag_index_traite;
use crate::traitement_media::emettre_processing_trigger;
use crate::transactions::{NodeFichierRepBorrowed, NodeFichierRepOwned, NodeFichierRepRow, NodeFichierVersionOwned, TransactionSupprimerJobVideoV2};

const CONST_MAX_RETRY: i32 = 4;
const CONST_LIMITE_BATCH: i64 = 1_000;
const CONST_EXPIRATION_SECS: i64 = 180;
const CONST_INTERVALLE_ENTRETIEN: u64 = 60;

const CONST_CHAMP_RETRY: &str = "retry";
const CONST_CHAMP_DATE_MAJ: &str = "date_maj";

#[async_trait]
pub trait JobHandler: Clone + Sized + Sync {
    /// Nom de la collection ou se trouvent les jobs
    fn get_nom_collection(&self) -> &str;

    /// Retourne le nom du flag de la table GrosFichiers/versionFichiers pour ce type de job.
    fn get_nom_flag(&self) -> &str;

    /// Retourne l'action a utiliser dans le routage de l'evenement trigger.
    fn get_action_evenement(&self) -> &str;

    /// Marque une job comme terminee avec erreur irrecuperable.
    async fn marquer_job_erreur<M,G,S>(&self, middleware: &M, gestionnaire_domaine: &G, job: BackgroundJob, erreur: S)
        -> Result<(), CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            G: GestionnaireDomaineV2 + AiguillageTransactions,
            S: ToString + Send;

    /// Emettre un evenement de job disponible.
    /// evenements emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job<M>(&self, middleware: &M, batch_size: Option<i64>)
        where M: GenerateurMessages + MongoDao + ValidateurX509
    {
        let batch_size = batch_size.unwrap_or_else(||CONST_LIMITE_BATCH);

        error!("emettre_evenements_job TODO - FIX ME!");
        // let visites = match trouver_jobs_instances(middleware, self).await {
        //     Ok(visites) => match visites {
        //         Some(inner) => inner,
        //         None => {
        //             debug!("JobHandler.emettre_evenements_job Aucune job pour {}", self.get_action_evenement());
        //             return  // Rien a faire
        //         }
        //     },
        //     Err(e) => {
        //         error!("JobHandler.emettre_evenements_job Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
        //         return
        //     }
        // };
        //
        // for filehost_id in visites {
        //     self.emettre_trigger(middleware, filehost_id, fuuid, mimetype).await;
        // }
    }

    /// Emet un evenement pour declencher le traitement pour une instance
    async fn emettre_trigger<M,I>(&self, middleware: &M, background_job: &BackgroundJob)
    where M: GenerateurMessages {

        let trigger = JobTrigger::from(background_job);

        for filehost_id in &background_job.filehost_ids {
            let routage = RoutageMessageAction::builder("media", self.get_action_evenement(), vec![Securite::L3Protege])
                .partition(filehost_id)
                .build();
            if let Err(e) = middleware.emettre_evenement(routage, &trigger).await {
                error!("JobHandler.emettre_trigger Erreur emission trigger {} : {:?}", self.get_action_evenement(), e);
            }
        }
    }

    // async fn sauvegarder_job<M,S,U>(
    //     &self, middleware: &M, fuuid: S, user_id: U, instance: Option<String>,
    //     champs_cles: Option<HashMap<String, String>>,
    //     parametres: Option<HashMap<String, Bson>>,
    //     emettre_trigger: bool
    // )
    //     -> Result<(), CommonError>
    //     where M: GenerateurMessages + MongoDao,
    //           S: AsRef<str> + Send, U: AsRef<str> + Send
    // {
    //     let instances = sauvegarder_job(middleware, self, fuuid, user_id, instance.clone(), champs_cles, parametres).await?;
    //     if let Some(inner) = instances {
    //         if emettre_trigger {
    //             for instance in inner.into_iter() {
    //                 self.emettre_trigger(middleware, instance).await;
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    // /// Set le flag de traitement complete
    // async fn set_flag<M,S,U>(
    //     &self, middleware: &M, fuuid: S, user_id: Option<U>,
    //     cles_supplementaires: Option<HashMap<String, String>>,
    //     valeur: bool
    // ) -> Result<(), CommonError>
    // where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
    //     set_flag(middleware, self, fuuid, user_id, cles_supplementaires, valeur).await
    // }

    // async fn get_prochaine_job<M>(&self, middleware: &M, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
    //     -> Result<ReponseJob, CommonError>
    //     where M: GenerateurMessages + MongoDao
    // {
    //     get_prochaine_job_versions(middleware, self.get_nom_collection(), certificat, commande).await
    // }

    // async fn entretien<M,G>(&self, middleware: &M, gestionnaire: &G, limite_batch: Option<i64>)
    //     where
    //         M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
    //         G: GestionnaireDomaine;
}

#[async_trait]
pub trait JobHandlerVersions: JobHandler {
    // /// Set le flag de traitement complete
    // async fn set_flag<M,S,U>(
    //     &self, middleware: &M, fuuid: S, user_id: Option<U>,
    //     cles_supplementaires: Option<HashMap<String, String>>,
    //     valeur: bool
    // ) -> Result<(), CommonError>
    // where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
    //     set_flag_versions(middleware, self, fuuid, user_id, cles_supplementaires, valeur).await
    // }

    // async fn sauvegarder_job<M,S,U>(&self, middleware: &M, background_job: BackgroundJob, emettre_trigger: bool)
    //     -> Result<(), CommonError>
    //     where M: GenerateurMessages + MongoDao,
    //           S: AsRef<str> + Send, U: AsRef<str> + Send
    // {
    //     let fuuid = fuuid.as_ref();
    //
    //     let filehost_ids = sauvegarder_job(
    //         middleware, self, fuuid, user_id, filehost_ids.clone(), champs_cles, parametres).await?;
    //
    //     if let Some(inner) = filehost_ids {
    //         if emettre_trigger {
    //             for filehost_id in inner.into_iter() {
    //                 self.emettre_trigger(middleware, filehost_id.as_str(), fuuid, mimetype).await;
    //             }
    //         }
    //     }
    //
    //     Ok(())
    // }

    // async fn get_prochaine_job<M>(&self, middleware: &M, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
    //     -> Result<ReponseJob, CommonError>
    //     where M: GenerateurMessages + MongoDao
    // {
    //     get_prochaine_job_versions(middleware, self.get_nom_collection(), certificat, commande).await
    // }

    /// Doit etre invoque regulierement pour generer nouvelles jobs, expirer vieilles, etc.
    async fn entretien<M,G>(&self, middleware: &M, gestionnaire: &G, limite_batch: Option<i64>)
        where
            M: GenerateurMessages + MongoDao + ValidateurX509,
            G: GestionnaireDomaineV2 + AiguillageTransactions
    {
        error!("Fix me");   // TODO - fix me

        // debug!("entretien Cycle entretien JobHandler {}", self.get_nom_flag());
        //
        // let limite_batch = match limite_batch {
        //     Some(inner) => inner,
        //     None => CONST_LIMITE_BATCH
        // };
        //
        // if let Err(e) = entretien_jobs_versions(middleware, gestionnaire, self, limite_batch).await {
        //     error!("traitement_jobs.JobHandler.entretien {} Erreur sur ajouter_jobs_manquantes : {:?}", self.get_nom_flag(), e);
        // }
        //
        // // Emettre des triggers au besoin.
        // self.emettre_evenements_job(middleware).await;
    }
}

// #[async_trait]
// pub trait JobHandlerFichiersRep: JobHandler {
//     /// Set le flag de traitement complete
//     // async fn set_flag<M,S,U>(
//     //     &self, middleware: &M, tuuid: S, user_id: Option<U>,
//     //     cles_supplementaires: Option<HashMap<String, String>>,
//     //     valeur: bool
//     // ) -> Result<(), CommonError>
//     // where M: MongoDao, S: AsRef<str> + Send, U: AsRef<str> + Send {
//     //     set_flag_fichiersrep(middleware, self, tuuid, user_id, cles_supplementaires, valeur).await
//     // }
//
//     // async fn sauvegarder_job<M,S,U>(
//     //     &self, middleware: &M, tuuid: S, user_id: U, instances: Option<Vec<String>>,
//     //     champs_cles: Option<HashMap<String, String>>,
//     //     parametres: Option<HashMap<String, Bson>>,
//     //     emettre_trigger: bool
//     // )
//     //     -> Result<(), CommonError>
//     //     where M: GenerateurMessages + MongoDao,
//     //           S: AsRef<str> + Send, U: AsRef<str> + Send
//     // {
//     //     let instances = sauvegarder_job_fichiersrep(
//     //         middleware, self, tuuid, user_id, instances.clone(),
//     //         champs_cles, parametres).await?;
//     //     if let Some(inner) = instances {
//     //         if emettre_trigger {
//     //             for instance in inner.into_iter() {
//     //                 self.emettre_trigger(middleware, instance).await;
//     //             }
//     //         }
//     //     }
//     //     Ok(())
//     // }
//
//     // async fn get_prochaine_job<M>(&self, middleware: &M, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
//     //     -> Result<ReponseJob, CommonError>
//     //     where M: GenerateurMessages + MongoDao
//     // {
//     //     get_prochaine_job_fichiersrep(middleware, self.get_nom_collection(), certificat, commande).await
//     // }
//
//     /// Doit etre invoque regulierement pour generer nouvelles jobs, expirer vieilles, etc.
//     async fn entretien<M,G>(&self, middleware: &M, gestionnaire: &G, limite_batch: Option<i64>)
//         where
//             M: GenerateurMessages + MongoDao + ValidateurX509,
//             G: GestionnaireDomaineV2 + AiguillageTransactions
//     {
//         error!("TODO - fix me");  // TODO - fix entretien
//
//         // debug!("entretien Cycle entretien JobHandler {}", self.get_nom_flag());
//         //
//         // let limite_batch = match limite_batch {
//         //     Some(inner) => inner,
//         //     None => CONST_LIMITE_BATCH
//         // };
//         //
//         // if let Err(e) = entretien_jobs_fichiersrep(middleware, gestionnaire, self, limite_batch).await {
//         //     error!("traitement_jobs.JobHandler.entretien {} Erreur sur ajouter_jobs_manquantes : {:?}", self.get_nom_flag(), e);
//         // }
//         //
//         // // Emettre des triggers au besoin.
//         // self.emettre_evenements_job(middleware).await;
//     }
// }

// #[derive(Deserialize)]
// struct DocJob {
//     instances: Option<Vec<String>>
// }

// /// Emet un trigger media image si au moins une job media est due.
// pub async fn trouver_jobs_instances<J,M>(middleware: &M, job_handler: &J)
//     -> Result<Option<Vec<String>>, CommonError>
//     where M: MongoDao, J: JobHandler
// {
//     let doc_job: Option<DocJob> = {
//         let filtre = doc! {
//             CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING
//         };
//         let options = FindOneOptions::builder().projection(doc! {"instances": true}).build();
//         let collection = middleware.get_collection(job_handler.get_nom_collection())?;
//         match collection.find_one(filtre, options).await? {
//             Some(inner) => Some(convertir_bson_deserializable(inner)?),
//             None => None
//         }
//     };
//
//     match doc_job {
//         Some(inner) => {
//             match inner.instances {
//                 Some(instances) => Ok(Some(instances)),
//                 None => Ok(None)
//             }
//         },
//         None => Ok(None)
//     }
// }

// async fn set_flag_versions<M,J,S,U>(
//     middleware: &M, job_handler: &J, fuuid: S, user_id: Option<U>,
//     cles_supplementaires: Option<HashMap<String, String>>,
//     valeur: bool
// ) -> Result<(), CommonError>
//     where M: MongoDao, J: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
// {
//     let fuuid = fuuid.as_ref();
//     let user_id = match user_id.as_ref() {
//         Some(inner) => Some(inner.as_ref()),
//         None => None
//     };
//
//     let mut filtre = doc!{
//         CHAMP_FUUID: fuuid,
//     };
//     if let Some(inner) = user_id {
//         // Lagacy - supporte vieilles transactions sans user_id
//         filtre.insert(CHAMP_USER_ID, inner);
//     }
//
//     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//
//     // Set flag
//     let ops = doc! {
//         "$set": { job_handler.get_nom_flag(): valeur },
//         "$currentDate": { CHAMP_MODIFICATION: true }
//     };
//     debug!("set_flag {}={} : modifier table versions pour {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), valeur, user_id, fuuid, filtre.clone());
//     collection_versions.update_one(filtre.clone(), ops, None).await?;
//
//     // Completer flags pour job
//     if let Some(inner) = cles_supplementaires {
//         for (k, v) in inner.into_iter() {
//             filtre.insert(k, v);
//         }
//     }
//
//     match valeur {
//         true => {
//             debug!("set_flag supprimer job ({}) sur {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), user_id, fuuid, filtre);
//
//             // Set flag
//             // let ops = doc! {
//             //     "$set": { job_handler.get_nom_flag(): true },
//             //     "$currentDate": { CHAMP_MODIFICATION: true }
//             // };
//             // collection_versions.update_one(filtre.clone(), ops, None).await?;
//
//             // Retirer job
//             let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
//             let result = collection_jobs.delete_one(filtre.clone(), None).await?;
//             debug!("set_flag Delete result sur table {}, filtre {:?} : {:?}", job_handler.get_nom_collection(), filtre, result);
//         },
//         false => {
//             // Rien a faire
//             debug!("set_flag {} false : supprimer job sur {:?}/{} et modifier table versions", job_handler.get_nom_flag(), user_id, fuuid);
//         }
//     }
//
//     Ok(())
// }

// async fn set_flag_fichiersrep<M,J,S,U>(
//     middleware: &M, job_handler: &J, tuuid: S, user_id: Option<U>,
//     cles_supplementaires: Option<HashMap<String, String>>,
//     valeur: bool
// ) -> Result<(), CommonError>
//     where M: MongoDao, J: JobHandler, S: AsRef<str> + Send, U: AsRef<str> + Send
// {
//     let tuuid = tuuid.as_ref();
//     let user_id = match user_id.as_ref() {
//         Some(inner) => match Some(inner.as_ref()) {
//             Some(inner) => inner,
//             None => Err(format!("traitement_jobs.set_flag_fichiersrep User_id manquant (1)"))?
//         },
//         None => Err(format!("traitement_jobs.set_flag_fichiersrep User_id manquant (2)"))?
//     };
//
//     let mut filtre = doc!{ CHAMP_TUUID: tuuid, CHAMP_USER_ID: user_id };
//
//     // let mut filtre = doc!{
//     //     CHAMP_FUUIDS_VERSIONS: fuuid,
//     // };
//     // if let Some(inner) = user_id {
//     //     // Legacy - supporte vieilles commandes sans user_id
//     //     filtre.insert(CHAMP_USER_ID, inner);
//     // }
//
//     let collection_fichiersrep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
//
//     // Set flag
//     let ops = doc! {
//         "$set": { job_handler.get_nom_flag(): valeur },
//         "$currentDate": { CHAMP_MODIFICATION: true }
//     };
//     debug!("set_flag {}={} : modifier table versions pour {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), valeur, user_id, tuuid, filtre.clone());
//     collection_fichiersrep.update_one(filtre.clone(), ops, None).await?;
//
//     // Completer flags pour job
//     if let Some(inner) = cles_supplementaires {
//         for (k, v) in inner.into_iter() {
//             filtre.insert(k, v);
//         }
//     }
//
//     match valeur {
//         true => {
//             debug!("set_flag supprimer job ({}) sur {:?}/{} (filtre : {:?}", job_handler.get_nom_flag(), user_id, tuuid, filtre);
//
//             // Set flag
//             // let ops = doc! {
//             //     "$set": { job_handler.get_nom_flag(): true },
//             //     "$currentDate": { CHAMP_MODIFICATION: true }
//             // };
//             // collection_versions.update_one(filtre.clone(), ops, None).await?;
//
//             // Retirer job
//             let collection_jobs = middleware.get_collection(job_handler.get_nom_collection())?;
//             let result = collection_jobs.delete_one(filtre.clone(), None).await?;
//             debug!("set_flag Delete result sur table {}, filtre {:?} : {:?}", job_handler.get_nom_collection(), filtre, result);
//         },
//         false => {
//             // Rien a faire
//             debug!("set_flag {} false : supprimer job sur {:?}/{} et modifier table versions", job_handler.get_nom_flag(), user_id, tuuid);
//         }
//     }
//
//     Ok(())
// }

#[derive(Debug, Deserialize)]
struct RowVersionsIds {
    tuuid: String,
    fuuid: String,
    mimetype: String,
    user_id: String,
    visites: Option<HashMap<String, i64>>,
}

// async fn entretien_jobs_versions<J,G,M>(middleware: &M, gestionnaire: &G, job_handler: &J, limite_batch: i64) -> Result<(), CommonError>
//     where
//         M: GenerateurMessages + MongoDao + ValidateurX509,
//         G: GestionnaireDomaineV2 + AiguillageTransactions,
//         J: JobHandler + JobHandlerVersions
// {
//     debug!("entretien_jobs Debut");
//
//     let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(
//         job_handler.get_nom_collection())?;
//     let champ_flag_index = job_handler.get_nom_flag();
//
//     // Reset jobs indexation avec start_date expire pour les reprendre immediatement
//     {
//         let filtre_start_expire = doc! {
//             CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_RUNNING,
//             CONST_CHAMP_DATE_MAJ: { "$lte": Utc::now() - Duration::seconds(CONST_EXPIRATION_SECS) },
//             // CONST_CHAMP_RETRY: { "$lt": CONST_MAX_RETRY },
//         };
//         let ops_expire = doc! {
//             "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING },
//             "$unset": { CONST_CHAMP_DATE_MAJ: true },
//             "$currentDate": { CHAMP_MODIFICATION: true },
//         };
//         let options = UpdateOptions::builder().hint(Hint::Name("etat_jobs_2".to_string())).build();
//         collection_jobs.update_many(filtre_start_expire, ops_expire, options).await?;
//     }
//
//     let collection_versions = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
//         NOM_COLLECTION_VERSIONS)?;
//
//     let mut curseur = {
//         let opts = FindOptions::builder()
//             // .hint(Hint::Name(String::from("flag_media_traite")))
//             .sort(doc! {champ_flag_index: 1, CHAMP_CREATION: 1})
//             .projection(doc!{
//                 CHAMP_FUUID: true, CHAMP_TUUID: true, CHAMP_USER_ID: true, CHAMP_MIMETYPE: true, "visites": true,
//
//                 // Information requise a cause du format NodeFichierVersionBorrowed
//                 CHAMP_METADATA: true, CHAMP_TAILLE: true, CHAMP_FUUIDS: true, CHAMP_FUUIDS_RECLAMES: true,
//                 CHAMP_SUPPRIME: true,
//             })
//             .limit(limite_batch)
//             .build();
//         let filtre = doc! {
//             champ_flag_index: false,
//             CHAMP_SUPPRIME: false,
//         };
//         debug!("traiter_indexation_batch filtre {:?}", filtre);
//         collection_versions.find(filtre, Some(opts)).await?
//     };
//
//     while curseur.advance().await? {
//         let version_mappee = match curseur.deserialize_current() {
//             Ok(inner) => inner,
//             Err(e) => {
//                 warn!("traiter_indexation_batch Erreur mapping document : {:?} - SKIP", e);
//                 continue;
//             }
//         };
//         debug!("traiter_indexation_batch Ajouter job (si applicable) pour {:?}", version_mappee);
//
//         let tuuid_ref = version_mappee.tuuid;
//         let fuuid_ref = version_mappee.fuuid;
//         let user_id = version_mappee.user_id;
//         let mimetype_ref = version_mappee.mimetype;
//         let cle_id = match version_mappee.cle_id.as_ref() {
//             Some(inner) => *inner,
//             None => fuuid_ref
//         };
//
//         // Creer ou mettre a jour la job
//         let instances = version_mappee.visites.into_keys().map(|s| s.to_owned()).collect::<Vec<String>>();
//         let mut champs_cles = HashMap::new();
//         champs_cles.insert("mimetype".to_string(), mimetype_ref.to_string());
//         // champs_cles.insert("tuuid".to_string(), tuuid_ref.to_string());
//         let mut parametres = HashMap::new();
//         parametres.insert("cle_id".to_string(), Bson::String(cle_id.to_string()));
//         // parametres.insert("mimetype".to_string(), Bson::String(mimetype_ref.to_string()));
//         parametres.insert("tuuid".to_string(), Bson::String(tuuid_ref.to_string()));
//         if let Err(e) = job_handler.sauvegarder_job(
//             middleware, fuuid_ref, user_id,
//             Some(instances), None, Some(parametres),
//             false).await
//         {
//             info!("entretien_jobs Erreur creation job : {:?}", e)
//         }
//     }
//
//     {
//         let filtre = doc! {
//             // Inclue etat pour utiliser index etat_jobs_2
//             CHAMP_ETAT_JOB: {"$in": [
//                 VIDEO_CONVERSION_ETAT_PENDING,
//                 VIDEO_CONVERSION_ETAT_ERROR,
//                 VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES,
//             ]},
//             CHAMP_FLAG_DB_RETRY: {"$gte": MEDIA_RETRY_LIMIT}
//         };
//         let options = FindOptions::builder().hint(Hint::Name(NOM_INDEX_ETAT_JOBS.to_string())).build();
//         let mut curseur = collection_jobs.find(filtre, options).await?;
//         while curseur.advance().await? {
//             let job = curseur.deserialize_current()?;
//             warn!("traiter_indexation_batch Job sur fuuid {:?} (user_id {:?}) expiree, on met le flag termine pour annuler la job.", job.fuuid, job.user_id);
//
//             // Fabriquer transaction pour annuler la job et marquer le traitement complete
//             if let Err(e) = job_handler.marquer_job_erreur(middleware, gestionnaire, job, "Too many retries").await {
//                 error!("traiter_indexation_batch Erreur marquer job supprimee : {:?}", e);
//             }
//         }
//     }
//
//     Ok(())
// }

// async fn entretien_jobs_fichiersrep<J,G,M>(middleware: &M, gestionnaire: &G, job_handler: &J, limite_batch: i64) -> Result<(), CommonError>
//     where
//         M: GenerateurMessages + MongoDao + ValidateurX509,
//         G: GestionnaireDomaineV2 + AiguillageTransactions,
//         J: JobHandler + JobHandlerFichiersRep
// {
//     debug!("entretien_jobs_fichiersrep Debut");
//
//     let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(
//         job_handler.get_nom_collection())?;
//     let champ_flag_index = job_handler.get_nom_flag();
//
//     // Reset jobs indexation avec start_date expire pour les reprendre immediatement
//     {
//         let filtre_start_expire = doc! {
//             CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_RUNNING,
//             CONST_CHAMP_DATE_MAJ: { "$lte": Utc::now() - Duration::seconds(CONST_EXPIRATION_SECS) },
//             // CONST_CHAMP_RETRY: { "$lt": CONST_MAX_RETRY },
//         };
//         let ops_expire = doc! {
//             "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING },
//             "$unset": { CONST_CHAMP_DATE_MAJ: true },
//             "$currentDate": { CHAMP_MODIFICATION: true },
//         };
//         let options = UpdateOptions::builder().hint(Hint::Name("etat_jobs_2".to_string())).build();
//         collection_jobs.update_many(filtre_start_expire, ops_expire, options).await?;
//     }
//
//     let collection_fichiersrep = middleware.get_collection_typed::<NodeFichierRepBorrowed>(
//         NOM_COLLECTION_FICHIERS_REP)?;
//     let collection_versions = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
//         NOM_COLLECTION_VERSIONS)?;
//
//     let mut curseur = {
//         let opts = FindOptions::builder()
//             // .hint(Hint::Name(String::from("flag_media_traite")))
//             .sort(doc! {champ_flag_index: 1, CHAMP_CREATION: 1})
//             .projection(doc!{
//                 CHAMP_FUUIDS_VERSIONS: true, CHAMP_TUUID: true, CHAMP_USER_ID: true,
//                 CHAMP_MIMETYPE: true, CHAMP_PATH_CUUIDS: true,
//
//                 // Information requise a cause du format NodeFichierVersionBorrowed
//                 CHAMP_TYPE_NODE: true, CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: true,
//                 CHAMP_METADATA: true,
//             })
//             .limit(limite_batch)
//             .build();
//         let filtre = doc! {
//             champ_flag_index: false,
//             CHAMP_SUPPRIME: false,
//             CHAMP_SUPPRIME_INDIRECT: false,
//         };
//         debug!("entretien_jobs_fichiersrep filtre {:?}", filtre);
//         collection_fichiersrep.find(filtre, Some(opts)).await?
//     };
//
//     while curseur.advance().await? {
//         let version_mappee = match curseur.deserialize_current() {
//             Ok(inner) => inner,
//             Err(e) => {
//                 warn!("entretien_jobs_fichiersrep Erreur mapping document : {:?} - SKIP", e);
//                 continue;
//             }
//         };
//         debug!("entretien_jobs_fichiersrep Ajouter job (si applicable) pour {:?}", version_mappee);
//
//         let tuuid_ref = version_mappee.tuuid;
//         let user_id = version_mappee.user_id;
//         let type_node = TypeNode::try_from(version_mappee.type_node)?;
//
//         match type_node {
//             TypeNode::Fichier => {
//                 let mimetype_ref = match version_mappee.mimetype {
//                     Some(inner) => inner,
//                     None => {
//                         warn!("entretien_jobs_fichiersrep Aucun mimetype pour fichier tuuid {} - SKIP", tuuid_ref);
//                         continue
//                     }
//                 };
//
//                 let fuuid_ref = match version_mappee.fuuids_versions {
//                     Some(inner) => match inner.get(0) {
//                         Some(inner) => *inner,
//                         None => {
//                             warn!("entretien_jobs_fichiersrep Aucun fuuid pour tuuid {} - SKIP", tuuid_ref);
//                             continue
//                         }
//                     },
//                     None => {
//                         warn!("entretien_jobs_fichiersrep Aucun fuuid pour tuuid {} - SKIP", tuuid_ref);
//                         continue;
//                     }
//                 };
//
//                 // Charger info de version
//                 let filtre_version = doc!{ CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid_ref };
//                 let mut curseur_version = collection_versions.find(filtre_version, None).await?;
//                 let (visites, cle_id) = match curseur_version.advance().await? {
//                     true => {
//                         let r = curseur_version.deserialize_current()?;
//                         let visites: Vec<String> = r.visites.into_keys().map(|f| f.to_string()).collect();
//                         let cle_id = match r.cle_id {
//                             Some(inner) => inner.to_owned(),
//                             None => r.fuuid.to_owned()
//                         };
//                         (visites, cle_id)
//                     },
//                     false => {
//                         warn!("entretien_jobs_fichiersrep Aucune information de version pour pour user_id {}, fuuid {} - SKIP", user_id, fuuid_ref);
//                         continue
//                     }
//                 };
//
//                 // Creer ou mettre a jour la job
//                 //for instance in visites {
//                 let mut champs_cles = HashMap::new();
//                 champs_cles.insert("mimetype".to_string(), mimetype_ref.to_string());
//                 // champs_cles.insert("tuuid".to_string(), tuuid_ref.to_string());
//                 let mut champs_parametres = HashMap::new();
//                 champs_parametres.insert("fuuid".to_string(), Bson::String(fuuid_ref.to_string()));
//                 champs_parametres.insert("cle_id".to_string(), Bson::String(cle_id.to_string()));
//                 match version_mappee.path_cuuids.as_ref() {
//                     Some(inner) => {
//                         let array_cuuids: Vec<Bson> = inner.iter().map(|v| Bson::String(v.to_string())).collect();
//                         champs_parametres.insert("path_cuuids".to_string(), Bson::Array(array_cuuids));
//                     },
//                     None => ()
//                 }
//
//                 if let Err(e) = job_handler.sauvegarder_job(
//                     middleware, tuuid_ref, user_id,
//                     Some(visites), Some(champs_cles), Some(champs_parametres),
//                     false).await
//                 {
//                     info!("entretien_jobs Erreur creation job : {:?}", e)
//                 }
//                 //}
//             },
//             _ => {
//                 // Repertoire
//                 let cle_id = match version_mappee.metadata.cle_id.as_ref() {
//                     Some(inner) => *inner,
//                     None => match version_mappee.metadata.ref_hachage_bytes.as_ref() {
//                         Some(inner) => *inner,
//                         None => {
//                             warn!("Repertoire metadata sans cle_id/ref_hachage_bytes ne peut etre indexe : {}", tuuid_ref);
//                             continue
//                         }
//                     }
//                 };
//                 let mut parametres = HashMap::new();
//                 parametres.insert("cle_id".to_string(), Bson::from(cle_id));
//                 if let Err(e) = job_handler.sauvegarder_job(
//                     middleware, tuuid_ref, user_id,
//                     None, None, Some(parametres),
//                     false).await
//                 {
//                     info!("entretien_jobs Erreur creation job : {:?}", e)
//                 }
//             }
//         }
//     }
//
//     // Cleanup des jobs avec retry excessifs. Ces jobs sont orphelines (e.g. la correspondante dans
//     // versions est deja traitee).
//     {
//         let filtre = doc! {
//             // Inclue etat pour utiliser index etat_jobs_2
//             CHAMP_ETAT_JOB: {"$in": [
//                 VIDEO_CONVERSION_ETAT_PENDING,
//                 // VIDEO_CONVERSION_ETAT_RUNNING,
//                 // VIDEO_CONVERSION_ETAT_PERSISTING,
//                 VIDEO_CONVERSION_ETAT_ERROR,
//                 VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES,
//             ]},
//             CHAMP_FLAG_DB_RETRY: {"$gte": MEDIA_RETRY_LIMIT}
//         };
//         // let options = FindOptions::builder().hint(Hint::Name(NOM_INDEX_ETAT_JOBS.to_string())).build();
//         // let mut curseur = collection_jobs.find(filtre, options).await?;
//         let mut curseur = collection_jobs.find(filtre, None).await?;
//         while curseur.advance().await? {
//             let job = curseur.deserialize_current()?;
//             warn!("entretien_jobs_fichiersrep Job sur tuuid {:?}, fuuid: {:?}, (user_id {}) expiree, on met le flag termine pour annuler la job.",
//                 job.tuuid, job.fuuid);
//
//             // Fabriquer transaction pour annuler la job et marquer le traitement complete
//             if let Err(e) = job_handler.marquer_job_erreur(middleware, gestionnaire, job, "Too many retries").await {
//                 error!("entretien_jobs_fichiersrep Erreur marquer job supprimee : {:?}", e);
//             }
//         }
//     }
//
//     Ok(())
// }

// pub async fn sauvegarder_job<M,J,S,U>(
//     middleware: &M, job_handler: &J,
//     fuuid: S, user_id: U, instances: Option<Vec<String>>,
//     champs_cles: Option<HashMap<String, String>>,
//     parametres: Option<HashMap<String, Bson>>
// )
//     -> Result<Option<Vec<String>>, CommonError>
//     where M: MongoDao, J: JobHandler,
//           S: AsRef<str> + Send, U: AsRef<str> + Send
// {
//     // Creer ou mettre a jour la job
//     let now = Utc::now();
//
//     let fuuid = fuuid.as_ref();
//     let user_id = user_id.as_ref();
//     // let instance = instance.as_ref();
//
//     let mut filtre = doc!{ CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid };
//
//     if let Some(inner) = champs_cles.as_ref() {
//         for (k, v) in inner.iter() {
//             filtre.insert(k.to_owned(), v.to_owned());
//         }
//     }
//
//     let mut set_on_insert = doc!{
//         CHAMP_FUUID: fuuid,
//         CHAMP_USER_ID: user_id,
//         CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING,
//         CONST_CHAMP_RETRY: 0,
//         CHAMP_CREATION: &now,
//     };
//
//     if let Some(inner) = champs_cles {
//         for (k, v) in inner.iter() {
//             set_on_insert.insert(k, v);
//         }
//     }
//
//     // Ajouter parametres optionnels (e.g. codecVideo, preset, etc.)
//     if let Some(inner) = parametres {
//         for (k, v) in inner.into_iter() {
//             set_on_insert.insert(k, v);
//         }
//     }
//
//     let instances = match instances {
//         Some(inner) => inner,
//         None => {
//             // Tenter de charger les visites pour le fichier
//             let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//             let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUID: fuuid };
//             match collection.find_one(filtre, None).await? {
//                 Some(inner) => {
//                     let fichier_mappe: FichierDetail = convertir_bson_deserializable(inner)?;
//                     match fichier_mappe.visites {
//                         Some(inner) => {
//                             let liste_visites: Vec<String> = inner.into_keys().collect();
//                             liste_visites
//                         },
//                         None => {
//                             debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (1 - aucunes instance avec visite) - SKIP", fuuid);
//                             return Ok(None)
//                         }
//                     }
//                 },
//                 None => {
//                     debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (2 - aucunes instance avec visite) - SKIP", fuuid);
//                     return Ok(None)
//                 }
//             }
//         }
//     };
//
//     let mut ops_job = doc! {
//         "$setOnInsert": set_on_insert,
//         "$addToSet": {CHAMP_INSTANCES: {"$each": &instances}},
//         "$currentDate": {
//             CHAMP_MODIFICATION: true,
//         }
//     };
//
//     let options = FindOneAndUpdateOptions::builder()
//         .upsert(true)
//         .build();
//
//     let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(job_handler.get_nom_collection())?;
//     if let Some(job) = collection_jobs.find_one_and_update(filtre.clone(), ops_job, options).await? {
//         if let Some(retries) = job.retry {
//             if retries >= CONST_MAX_RETRY {
//                 warn!("sauvegarder_job Job excede max retries, on la desactive");
//                 let ops = doc! {
//                     "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES },
//                     "$currentDate": { CHAMP_MODIFICATION: true },
//                 };
//                 collection_jobs.update_one(filtre, ops, None).await?;
//                 Err(format!("sauvegarder_job Job existante avec trop de retries"))?
//             }
//         }
//     }
//
//     Ok(Some(instances))
// }

// pub async fn sauvegarder_job_fichiersrep<M,J,S,U>(
//     middleware: &M, job_handler: &J,
//     tuuid: S, user_id: U, instances: Option<Vec<String>>,
//     champs_cles: Option<HashMap<String, String>>,
//     parametres: Option<HashMap<String, Bson>>
// )
//     -> Result<Option<Vec<String>>, CommonError>
//     where M: MongoDao, J: JobHandler,
//           S: AsRef<str> + Send, U: AsRef<str> + Send
// {
//     // Creer ou mettre a jour la job
//     let now = Utc::now();
//
//     let tuuid = tuuid.as_ref();
//     let user_id = user_id.as_ref();
//     // let instance = instance.as_ref();
//
//     let fuuid = match parametres.as_ref() {
//         Some(inner) => match inner.get(CHAMP_FUUID) {
//             Some(inner) => match inner.as_str() {
//                 Some(inner) => Some(inner.to_owned()),
//                 None => None
//             },
//             None => None
//         },
//         None => None
//     };
//
//     let mut filtre = doc!{ CHAMP_USER_ID: user_id, CHAMP_TUUID: tuuid };
//
//     if let Some(inner) = champs_cles.as_ref() {
//         for (k, v) in inner.iter() {
//             filtre.insert(k.to_owned(), v.to_owned());
//         }
//     }
//
//     let mut set_on_insert = doc!{
//         CHAMP_TUUID: tuuid,
//         CHAMP_USER_ID: user_id,
//         CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING,
//         CONST_CHAMP_RETRY: 0,
//         CHAMP_CREATION: &now,
//     };
//
//     if let Some(inner) = champs_cles.as_ref() {
//         for (k, v) in inner.iter() {
//             set_on_insert.insert(k.to_string(), v.to_string());
//         }
//     }
//
//     // Ajouter parametres optionnels (e.g. codecVideo, preset, etc.)
//     if let Some(inner) = parametres {
//         for (k, v) in inner.into_iter() {
//             set_on_insert.insert(k, v);
//         }
//     }
//
//     let instances = match instances {
//         Some(inner) => Some(inner),
//         None => {
//             match fuuid {
//                 Some(fuuid) => {
//                     // Tenter de charger les visites pour le fichier
//                     let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//                     let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUID: &fuuid };
//                     match collection.find_one(filtre, None).await? {
//                         Some(inner) => {
//                             let fichier_mappe: FichierDetail = convertir_bson_deserializable(inner)?;
//                             match fichier_mappe.visites {
//                                 Some(inner) => {
//                                     let liste_visites: Vec<String> = inner.into_keys().collect();
//                                     Some(liste_visites)
//                                 },
//                                 None => {
//                                     debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (1 - aucunes instance avec visite) - SKIP", fuuid);
//                                     return Ok(None)
//                                 }
//                             }
//                         },
//                         None => {
//                             debug!("sauvegarder_job Le fichier {} n'est pas encore disponible (2 - aucunes instance avec visite) - SKIP", fuuid);
//                             return Ok(None)
//                         }
//                     }
//                 },
//                 None => None
//             }
//         }
//     };
//
//     let mut ops_job = if let Some(instances) = instances.as_ref() {
//         doc! {
//             "$setOnInsert": set_on_insert,
//             "$addToSet": {CHAMP_INSTANCES: {"$each": &instances}},
//             "$currentDate": {
//                 CHAMP_MODIFICATION: true,
//             }
//         }
//     } else {
//         // Aucunes instances requises (e.g. collection, repertoire)
//         doc! {
//             "$setOnInsert": set_on_insert,
//             "$unset": {CHAMP_INSTANCES: true},  // Retirer champ instances
//             "$currentDate": {
//                 CHAMP_MODIFICATION: true,
//             }
//         }
//     };
//
//     let options = FindOneAndUpdateOptions::builder()
//         .upsert(true)
//         .build();
//
//     let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(job_handler.get_nom_collection())?;
//     if let Some(job) = collection_jobs.find_one_and_update(filtre.clone(), ops_job, options).await? {
//         if let Some(retries) = job.retry {
//             if retries >= CONST_MAX_RETRY {
//                 warn!("sauvegarder_job Job excede max retries, on la desactive");
//                 let ops = doc! {
//                     "$set": { CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_ERROR_TOOMANYRETRIES },
//                     "$currentDate": { CHAMP_MODIFICATION: true },
//                 };
//                 collection_jobs.update_one(filtre, ops, None).await?;
//                 Err(format!("sauvegarder_job Job existante avec trop de retries"))?
//             }
//         }
//     }
//
//     Ok(instances)
// }

// #[derive(Debug)]
// pub struct CommandeGetJob {
//     // pub instance_id: Option<String>,
//     pub filehost_id: Option<String>,
//     /// Filtre format de fallback uniquement pour les videos
//     pub fallback: Option<bool>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackgroundJobParams {
    #[serde(skip_serializing_if="Option::is_none")]
    pub defaults: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub thumbnails: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(rename="codecVideo", skip_serializing_if="Option::is_none")]
    pub codec_video: Option<String>,
    #[serde(rename="codecAudio", skip_serializing_if="Option::is_none")]
    pub codec_audio: Option<String>,
    #[serde(rename="resolutionVideo", skip_serializing_if="Option::is_none")]
    pub resolution_video: Option<u32>,
    #[serde(rename="qualityVideo", skip_serializing_if="Option::is_none")]
    pub quality_video: Option<i32>,
    #[serde(rename="bitrateVideo", skip_serializing_if="Option::is_none")]
    pub bitrate_video: Option<u32>,
    #[serde(rename="bitrateAudio", skip_serializing_if="Option::is_none")]
    pub bitrate_audio: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub preset: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio_stream_idx: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitle_stream_idx: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackgroundJob {
    pub job_id: String,

    // Parametres de la job
    pub tuuid: String,
    pub fuuid: Option<String>,
    pub mimetype: String,
    pub filehost_ids: Vec<String>,
    pub params: Option<BackgroundJobParams>,

    // Valeurs pour video (progress update) et index (access rights)
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<String>,

    // Dechiffrage fichier (fuuid)
    pub cle_id: String,
    pub format: String,
    pub nonce: String,

    // Etat de la job
    pub etat: i32,
    #[serde(rename="_mg-derniere-modification", with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub date_modification: chrono::DateTime<Utc>,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime")]
    pub date_maj: Option<chrono::DateTime<Utc>>,
    pub retry: i32,

    // Business key, combined with tuuid to make a unique job value
    pub cle_conversion: Option<String>,
}

impl BackgroundJob {
    pub fn new<T,F,M,I,C,E,N>(tuuid: T, fuuid: F, mimetype: M, filehost_ids: &Vec<I>, cle_id: C, format: E, nonce: N) -> BackgroundJob
        where T: ToString, F: ToString, M: ToString, I: ToString, E: ToString, C: ToString, N: ToString
    {
        let job_id = Uuid::new_v4();  // Generate random identifier
        Self {
            job_id: job_id.to_string(),
            tuuid: tuuid.to_string(),
            fuuid: Some(fuuid.to_string()),
            mimetype: mimetype.to_string(),
            filehost_ids: filehost_ids.iter().map(|id| id.to_string()).collect(),
            params: None,
            user_id: None,
            cle_id: cle_id.to_string(),
            format: format.to_string(),
            nonce: nonce.to_string(),
            etat: VIDEO_CONVERSION_ETAT_PENDING,
            date_modification: Utc::now(),
            date_maj: None,
            retry: 0,
            cle_conversion: None,
        }
    }

    pub fn new_index<T,F,U,M,I,C,E,N>(tuuid: T, fuuid: Option<F>, user_id: U, mimetype: M, filehost_ids: &Vec<I>, cle_id: C, format: E, nonce: N) -> BackgroundJob
    where T: ToString, F: ToString, U: ToString, M: ToString, I: ToString, E: ToString, C: ToString, N: ToString
    {
        let job_id = Uuid::new_v4();  // Generate random identifier
        Self {
            job_id: job_id.to_string(),
            tuuid: tuuid.to_string(),
            fuuid: match fuuid {Some(inner) => Some(inner.to_string()), None => None},
            mimetype: mimetype.to_string(),
            filehost_ids: filehost_ids.iter().map(|id| id.to_string()).collect(),
            params: None,
            user_id: Some(user_id.to_string()),
            cle_id: cle_id.to_string(),
            format: format.to_string(),
            nonce: nonce.to_string(),
            etat: VIDEO_CONVERSION_ETAT_PENDING,
            date_modification: Utc::now(),
            date_maj: None,
            retry: 0,
            cle_conversion: None,
        }
    }
}

#[derive(Serialize)]
pub struct JobTrigger<'a> {
    pub job_id: &'a str,
    pub tuuid: &'a str,
    pub fuuid: Option<&'a str>,
    pub mimetype: &'a str,
    pub filehost_ids: &'a Vec<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub params: Option<&'a BackgroundJobParams>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub user_id: Option<&'a str>,
    pub cle_id: &'a str,
    pub format: &'a str,
    pub nonce: &'a str,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_cuuids: Option<Vec<String>>,
}

impl<'a> From<&'a BackgroundJob> for JobTrigger<'a> {
    fn from(value: &'a BackgroundJob) -> JobTrigger<'a> {
        Self {
            job_id: value.job_id.as_str(),
            tuuid: value.tuuid.as_str(),
            fuuid: match &value.fuuid {Some(inner)=>Some(inner), None=>None},
            mimetype: value.mimetype.as_str(),
            filehost_ids: &value.filehost_ids,
            params: match &value.params {Some(inner)=>Some(inner), None=>None},
            user_id: match value.user_id.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None},
            cle_id: value.cle_id.as_str(),
            format: value.format.as_str(),
            nonce: value.nonce.as_str(),
            metadata: None,
            path_cuuids: None,
        }
    }
}

// #[derive(Serialize, Deserialize)]
// pub struct ReponseJob {
//     pub ok: bool,
//     pub err: Option<String>,
//     pub tuuid: String,
//     pub fuuid: String,
//     pub mimetype: Option<String>,
//     pub metadata: Option<DataChiffre>,
//     pub cle: Option<CleSecreteSerialisee>,
//     pub path_cuuids: Option<Vec<String>>,
//
//     // Champs video
//     pub cle_conversion: Option<String>,
//     #[serde(rename="codecVideo")]
//     pub codec_video: Option<String>,
//     #[serde(rename="codecAudio")]
//     pub codec_audio: Option<String>,
//     #[serde(rename="resolutionVideo")]
//     pub resolution_video: Option<u32>,
//     #[serde(rename="qualityVideo")]
//     pub quality_video: Option<i32>,
//     #[serde(rename="bitrateVideo")]
//     pub bitrate_video: Option<u32>,
//     #[serde(rename="bitrateAudio")]
//     pub bitrate_audio: Option<u32>,
//     pub preset: Option<String>,
// }

// impl From<&str> for ReponseJob {
//     fn from(value: &str) -> Self {
//         Self {
//             ok: false,
//             err: Some(value.to_string()),
//             tuuid: None,
//             fuuid: None,
//             user_id: None,
//             mimetype: None,
//             metadata: None,
//             cle: None,
//             path_cuuids: None,
//             cle_conversion: None,
//             codec_video: None,
//             codec_audio: None,
//             resolution_video: None,
//             quality_video: None,
//             bitrate_video: None,
//             bitrate_audio: None,
//             preset: None,
//         }
//     }
// }

// impl From<BackgroundJob> for ReponseJob {
//     fn from(value: BackgroundJob) -> Self {
//
//         // String params
//         let mimetype = match value.champs_optionnels.get("mimetype") {
//             Some(inner) => Some(inner.to_string()),
//             None => None
//         };
//         let cle_conversion = match value.champs_optionnels.get("cle_conversion") {
//             Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
//             None => None
//         };
//         let codec_video = match value.champs_optionnels.get("codecVideo") {
//             Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
//             None => None
//         };
//         let codec_audio = match value.champs_optionnels.get("codecAudio") {
//             Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
//             None => None
//         };
//         let preset = match value.champs_optionnels.get("preset") {
//             Some(inner) => match inner.as_str() {Some(s)=>Some(s.to_owned()), None=>None},
//             None => None
//         };
//         let path_cuuids = match value.champs_optionnels.get("path_cuuids") {
//             Some(inner) => match inner.as_array() {
//                 Some(inner) => {
//                     let mut path_cuuids = Vec::new();
//                     for v in inner {
//                         if let Some(v) = v.as_str() {
//                             path_cuuids.push(v.to_owned());
//                         }
//                     }
//                     Some(path_cuuids)
//                 },
//                 None => None
//             },
//             None => None
//         };
//
//         // u32 params
//         let resolution_video = match value.champs_optionnels.get("resolutionVideo") {
//             Some(inner) => match inner.as_i64() {
//                 Some(inner) => Some(inner as u32),
//                 None => None
//             },
//             None => None
//         };
//         let quality_video = match value.champs_optionnels.get("qualityVideo") {
//             Some(inner) => match inner.as_i64() {
//                 Some(inner) => Some(inner as i32),
//                 None => None
//             },
//             None => None
//         };
//         let bitrate_video = match value.champs_optionnels.get("bitrateVideo") {
//             Some(inner) => match inner.as_i64() {
//                 Some(inner) => Some(inner as u32),
//                 None => None
//             },
//             None => None
//         };
//         let bitrate_audio = match value.champs_optionnels.get("bitrateAudio") {
//             Some(inner) => match inner.as_i64() {
//                 Some(inner) => Some(inner as u32),
//                 None => None
//             },
//             None => None
//         };
//
//         Self {
//             ok: true,
//             err: None,
//             tuuid: Some(value.tuuid),
//             fuuid: value.fuuid,
//             user_id: Some(value.user_id),
//             mimetype,
//             metadata: None,
//             cle: None,
//             path_cuuids,
//             cle_conversion,
//             codec_video,
//             codec_audio,
//             resolution_video,
//             quality_video,
//             bitrate_video,
//             bitrate_audio,
//             preset,
//         }
//     }
// }

// pub async fn get_prochaine_job_versions<M,S>(middleware: &M, nom_collection: S, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
//     -> Result<ReponseJob, CommonError>
//     where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
// {
//     let nom_collection = nom_collection.as_ref();
//
//     debug!("get_prochaine_job Get pour {} : {:?}", nom_collection, commande);
//     let job = match trouver_prochaine_job_traitement(middleware, nom_collection, &commande).await? {
//         Some(inner) => inner,
//         None => {
//             // Il ne reste aucunes jobs
//             return Ok(ReponseJob::from("Aucun fichier a traiter"))
//         }
//     };
//
//     debug!("get_prochaine_job Prochaine job : {:?}", job);
//
//     let tuuid = job.tuuid.as_str();
//
//     // Recuperer les metadonnees et information de version
//     let filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_TUUID: tuuid };
//     let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(
//         NOM_COLLECTION_VERSIONS)?;
//     let fichier_version = match collection_versions.find_one(filtre, None).await? {
//         Some(inner) => inner,
//         None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job pour document inexistant user_id:{} tuuid:{}", job.user_id, tuuid))?
//     };
//
//     // Utiliser la version courante (fuuid[0])
//     let fuuid = fichier_version.fuuid.as_str();
//     let cle_id = match fichier_version.cle_id.as_ref() {
//         Some(inner) => inner.as_str(),
//         None => fuuid
//     };
//
//     // Recuperer la cle de dechiffrage du fichier
//     let mut cle = get_cle_job_indexation(middleware, cle_id).await?;
//
//     if fichier_version.cle_id.is_some() {
//         // Transferer information de dechiffrage symmetrique
//         cle.set_symmetrique(fichier_version.format, fichier_version.nonce, fichier_version.verification)?;
//     }
//
//     let metadata = fichier_version.metadata;
//     let mimetype = fichier_version.mimetype;
//
//     let mut reponse_job = ReponseJob::from(job);
//     reponse_job.metadata = Some(metadata);
//     reponse_job.mimetype = Some(mimetype);
//     reponse_job.cle = Some(cle);
//     debug!("get_prochaine_job Reponse job : {:?}", reponse_job.tuuid);
//
//     Ok(reponse_job)
// }

// pub async fn get_prochaine_job_fichiersrep<M,S>(middleware: &M, nom_collection: S, certificat: &EnveloppeCertificat, commande: CommandeGetJob)
//     -> Result<ReponseJob, CommonError>
//     where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
// {
//     let nom_collection = nom_collection.as_ref();
//
//     debug!("commande_get_job Get pour {} : {:?}", nom_collection, commande);
//     let job = match trouver_prochaine_job_traitement(middleware, nom_collection, &commande).await? {
//         Some(inner) => inner,
//         None => {
//             // Il ne reste aucunes jobs
//             return Ok(ReponseJob::from("Aucun fichier a traiter"))
//         }
//     };
//
//     debug!("get_prochaine_job_fichiersrep Prochaine job : {:?}", job);
//
//     let tuuid = job.tuuid.as_str();
//
//     // Recuperer les metadonnees et information de version
//     let (fichier_rep, cle) = {
//         let filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_TUUID: tuuid };
//         let collection_rep = middleware.get_collection_typed::<NodeFichierRepOwned>(
//             NOM_COLLECTION_FICHIERS_REP)?;
//
//         let fichier_rep = match collection_rep.find_one(filtre, None).await? {
//             Some(inner) => inner,
//             None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job pour document inexistant user_id:{} tuuid:{}", job.user_id, tuuid))?
//         };
//
//         let (fichier_version, fuuid) = if fichier_rep.type_node.as_str() == "Fichier" {
//             // Charger information de dechiffrage symmetrique
//             let fuuid = match fichier_rep.fuuids_versions.as_ref() {
//                 Some(inner) => match inner.get(0) {
//                     Some(inner) => inner.as_str(),
//                     None => Err(format!("traitement_jobs.get_prochaine_job Aucun fuuid courant pour tuuid {}", tuuid))?
//                 },
//                 None => Err(format!("traitement_jobs.get_prochaine_job Aucuns version_fuuids pour tuuid {}", tuuid))?
//             };
//
//             let filtre = doc! { CHAMP_USER_ID: &job.user_id, CHAMP_FUUID: fuuid };
//             let collection_version = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
//             match collection_version.find_one(filtre, None).await {
//                 Ok(inner) => (inner, fuuid),
//                 Err(e) => Err(Error::String(format!("traitement_jobs.get_prochaine_job Erreur mapping fichier {} de la table versions", fuuid)))?
//             }
//         } else {
//             let ref_hachage_bytes = match fichier_rep.metadata.cle_id.as_ref() {
//                 Some(inner) => inner.as_str(),
//                 None => match fichier_rep.metadata.ref_hachage_bytes.as_ref() {
//                     Some(inner) => inner.as_str(),
//                     None => Err(Error::Str("traitement_jobs.get_prochaine_job Erreur repertoire sans cle_id/ref_hachage_bytes"))?
//                 }
//             };
//             (None, ref_hachage_bytes)
//         };
//
//         let cle_id = match job.champs_optionnels.get("cle_id") {
//             Some(inner) => match inner.as_str() {
//                 Some(inner) => inner,
//                 None => Err(format!("traitement_jobs.get_prochaine_job Erreur traitement - job cle_id mauvais format pour user_id:{} tuuid:{}", job.user_id, tuuid))?
//             },
//             None => fuuid
//         };
//
//         // Recuperer la cle de dechiffrage du fichier
//         // let cle = get_cle_job_indexation(middleware, tuuid, cle_id).await?;
//         let mut cle = match get_cle_job_indexation(middleware, cle_id).await {
//             Ok(inner) => inner,
//             Err(e) => Err(Error::String(format!("Erreur get_cle_job_indexation tuuid {} cle_id {} : {:?}", tuuid, cle_id, e)))?
//         };
//
//         // Injecter information de dechiffrage si applicable
//         if let Some(fichier_version) = fichier_version {
//             if let Some(cle_id) = fichier_version.cle_id {
//                 if let Some(cle_id_recue) = cle.cle_id.as_ref() {
//                     if cle_id.as_str() == cle_id_recue.as_str() {
//                         // Inserer information de dechiffrage symmetrique
//                         cle.set_symmetrique(fichier_version.format, fichier_version.nonce, fichier_version.verification)?;
//                     }
//                 }
//             }
//         }
//
//         (fichier_rep, cle)
//     };
//
//     let metadata = fichier_rep.metadata;
//     let path_cuuids = fichier_rep.path_cuuids;
//
//     let mimetype = match fichier_rep.mimetype.as_ref() {
//         Some(inner) => inner.as_str(),
//         None => "application/octet-stream"
//     };
//
//     let mut reponse_job = ReponseJob::from(job);
//     reponse_job.metadata = Some(metadata);
//     reponse_job.mimetype = Some(mimetype.to_string());
//     reponse_job.cle = Some(cle);
//     reponse_job.path_cuuids = path_cuuids;
//     debug!("get_prochaine_job_fichiersrep Reponse job : {:?}", reponse_job.tuuid);
//
//     Ok(reponse_job)
// }

// /// Trouver prochaine job
// /// Inclue les jobs avec too many retries
// pub async fn trouver_prochaine_job_traitement<M,S>(middleware: &M, nom_collection: S, commande: &CommandeGetJob)
//                                                    -> Result<Option<BackgroundJob>, CommonError>
//     where M: GenerateurMessages + MongoDao, S: AsRef<str> + Send
// {
//     let collection = middleware.get_collection(nom_collection.as_ref())?;
//
//     let job: Option<BackgroundJob> = {
//         // Tenter de trouver la prochaine job disponible
//         let mut filtre = doc! {
//             CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_PENDING,
//             CHAMP_FLAG_DB_RETRY: {"$lt": MEDIA_RETRY_LIMIT},
//         };
//
//         // Verifier si on utilise le filtre fallback pour les videos
//         if Some(true) == commande.fallback {
//             filtre.insert("fallback", true);
//         }
//
//         // Si le champ instances n'existe pas, l'instance de s'applique pas (e.g. repertoire).
//         // Sinon on attend qu'au moins une instance soit disponible.
//         match commande.filehost_id.as_ref() {
//             Some(instance_id) => {
//                 filtre.insert("$or", vec![doc!{"instances": {"$exists": false}}, doc!{"instances": instance_id}]);
//             },
//             None => {
//                 // Si le champ instances n'existe pas, l'instance de s'applique pas.
//                 // Sinon on attend qu'au moins une instance soit disponible.
//                 filtre.insert("$or", vec![doc!{"instances": {"$exists": false}}, doc!{"instances.0": {"$exists": true}}]);
//             }
//         }
//
//         let hint = Some(Hint::Name("etat_jobs_2".into()));
//         let options = FindOneAndUpdateOptions::builder()
//             .hint(hint)
//             .return_document(ReturnDocument::Before)
//             .build();
//         let ops = doc! {
//             "$set": {CHAMP_ETAT_JOB: VIDEO_CONVERSION_ETAT_RUNNING},
//             "$inc": {CHAMP_FLAG_DB_RETRY: 1},
//             "$currentDate": {CHAMP_MODIFICATION: true, CONST_CHAMP_DATE_MAJ: true}
//         };
//         match collection.find_one_and_update(filtre, ops, options).await? {
//             Some(d) => {
//                 debug!("trouver_prochaine_job_traitement (1) Charger job : {:?}", d);
//                 Some(convertir_bson_deserializable(d)?)
//             },
//             None => None
//         }
//     };
//
//     Ok(job)
// }

// pub async fn get_cle_job_indexation<M,S>(middleware: &M, cle_id: S)
//     -> Result<CleSecreteSerialisee, CommonError>
//     where
//         M: GenerateurMessages + MongoDao,
//         S: AsRef<str>
// {
//     let cle_id = cle_id.as_ref();
//
//     let demande_rechiffrage = RequeteDechiffrage {
//         domaine: DOMAINE_NOM.to_string(),
//         liste_hachage_bytes: None,
//         cle_ids: Some(vec![cle_id.to_owned()]),
//         certificat_rechiffrage: None,
//         inclure_signature: None,
//     };
//     let routage = RoutageMessageAction::builder(
//         DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
//     )
//         .build();
//
//     // Recuperer la cle de dechiffrage
//     let mut cle = if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_requete(routage, &demande_rechiffrage).await? {
//         let reponse_cle = reponse.message.parse()?;
//         match reponse_cle.kind {
//             millegrilles_cryptographie::messages_structs::MessageKind::ReponseChiffree => {
//                 let enveloppe_privee = middleware.get_enveloppe_signature();
//                 let reponse_dechiffree: ReponseRequeteDechiffrageV2 = reponse_cle.dechiffrer(enveloppe_privee.as_ref())?;
//                 match reponse_dechiffree.cles {
//                     Some(mut inner) => match inner.pop() {
//                         Some(inner) => inner,
//                         None => Err(CommonError::Str("get_cle_job_indexation Aucunes cles recues"))?
//                     },
//                     None => Err(CommonError::Str("get_cle_job_indexation Aucunes cles recues (None)"))?
//                 }
//             },
//             millegrilles_cryptographie::messages_structs::MessageKind::Reponse => {
//                 // La reponse n'est pas chiffree, l'acces est refuse
//                 let reponse: ReponseRequeteDechiffrageV2 = reponse_cle.contenu()?.deserialize()?;
//                 Err(CommonError::String(format!("get_cle_job_indexation Acces refuse a la cle : {:?}", reponse.err)))?
//             },
//             _ => Err(CommonError::Str("get_cle_job_indexation Erreur attente reponse cles pour job, mauvais kind de message recu"))?
//         }
//     } else {
//         Err(CommonError::Str("get_cle_job_indexation Erreur attente reponse cles pour job, mauvais type de message recu"))?
//     };
//
//     // Verifier que le cle_id recu correspond a la cle demandee
//     if let Some(cle_id_recu) = cle.cle_id.as_ref() {
//         if cle_id_recu.as_str() != cle_id {
//             Err(CommonError::Str("get_cle_job_indexation La cle dechiffree ne correspond pas au cle_id"))?
//         }
//     } else {
//         Err(CommonError::Str("get_cle_job_indexation La cle dechiffree ne contient pas de cle_id"))?
//     }
//
//     Ok(cle.try_into()?)
// }

#[derive(Clone, Debug, Deserialize)]
pub struct ParametresConfirmerJobIndexation {
    pub job_id: String,
    pub tuuid: String,
    pub fuuid: Option<String>,
    pub supprimer: Option<bool>,
    // pub user_id: String,
    // pub cle_conversion: Option<String>,
}

pub async fn sauvegarder_job<'a, M>(middleware: &M, job: &BackgroundJob, trigger: Option<JobTrigger<'a>>, nom_collection: &str, domain: &str, action_trigger: &str, session: &mut ClientSession)
    -> Result<BackgroundJob, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;

    // Verifier si une job existe deja pour le fichier represente
    let cle_conversion = match job.params.as_ref() {
        Some(params) => {
            if Some(true) == params.defaults {
                "defaults".to_string()
            } else {
                // Generate unique key from params
                format!("{:?};{:?};{:?};{:?};{:?};{:?}", params.mimetype, params.codec_video,
                        params.resolution_video, params.bitrate_audio, params.audio_stream_idx,
                        params.subtitle_stream_idx)
            }
        },
        None => "defaults".to_string()
    };
    let filtre = doc!{"tuuid": &job.tuuid, "cle_conversion": &cle_conversion};
    let ops = doc! {
        "$addToSet": {"filehost_ids": {"$each": &job.filehost_ids}},  // Merge the filehost_ids if appropriate
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = FindOneAndUpdateOptions::builder().return_document(ReturnDocument::After).build();
    let updated_job = match collection.find_one_and_update_with_session(filtre, ops, options, session).await? {
        Some(inner) => inner,
        None => {
            debug!("sauvegarder_job No job updated, returning cloned job");
            let mut job_copy = job.clone();
            job_copy.cle_conversion = Some(cle_conversion);
            collection.insert_one_with_session(job_copy, None, session).await?;
            job.clone()
        }
    };

    // Commit to ensure job is available before emitting trigger
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    // Emettre job pour traitement.
    match trigger {
        Some(inner) => emettre_processing_trigger(middleware, inner, domain, action_trigger).await,
        None => emettre_processing_trigger(middleware, &updated_job, domain, action_trigger).await
    }

    Ok(updated_job)
}

pub async fn creer_jobs_manquantes<M>(middleware: &M) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match creer_jobs_manquantes_session(middleware, &mut session).await {
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

async fn creer_jobs_manquantes_session<M>(middleware: &M, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao + GenerateurMessages
{
    if let Err(e) = creer_jobs_manquantes_queue(middleware, NOM_COLLECTION_IMAGES_JOBS, CHAMP_FLAG_MEDIA_TRAITE, session).await {
        error!("creer_jobs_manquantes Erreur creation jobs manquantes images: {:?}", e);
    }
    if let Err(e) = creer_jobs_manquantes_queue(middleware, NOM_COLLECTION_VIDEO_JOBS, CHAMP_FLAG_VIDEO_TRAITE, session).await {
        error!("creer_jobs_manquantes Erreur creation jobs manquantes videos: {:?}", e);
    }

    // Index - visiter tables VERSION et FICHIER_REP
    if let Err(e) = creer_jobs_manquantes_queue(middleware, NOM_COLLECTION_INDEXATION_JOBS, CHAMP_FLAG_INDEX, session).await {
        error!("creer_jobs_manquantes Erreur creation jobs manquantes index: {:?}", e);
    }
    if let Err(e) = creer_jobs_manquantes_fichiersrep(middleware, NOM_COLLECTION_INDEXATION_JOBS, CHAMP_FLAG_INDEX, session).await {
        error!("creer_jobs_manquantes Erreur creation jobs manquantes index: {:?}", e);
    }

    Ok(())
}

pub async fn creer_jobs_manquantes_queue<M>(middleware: &M, nom_collection: &str, flag_job: &str, session: &mut ClientSession) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages
{
    let collection_reps = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
    let collection_version = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
    let filtre_version = doc!{flag_job: false, "tuuids.0": {"$exists": true}, "visites.nouveau": {"$exists": false}};
    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;
    let mut curseur = collection_version.find_with_session(filtre_version, None, session).await?;
    let mut fuuids = Vec::new();
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        let fuuid = row.fuuid;
        // let tuuid = row.tuuid;

        // Verifier si une job existe pour ce fuuid. Ignorer fichiers en cours d'upload (nouveau).
        let filtre_job = doc! {"fuuid": fuuid};
        let count = collection_jobs.count_documents_with_session(filtre_job, None, session).await?;

        if count == 0 {
            debug!("creer_jobs_manquantes_queue Creer job {} manquante pour fuuid {}", flag_job, fuuid);
            let filtre_reps = doc!{"fuuids_versions": fuuid};
            let mut cursor_reps = collection_reps.find_with_session(filtre_reps, None, session).await?;
            while cursor_reps.advance(session).await? {
                let row_reps = cursor_reps.deserialize_current()?;
                let tuuid = row_reps.tuuid.as_str();
                let user_id = row_reps.user_id.as_str();

                if row.cle_id.is_some() && row.format.is_some() && row.nonce.is_some() {
                    let cle_id = row.cle_id.expect("cle_id");
                    let format: &str = row.format.clone().expect("format").into();
                    let nonce = row.nonce.expect("nonce");
                    let visites: Vec<&String> = row.visites.keys().collect();

                    let mut job = BackgroundJob::new(tuuid, fuuid, row.mimetype, &visites, cle_id, format, nonce);
                    if flag_job == CHAMP_FLAG_VIDEO_TRAITE {
                        // Champs supplementaires pour video
                        let params_initial = BackgroundJobParams {
                            defaults: Some(true),
                            thumbnails: Some(true),
                            mimetype: None,
                            codec_video: None,
                            codec_audio: None,
                            resolution_video: None,
                            quality_video: None,
                            bitrate_video: None,
                            bitrate_audio: None,
                            preset: None,
                            audio_stream_idx: None,
                            subtitle_stream_idx: None,
                        };
                        job.params = Some(params_initial);

                        job.user_id = Some(user_id.to_string());
                    } else if flag_job == CHAMP_FLAG_INDEX {
                        job.user_id = Some(user_id.to_string());
                    }
                    collection_jobs.insert_one_with_session(job, None, session).await?;
                    fuuids.push(fuuid.to_owned());
                } else {
                    // Old format. The keymaster has the key where cle_id == fuuid.
                    let cle_id = fuuid;
                    let mimetype = row.mimetype;

                    // Values for format and header (nonce) are available directly from the key.
                    let mut key_information = get_decrypted_keys(middleware, vec![cle_id.to_owned()]).await?;
                    if key_information.len() == 1 {
                        let key = key_information.pop().expect("pop key_information");
                        if key.format.is_some() && key.nonce.is_some() {
                            debug!("Cle_id {} information recovered successfully from keymaster", cle_id);
                            let format: &str = key.format.expect("format").into();
                            let nonce = key.nonce.expect("nonce");
                            let visites: Vec<&String> = vec![];
                            let job = BackgroundJob::new_index(tuuid, Some(fuuid), user_id, mimetype, &visites, cle_id, format, nonce);
                            collection_jobs.insert_one_with_session(job, None, session).await?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn creer_jobs_manquantes_fichiersrep<M>(middleware: &M, nom_collection: &str, flag_job: &str, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao
{
    let collection_reps = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre_reps = doc!{"supprime": false, "supprime_indirect": false, flag_job: false};
    let collection_jobs = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;
    let mut curseur = collection_reps.find_with_session(filtre_reps, None, session).await?;
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        let tuuid = &row.tuuid;
        let user_id = &row.user_id;

        // Verifier si une job existe pour ce tuuid/fuuid
        let filtre_job = doc! {"tuuid": tuuid};
        let count = collection_jobs.count_documents_with_session(filtre_job, None, session).await?;

        if count == 0 {
            debug!("creer_jobs_manquantes_queue Creer job {} manquante pour tuuid {}", flag_job, tuuid);
            let metadata = row.metadata;
            if metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
                let cle_id = metadata.cle_id.expect("cle_id");
                let format = metadata.format.expect("format");
                let nonce = metadata.nonce.expect("nonce");
                let mimetype = row.mimetype.unwrap_or_else(|| "application/octet-stream".to_string());
                let visites: Vec<&String> = vec![];
                let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, mimetype, &visites, cle_id, format, nonce);
                collection_jobs.insert_one(job, None).await?;
            }
        }
    }

    Ok(())
}

pub async fn entretien_jobs_expirees<M>(middleware: &M, fetch_filehosts: bool) -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match entretien_jobs_expirees_session(middleware, fetch_filehosts, &mut session).await {
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

async fn entretien_jobs_expirees_session<M>(middleware: &M, fetch_filehosts: bool, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_IMAGES_JOBS, 180, 1000 , "media", "processImage", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees Erreur entretien images: {:?}", e);
    }
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_VIDEO_JOBS, 600, 100, "media", "processVideo", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees Erreur entretien videos: {:?}", e);
    }
    if let Err(e) = reactiver_jobs(middleware, NOM_COLLECTION_INDEXATION_JOBS, 180, 2000, "solrrelai", "processIndex", fetch_filehosts, session).await {
        error!("entretien_jobs_expirees Erreur entretien index: {:?}", e);
    }
    Ok(())
}

pub async fn maintenance_impossible_jobs<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    match maintenance_impossible_jobs_session(middleware, gestionnaire, &mut session).await {
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

async fn maintenance_impossible_jobs_session<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    // Cleanup of jobs that will never complete
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_IMAGES_JOBS, 180, "processImage", session).await {
        error!("entretien_jobs_expirees Erreur entretien images: {:?}", e);
    }
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_VIDEO_JOBS, 600, "processVideo", session).await {
        error!("entretien_jobs_expirees Erreur entretien videos: {:?}", e);
    }
    if let Err(e) = remove_impossible_jobs(middleware, gestionnaire, NOM_COLLECTION_INDEXATION_JOBS, 180, "processIndex", session).await {
        error!("entretien_jobs_expirees Erreur entretien index: {:?}", e);
    }

    Ok(())
}

/// Resubmits a batch of pending jobs to queue. Reactivates running jobs that have expired.
pub async fn reactiver_jobs<M>(middleware: &M,
                               nom_collection: &str, timeout: i64, limit: i64,
                               domain: &str, action: &str, fetch_filehosts: bool, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;

    // Reset le flag des jobs expirees
    let expiration = Utc::now() - chrono::Duration::new(timeout, 0).expect("duration");
    let filtre = doc!{"etat": VIDEO_CONVERSION_ETAT_RUNNING, "date_maj": {"$lte": expiration}};
    let ops = doc!{
        "$set": {"etat": VIDEO_CONVERSION_ETAT_PENDING},
        "$inc": {"retry": 1},
    };
    collection.update_many_with_session(filtre, ops, None, session).await?;

    let filtre = doc!{"etat": VIDEO_CONVERSION_ETAT_PENDING, "retry": {"$lte": CONST_MAX_RETRY}};
    let options = FindOptions::builder().limit(limit).build();

    // Resubmit jobs - duplicates in the Q will be caught when requesting job decryption key
    let mut fuuids = Vec::new();
    let mut curseur = collection.find_with_session(filtre, options, session).await?;
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;
        if let Some(fuuid) = row.fuuid.as_ref() {
            fuuids.push(fuuid.to_owned());
        }

        let trigger: JobTrigger = match action {
            "processIndex" => {
                let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
                let filtre = doc!{"tuuid": &row.tuuid};
                match collection.find_one(filtre, None).await? {
                    Some(fichier) => {
                        let mut trigger = JobTrigger::from(&row);
                        trigger.metadata = Some(fichier.metadata);
                        trigger.path_cuuids = fichier.path_cuuids;
                        trigger
                    },
                    None => {
                        // Cleanup job pour fichier inconnu
                        let filtre = doc!{"job_id": &row.job_id};
                        collection.delete_one(filtre, None).await?;
                        Err(CommonError::String(format!("reactiver_jobs Fichier inconnu tuuid (job maintenant supprimee):{}", row.tuuid)))?
                    }
                }
            },
            _ => (&row).into()
        };

        emettre_processing_trigger(middleware, trigger, domain, action).await;
    }

    debug!("reactiver_jobs Job collection {}, fuuids: {}", nom_collection, fuuids.len());

    // Synchronise with core in case some files were received without GrosFichiers being notified.
    if ! fuuids.is_empty() && fetch_filehosts {
        if let Err(e) = sync_jobs_core_filehosts(middleware, nom_collection, &fuuids, session).await {
            warn!("reactiver_jobs Error sync jobs with fuuids in core: {:?}", e);
        }
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct FuuidVisitResponseItem {pub fuuid: String, pub visits: HashMap<String, i64>}

#[derive(Deserialize)]
struct RequestFilehostsForFuuidsResponse {fuuids: Vec<FuuidVisitResponseItem>}

pub async fn sync_jobs_core_filehosts<M>(middleware: &M, nom_collection: &str, fuuids: &Vec<String>, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    debug!("Sync filehost_ids for {} fuuids", fuuids.len());
    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "requestFilehostsForFuuids", vec![Securite::L3Protege])
        .build();
    if let Some(TypeMessage::Valide(response)) = middleware.transmettre_requete(routage, json!({"fuuids": fuuids})).await? {
        debug!("Response: {}", from_utf8(&response.message.buffer)?);
        let response: RequestFilehostsForFuuidsResponse = deser_message_buffer!(response.message);

        let collection_jobs = middleware.get_collection(nom_collection)?;
        for fuuid_visits in response.fuuids {
            // Update the jobs table
            let filehost_ids: Vec<&String> = fuuid_visits.visits.keys().collect();
            let filtre = doc!{"fuuid": &fuuid_visits.fuuid};
            let ops = doc!{"$addToSet": {"filehost_ids": {"$each": filehost_ids}}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection_jobs.update_many_with_session(filtre.clone(), ops, None, session).await?;

            // Update visits in the versions tables
            sauvegarder_visites(middleware, fuuid_visits.fuuid.as_str(), &fuuid_visits.visits, session).await?;
        }
    }

    Ok(())
}

/// Deactivates for good jobs that have never been picked up or that have too many retries.
pub async fn remove_impossible_jobs<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager,
                                       nom_collection: &str, limit: i64, action: &str, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao + GenerateurMessages + ValidateurX509 {

    let expiration = Utc::now() - Duration::days(1);
    let collection = middleware.get_collection_typed::<BackgroundJob>(nom_collection)?;
    let filtre = doc!{
        "$or": [
            {"retry": {"$gt": CONST_MAX_RETRY}},  // Any job with retry > CONST_MAX_RETRY
            {
                CHAMP_MODIFICATION: {"$lte": expiration}
            },
        ]
    };

    let options = FindOptions::builder().limit(limit).build();
    let mut curseur = collection.find_with_session(filtre, options, session).await?;
    while curseur.advance(session).await? {
        let row = curseur.deserialize_current()?;

        // Cancel the job, emit a transaction to clear for good
        info!("remove_impossible_jobs Trop d'echecs sur traitement {} fuuid {:?}, desactiver pour de bon", action, row.fuuid);
        match action {
            "processImage" => {
                match row.fuuid.as_ref() {
                    Some(fuuid) => {
                        // Create transaction to prevent job from running on restore.
                        let transaction = TransactionSupprimerJobImageV2 {
                            tuuid: row.tuuid,
                            fuuid: fuuid.to_owned(),
                            err: None,
                        };
                        sauvegarder_traiter_transaction_serializable_v2(
                            middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_IMAGE_SUPPRIMER_JOB_V2).await?;
                    },
                    None => {
                        warn!("remove_impossible_jobs Job image tuuid:{} sans fuuid, ignorer", row.tuuid);
                    }
                }
            },
            "processVideo" => {
                match row.fuuid.as_ref() {
                    Some(fuuid) => {
                        // Create transaction to prevent job from running on restore.
                        let transaction = TransactionSupprimerJobVideoV2 {
                            tuuid: row.tuuid,
                            fuuid: fuuid.to_owned(),
                            job_id: row.job_id.clone(),
                        };
                        sauvegarder_traiter_transaction_serializable_v2(
                            middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_VIDEO_SUPPRIMER_JOB_V2).await?;
                    },
                    None => {
                        warn!("remove_impossible_jobs Job video tuuid:{} sans fuuid, ignorer", row.tuuid);
                    }
                }
            },
            "processIndex" => {
                // Toggle index flag in reps/versions collections. There are no transactions for indexing.
                let fuuid = match row.fuuid.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None};
                set_flag_index_traite(middleware, row.job_id.as_str(), row.tuuid.as_str(), fuuid, session).await?;
            },
            _ => warn!("remove_impossible_jobs Unknown expired job type: {}", action)
        }

        let filtre = doc!{"job_id": &row.job_id};
        collection.delete_one_with_session(filtre, None, session).await?;
    }

    Ok(())
}
