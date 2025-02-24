use std::collections::{HashMap, HashSet};
use std::time::Duration;
use log::{debug, error, info, warn};

use millegrilles_common_rust::bson::{doc, Bson};
use millegrilles_common_rust::{bson, chrono};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::redis::SetOptions;
use millegrilles_common_rust::tokio::time::sleep;
use serde::Serialize;
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use crate::commandes::VisitWorkRow;
use crate::domain_manager::GrosFichiersDomainManager;
use crate::evenements::declencher_traitement_nouveau_fuuid;
use crate::grosfichiers_constantes::*;

pub async fn calculer_quotas<M>(middleware: &M)
-> Result<(), CommonError>
where M: MongoDao
{
    calculer_quotas_fichiers_usagers(middleware).await
}

#[derive(Deserialize)]
struct QuotaFichiersAggregateRow {
    #[serde(rename="_id")]
    user_id: String,
    bytes_total_versions: i64,
    nombre_total_versions: i64,
}

async fn calculer_quotas_fichiers_usagers<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao
{
    let pipeline = vec! [
        doc!{"$match": {"tuuids.0": {"$exists": true}}}, // Check if at least one tuuid is linked (means not deleted)
        doc! { "$project": {"tuuids": 1, CHAMP_TAILLE: 1} },
        doc! { "$lookup": {
            // Lookup the rep table to get the user ids.
            "from": NOM_COLLECTION_FICHIERS_REP,
            "localField": CHAMP_TUUIDS,
            "foreignField": CHAMP_TUUID,
            "pipeline": [
                // Check that the file is not deleted even tough the tuuids array should not contain deleted files.
                {"$match": {CHAMP_SUPPRIME: false}},
                {"$group": {"_id": "$user_id"}},
            ],
            "as": "users",
        }},
        doc! { "$unwind": {"path": "$users"} },  // Expand the users array to get a single user_id per row
        doc! { "$project": {"users": 1, CHAMP_TAILLE: 1} },
        doc!{"$group": {
            "_id": "$users._id",
            "bytes_total_versions": {"$sum": "$taille"},
            "nombre_total_versions": {"$count": {}},
        }},
        doc! { "$addFields": {"user_id": "$_id", CHAMP_MODIFICATION: "$$NOW"} },
        doc! { "$unset": "_id" },
        doc!{"$merge": {
            "into": NOM_COLLECTION_QUOTAS_USAGERS,
            "on": "user_id",
            "whenNotMatched": "insert",
        }}
    ];

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    collection_versions.aggregate(pipeline, None).await?;

    Ok(())
}

pub async fn reclamer_fichiers<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, nouveau: bool)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match verifier_visites_nouvelles(middleware, gestionnaire, &mut session).await {
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

#[derive(Deserialize)]
struct FuuidRow {
    fuuids_reclames: Vec<String>
}

const VISIT_BATCH_SIZE: usize = 1000;

async fn verifier_visites_nouvelles<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    let now = Utc::now();

    // Faire une verification des fichiers qui sont encore "nouveaux" avec une date de
    // creation recente (< 30 minutes).
    let delai_expiration = Duration::from_secs(1800);
    let expiration = now - delai_expiration;
    // let expiration_secs = expiration.timestamp();

    debug!("verifier_visites_nouvelles Verifier nouveaux (visites.nouveau, epoch {} et plus recent)", expiration);

    let filtre = doc!{
        "visites.nouveau": {"$gte": expiration},
        "tuuids.0": {"$exists": true},  // Check if at least one tuuid is linked (means not deleted)
    };

    let collection_versions = middleware.get_collection_typed::<FuuidRow>(NOM_COLLECTION_VERSIONS)?;
    let options = FindOptions::builder()
        .limit(VISIT_BATCH_SIZE as i64)
        .hint(Hint::Name("last_visits".to_string()))  // Sorts by last_visit ASC
        .projection(doc!{"fuuids_reclames": 1})
        .build();

    let visits = {
        let mut curseur = collection_versions.find_with_session(filtre, options, session).await?;
        let mut visits = Vec::with_capacity(VISIT_BATCH_SIZE);
        while let Some(row) = curseur.next(session).await {
            let fuuids = row?.fuuids_reclames;
            visits.extend(fuuids);
            if visits.len() > VISIT_BATCH_SIZE {
                // Already 1000 items, break and continue with another batch later
                break
            }
        }

        visits
    };

    debug!("verifier_visites_nouvelles Verifier {} fuuids", visits.len());

    if visits.len() == 0 {
        return Ok(())  // Nothing to do
    }

    let reponse = verifier_visites_topologies(middleware, &visits).await?;
    if let Some(visites) = reponse.visits {
        debug!("verifier_visites_nouvelles Visite {} nouveaux fuuids", visites.len());
        for item in visites {
            // Emettre evenement consigne pour indiquer que le fichier n'est plus nouveau
            sauvegarder_visites(middleware, item.fuuid.as_str(), &item.visits, session).await?;
            declencher_traitement_nouveau_fuuid(middleware, gestionnaire, &item.fuuid, item.visits.keys().collect(), session).await?;
        }
    }
    if let Some(unknown) = reponse.unknown {
        debug!("verifier_visites_nouvelles {} fuuids inconnus", unknown.len());
        sauvegarder_fuuid_inconnu(middleware, &unknown, session).await?;
    }

    Ok(())
}

/// Claims all required files on filehosts. Prevents them from being deleted.
pub async fn claim_all_files<M>(middleware: &M) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("claim_all_files Claim fuuids");

    // Faire une reclamation des fichiers regulierement (tous les jours) pour eviter qu'ils soient
    // consideres comme orphelins (et supprimes).
    let filtre = doc!{
        "tuuids.0": {"$exists": true},  // Check if at least one tuuid is linked (means not deleted)
    };

    let options = FindOptions::builder()
        .projection(doc!{"fuuids_reclames": 1})
        .build();

    let collection_versions = middleware.get_collection_typed::<FuuidRow>(NOM_COLLECTION_VERSIONS)?;
    let mut cursor = collection_versions.find(filtre, options).await?;
    let mut visits = Vec::with_capacity(VISIT_BATCH_SIZE);
    let mut batch_no = 0;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        visits.extend(row.fuuids_reclames);

        if(visits.len() >= VISIT_BATCH_SIZE) {
            let mut reponse = claim_files(middleware, batch_no, false, &visits).await?;
            for _ in 0..3 {
                if reponse.ok {
                    break;  // Success
                }
                // Wait 5 seconds
                warn!("claim_all_files Error receiving response for batch of claims, retrying: Error: {:?}", reponse.err);
                sleep(Duration::from_secs(5)).await;
                reponse = claim_files(middleware, batch_no, false, &visits).await?;
            }

            if ! reponse.ok {
                Err(format!("Error claiming files, aborting: {:?}", reponse.err))?;
            }

            debug!("claim_all_files Batch {} of {} fuuids claimed", batch_no, visits.len());
            visits.clear();
            batch_no += 1;
        }
    }

    // Last batch
    let mut reponse = claim_files(middleware, batch_no, true, &visits).await?;
    for _ in 0..3 {
        if reponse.ok {
            break;  // Success
        }
        // Wait 5 seconds
        warn!("claim_all_files Error receiving response for last batch of claims, retrying: Error: {:?}", reponse.err);
        sleep(Duration::from_secs(5)).await;
        reponse = claim_files(middleware, batch_no, true, &visits).await?;
    }
    if ! reponse.ok {
        warn!("claim_all_files Error on last batch of claims: {:?}", reponse.err);
    }

    // let options = FindOptions::builder()
    //     .limit(VISIT_BATCH_SIZE as i64)
    //     .hint(Hint::Name("last_visits".to_string()))
    //     .projection(doc!{"fuuids_reclames": 1})
    //     .build();
    //
    // for batch_no in 1..101 {  // Max of 100 batches at once
    //     let visits = {
    //         let mut curseur = collection_versions.find_with_session(filtre.clone(), options.clone(), session).await?;
    //         let mut visits = Vec::with_capacity(VISIT_BATCH_SIZE);
    //         while let Some(row) = curseur.next(session).await {
    //             let fuuids = row?.fuuids_reclames;
    //             visits.extend(fuuids);
    //             if visits.len() >= VISIT_BATCH_SIZE {
    //                 // Already 1000 items, break and continue with another batch later
    //                 break
    //             }
    //         }
    //
    //         visits
    //     };
    //
    //     info!("verifier_visites_expirees Batch {} verifier {} fuuids", batch_no, visits.len());
    //
    //     if visits.len() == 0 {
    //         break  // Nothing to do
    //     }
    //
    //     // Faire un set de fuuids pour s'assurer qu'ils sont tous dans les reponses
    //     let mut visits_set = HashSet::new();
    //     visits_set.extend(visits.iter().map(|v| v.as_str()));
    //
    //     let reponse = verifier_visites_topologies(middleware, &visits).await?;
    //     if let Some(visites) = reponse.visits {
    //         debug!("verifier_visites_expirees Visite {} fuuids", visites.len());
    //
    //         // Touch the reps to allow client updates
    //         let filtre = doc!{"fuuids_versions": {"$in": visites.iter().map(|x|x.fuuid.as_str()).collect::<Vec<_>>()}};
    //         let ops = doc!{"$currentDate": {CHAMP_MODIFICATION: true}};
    //         let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    //         collection.update_one_with_session(filtre, ops, None, session).await?;
    //
    //         for item in visites {
    //             sauvegarder_visites(middleware, item.fuuid.as_str(), &item.visits, session).await?;
    //             visits_set.remove(item.fuuid.as_str());
    //         }
    //     }
    //     if let Some(unknown) = reponse.unknown {
    //         debug!("verifier_visites_expirees {} fuuids inconnus", unknown.len());
    //         sauvegarder_fuuid_inconnu(middleware, &unknown, session).await?;
    //         for f in &unknown {
    //             visits_set.remove(f.as_str());
    //         }
    //     }
    //
    //     if visits_set.len() > 0 {
    //         warn!("verifier_visites_expirees {} fuuids sans reponse sur claim, marquer inconnus", visits_set.len());
    //         // Record remaining fuuids as also missing
    //         let remaining: Vec<String> = visits_set.iter().map(|v| v.to_string()).collect();
    //         sauvegarder_fuuid_inconnu(middleware, &remaining, session).await?;
    //     }
    //
    //     // Commit batch
    //     session.commit_transaction().await?;
    //     start_transaction_regular(session).await?;
    //
    //     if visits.len() < VISIT_BATCH_SIZE {
    //         break  // All current files covered
    //     }
    // }

    Ok(())
}

#[derive(Serialize)]
struct RequeteFuuidsVisites<'a> {
    fuuids: &'a Vec<&'a str>,
    batch_no: Option<usize>,
    done: Option<bool>,
}

#[derive(Deserialize)]
pub struct RowFuuidVisit {
    pub fuuid: String,
    pub visits: HashMap<String, i64>,
}

#[derive(Deserialize)]
pub struct RequeteGetVisitesFuuidsResponse {
    pub ok: bool,
    pub err: Option<String>,
    pub visits: Option<Vec<RowFuuidVisit>>,
    pub unknown: Option<Vec<String>>
}

pub async fn verifier_visites_topologies<M,S,I>(middleware: &M, fuuids: I) -> Result<RequeteGetVisitesFuuidsResponse, CommonError>
    where M: GenerateurMessages, S: AsRef<str>, I: IntoIterator<Item=S>
{
    let fuuids_1 = fuuids.into_iter().collect::<Vec<_>>();  // Copy S reference for ownership
    let fuuids_2 = fuuids_1.iter().map(|f| f.as_ref()).collect::<Vec<_>>(); // Extract &str
    let requete = RequeteFuuidsVisites { fuuids: &fuuids_2, batch_no: None, done: None };

    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "claimAndFilehostVisits", vec![Securite::L3Protege]).build();
    if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_commande(routage, &requete).await? {
        let reponse: RequeteGetVisitesFuuidsResponse = deser_message_buffer!(reponse.message);
        if ! reponse.ok {
            Err("verifier_visites_topologies Erreur dans reponse CoreTopologie pour getFilehostVisitsForFuuids")?;
        }
        Ok(reponse)
    } else {
        Err("verifier_visites_topologies Mauvais type de reponse pour getFilehostVisitsForFuuids")?
    }
}

async fn claim_files<M,S,I>(middleware: &M, batch_no: usize, done: bool, fuuids: I) -> Result<RequeteGetVisitesFuuidsResponse, CommonError>
where M: GenerateurMessages, S: AsRef<str>, I: IntoIterator<Item=S>
{
    let fuuids_1 = fuuids.into_iter().collect::<Vec<_>>();  // Copy S reference for ownership
    let fuuids_2 = fuuids_1.iter().map(|f| f.as_ref()).collect::<Vec<_>>(); // Extract &str
    let requete = RequeteFuuidsVisites { fuuids: &fuuids_2, batch_no: Some(batch_no), done: Some(done) };

    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "claimFiles", vec![Securite::L3Protege]).build();
    if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_commande(routage, &requete).await? {
        let reponse: RequeteGetVisitesFuuidsResponse = deser_message_buffer!(reponse.message);
        if ! reponse.ok {
            Err("verifier_visites_topologies Erreur dans reponse CoreTopologie pour getFilehostVisitsForFuuids")?;
        }
        Ok(reponse)
    } else {
        Err("verifier_visites_topologies Mauvais type de reponse pour getFilehostVisitsForFuuids")?
    }
}

pub async fn sauvegarder_visites<M>(middleware: &M, fuuid: &str, visites: &HashMap<String, i64>, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: MongoDao
{
    let filtre = doc!{"fuuid": fuuid};

    let mut visits_date = doc!{};
    for (k,v) in visites {
        let date_time = match DateTime::from_timestamp(*v, 0) {
            Some(inner) => inner,
            None => Err("sauvegarder_visites Invalid visit date")?
        };
        visits_date.insert(k.to_string(), date_time);
    }

    let ops = doc!{
        "$set": {"visites": visits_date},
        "$currentDate": {CHAMP_MODIFICATION: true, CONST_FIELD_LAST_VISIT_VERIFICATION: true},
    };

    debug!("sauvegarder_visites ops {:?}", ops);

    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    collection.update_one_with_session(filtre, ops, None, session).await?;

    Ok(())
}

async fn sauvegarder_fuuid_inconnu<M>(middleware: &M, fuuids: &Vec<String>, session: &mut ClientSession) -> Result<(), CommonError>
where M: MongoDao
{
    let filtre = doc!{"fuuid": {"$in": fuuids}};
    let ops = doc!{
        "$currentDate": {CHAMP_MODIFICATION: true, CONST_FIELD_LAST_VISIT_VERIFICATION: true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    collection.update_many_with_session(filtre, ops, None, session).await?;

    Ok(())
}

// #[derive(Deserialize)]
// struct FuuidVisitWorkRow {
//     fuuid: String,
//     filehost_id: Option<String>,
//     #[serde(with="opt_chrono_datetime_as_bson_datetime")]
//     visit_time: Option<DateTime<Utc>>,
// }

/// Processes the entries received in the temp visits table.
pub async fn process_visits<M>(middleware: &M) -> Result<(), CommonError>
    where M: ConfigMessages + MongoDao
{
    // Check if we have some records to process
    let collection_temp_visits = middleware.get_collection(NOM_COLLECTION_TEMP_VISITS)?;
    {
        let count_options = CountOptions::builder().limit(1).build();
        let result = collection_temp_visits.count_documents(doc! {}, count_options).await?;
        if result == 0 {
            debug!("process_visits No entries to process");
            return Ok(())
        }  // Nothing to do
    }

    // Take over the collection, rename it to _WORK
    let collection_visits_work_name = format!("{}_WORK", NOM_COLLECTION_TEMP_VISITS);
    middleware.rename_collection(NOM_COLLECTION_TEMP_VISITS, &collection_visits_work_name, true).await?;

    let collection_work = middleware.get_collection_typed::<VisitWorkRow>(collection_visits_work_name.as_str())?;
    // Create an index to facilitate grouping by fuuid
    {
        let options_fuuids = IndexOptions { nom_index: Some(format!("fuuids")), unique: false };
        let champs_index_fuuids_version = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
        middleware.create_index(middleware, collection_visits_work_name.as_str(), champs_index_fuuids_version, Some(options_fuuids)).await?;
    }

    info!("process_visits Processing visit batches START");

    // Process the unknown visits - this empties the visites object.
    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let filtre = doc!{"visit_time": null};
    let mut cursor = collection_work.find(filtre, None).await?;
    let mut removed_visits = Vec::new();
    let ops = doc!{
        "$set": {CHAMP_VISITES: {}},
        "$currentDate": {CHAMP_MODIFICATION: true, "last_visit_verification": true},
    };
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        removed_visits.push(row.fuuid);
        if removed_visits.len() > 50 {
            let filtre = doc!{"fuuid": {"$in": &removed_visits}};
            collection_versions.update_many(filtre, ops.clone(), None).await?;
            removed_visits.clear();
        }
    }
    if ! removed_visits.is_empty() {
        let filtre = doc!{"fuuid": {"$in": removed_visits}};
        collection_versions.update_many(filtre, ops.clone(), None).await?;
    }

    // Aggregation pipeline to process the visits
    let pipeline = vec![
        doc!{"$sort": {CHAMP_FUUID: 1}},                    // Should use the index
        doc!{"$match": {"visit_time": {"$exists": true}}},  // Filter out unknown fuuid entries

        doc!{"$addFields": {"obj": {"k": "$filehost_id", "v": "$visit_time"}}},
        doc!{"$group": {"_id": "$fuuid", "items": {"$push": "$obj"}}},
        doc!{"$addFields": {
            "fuuid": "$_id",
            CHAMP_VISITES: {"$arrayToObject": "$items"},
            CHAMP_MODIFICATION: "$$NOW",            // Required for changes to get picked-up
            "last_visit_verification": "$$NOW",
        }},
        doc!{"$unset": ["_id", "items"]},
        doc!{"$merge": {
            "into": NOM_COLLECTION_VERSIONS,
            "on": "fuuid",
            "whenNotMatched": "discard",
        }},
    ];
    collection_work.aggregate(pipeline, None).await?;

    info!("process_visits Processing visit batches DONE");

    // Done with the work collection, cleanup.
    collection_work.drop(None).await?;

    Ok(())
}