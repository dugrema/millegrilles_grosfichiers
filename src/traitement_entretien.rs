use std::collections::{HashMap, HashSet};
use std::time::Duration;
use log::{debug, error, info, warn};

use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, MongoDao};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::redis::SetOptions;
use millegrilles_common_rust::tokio::time::sleep;
use serde::Serialize;
use crate::domain_manager::GrosFichiersDomainManager;
use crate::evenements::declencher_traitement_nouveau_fuuid;
use crate::grosfichiers_constantes::*;

pub async fn calculer_quotas<M>(middleware: &M)
-> Result<(), CommonError>
where M: MongoDao
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match calculer_quotas_fichiers_usagers(middleware, &mut session).await {
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

#[derive(Deserialize)]
struct QuotaFichiersAggregateRow {
    #[serde(rename="_id")]
    user_id: String,
    bytes_total_versions: i64,
    nombre_total_versions: i64,
}

async fn calculer_quotas_fichiers_usagers<M>(middleware: &M, session: &mut ClientSession) -> Result<(), CommonError>
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
    ];

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let collection_quotas = middleware.get_collection(NOM_COLLECTION_QUOTAS_USAGERS)?;
    let mut result = collection_versions.aggregate_with_session(pipeline, None, session).await?;
    while let Some(row) = result.next(session).await {
        let row = row?;
        let row: QuotaFichiersAggregateRow = convertir_bson_deserializable(row)?;
        let filtre_upsert = doc!{"user_id": row.user_id};
        let ops = doc!{
            "$setOnInsert": {CHAMP_CREATION: Utc::now()},
            "$set": {
                "bytes_total_versions": row.bytes_total_versions,
                "nombre_total_versions": row.nombre_total_versions,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let options = UpdateOptions::builder().upsert(true).build();
        collection_quotas.update_one_with_session(filtre_upsert, ops, options, session).await?;
    }

    Ok(())
}

pub async fn reclamer_fichiers<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, nouveau: bool)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match reclamer_fichiers_session(middleware, gestionnaire, nouveau, &mut session).await {
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

pub async fn reclamer_fichiers_session<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, nouveau: bool, session: &mut ClientSession)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("verifier_visites Debut");

    if let Err(e) = verifier_visites_nouvelles(middleware, gestionnaire, session).await {
        error!("verifier_visites Erreur entretien visites nouveaux: {:?}", e);
    }

    // if ! nouveau {
    //     // Detecter fichiers
    //     if let Err(e) = verifier_visites_expirees_session(middleware, session).await {
    //         error!("verifier_visites Erreur entretien visites fichiers: {:?}", e);
    //     }
    // }

    debug!("verifier_visites Fin");
    Ok(())
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
    let expiration_secs = expiration.timestamp();

    debug!("verifier_visites_nouvelles Verifier nouveaux (visites.nouveau, epoch {} et plus recent)", expiration_secs);

    let filtre = doc!{
        "visites.nouveau": {"$gte": expiration_secs},
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

pub async fn verifier_visites_expirees<M>(middleware: &M) -> Result<(), CommonError>
where M: GenerateurMessages + MongoDao
{
    debug!("verifier_visites_expirees Claim fuuids");

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
                warn!("Error receiving response for batch of claims, retrying: Error: {:?}", reponse.err);
                sleep(Duration::from_secs(5)).await;
                reponse = claim_files(middleware, batch_no, false, &visits).await?;
            }

            if ! reponse.ok {
                Err(format!("Error claiming files, aborting: {:?}", reponse.err))?;
            }

            debug!("verifier_visites_expirees Batch {} of {} fuuids claimed", batch_no, visits.len());
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
        warn!("Error receiving response for last batch of claims, retrying: Error: {:?}", reponse.err);
        sleep(Duration::from_secs(5)).await;
        reponse = claim_files(middleware, batch_no, true, &visits).await?;
    }
    if ! reponse.ok {
        warn!("Error on last batch of claims: {:?}", reponse.err);
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
    let ops = doc!{
        "$set": {"visites": convertir_to_bson(visites)?},
        "$currentDate": {CHAMP_MODIFICATION: true, CONST_FIELD_LAST_VISIT_VERIFICATION: true},
    };

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
