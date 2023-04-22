use std::collections::HashSet;
use std::error::Error;
use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use crate::grosfichiers::emettre_evenement_maj_fichier;

use crate::grosfichiers_constantes::*;
use crate::traitement_media::emettre_commande_media;

const LIMITE_FUUIDS_BATCH: usize = 10000;

pub async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive]) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_evenement: Exchange evenement invalide (pas 2.prive)")),
    }?;

    match m.action.as_str() {
        // EVENEMENT_CONFIRMER_ETAT_FUUIDS => {
        //     evenement_confirmer_etat_fuuids(middleware, m).await?;
        //     Ok(None)
        // },
        EVENEMENT_TRANSCODAGE_PROGRES => evenement_transcodage_progres(middleware, m).await,
        EVENEMENT_FICHIERS_SYNCPRET => evenement_fichiers_syncpret(middleware, m).await,
        EVENEMENT_FICHIERS_VISITER_FUUIDS => evenement_visiter_fuuids(middleware, m).await,
        EVENEMENT_FICHIERS_CONSIGNE => evenement_fichier_consigne(middleware, m).await,
        _ => Err(format!("grosfichiers.consommer_evenement: Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

// async fn evenement_confirmer_etat_fuuids<M>(middleware: &M, m: MessageValideAction)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao,
// {
//     let uuid_transaction = m.correlation_id.clone();
//
//     if !m.verifier_exchanges(vec![L2Prive]) {
//         error!("evenement_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", uuid_transaction);
//         return Ok(None)
//     }
//
//     debug!("evenement_confirmer_etat_fuuids Message : {:?}", & m.message);
//     let evenement: EvenementConfirmerEtatFuuids = m.message.get_msg().map_contenu(None)?;
//     debug!("evenement_confirmer_etat_fuuids parsed : {:?}", evenement);
//
//     repondre_fuuids(middleware, &evenement.fuuids).await?;
//
//     Ok(None)
// }

async fn evenement_transcodage_progres<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let uuid_transaction = m.correlation_id.clone();

    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", uuid_transaction);
        return Ok(None)
    }
    if !m.verifier_roles(vec![RolesCertificats::Media]) {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas de role media");
        return Ok(None)
    }

    debug!("evenement_transcodage_progres Message : {:?}", & m.message);
    let evenement: EvenementTranscodageProgres = m.message.get_msg().map_contenu()?;
    debug!("evenement_transcodage_progres parsed : {:?}", evenement);

    let height = match evenement.height {
        Some(h) => h,
        None => {
            // Height/resolution n'est pas fourni, rien a faire
            return Ok(None)
        }
    };

    let bitrate_quality = match &evenement.video_quality {
        Some(q) => q.to_owned(),
        None => match &evenement.video_bitrate {
            Some(b) => b.to_owned() as i32,
            None => 0
        }
    };

    let cle_video = format!("{};{};{}p;{}", evenement.mimetype, evenement.video_codec, height, bitrate_quality);
    let filtre = doc! {
        CHAMP_FUUID: &evenement.fuuid,
        CHAMP_CLE_CONVERSION: &cle_video
    };

    let mut ops = doc! {
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    match evenement.pct_progres {
        Some(p) => {
            let set_ops = doc! {"pct_progres": p};
            ops.insert("$set", set_ops);
        },
        None => ()
    }
    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    collection.update_one(filtre, ops, None).await?;

    Ok(None)
}

async fn transmettre_fuuids_fichiers<M>(middleware: &M, fuuids: &Vec<String>, archive: bool)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let confirmation = doc! {
        "fuuids": fuuids,
        "archive": archive,
    };
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_ACTIVITE_FUUIDS)
        .exchanges(vec![L2Prive])
        .build();
    middleware.transmettre_commande(routage, &confirmation, false).await?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct RowFichiersSyncpret {
    fuuids: Vec<String>,
    archive: Option<bool>,
}

async fn evenement_fichiers_syncpret<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_fichiers_syncpret Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.verifier_roles(vec![RolesCertificats::Fichiers]) {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let mut fichiers_actifs: Vec<String> = Vec::with_capacity(10000);
    let mut fichiers_archives: Vec<String> = Vec::with_capacity(10000);

    let projection = doc!{ CHAMP_ARCHIVE: 1, CHAMP_FUUIDS: 1 };
    let options = FindOptions::builder().projection(projection).build();
    let filtre = doc! { CHAMP_SUPPRIME: false, CHAMP_FUUIDS: {"$exists": true} };
    let mut curseur = collection.find(filtre, Some(options)).await?;
    while let Some(f) = curseur.next().await {
        let info_fichier: RowFichiersSyncpret = convertir_bson_deserializable(f?)?;
        let archive = match info_fichier.archive { Some(b) => b, None => false };
        if archive {
            fichiers_archives.extend(info_fichier.fuuids.into_iter());
        } else {
            fichiers_actifs.extend(info_fichier.fuuids.into_iter());
        }

        if fichiers_actifs.len() >= LIMITE_FUUIDS_BATCH {
            transmettre_fuuids_fichiers(middleware, &fichiers_actifs, false).await?;
            fichiers_actifs.clear();
        }
        if fichiers_archives.len() >= LIMITE_FUUIDS_BATCH {
            transmettre_fuuids_fichiers(middleware, &fichiers_archives, true).await?;
            fichiers_archives.clear();
        }
    }

    if ! fichiers_actifs.is_empty() {
        transmettre_fuuids_fichiers(middleware, &fichiers_actifs, false).await?;
    }
    if ! fichiers_archives.is_empty() {
        transmettre_fuuids_fichiers(middleware, &fichiers_archives, true).await?;
    }

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementTranscodageProgres {
    fuuid: String,
    mimetype: String,
    #[serde(rename="videoCodec")]
    video_codec: String,
    #[serde(rename="videoBitrate")]
    video_bitrate: Option<u32>,
    #[serde(rename="videoQuality")]
    video_quality: Option<i32>,
    height: Option<u32>,
    #[serde(rename="pctProgres")]
    pct_progres: Option<i32>,
    passe: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowEtatFuuid {
    fuuids: Vec<String>,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseConfirmerEtatFuuids {
    fuuids: Vec<ConfirmationEtatFuuid>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfirmationEtatFuuid {
    fuuid: String,
    supprime: bool,
}

#[derive(Clone, Deserialize)]
struct EvenementVisiterFuuids { fuuids: Vec<String> }

async fn evenement_visiter_fuuids<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_visiter_fuuids Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.verifier_roles(vec![RolesCertificats::Fichiers]) {
        error!("evenement_visiter_fuuids Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    debug!("evenements.evenement_visiter_fuuids Mapper EvenementVisiterFuuids a partir de {:?}", m.message);
    let evenement: EvenementVisiterFuuids = m.message.parsed.map_contenu()?;
    let date_visite = &m.message.parsed.estampille;

    // Recuperer instance_id
    let instance_id = match m.message.certificat.as_ref() {
        Some(inner) => {
            match inner.subject()?.get("commonName") {
                Some(inner) => inner.clone(),
                None => Err(format!("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
            }
        },
        None => Err(format!("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
    };

    debug!("evenement_visiter_fuuids  Visiter {} fuuids de l'instance {}", evenement.fuuids.len(), instance_id);
    marquer_visites_fuuids(middleware, &evenement.fuuids, date_visite, instance_id).await?;

    Ok(None)
}

#[derive(Clone, Deserialize)]
struct EvenementFichierConsigne { hachage_bytes: String }

#[derive(Clone, Deserialize)]
struct DocumentFichierDetailIds { fuuid: String, tuuid: String, flag_media: Option<String>, flag_media_traite: Option<bool>, mimetype: Option<String> }

async fn evenement_fichier_consigne<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_fichier_consigne Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.verifier_roles(vec![RolesCertificats::Fichiers]) {
        error!("evenement_fichier_consigne Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    debug!("evenements.evenement_fichier_consigne Mapper EvenementVisiterFuuids a partir de {:?}", m.message);
    let evenement: EvenementFichierConsigne = m.message.parsed.map_contenu()?;
    let date_visite = &m.message.parsed.estampille;

    // Recuperer instance_id
    let instance_id = match m.message.certificat.as_ref() {
        Some(inner) => {
            match inner.subject()?.get("commonName") {
                Some(inner) => inner.clone(),
                None => Err(format!("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
            }
        },
        None => Err(format!("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
    };

    let filtre = doc! { "fuuids": &evenement.hachage_bytes };
    let projection = doc! {"tuuid": 1, "fuuid": 1, "flag_media": 1, "flag_media_traite": 1, "mimetype": 1};
    let options = FindOneOptions::builder().projection(projection).build();
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let doc_fuuid: DocumentFichierDetailIds = match collection.find_one(filtre, Some(options)).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            warn!("evenements.evenement_visiter_fuuids Le document fuuid {} n'existe pas, abort evenement", evenement.hachage_bytes);
            return Ok(None)
        }
    };

    let fuuids = vec![evenement.hachage_bytes];

    marquer_visites_fuuids(middleware, &fuuids, date_visite, instance_id).await?;

    // Emettre un evenement sur le fichier (tuuid)
    emettre_evenement_maj_fichier(middleware, &doc_fuuid.tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await?;

    if let Some(false) = doc_fuuid.flag_media_traite {
        if let Some(mimetype) = doc_fuuid.mimetype.as_ref() {
            debug!("Consignation sur fichier media non traite, emettre evenement pour tuuid {}", doc_fuuid.tuuid);
            if let Err(e) = emettre_commande_media(middleware, &doc_fuuid.tuuid, &doc_fuuid.fuuid, mimetype, false).await {
                error!("evenements.evenement_fichier_consigne Erreur emission commande generer image {} : {:?}", doc_fuuid.fuuid, e);
            }
        }
    }

    Ok(None)
}

async fn marquer_visites_fuuids<M>(
    middleware: &M, fuuids: &Vec<String>, date_visite: &DateEpochSeconds, instance_id: String)
    -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    debug!("marquer_visites_fuuids  Visiter {} fuuids de l'instance {}", fuuids.len(), instance_id);

    let ops = doc! {
        "$set": {format!("visites.{}", instance_id): date_visite},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    // Marquer fichiersrep
    {
        let filtre_rep = doc! {
            "fuuids": {"$in": fuuids},  // Utiliser index
            "fuuid_v_courante": {"$in": fuuids}
        };
        debug!("marquer_visites_fuuids Filtre fichierrep {:?}", filtre_rep);
        let collection_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        collection_rep.update_many(filtre_rep, ops.clone(), None).await?;
    }

    // Marquer versions
    {
        let filtre_versions = doc! {
            "fuuids": {"$in": fuuids},  // Utiliser index
            "fuuid": {"$in": fuuids}
        };
        debug!("marquer_visites_fuuids Filtre versions {:?}", filtre_versions);
        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        collection_versions.update_many(filtre_versions, ops, None).await?;
    }

    Ok(())
}
