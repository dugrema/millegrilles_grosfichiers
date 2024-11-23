use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::{debug, error, info, warn};
use millegrilles_common_rust::{chrono, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L1Public, L2Prive, L3Protege};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::time as tokio_time;
use millegrilles_common_rust::tokio::time::{Duration as DurationTokio, timeout};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use crate::domain_manager::GrosFichiersDomainManager;
// use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_fichier, EvenementContenuCollection};

use crate::grosfichiers_constantes::*;
use crate::requetes::mapper_fichier_db;
use crate::traitement_index::{entretien_supprimer_fichiersrep, sauvegarder_job_index};
use crate::traitement_jobs::{BackgroundJob, BackgroundJobParams};
use crate::traitement_media::{sauvegarder_job_images, sauvegarder_job_video};

const LIMITE_FUUIDS_BATCH: usize = 10000;
const EXPIRATION_THROTTLING_EVENEMENT_CUUID_CONTENU: i64 = 1;

pub async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive])? {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_evenement: Exchange evenement invalide (pas 2.prive)")),
    }?;

    let action = {
        match &m.type_message {
            TypeMessageOut::Evenement(r) => r.action.clone(),
            _ => Err(CommonError::Str("evenements.consommer_evenement Mauvais type de message (pas evenement)"))?
        }
    };

    match action.as_str() {
        EVENEMENT_TRANSCODAGE_PROGRES => evenement_transcodage_progres(middleware, m).await,
        EVENEMENT_FICHIERS_SYNCPRET => evenement_fichiers_syncpret(middleware, m).await,
        EVENEMENT_FICHIERS_VISITER_FUUIDS => evenement_visiter_fuuids(middleware, m).await,
        EVENEMENT_FILEHOST_NEWFUUID => evenement_filehost_newfuuid(middleware, gestionnaire, m).await,
        EVENEMENT_FICHIERS_SYNC_PRIMAIRE => evenement_fichier_sync_primaire(middleware, gestionnaire, m).await,
        EVENEMENT_CEDULE => Ok(None),  // Obsolete
        EVENEMENT_RESET_VISITS_CLAIMS => evenement_reset_claims(middleware, gestionnaire, m).await,
        _ => Err(format!("grosfichiers.consommer_evenement: Mauvais type d'action pour un evenement : {}", action))?,
    }
}

async fn evenement_transcodage_progres<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao,
{
    if !m.certificat.verifier_exchanges(vec![L2Prive])? {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", m.type_message);
        return Ok(None)
    }
    if !m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas de role media");
        return Ok(None)
    }

    debug!("evenement_transcodage_progres Message : {:?}", & m.type_message);
    let message_ref = m.message.parse()?;
    let evenement: EvenementTranscodageProgres = message_ref.contenu()?.deserialize()?;
    debug!("evenement_transcodage_progres parsed : {:?}", evenement);

    let filtre = doc! {
        "job_id": &evenement.job_id,
    };

    let mut ops = doc! {
        "$currentDate": { CHAMP_DATE_MAJ: true }
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

async fn transmettre_fuuids_fichiers<M>(middleware: &M, fuuids: &Vec<String>, archive: bool, termine: bool, total: Option<i64>)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao,
{
    let confirmation = doc! {
        "fuuids": fuuids,
        "archive": archive,
        "termine": termine,
        "total": total,
    };
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_ACTIVITE_FUUIDS, vec![L2Prive])
        .blocking(false)
        .build();
    middleware.transmettre_commande(routage, &confirmation).await?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct RowFichiersSyncpret<'a> {
    #[serde(borrow)]
    fuuids_reclames: Vec<&'a str>,
    archive: Option<bool>,
}

pub async fn evenement_fichiers_syncpret<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    if !m.certificat.verifier_exchanges(vec![L2Prive])? {
        error!("evenement_fichiers_syncpret Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    // Repondre immediatement pour declencher sync
    {
        match m.type_message {
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Evenement(r) => {
                let reponse = json!({ "ok": true });
                if let Some(correlation_id) = r.correlation_id.as_ref() {
                    if let Some(reply_q) = r.reply_to.as_ref() {
                        let routage = RoutageMessageReponse::new(reply_q, correlation_id);
                        middleware.repondre(routage, reponse).await?;
                    }
                }
            },
            _ => error!("evenement_fichiers_syncpret Mauvais type message, devrait etre commande/evenement")
        }
    }

    let collection = middleware.get_collection_typed::<RowFichiersSyncpret>(NOM_COLLECTION_VERSIONS)?;

    let mut fichiers_actifs: Vec<String> = Vec::with_capacity(10000);
    let mut fichiers_archives: Vec<String> = Vec::with_capacity(10000);

    let projection = doc!{ CHAMP_ARCHIVE: 1, CHAMP_FUUIDS_RECLAMES: 1 };
    let options = FindOptions::builder().projection(projection).build();
    let filtre = doc! { CHAMP_SUPPRIME: false, CHAMP_FUUIDS_RECLAMES: {"$exists": true} };
    let mut curseur = collection.find(filtre, Some(options)).await?;
    // while let Some(f) = curseur.next().await {
    let mut total = 0 as i64;
    while curseur.advance().await? {
        let info_fichier = curseur.deserialize_current()?;
        // let info_fichier: RowFichiersSyncpret = convertir_bson_deserializable(f?)?;
        let archive = match info_fichier.archive { Some(b) => b, None => false };
        if archive {
            total += info_fichier.fuuids_reclames.len() as i64;
            fichiers_archives.extend(info_fichier.fuuids_reclames.into_iter().map(|s| s.to_owned()));
        } else {
            total += info_fichier.fuuids_reclames.len() as i64;
            fichiers_actifs.extend(info_fichier.fuuids_reclames.into_iter().map(|s| s.to_owned()));
        }

        if fichiers_actifs.len() >= LIMITE_FUUIDS_BATCH {
            transmettre_fuuids_fichiers(middleware, &fichiers_actifs, false, false, None).await?;
            fichiers_actifs.clear();
            tokio_time::sleep(Duration::from_millis(500)).await;
        }
        if fichiers_archives.len() >= LIMITE_FUUIDS_BATCH {
            transmettre_fuuids_fichiers(middleware, &fichiers_archives, true, false, None).await?;
            fichiers_archives.clear();
        }
    }

    if ! fichiers_actifs.is_empty() {
        transmettre_fuuids_fichiers(middleware, &fichiers_actifs, false, false, Some(total.clone())).await?;
    }
    if ! fichiers_archives.is_empty() {
        transmettre_fuuids_fichiers(middleware, &fichiers_archives, true, false, Some(total.clone())).await?;
    }

    // Transmettre message avec flag termine dans tous les cas
    transmettre_fuuids_fichiers(middleware, &vec![], false, true, Some(total)).await?;

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementTranscodageProgres {
    job_id: String,
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

async fn evenement_visiter_fuuids<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    if !m.certificat.verifier_exchanges(vec![L2Prive])? {
        error!("evenement_visiter_fuuids Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        error!("evenement_visiter_fuuids Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    debug!("evenements.evenement_visiter_fuuids Mapper EvenementVisiterFuuids a partir de {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let evenement: EvenementVisiterFuuids = message_ref.contenu()?.deserialize()?;
    let date_visite = &message_ref.estampille;

    // Recuperer instance_id
    let instance_id = match m.certificat.subject()?.get("commonName") {
        Some(inner) => inner.to_owned(),
        None => Err(CommonError::Str("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
    };

    debug!("evenement_visiter_fuuids  Visiter {} fuuids de l'instance {}", evenement.fuuids.len(), instance_id);
    marquer_visites_fuuids(middleware, &evenement.fuuids, date_visite, instance_id).await?;

    Ok(None)
}

// async fn evenement_filecontroler_visiter_fuuids<M>(middleware: &M, m: MessageValide)
//     -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
//     where M: GenerateurMessages + MongoDao
// {
//     if !m.certificat.verifier_exchanges(vec![L1Public])? {
//         error!("evenement_filecontroler_visiter_fuuids Acces refuse, certificat n'est pas d'un exchange L1");
//         return Ok(None)
//     }
//
//     if !m.certificat.verifier_roles_string(vec![DOMAINE_FILECONTROLER_NOM.into()])? {
//         error!("evenement_filecontroler_visiter_fuuids Acces refuse, certificat n'est pas de role filecontroler");
//         return Ok(None)
//     }
//
//     debug!("evenement_filecontroler_visiter_fuuids Mapper EvenementVisiterFuuids a partir de {:?}", m.type_message);
//     let message_ref = m.message.parse()?;
//     let evenement: FilecontrolerVisitEvent = message_ref.contenu()?.deserialize()?;
//     let date_visite = &message_ref.estampille;
//
//     debug!("evenement_filecontroler_visiter_fuuids Visiter fuuid {} de filehost_id {}", evenement.fuuid, evenement.filehost_id);
//     marquer_visites_fuuids_filecontroler(middleware, &vec![evenement.fuuid], date_visite, evenement.filehost_id).await?;
//
//     Ok(None)
// }

#[derive(Clone, Deserialize)]
struct EvenementFichierConsigne { hachage_bytes: String }

#[derive(Clone, Deserialize)]
struct DocumentFichierDetailIds {
    fuuid: String,
    tuuid: String,
    user_id: String,
    flag_media: Option<String>,
    flag_media_traite: Option<bool>,
    flag_video_traite: Option<bool>,
    flag_index: Option<bool>,
    mimetype: Option<String>,
    visites: Option<HashMap<String, u32>>,
    cle_id: Option<String>,
    format: Option<String>,
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct FilecontrolerNewFuuidEvent {
    filehost_id: String,
    fuuid: String,
}

// async fn evenement_fichier_consigne<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, m: MessageValide)
async fn evenement_filehost_newfuuid<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    if !m.certificat.verifier_exchanges(vec![L1Public])? {
        error!("evenement_filehost_newfuuid Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.certificat.verifier_roles_string(vec![DOMAINE_FILECONTROLER_NOM.into()])? {
        error!("evenement_filehost_newfuuid Acces refuse, certificat n'est pas de role filecontroler");
        return Ok(None)
    }

    debug!("evenement_filehost_newfuuid Mapper EvenementVisiterFuuids a partir de {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let evenement: FilecontrolerNewFuuidEvent = message_ref.contenu()?.deserialize()?;
    let date_visite = &message_ref.estampille;

    let filehost_id = evenement.filehost_id;

    // Marquer la visite courante
    marquer_visites_fuuids(middleware, &vec![evenement.fuuid.clone()], date_visite, filehost_id.clone()).await?;

    let fuuid = &evenement.fuuid;
    declencher_traitement_nouveau_fuuid(middleware, gestionnaire, fuuid, vec![filehost_id.as_str()]).await?;

    Ok(None)
}

pub async fn declencher_traitement_nouveau_fuuid<M,V>(middleware: &M, gestionnaire: &GrosFichiersDomainManager,
                                                      fuuid: &str, filehost_ids: Vec<V>)
    -> Result<(), CommonError>
    where M: GenerateurMessages + MongoDao, V: ToString
{
    let filtre = doc! { "fuuids": fuuid };
    let projection = doc! {
        "user_id": 1, "tuuid": 1, "fuuid": 1, "flag_media": 1, "mimetype": 1,
        CHAMP_FLAG_MEDIA_TRAITE: 1, CHAMP_FLAG_INDEX: 1, CHAMP_FLAG_VIDEO_TRAITE: 1,
        "cle_id": 1, "format": 1, "nonce": 1,
    };
    let options = FindOptions::builder().projection(projection).build();
    let collection = middleware.get_collection_typed::<DocumentFichierDetailIds>(NOM_COLLECTION_VERSIONS)?;

    let filehost_ids = filehost_ids.into_iter().map(|f|f.to_string()).collect();

    let mut curseur = collection.find(filtre, Some(options)).await?;
    while curseur.advance().await? {
        let doc_fuuid = curseur.deserialize_current()?;

        let cle_id = match doc_fuuid.cle_id.as_ref() {
            Some(inner) => inner.as_str(),
            None => doc_fuuid.fuuid.as_str()
        };

        let image_traitee = match doc_fuuid.flag_media_traite {
            Some(inner) => inner,
            None => false
        };

        let video_traite = match doc_fuuid.flag_video_traite {
            Some(inner) => inner,
            None => false
        };

        let index_traite = match doc_fuuid.flag_index {
            Some(inner) => inner,
            None => false
        };

        emettre_evenement_maj_fichier(middleware, gestionnaire, &doc_fuuid.tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await?;
        let tuuid = doc_fuuid.tuuid;

        // Extract information for background job if all fields present
        let job = if doc_fuuid.mimetype.is_some() && doc_fuuid.format.is_some() && doc_fuuid.nonce.is_some() {
            let mimetype = doc_fuuid.mimetype.expect("mimetype");
            let format = doc_fuuid.format.expect("format");
            let nonce = doc_fuuid.nonce.expect("nonce");
            let job = BackgroundJob::new(tuuid, fuuid, mimetype, &filehost_ids, cle_id, format, nonce);
            Some(job)
        } else {
            None
        };

        if let Some(mut job) = job {

            if ! image_traitee {
                // Note : La job est uniquement creee si le format est une image. Exclus les videos.
                sauvegarder_job_images(middleware, &job).await?;
            }

            if ! video_traite {
                // Note : La job est uniquement creee si le format est video
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
                let user_id = doc_fuuid.user_id.clone();
                job.user_id = Some(user_id);
                sauvegarder_job_video(middleware, &job).await?;
            }

            if ! index_traite {
                let user_id = doc_fuuid.user_id.clone();
                job.user_id = Some(user_id);
                sauvegarder_job_index(middleware, &job).await?;
            }

        }

    }

    Ok(())
}

async fn marquer_visites_fuuids<M>(
    middleware: &M, fuuids: &Vec<String>, date_visite: &DateTime<Utc>, filehost_id: String)
    -> Result<(), CommonError>
    where M: MongoDao
{
    debug!("marquer_visites_fuuids  Visiter {} fuuids du filehost_id {}", fuuids.len(), filehost_id);

    // Marquer versions
    {
        let filtre_versions = doc! {
            "fuuids": {"$in": fuuids},  // Utiliser index
        };
        debug!("marquer_visites_fuuids Filtre versions {:?}", filtre_versions);

        let ops = doc! {
            "$set": {format!("visites.{}", filehost_id): date_visite.timestamp()},
            "$unset": {"visites.nouveau": true},
            "$currentDate": { CHAMP_MODIFICATION: true },
        };

        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        collection_versions.update_many(filtre_versions, ops, None).await?;
    }

    // Marquer fichiersrep (date modification, requis pour pour sync)
    {
        let filtre_rep = doc! {
            CHAMP_FUUIDS_VERSIONS: {"$in": fuuids},  // Utiliser index
        };
        debug!("marquer_visites_fuuids Filtre fichierrep {:?}", filtre_rep);
        let collection_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

        let ops = doc! {
            "$currentDate": { CHAMP_MODIFICATION: true },
        };

        collection_rep.update_many(filtre_rep, ops, None).await?;
    }

    Ok(())
}

async fn marquer_visites_fuuids_filecontroler<M>(
    middleware: &M, fuuids: &Vec<String>, date_visite: &DateTime<Utc>, instance_id: String)
    -> Result<(), CommonError>
where M: MongoDao
{
    debug!("marquer_visites_fuuids_filecontroler  Visiter {} fuuids de l'instance {}", fuuids.len(), instance_id);

    // Marquer versions
    {
        let filtre_versions = doc! {
            "fuuids": {"$in": fuuids},  // Utiliser index
            // "fuuid": {"$in": fuuids}
        };
        debug!("marquer_visites_fuuids_filecontroler Filtre versions {:?}", filtre_versions);

        let ops = doc! {
            "$set": {format!("visites.{}", instance_id): date_visite.timestamp()},
            "$unset": {"visites.nouveau": true},
            "$currentDate": { CHAMP_MODIFICATION: true },
        };

        let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        collection_versions.update_many(filtre_versions, ops, None).await?;
    }

    // Marquer fichiersrep (date modification, requis pour pour sync)
    {
        let filtre_rep = doc! {
            CHAMP_FUUIDS_VERSIONS: {"$in": fuuids},  // Utiliser index
        };
        debug!("marquer_visites_fuuids_filecontroler Filtre fichierrep {:?}", filtre_rep);
        let collection_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

        let ops = doc! {
            "$currentDate": { CHAMP_MODIFICATION: true },
        };

        collection_rep.update_many(filtre_rep, ops, None).await?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct HandlerEvenements {
    /// Key: user_id/cuuid, value : epoch secs
    events_cuuid_content_expiration: Mutex<HashMap<String, EvenementHolder>>,
}

impl Clone for HandlerEvenements {
    /// Creer nouvelle copie vide
    fn clone(&self) -> Self {
        HandlerEvenements::new()
    }
}

#[derive(Clone, Debug)]
enum EvenementHolderType {
    ContenuCollection(EvenementContenuCollection),
}

#[derive(Clone, Debug)]
struct EvenementHolder {
    expiration: i64,
    evenement: Option<EvenementHolderType>,
}

impl EvenementHolder {
    fn new() -> Self {
        Self { expiration: Utc::now().timestamp(), evenement: None }
    }
}

impl HandlerEvenements {
    pub fn new() -> Self {
        HandlerEvenements {
            events_cuuid_content_expiration: Mutex::new(HashMap::new()),
        }
    }

    fn extraire_liste_expires(val: &Mutex<HashMap<String, EvenementHolder>>) -> Result<Option<Vec<EvenementHolder>>, CommonError>
    {
        let mut lock = match val.lock() {
            Ok(inner) => inner,
            Err(e) => Err(format!("evenements.HandlerEvenements.extraire_liste_expires Erreur lock : {}", e))?
        };

        if lock.is_empty() {
            return Ok(None);  // Aucun evenement
        }

        let expiration = Utc::now() - chrono::Duration::seconds(EXPIRATION_THROTTLING_EVENEMENT_CUUID_CONTENU);
        let expiration = expiration.timestamp();
        let mut expired_keys = Vec::new();

        // Conserver les keys a transmettre
        for (key, value) in lock.iter() {
            if value.expiration < expiration {
                expired_keys.push(key.to_owned());
            }
        }

        // Retirer les evenements a emettre
        let mut holders = Vec::new();
        for key in expired_keys.into_iter() {
            if let Some(holder) = lock.remove(&key) {
                holders.push(holder);
            }
        }

        debug!("extraire_liste_expires Emettre {} evenements expires", holders.len());

        return Ok(Some(holders))
    }

    pub async fn emettre_cuuid_content_expires<M>(&self, middleware: &M, gestionnaire: &GrosFichiersDomainManager) -> Result<(), CommonError>
        where M: MongoDao + GenerateurMessages
    {
        if let Some(evenements_expires) = HandlerEvenements::extraire_liste_expires(
            &self.events_cuuid_content_expiration)?
        {
            for holder in evenements_expires {
                match holder.evenement {
                    Some(inner) => {
                        if let EvenementHolderType::ContenuCollection(evenement) = inner {
                            emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                        } else {
                            error!("emettre_cuuid_content_expires Mauvais type de Holder pour evenement emettre_cuuid_content_expires");
                        }
                    },
                    None => ()  // Rien a faire, le lock a ete retire
                }
            }
        }
        Ok(())
    }

    /// Insere une entree pour throttling d'evenement sur une collection (cuuid)
    /// Retourne false si la collection n'est pas presentement en throttling
    pub fn verifier_evenement_cuuid_contenu(&self, evenement: EvenementContenuCollection) -> Result<Option<EvenementContenuCollection>, CommonError>
    {
        let mut lock = match self.events_cuuid_content_expiration.lock() {
            Ok(inner) => inner,
            Err(e) => Err(format!("evenements.HandlerEvenements.extraire_liste_expires Erreur lock : {}", e))?
        };

        if lock.len() > 100 {
            warn!("verifier_evenement_cuuid_contenu Limite atteinte, throttling ignore");
            return Ok(Some(evenement));
        }

        let cuuid = &evenement.cuuid;
        match lock.get_mut(cuuid) {
            Some(val) => {
                match val.evenement.as_mut() {
                    Some(inner) => {
                        if let EvenementHolderType::ContenuCollection(evenement_existant) = inner {
                            evenement_existant.merge(evenement)?;
                        } else {
                            error!("verifier_evenement_cuuid_contenu Mauvais type de Holder pour evenement emettre_cuuid_content_expires");
                        }
                    },
                    None => {
                        // Inserer l'evenement recu tel quel pour re-emission apres expiration
                        val.evenement = Some(EvenementHolderType::ContenuCollection(evenement));
                    }
                }

                // Throttling actif (return None)
                Ok(None)
            },
            None => {
                // Creer un placeholder. Throttling actif pour prochains evenements.
                lock.insert(cuuid.to_owned(), EvenementHolder::new());

                // Pas de throttling pour cet evenement.
                Ok(Some(evenement))
            }
        }
    }

    // pub async fn thread<M>(&self, middleware: &M, gestionnaire: Arc<GrosFichiersDomainManager>)
    //     where M: GenerateurMessages + MongoDao
    // {
    //     loop {
    //         debug!("evenements.HandlerEvenements.thread loop");
    //         if let Err(e) = self.emettre_cuuid_content_expires(middleware, gestionnaire.as_ref()).await {
    //             error!("evenements.HandlerEvenements.thread Erreur emettre_cuuid_content_expires : {}", e);
    //         }
    //
    //         tokio_time::sleep(DurationTokio::new(5, 0)).await;
    //     }
    // }
}

#[derive(Clone, Deserialize)]
struct EvenementFichierSyncPrimaire { termine: Option<bool> }

async fn evenement_fichier_sync_primaire<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if !m.certificat.verifier_exchanges(vec![L2Prive])? {
        error!("evenement_fichier_sync_primaire Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        error!("evenement_fichier_sync_primaire Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    debug!("evenements.evenement_fichier_sync_primaire Mapper EvenementVisiterFuuids a partir de {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let evenement: EvenementFichierSyncPrimaire = message_ref.contenu()?.deserialize()?;

    if Some(true) == evenement.termine {
        debug!("evenement_fichier_sync_primaire Declencher nettoyage apres sync primaire");
        if let Err(e) = entretien_supprimer_fichiersrep(middleware, gestionnaire).await {
            error!("evenement_fichier_sync_primaire Erreur suppression fichiers indexes et supprimes: {:?}", e);
        }
    }

    Ok(None)
}

pub async fn emettre_evenement_contenu_collection<M>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, evenement: EvenementContenuCollection)
                                                     -> Result<(), CommonError>
where
    M: GenerateurMessages + MongoDao
{
    debug!("grosfichiers.emettre_evenement_contenu_collection Emettre evenement maj pour collection {:?}", evenement);

    // let evenement_ref = evenement.borrow();

    // Voir si on throttle le message. Si l'evenement est retourne, on l'emet immediatement.
    // Si on recoit None, l'evenement a ete conserve pour re-emission plus tard.
    if let Some(inner) = gestionnaire.evenements_handler.verifier_evenement_cuuid_contenu(evenement)? {
        let routage = {
            let mut routage_builder = RoutageMessageAction::builder(
                DOMAINE_NOM, EVENEMENT_MAJ_CONTENU_COLLECTION, vec![Securite::L2Prive]);
            routage_builder = routage_builder.partition(inner.cuuid.clone());
            routage_builder.build()
        };

        debug!("grosfichiers.emettre_evenement_contenu_collection Emettre evenement maj pour collection immediatement {:?}", routage);
        middleware.emettre_evenement(routage, &inner).await?;
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementContenuCollection {
    pub cuuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fichiers_ajoutes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fichiers_modifies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collections_ajoutees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collections_modifiees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retires: Option<Vec<String>>,
}

impl EvenementContenuCollection {
    pub fn new<S>(cuuid: S) -> Self
    where S: ToString
    {
        Self {
            cuuid: cuuid.to_string(),
            fichiers_ajoutes: None,
            fichiers_modifies: None,
            collections_ajoutees: None,
            collections_modifiees: None,
            retires: None,
        }
    }

    /// Combine deux instances de EvenementContenuCollection
    pub fn merge(&mut self, mut other: Self) -> Result<(), CommonError> {
        if self.cuuid.as_str() != other.cuuid.as_str() {
            Err(format!("EvenementContenuCollection.merge cuuid mismatch"))?
        }

        match self.fichiers_ajoutes.as_mut() {
            Some(inner) => match other.fichiers_ajoutes {
                Some(inner_other) => inner.extend(inner_other),
                None => () // Rien a faire
            },
            None => self.fichiers_ajoutes = other.fichiers_ajoutes
        }

        match self.fichiers_modifies.as_mut() {
            Some(inner) => match other.fichiers_modifies {
                Some(inner_other) => inner.extend(inner_other),
                None => () // Rien a faire
            },
            None => self.fichiers_modifies = other.fichiers_modifies
        }

        match self.collections_ajoutees.as_mut() {
            Some(inner) => match other.collections_ajoutees {
                Some(inner_other) => inner.extend(inner_other),
                None => () // Rien a faire
            },
            None => self.collections_ajoutees = other.collections_ajoutees
        }

        match self.collections_modifiees.as_mut() {
            Some(inner) => match other.collections_modifiees {
                Some(inner_other) => inner.extend(inner_other),
                None => () // Rien a faire
            },
            None => self.collections_modifiees = other.collections_modifiees
        }

        match self.retires.as_mut() {
            Some(inner) => match other.retires {
                Some(inner_other) => inner.extend(inner_other),
                None => () // Rien a faire
            },
            None => self.retires = other.retires
        }

        Ok(())
    }
}

pub async fn emettre_evenement_maj_fichier<M, S, T>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, tuuid: S, action: T)
                                                    -> Result<(), CommonError>
where
    M: GenerateurMessages + MongoDao,
    S: AsRef<str>,
    T: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    let action_str = action.as_ref();
    debug!("grosfichiers.emettre_evenement_maj_fichier Emettre evenement maj pour fichier {} (action: {})", tuuid_str, action_str);

    // Charger fichier
    let filtre = doc! {CHAMP_TUUID: tuuid_str};
    let collection = middleware.get_collection_typed::<NodeFichiersRepBorrow>(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, None).await?;
    if curseur.advance().await? {
        let doc_fichier = curseur.deserialize_current()?;

        // Extraire liste de fuuids directement
        // if let Some(fuuids) = doc_fichier.fuuids_versions.as_ref() {
        //     if let Some(fuuid) = fuuids.first() {
        //         let routage_action = RoutageMessageAction::builder(DOMAINE_NOM, action_str)
        //             .exchanges(vec![Securite::L2Prive])
        //             .build();
        //
        //         middleware.emettre_evenement(routage_action.clone(), &json!({CHAMP_FUUIDS: vec![*fuuid]})).await?;
        //     }
        // }

        if let Some(cuuids) = doc_fichier.path_cuuids.as_ref() {
            if let Some(cuuid) = cuuids.first() {
                let mut evenement = EvenementContenuCollection::new(*cuuid);
                // evenement.cuuid = Some((*cuuid).to_owned());
                evenement.fichiers_modifies = Some(vec![tuuid_str.to_owned()]);
                emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
            }
        }

    } else {
        Err(format!("grosfichiers.emettre_evenement_maj_fichier Document {} introuvable", tuuid_str))?
    }

    Ok(())
}

pub async fn emettre_evenement_maj_collection<M, S>(middleware: &M, gestionnaire: &GrosFichiersDomainManager, tuuid: S) -> Result<(), CommonError>
where
    M: GenerateurMessages + MongoDao,
    S: AsRef<str>
{
    let tuuid_str = tuuid.as_ref();
    debug!("grosfichiers.emettre_evenement_maj_collection Emettre evenement maj pour collection {}", tuuid_str);

    // Charger fichier
    let filtre = doc! {CHAMP_TUUID: tuuid_str};
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_fichier = match collection.find_one(filtre, None).await {
        Ok(inner) => inner,
        Err(e) => Err(format!("grosfichiers.where Erreur collection.find_one pour {} : {:?}", tuuid_str, e))?
    };
    match doc_fichier {
        Some(inner) => {
            let fichier_mappe = match mapper_fichier_db(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("grosfichiers.emettre_evenement_maj_collection Erreur mapper_fichier_db : {:?}", e))?
            };
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_COLLECTION, vec![Securite::L2Prive])
                .partition(tuuid_str)
                .build();
            middleware.emettre_evenement(routage, &fichier_mappe).await?;

            if let Some(cuuid) = fichier_mappe.cuuid {
                // Emettre evenement de mise a jour de la collection parent.
                let mut evenement_modif = EvenementContenuCollection::new(cuuid.clone());
                // evenement_modif.cuuid = Some(cuuid.clone());
                evenement_modif.collections_modifiees = Some(vec![tuuid_str.to_string()]);
                emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_modif).await?;
                // let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_CONTENU_COLLECTION)
                //     .exchanges(vec![Securite::L2Prive])
                //     .partition(cuuid)
                //     .build();
                // middleware.emettre_evenement(routage, &evenement_modif).await?;
            }
        },
        None => Err(format!("grosfichiers.emettre_evenement_maj_collection Collection {} introuvable", tuuid_str))?
    };

    Ok(())
}

async fn evenement_reset_claims<M>(middleware: &M, _gestionnaire: &GrosFichiersDomainManager, m: MessageValide)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if !m.certificat.verifier_exchanges(vec![L3Protege])? {
        error!("evenement_reset_claims Acces refuse, certificat n'est pas d'un exchange L1");
        return Ok(None)
    }
    if !m.certificat.verifier_domaines(vec![TOPOLOGIE_NOM_DOMAINE.into()])? {
        error!("evenement_reset_claims Acces refuse, certificat n'est pas de domaine CoreTopologie");
        return Ok(None)
    }

    let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let date_initial_verification = DateTime::from_timestamp(1704085200, 0).expect("from_timestamp");
    let ops = doc! {
        "$set": {CONST_FIELD_LAST_VISIT_VERIFICATION: date_initial_verification},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection_versions.update_many(doc!{}, ops, None).await?;

    info!("Visits/claims reset done");

    Ok(None)
}
