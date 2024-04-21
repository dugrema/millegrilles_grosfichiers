use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::{debug, error, warn};
use millegrilles_common_rust::{chrono, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::time as tokio_time;
use millegrilles_common_rust::tokio::time::{Duration as DurationTokio, timeout};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;

use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_fichier, EvenementContenuCollection, GestionnaireGrosFichiers};

use crate::grosfichiers_constantes::*;
use crate::traitement_index::entretien_supprimer_fichiersrep;
use crate::traitement_jobs::{JobHandler, JobHandlerFichiersRep, JobHandlerVersions};

const LIMITE_FUUIDS_BATCH: usize = 10000;
const EXPIRATION_THROTTLING_EVENEMENT_CUUID_CONTENU: i64 = 1;

pub async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L2Prive])? {
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
        // EVENEMENT_CONFIRMER_ETAT_FUUIDS => {
        //     evenement_confirmer_etat_fuuids(middleware, m).await?;
        //     Ok(None)
        // },
        EVENEMENT_TRANSCODAGE_PROGRES => evenement_transcodage_progres(middleware, m).await,
        EVENEMENT_FICHIERS_SYNCPRET => evenement_fichiers_syncpret(middleware, m).await,
        EVENEMENT_FICHIERS_VISITER_FUUIDS => evenement_visiter_fuuids(middleware, m).await,
        EVENEMENT_FICHIERS_CONSIGNE => evenement_fichier_consigne(middleware, gestionnaire, m).await,
        EVENEMENT_FICHIERS_SYNC_PRIMAIRE => evenement_fichier_sync_primaire(middleware, gestionnaire, m).await,
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
        "$currentDate": { CHAMP_MODIFICATION: true, CHAMP_DATE_MAJ: true }
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
    // flag_index: Option<bool>,
    mimetype: Option<String>,
    visites: Option<HashMap<String, u32>>,
    cle_id: Option<String>,
}

async fn evenement_fichier_consigne<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    if !m.certificat.verifier_exchanges(vec![L2Prive])? {
        error!("evenement_fichier_consigne Acces refuse, certificat n'est pas d'un exchange L2");
        return Ok(None)
    }
    if !m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        error!("evenement_fichier_consigne Acces refuse, certificat n'est pas de role fichiers");
        return Ok(None)
    }

    debug!("evenements.evenement_fichier_consigne Mapper EvenementVisiterFuuids a partir de {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let evenement: EvenementFichierConsigne = message_ref.contenu()?.deserialize()?;
    let date_visite = &message_ref.estampille;

    // Recuperer instance_id
    let instance_id = match m.certificat.subject()?.get("commonName") {
        Some(inner) => inner.clone(),
        None => Err(CommonError::Str("evenements.evenement_visiter_fuuids Certificat sans commonName"))?
    };

    // Marquer la visite courante
    marquer_visites_fuuids(middleware, &vec![evenement.hachage_bytes.clone()], date_visite, instance_id.clone()).await?;

    let filtre = doc! { "fuuids": &evenement.hachage_bytes };
    let projection = doc! {
        "user_id": 1, "tuuid": 1, "fuuid": 1, "flag_media": 1, "mimetype": 1, "visites": 1,
        CHAMP_FLAG_MEDIA_TRAITE: 1, CHAMP_FLAG_INDEX: 1, CHAMP_FLAG_VIDEO_TRAITE: 1,
        "cle_id": 1,
    };
    let options = FindOptions::builder().projection(projection).build();
    let collection = middleware.get_collection_typed::<DocumentFichierDetailIds>(NOM_COLLECTION_VERSIONS)?;

    let mut curseur = collection.find(filtre, Some(options)).await?;
    while curseur.advance().await? {
        let doc_fuuid = curseur.deserialize_current()?;

        let fuuids = vec![doc_fuuid.fuuid.clone()];
        let instances: Vec<String> = match doc_fuuid.visites {
            Some(inner) => inner.into_keys().collect(),
            None => {
                debug!("Aucunes visites sur {}, skip", doc_fuuid.fuuid);
                continue;
            }
        };

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

        for instance in &instances {
            marquer_visites_fuuids(middleware, &fuuids, date_visite, instance.clone()).await?;
        }

        emettre_evenement_maj_fichier(middleware, gestionnaire, &doc_fuuid.tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await?;

        if let Some(mimetype) = doc_fuuid.mimetype {
            let mut parametres_index = HashMap::new();
            parametres_index.insert("mimetype".to_string(), Bson::String(mimetype.to_string()));
            parametres_index.insert("fuuid".to_string(), Bson::String(doc_fuuid.fuuid.clone()));
            parametres_index.insert("cle_id".to_string(), Bson::String(cle_id.to_owned()));
            gestionnaire.indexation_job_handler.sauvegarder_job(
                middleware, doc_fuuid.tuuid.clone(), doc_fuuid.user_id.clone(), Some(vec![instance_id.clone()]),
                None, Some(parametres_index), true
            ).await?;

            let mut champs_cles = HashMap::new();
            champs_cles.insert("mimetype".to_string(), mimetype);
            let mut champs_parametres = HashMap::new();
            champs_parametres.insert("tuuid".to_string(), Bson::String(doc_fuuid.tuuid.clone()));
            champs_parametres.insert("cle_id".to_string(), Bson::String(cle_id.to_owned()));

            if ! image_traitee {
                // Note : La job est uniquement creee si le format est une image
                gestionnaire.image_job_handler.sauvegarder_job(
                    middleware, doc_fuuid.fuuid.clone(), doc_fuuid.user_id.clone(), Some(vec![instance_id.clone()]),
                    Some(champs_cles.clone()), Some(champs_parametres.clone()), true
                ).await?;
            }

            if ! video_traite {
                // Note : La job est uniquement creee si le format est une image
                gestionnaire.video_job_handler.sauvegarder_job(
                    middleware, doc_fuuid.fuuid, doc_fuuid.user_id, Some(vec![instance_id.clone()]),
                    Some(champs_cles), Some(champs_parametres), true
                ).await?;
            }

        }

    }

    Ok(None)
}

async fn marquer_visites_fuuids<M>(
    middleware: &M, fuuids: &Vec<String>, date_visite: &DateTime<Utc>, instance_id: String)
    -> Result<(), CommonError>
    where M: MongoDao
{
    debug!("marquer_visites_fuuids  Visiter {} fuuids de l'instance {}", fuuids.len(), instance_id);

    // Marquer versions
    {
        let filtre_versions = doc! {
            "fuuids": {"$in": fuuids},  // Utiliser index
            // "fuuid": {"$in": fuuids}
        };
        debug!("marquer_visites_fuuids Filtre versions {:?}", filtre_versions);

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
        debug!("marquer_visites_fuuids Filtre fichierrep {:?}", filtre_rep);
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

    pub async fn emettre_cuuid_content_expires<M>(&self, middleware: &M, gestionnaire: &GestionnaireGrosFichiers) -> Result<(), CommonError>
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

    // pub async fn thread<M>(&self, middleware: &M, gestionnaire: Arc<GestionnaireGrosFichiers>)
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

async fn evenement_fichier_sync_primaire<M>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, m: MessageValide)
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
