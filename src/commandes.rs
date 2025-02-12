use std::collections::{HashMap, HashSet};
use std::iter::Map;
use std::str::from_utf8;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{chrono, get_replyq_correlation, serde_json, serde_json::json};
use millegrilles_common_rust::bson::{Bson, doc, to_bson_with_options, SerializerOptions};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use millegrilles_common_rust::common_messages::{verifier_reponse_ok, RequeteDechiffrage};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L4Secure};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable, sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::{ClientSession, Collection};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::error::{Error, Error as CommonError};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::redis::Client;
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;

use crate::data_structs::MediaOwnedRow;
use crate::domain_manager::GrosFichiersDomainManager;
use crate::evenements::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, evenement_fichiers_syncpret, EvenementContenuCollection};

use crate::grosfichiers_constantes::*;
use crate::requetes::{ContactRow, mapper_fichier_db, verifier_acces_usager, verifier_acces_usager_tuuids, verifier_acces_usager_media};
use crate::traitement_entretien::{verifier_visites_topologies, RequeteGetVisitesFuuidsResponse};
use crate::traitement_index::{reset_flag_indexe, sauvegarder_job_index, set_flag_index_traite};
use crate::traitement_jobs::{BackgroundJob, BackgroundJobParams, JobHandler, JobHandlerVersions, ParametresConfirmerJobIndexation};
use crate::traitement_media::{commande_supprimer_job_image, commande_supprimer_job_image_v2, commande_supprimer_job_video, commande_supprimer_job_video_v2, sauvegarder_job_images, sauvegarder_job_video, set_flag_image_traitee, set_flag_video_traite};
use crate::transactions::*;

const REQUETE_MAITREDESCLES_VERIFIER_PREUVE: &str = "verifierPreuve";

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    // debug!("consommer_commande : {:?}", &m.type_message);

    if middleware.get_mode_regeneration() {
        return Ok(Some(middleware.reponse_err(Some(503), None, Some("System rebuild in progress"))?))
    }

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message)),
                }
            }
        }?;
    }

    let action = match &m.type_message {
        TypeMessageOut::Commande(r) => r.action.clone(),
        _ => Err(CommonError::Str("grosfichiers.consommer_commande Mauvais type message, doit etre Commande"))?
    };

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        // Commandes standard
        TRANSACTION_NOUVELLE_VERSION => commande_nouvelle_version(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_NOUVELLE_COLLECTION => commande_nouvelle_collection(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => commande_associer_conversions(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_ASSOCIER_VIDEO => commande_associer_video(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => commande_ajouter_fichiers_collection(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => commande_deplacer_fichiers_collection(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => commande_supprimer_documents(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_RECUPERER_DOCUMENTS_V2 => commande_recuperer_documents_v2(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_RECYCLE_ITEMS_V3 => command_recycle_items_v3(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_DECRIRE_FICHIER => commande_decrire_fichier(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_DECRIRE_COLLECTION => commande_decrire_collection(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_VIDEO => commande_supprimer_video(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_ORPHELINS => commande_supprimer_orphelins(middleware, m, gestionnaire, &mut session).await,

        // Sync
        COMMANDE_RECLAMER_FUUIDS => evenement_fichiers_syncpret(middleware, m, &mut session).await,
        COMMAND_VISITS => command_receive_visits(middleware, m, &mut session).await,

        COMMANDE_JOB_GET_KEY => commande_get_job_key(middleware, m, &mut session).await,
        COMMANDE_COMPLETER_PREVIEWS => commande_completer_previews(middleware, m, &mut session).await,
        TRANSACTION_IMAGE_SUPPRIMER_JOB_V2 => commande_supprimer_job_image_v2(middleware, m, gestionnaire, &mut session).await,

        // Video
        COMMANDE_VIDEO_TRANSCODER => commande_video_convertir(middleware, m, &mut session).await,
        TRANSACTION_VIDEO_SUPPRIMER_JOB_V2 => commande_supprimer_job_video_v2(middleware, m, gestionnaire, &mut session).await,

        // Indexation
        COMMANDE_REINDEXER => commande_reindexer(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_CONFIRMER_FICHIER_INDEXE => commande_confirmer_fichier_indexe(middleware, m, &mut session).await,

        // Partage de collections
        TRANSACTION_AJOUTER_CONTACT_LOCAL => commande_ajouter_contact_local(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_CONTACTS => commande_supprimer_contacts(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_PARTAGER_COLLECTIONS => commande_partager_collections(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_PARTAGE_USAGER => commande_supprimer_partage_usager(middleware, m, gestionnaire, &mut session).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        },
        Err(e) => {
            warn!("consommer_commande Command DB session aborted");
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn commande_nouvelle_version<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = m.message.parse_to_owned()?;
    let uuid_transaction = message_owned.id.as_str();
    debug!("commande_nouvelle_version Consommer commande : {:?}", & m.type_message);
    let commande: TransactionNouvelleVersion = message_owned.deserialize()?;

    let cuuid = commande.cuuid.as_str();

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(CommonError::Str("commandes.commande_nouvelle_version user_id manquant du certificat - SKIP"))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Valider la nouvelle version
    let tuuid = {
        let tuuid = match &commande.tuuid {
            Some(t) => t.to_owned(),
            None => uuid_transaction.to_string(),
        };

        let fuuid = commande.fuuid.as_str();
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let filtre = doc!{"fuuid": fuuid};
        let count = collection.count_documents_with_session(filtre, None, session).await?;
        if count > 0 {
            return Ok(Some(middleware.reponse_err(Some(409), None, Some("Fuuid exists"))?))
        }

        tuuid
    };

    // Traiter la cle
    match message_owned.attachements.take() {
        Some(mut attachements) => match attachements.remove("cle") {
            Some(cle) => {
                if let Some(reponse) = transmettre_cle_attachee(middleware, cle).await? {
                    error!("Erreur sauvegarde cle : {:?}", reponse);
                    return Ok(Some(reponse));
                }
            },
            None => {
                error!("Cle de nouvelle version manquante (1)");
                return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?));
            }
        },
        None => {
            error!("Cle de nouvelle version manquante (2)");
            return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?));
        }
    }

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Transaction processed OK, commit session and then emit messagse
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;  // New session

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION, session).await {
        warn!("transaction_nouvelle_version Erreur emettre_evenement_maj_fichier : {:?}", e);
    }

    let mut evenement_contenu = EvenementContenuCollection::new(cuuid.to_owned());
    evenement_contenu.fichiers_ajoutes = Some(vec![tuuid.clone()]);
    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;

    // Emit file claim - allows it to be synchronized to all filehosts immediately
    if let Err(e) = verifier_visites_topologies(middleware, &vec![commande.fuuid.clone()]).await {
        warn!("transaction_nouvelle_version Error claiming new file version {}: {:?}", tuuid, e);
    }

    Ok(response)
}

async fn commande_decrire_fichier<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_decrire_fichier Consommer commande : {:?}", & m.type_message);
    let commande: TransactionDecrireFichier = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_decrire_fichier User_id absent"))?
    };

    let role_admin = m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if !role_admin && !role_prive {
        debug!("commande_decrire_fichier Access denied, not a user/admin");
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    // Find matching file
    let collection_reps = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre_reps = doc!{"tuuid": &commande.tuuid, "user_id": &user_id};
    let file_rep = match collection_reps.find_one_with_session(filtre_reps, None, session).await? {
        Some(inner) => inner,
        None => Err(format!("commande_decrire_fichier File not found: tuuid:{}", commande.tuuid))?
    };

    // If this is a file, extract the first fuuid (most recent version)
    let fuuid = match file_rep.fuuids_versions.as_ref() {
        Some(mut inner) => {
            if let Some(fuuid) = inner.first() {
                fuuid.to_owned()
            } else {
                Err(format!("commande_decrire_fichier No file version found for tuuid:{}", commande.tuuid))?
            }
        },
        None => {
            Err(format!("commande_decrire_fichier No file version found for tuuid:{}", commande.tuuid))?
        }
    };

    let changement_media = match commande.mimetype.as_ref() {
        Some(mimetype) => {
            debug!("commande_decrire_fichier Verifier si le mimetype du fichier a change (nouveau: {})", mimetype);
            if file_rep.mimetype != commande.mimetype {
                debug!("commande_decrire_fichier Le mimetype a change de {:?} vers {:?}, reset traitement media de {}",
                    file_rep.mimetype, commande.mimetype, commande.tuuid);
                true
            } else {
                false
            }
        },
        None => false
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    let (flag_media_traite, flag_video_traite) = if changement_media {
        if let Some(mimetype) = commande.mimetype.as_ref() {
            // Ajouter flags media au fichier si approprie
            let (flag_media_traite, flag_video_traite, _) = get_flags_media(
                mimetype.as_str());
            let filtre = doc! {CHAMP_FUUID: &fuuid};
            let ops = doc! {
                "$set": {
                    // CHAMP_FLAG_MEDIA: flag_media,
                    CHAMP_FLAG_MEDIA_TRAITE: flag_media_traite,
                    CHAMP_FLAG_VIDEO_TRAITE: flag_video_traite,
                },
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            debug!("commande_decrire_fichier Reset flags media sur changement mimetype pour {} : {:?}", commande.tuuid, ops);
            let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(
                NOM_COLLECTION_VERSIONS)?;
            collection.update_one_with_session(filtre.clone(), ops, None, session).await?;
            (flag_media_traite, flag_video_traite)
        } else {
            warn!("commande_decrire_fichier Erreur utilisation fuuid sur changement (None)");
            (true, true)  // prevent media jobs from being created
        }
    } else {
        (true, true)  // prevent media jobs from being created
    };

    // Declencher indexation
    let tuuid = &commande.tuuid;
    let filtre = doc!{"fuuid": &fuuid};
    let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let mut cursor = collection.find_with_session(filtre, None, session).await?;
    if cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if row.cle_id.is_some() && row.format.is_some() && row.nonce.is_some() {

            // Create indexing job
            let cle_id = row.cle_id.clone().expect("cle_id");
            let format: &str = row.format.clone().expect("format").into();
            let nonce = row.nonce.clone().expect("nonce");
            let mimetype = row.mimetype.clone();
            let filehost_ids: Vec<&String> = row.visites.keys().collect();
            let job = BackgroundJob::new_index(tuuid, Some(fuuid), &user_id, mimetype, &filehost_ids, cle_id, format, nonce);
            sauvegarder_job_index(middleware, &job, session).await?;

            if ! flag_video_traite {
                // Create video job
                sauvegarder_job_video(middleware, &job, session).await?;
            } else if ! flag_media_traite {
                // Create media job
                sauvegarder_job_images(middleware, &job, session).await?;
            }
        }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_DECRIRE_FICHIER, session).await {
        warn!("transaction_decire_fichier Erreur emettre_evenement_maj_fichier : {:?}", e);
    }

    Ok(resultat)
}

async fn commande_nouvelle_collection<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_nouvelle_collection Consommer commande : {:?}", & m.type_message);
    let mut message_owned = m.message.parse_to_owned()?;
    let commande: TransactionNouvelleCollection = message_owned.deserialize()?;
    debug!("Commande commande_nouvelle_collection versions parsed : {:?}", commande);

    let cuuid = commande.cuuid.as_ref();

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            Err(format!("grosfichiers.consommer_commande: User_id missing from certificate"))?
        }
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        let user_id_str = user_id.as_str();
        let cuuid = commande.cuuid.as_ref();
        let resultat = verifier_autorisation_usager(middleware, user_id_str, None::<&Vec<String>>, cuuid).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Traiter la cle
    match message_owned.attachements.take() {
        Some(mut attachements) => match attachements.remove("cle") {
            Some(cle) => {
                if let Some(reponse) = transmettre_cle_attachee_domaines(middleware, cle).await? {
                    error!("Erreur sauvegarde cle : {:?}", reponse);
                    return Ok(Some(reponse));
                }
            },
            None => {
                error!("Cle de nouvelle collection manquante (1)");
                // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cle manquante"}), None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?));
            }
        },
        None => {
            error!("Cle de nouvelle collection manquante (2)");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cle manquante"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?));
        }
    }

    // Traiter la transaction
    let result = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Declencher indexation
    let tuuid = &message_owned.id;
    let metadata = commande.metadata;
    if metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
        let user_id = user_id.as_str();
        let cle_id = metadata.cle_id.expect("cle_id");
        let format = metadata.format.expect("format");
        let nonce = metadata.nonce.expect("nonce");
        let filehost_ids: Vec<&str> = Vec::new();
        let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, "", &filehost_ids, cle_id, format, nonce);
        sauvegarder_job_index(middleware, &job, session).await?;
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid, &user_id, session).await?;
    {
        // let mut evenement_contenu = EvenementContenuCollection::new();
        let mut evenement_contenu = match cuuid.as_ref() {
            Some(cuuid) => EvenementContenuCollection::new(cuuid.clone()),
            None => EvenementContenuCollection::new(user_id.clone())
        };
        evenement_contenu.collections_ajoutees = Some(vec![tuuid.clone()]);
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;
    }

    Ok(result)
}

async fn commande_associer_conversions<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_associer_conversions Consommer commande : {:?}", & m.type_message);
    let commande: TransactionAssocierConversions = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    if ! m.certificat.verifier_exchanges(vec![L4Secure])? {
        Err(format!("grosfichiers.commande_associer_conversions: Autorisation invalide (pas L4Secure) pour message {:?}", m.type_message))?
    }

    // Autorisation - doit etre signe par media
    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
        Err(format!("grosfichiers.commande_associer_conversions: Autorisation invalide (pas media) pour message {:?}", m.type_message))?
    }

    if commande.tuuid.is_none() {
        Err(format!("grosfichiers.commande_associer_conversions: Tuuid obligatoire depuis version 2024.9 {:?}", m.type_message))?
    }
    let tuuid = commande.tuuid.expect("tuuid");
    let user_id = commande.user_id;

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    if let Err(e) = touch_fichiers_rep(middleware, user_id.as_ref(), &vec![commande.fuuid.as_str()], session).await {
        error!("commande_associer_conversions Erreur touch_fichiers_rep {:?}/{} : {:?}", user_id, commande.fuuid, e);
    }

    let fuuid = &commande.fuuid;
    if let Err(e) = set_flag_image_traitee(middleware, Some(tuuid.as_str()), fuuid, session).await {
        error!("transaction_associer_conversions Erreur set flag true pour traitement job images {:?}/{} : {:?}", user_id, fuuid, e);
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_ASSOCIER_CONVERSION, session).await {
        warn!("commande_associer_conversions Erreur emettre_evenement_maj_fichier : {:?}", e);
    }

    // Emit file claim - allows it to be synchronized to all filehosts immediately
    let mut image_fuuids = Vec::new();
    for (_, image) in &commande.images {
        image_fuuids.push(image.hachage.to_owned());
    }
    if ! image_fuuids.is_empty() {
        if let Err(e) = verifier_visites_topologies(middleware, &image_fuuids).await {
            warn!("commande_associer_conversions Error claiming images for file {}: {:?}", tuuid, e);
        }
    }

    Ok(response)
}

async fn commande_associer_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_associer_video Consommer commande : {:?}", & m.type_message);
    let commande: TransactionAssocierVideo = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };
    // let commande: TransactionAssocierVideo = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_associer_video versions parsed : {:?}", commande);

    // Autorisation
    if ! m.certificat.verifier_exchanges(vec![L2Prive])? {
        Err(format!("grosfichiers.commande_associer_video: Autorisation invalide pour message {:?}", m.type_message))?
    }

    let user_id = m.certificat.get_user_id()?;
    let fuuid = &commande.fuuid;

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Remove video job
    let job_id = match commande.job_id.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None};
    set_flag_video_traite(middleware, commande.tuuid.as_ref(), fuuid, job_id, session).await?;

    // Touch - s'assure que le client va voir que le fichier a ete modifie (sync)
    if let Err(e) = touch_fichiers_rep(middleware, user_id.as_ref(), vec![fuuid], session).await {
        error!("commande_associer_video Erreur touch_fichiers_rep {:?}/{:?} : {:?}", user_id, fuuid, e);
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    if let Some(t) = commande.tuuid.as_ref() {
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, t, EVENEMENT_FUUID_ASSOCIER_VIDEO, session).await {
            warn!("commande_associer_video Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    // Emit file claim - allows it to be synchronized to all filehosts immediately
    if let Err(e) = verifier_visites_topologies(middleware, &vec![commande.fuuid_video.clone()]).await {
        warn!("commande_associer_conversions Error claiming new video for file {:?}: {:?}", commande.tuuid, e);
    }


    Ok(response)
}

pub struct InformationAutorisation {
    pub erreur: Option<MessageMilleGrillesOwned>,
    pub tuuids_repertoires: Vec<String>,
    pub tuuids_fichiers: Vec<String>,
    pub tuuids_refuses: Vec<String>,
    pub fuuids: Vec<String>,
}

impl InformationAutorisation {
    fn new() -> Self {
        Self {
            erreur: None,
            tuuids_repertoires: Vec::new(),
            tuuids_fichiers: Vec::new(),
            tuuids_refuses: Vec::new(),
            fuuids: Vec::new(),
        }
    }
}

/// Verifie si l'usager a acces aux tuuids (et cuuid au besoin)
async fn verifier_autorisation_usager<M,S,T,U>(middleware: &M, user_id: S, tuuids: Option<&Vec<U>>, cuuid_in: Option<T>)
    -> Result<InformationAutorisation, CommonError>
    where
        M: GenerateurMessages + MongoDao,
        S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
{
    let user_id_str = user_id.as_ref();
    let cuuid = match cuuid_in.as_ref() { Some(cuuid) => Some(cuuid.as_ref()), None => None };

    let mut reponse = InformationAutorisation::new();

    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    if let Some(cuuid) = cuuid.as_ref() {
        // Verifier que la collection destination (cuuid) appartient a l'usager
        let filtre = doc!{ CHAMP_TUUID: *cuuid, CHAMP_USER_ID: user_id_str };
        let collection_row_fichiers = middleware.get_collection_typed::<NodeFichiersRepBorrow>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection_row_fichiers.find(filtre, None).await?;
        if curseur.advance().await? {
            let mapping_collection = curseur.deserialize_current()?;
            if user_id_str != mapping_collection.user_id {
                warn!("verifier_autorisation_usager Le cuuid {:?} n'appartiennent pas a l'usager {:?}", cuuid, user_id_str);
                // reponse.erreur = Some(middleware.formatter_reponse(json!({"ok": false, "message": "cuuid n'appartient pas a l'usager"}), None)?);
                reponse.erreur = Some(middleware.reponse_err(None, Some("cuuid n'appartient pas a l'usager"), None)?.parse_to_owned()?);
                return Ok(reponse)
            }
        } else {
            warn!("verifier_autorisation_usager Le cuuid {:?} n'appartient pas a l'usager {:?} ou est inconnu", cuuid, user_id_str);
            // reponse.erreur = Some(middleware.formatter_reponse(json!({"ok": false, "message": "cuuid inconnu"}), None)?);
            reponse.erreur = Some(middleware.reponse_err(None, Some("cuuid inconnu"), None)?.parse_to_owned()?);
            return Ok(reponse)
        }
    }

    if tuuids.is_some() {
        let tuuids_vec: Vec<&str> = tuuids.expect("tuuids").iter().map(|t| t.as_ref()).collect();
        let mut tuuids_set: HashSet<&str> = HashSet::new();
        let filtre = doc!{
            CHAMP_TUUID: { "$in": &tuuids_vec },
            CHAMP_USER_ID: user_id_str
        };
        tuuids_set.extend(&tuuids_vec);

        let options = FindOptions::builder()
            .projection(doc!{
                CHAMP_TUUID: true, CHAMP_USER_ID: true, CHAMP_TYPE_NODE: true,
                CHAMP_SUPPRIME: true, CHAMP_SUPPRIME_INDIRECT: true,
                CHAMP_FUUIDS_VERSIONS: true
            })
            .build();
        let collection_row_fichiers = middleware.get_collection_typed::<NodeFichiersRepBorrow>(
            NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur_docs = collection_row_fichiers.find(filtre, options).await?;
        while curseur_docs.advance().await? {
            let row = curseur_docs.deserialize_current()?;
            tuuids_set.remove(row.tuuid);
            let type_node = TypeNode::try_from(row.type_node)?;
            match type_node {
                TypeNode::Fichier => {
                    reponse.tuuids_fichiers.push(row.tuuid.to_owned());
                    if let Some(fuuids) = row.fuuids_versions {
                        reponse.fuuids.extend(fuuids.into_iter().map(|c| c.to_owned()));
                    }
                },
                TypeNode::Collection | TypeNode::Repertoire => {
                    reponse.tuuids_repertoires.push(row.tuuid.to_owned());
                }
            }
        }

        if tuuids_set.len() > 0 {
            // Certains tuuids n'appartiennent pas a l'usager
            warn!("verifier_autorisation_usager Les tuuids {:?} n'appartiennent pas a l'usager {:?}", tuuids_set, user_id_str);
            reponse.tuuids_repertoires.extend(tuuids_set.into_iter().map(|c| c.to_owned()));
            return {
                // reponse.erreur = Some(middleware.formatter_reponse(json!({"ok": false, "message": "tuuids n'appartiennent pas a l'usager"}), None)?);
                reponse.erreur = Some(middleware.reponse_err(None, Some("tuuids n'appartiennent pas a l'usager"), None)?.parse_to_owned()?);
                Ok(reponse)
            }
        }
    }

    Ok(reponse)
}

struct ParseSelectionDirectoriesResult {
    destination_path: Vec<String>,
    files: Option<Vec<String>>,
    directories: Option<Vec<TransactionMoveV2Directory>>,
}

async fn parse_selection_directories<M>(
    middleware: &M, user_id: &str, destination_cuuid: &String, tuuids: &Vec<String>, session: &mut ClientSession,
    keep_deleted: bool, include_indirectly_deleted: bool,
)
    -> Result<ParseSelectionDirectoriesResult, CommonError>
    where M: MongoDao
{

    let collection_fichierrep =
        middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;

    // Get the destination path. This will replace the path of all files/directories being moved.
    // It will be used to update the path of subdirectories and their files.
    let destination_path = {
        let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
        let filtre = doc!{"tuuid": destination_cuuid};
        let destination_directory = match collection.find_one_with_session(filtre, None, session).await? {
            Some(inner) => inner,
            None => Err("Unknown destination directory")?
        };
        let mut destination_path = vec![destination_cuuid.to_owned()];
        if let Some(path_cuuids) = destination_directory.path_cuuids {
            destination_path.extend(path_cuuids.iter().map(|s| s.to_string()))
        }
        destination_path
    };

    debug!("commande_ajouter_fichiers_collection Destination path: {:?}", destination_path);

    let filtre = doc!{"tuuid": {"$in": tuuids}};
    let mut cursor = collection_fichierrep.find_with_session(filtre, None, session).await?;
    let mut files = Vec::new();
    let mut tuuids_by_cuuid: HashMap<String, Vec<String>> = HashMap::new();

    let mut directories: Vec<NodeInformation> = Vec::new();

    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        let parent = match row.path_cuuids.as_ref() {
            Some(inner) => match inner.get(0) {
                Some(inner) => Some(inner.to_string()),
                None => None
            },
            None => None
        };
        let node_info = NodeInformation { tuuid: row.tuuid.to_owned(), parent, destination_path: Some(destination_path.clone()) };
        if row.user_id != user_id {
            warn!("commande_ajouter_fichiers_collection File with wrong user_id, SKIPPING");
            continue
        }
        if row.type_node == TypeNode::Fichier.to_str() {
            files.push(node_info);
        } else {
            directories.push(node_info);
        }

        // Map all tuuids for post-transaction cleanup (search index, events)
        let cuuid = match row.path_cuuids {
            Some(path_cuuids) => match path_cuuids.get(0) {
                Some(cuuid) => *cuuid,
                None => "root",
            },
            None => "root"
        };
        match tuuids_by_cuuid.get_mut(cuuid) {
            Some(tuuids) => tuuids.push(row.tuuid.to_owned()),
            None => {
                tuuids_by_cuuid.insert(cuuid.to_owned(), vec![row.tuuid.to_owned()]);
            }
        }
    }

    // Make a list of all subdirectories to move. Include all subdirectories (deleted or not).
    let cuuids: Vec<&String> = directories.iter().map(|d| &d.tuuid).collect();
    let mut filtre = doc!{
        "path_cuuids": {"$in": &cuuids},
        "type_node": TypeNode::Repertoire.to_str()
    };
    if keep_deleted {
        // No filter to add - just keep all files whether they are deleted or not
    } else if include_indirectly_deleted {
        // Ignore files that were directly deleted (supprime == true && supprime_indirect == false)
        // This is used to copy files out from the Trash area
        filtre.insert("$or", vec![
            doc!{"supprime": false},
            doc!{"supprime_indirect": true},  // Implies supprime == true
        ]);
    } else {
        // keep_deleted is false
        filtre.insert("supprime", false);
    }
    let mut cursor = collection_fichierrep.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if row.user_id != user_id {
            warn!("commande_ajouter_fichiers_collection Directory with wrong user_id, SKIPPING");
            continue
        }
        // subdirectories.push(row.tuuid.to_owned());
        let parent = match row.path_cuuids.as_ref() {
            Some(inner) => match inner.get(0) {
                Some(inner) => Some(inner.to_string()),
                None => None
            },
            None => None
        };
        let node_info = NodeInformation { tuuid: row.tuuid.to_owned(), parent, destination_path: None };
        directories.push(node_info);

        // Add all directory tuuids for post-transaction cleanup (search index, events)
        let cuuid = match row.path_cuuids {
            Some(path_cuuids) => match path_cuuids.get(0) {
                Some(cuuid) => *cuuid,
                None => "root",
            },
            None => "root"
        };
        match tuuids_by_cuuid.get_mut(cuuid) {
            Some(tuuids) => tuuids.push(row.tuuid.to_owned()),
            None => {
                tuuids_by_cuuid.insert(cuuid.to_owned(), vec![row.tuuid.to_owned()]);
            }
        }
    }

    debug!("commande_ajouter_fichiers_collection Directories list: {:?}", directories);

    let directories_by_tuuid = {
        let mut directories_by_tuuid = HashMap::new();

        // Create destination node
        directories_by_tuuid.insert(
            destination_cuuid.to_owned(),
            NodeInformation { tuuid: destination_cuuid.to_owned(), parent: None, destination_path: None }
        );

        for directory in &directories {
            directories_by_tuuid.insert(directory.tuuid.to_owned(), directory.clone());
        }
        directories_by_tuuid
    };

    debug!("commande_ajouter_fichiers_collection Directories by tuuid: {:?}", directories_by_tuuid);

    // Fill in the destination path for each node
    for current_node in directories.iter_mut() {
        let mut node_destination_path = vec![];
        let mut depth = 0;

        // Start parent at current node
        let mut parent_node = directories_by_tuuid.get(&current_node.tuuid).expect("get node");
        loop {
            if depth > 100 {
                warn!("commande_ajouter_fichiers_collection Ininite loop detected on path, skipping tuuid: {}", current_node.tuuid);
                break;
            }
            depth += 1;

            match parent_node.destination_path.as_ref() {
                Some(path) => {
                    node_destination_path.extend(path.iter().map(|p| p.to_string()));
                    current_node.destination_path = Some(node_destination_path);
                    break  // Done
                },
                None => {
                    match parent_node.parent.as_ref() {
                        Some(parent) => {
                            node_destination_path.push(parent.to_string());
                            match directories_by_tuuid.get(parent) {
                                Some(ancestor) => {
                                    // Keep looping
                                    parent_node = ancestor;
                                },
                                None => {
                                    warn!("commande_ajouter_fichiers_collection No matching parent node, ignoring tuuid: {}", current_node.tuuid);
                                    break  // Error, no matching parent node. Ignore this node.
                                }
                            }
                        },
                        None => {
                            node_destination_path.extend(destination_path.clone());
                            current_node.destination_path = Some(node_destination_path);
                            break  // Done, no more parents this is the destination
                        }
                    }
                }
            }
        }
    }

    // Build list of moves
    let mut directories_by_tuuid = HashMap::new();
    directories_by_tuuid.insert(destination_cuuid.to_owned(), SubdirectoryList { node_information: NodeInformation {
        tuuid: destination_cuuid.to_owned(),
        parent: None,
        destination_path: Some((&destination_path[1..]).to_owned()),
    }, children: vec![]} );
    for directory in &directories {
        directories_by_tuuid.insert(directory.tuuid.to_owned(), SubdirectoryList { node_information: directory.clone(), children: vec![]} );
    }

    for directory in &directories {
        if let Some(parent) = directory.parent.as_ref() {
            match directories_by_tuuid.get_mut(parent) {
                Some(parent) => {
                    parent.children.push(directory.tuuid.clone());
                },
                None => {
                    // Unkonwn parent, add to destination
                    let destination = directories_by_tuuid.get_mut(destination_cuuid).expect("get_mut destination");
                    destination.children.push(directory.tuuid.clone());
                }
            }
        }
    }

    let directories = match directories_by_tuuid.len() {
        0 => None,
        _ => {
            let mut directories_move = Vec::new();
            for directory in directories_by_tuuid.into_values() {
                match directory.node_information.destination_path {
                    Some(mut destination) => {
                        if directory.children.len() == 0 {
                            continue  // No subdirectory, Skip
                        }
                        destination.insert(0, directory.node_information.tuuid);  // Push cuuid in front as parent for subfolders
                        directories_move.push(
                            TransactionMoveV2Directory {
                                path: destination,
                                directories: directory.children
                            }
                        );
                    }
                    None => {
                        warn!("Unable to move tuuid {}, no parent path", directory.node_information.tuuid);
                    }
                }
            }
            match directories_move.len() {
                0 => None,
                _ => Some(directories_move)
            }
        }
    };

    let files = match files.len() {
        0 => None,
        _ => Some(files.into_iter().map(|s| s.tuuid).collect())
    };

    Ok(ParseSelectionDirectoriesResult {destination_path, files, directories})
}


async fn commande_ajouter_fichiers_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_ajouter_fichiers_collection Consommer commande : {:?}", & m.type_message);
    let commande: TransactionAjouterFichiersCollection = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let include_deleted = commande.include_deleted.unwrap_or(false);

    // let commande: TransactionAjouterFichiersCollection = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_ajouter_fichiers_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err("Certificate with no user_id")?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let user_id_source = match commande.contact_id.as_ref() {
        Some(contact_id) => {
            debug!("commande_ajouter_fichiers_collection Verifier que le contact_id est valide (correspond aux tuuids)");
            let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let filtre = doc!{CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id};
            let contact = match collection.find_one_with_session(filtre, None, session).await? {
                Some(inner) => inner,
                None => {
                    // let reponse = json!({"ok": false, "err": "Contact_id invalide"});
                    // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                    return Ok(Some(middleware.reponse_err(None, None, Some("Contact_id invalide"))?))
                }
            };

            let resultat = verifier_acces_usager_tuuids(
                middleware, &contact.user_id, &commande.inclure_tuuids).await?;

            if resultat.len() != commande.inclure_tuuids.len() {
                // let reponse = json!({"ok": false, "err": "Acces refuse"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))

            }
            contact.user_id
        },
        None => user_id.clone()
    };

    if let Some(contact_id) = commande.contact_id.as_ref() {
        debug!("commande_ajouter_fichiers_collection Verifier que le contact_id est valide (correspond aux tuuids)");
        let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
        let filtre = doc!{CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id};
        let contact = match collection.find_one_with_session(filtre, None, session).await? {
            Some(inner) => inner,
            None => {
                // let reponse = json!({"ok": false, "err": "Contact_id invalide"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Contact_id invalide"))?))
            }
        };

        let resultat = verifier_acces_usager_tuuids(
            middleware, &contact.user_id, &commande.inclure_tuuids).await?;

        if resultat.len() != commande.inclure_tuuids.len() {
            return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
        }
    } else if role_prive {
        let user_id_str = user_id.as_str();
        let cuuid = commande.cuuid.as_str();
        let tuuids: Vec<&str> = commande.inclure_tuuids.iter().map(|t| t.as_str()).collect();
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.commande_ajouter_fichiers_collection: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let result = parse_selection_directories(
        middleware, user_id_source.as_str(), &commande.cuuid, &commande.inclure_tuuids, session, false, include_deleted).await?;

    // Check that the destination is not under the source (moving under itself breaks the graph)
    if let Some(directory_moves) = result.directories.as_ref() {
        for directory_move in directory_moves {
            for directory in &directory_move.directories {
                if result.destination_path.contains(directory) {
                    debug!("commande_deplacer_fichiers_collection Rejecting copy directory, the destination is under the source (this breaks the graph)");
                    return Ok(Some(middleware.reponse_err(Some(3), None, Some("Cannot copy a directory under itself"))?))
                }
            }
        }
    }

    if include_deleted {
        if let Some(files) = result.files.as_ref() {
            claim_files(middleware, session, user_id.as_str(), files).await?;
        }

        if let Some(directory_moves) = result.directories.as_ref() {
            // Check that all files to copy still exist;
            let mut cuuids = Vec::new();
            for directory in directory_moves {
                cuuids.extend(directory.directories.clone());
            }
            claim_files_under_cuuids(middleware, session, &user_id, &cuuids).await?;
        }
    }

    // Build the transaction
    let mut original_command = m.message.parse_to_owned()?;
    original_command.certificat = None;

    let transaction = TransactionCopyV2 {
        command: original_command,
        destination: result.destination_path,
        directories: result.directories,
        files: result.files,
        user_id,
        include_deleted: commande.include_deleted,
    };

    debug!("commande_ajouter_fichiers_collection Transaction\n{}", serde_json::to_string(&transaction)?);

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_COPY_V2).await?.0;

    // Job done, commit then emit events
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    for tuuid in &commande.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_AJOUTER_FICHIER_COLLECTION, session).await {
            warn!("transaction_ajouter_fichiers_collection Erreur emettre_evenement_maj_fichier : {:?}", e)
        }
    }

    let mut evenement_contenu = EvenementContenuCollection::new(commande.cuuid.clone());
    evenement_contenu.fichiers_ajoutes = Some(commande.inclure_tuuids.clone());
    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_contenu).await?;

    Ok(response)
}

#[derive(Clone, Debug)]
struct NodeInformation {
    tuuid: String,
    parent: Option<String>,
    destination_path: Option<Vec<String>>,
}

struct SubdirectoryList {
    node_information: NodeInformation,
    children: Vec<String>,
}

async fn commande_deplacer_fichiers_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_deplacer_fichiers_collection Consommer commande : {:?}", & m.type_message);
    let commande: TransactionDeplacerFichiersCollection = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // let commande: TransactionDeplacerFichiersCollection = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_deplacer_fichiers_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err("commande_deplacer_fichiers_collection Certificate with no user_id")?
    };

    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        let user_id_str = user_id.as_str();
        let cuuid = commande.cuuid_origine.as_str();
        let cuuid_destination = commande.cuuid_destination.as_str();
        let mut tuuids: Vec<&str> = commande.inclure_tuuids.iter().map(|t| t.as_str()).collect();
        tuuids.push(cuuid_destination);  // Piggyback pour verifier un des 2 cuuids
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.commande_deplacer_fichiers_collection: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let result = parse_selection_directories(
        middleware, user_id.as_str(), &commande.cuuid_destination, &commande.inclure_tuuids, session, true, true).await?;

    // Check that the destination is not under the source (moving under itself breask the graph)
    if let Some(directory_moves) = result.directories.as_ref() {
        for directory_move in directory_moves {
            for directory in &directory_move.directories {
                if result.destination_path.contains(directory) {
                    debug!("commande_deplacer_fichiers_collection Rejecting move directory, the destination is under the source (this breaks the graph)");
                    return Ok(Some(middleware.reponse_err(Some(3), None, Some("Cannot move a directory under itself"))?))
                }
            }
        }
    }

    // Build the transaction
    let mut original_command = m.message.parse_to_owned()?;
    original_command.certificat = None;

    let transaction = TransactionMoveV2 {
        command: original_command,
        destination: result.destination_path,
        directories: result.directories,
        files: result.files,
        user_id: Some(user_id),
    };

    debug!("commande_deplacer_fichiers_collection Transaction\n{}", serde_json::to_string(&transaction)?);

    let response = sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_MOVE_V2).await?.0;

    // Job done, commit then emit events
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    for tuuid in &commande.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_DEPLACER_FICHIER_COLLECTION, session).await {
            warn!("transaction_deplacer_fichiers_collection Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    let mut evenement_source = EvenementContenuCollection::new(commande.cuuid_origine.clone());
    evenement_source.retires = Some(commande.inclure_tuuids.clone());
    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_source).await?;
    let mut evenement_destination = EvenementContenuCollection::new(commande.cuuid_destination.clone());
    evenement_destination.fichiers_ajoutes = Some(commande.inclure_tuuids.clone());
    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement_destination).await?;

    Ok(response)
}

async fn commande_retirer_documents_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_retirer_documents_collection **OBSOLETE** Consommer commande : {:?}", & m.type_message);

    // let reponse = middleware.formatter_reponse(json!({"ok": false, "err": "Obsolete"}), None)?;
    // Ok(Some(reponse))
    Ok(Some(middleware.reponse_err(None, None, Some("Obsolete"))?))

    // let commande: TransactionRetirerDocumentsCollection = m.message.get_msg().map_contenu(None)?;
    // debug!("Commande commande_retirer_documents_collection versions parsed : {:?}", commande);
    //
    // // Autorisation: Action usager avec compte prive ou delegation globale
    // let user_id = m.get_user_id();
    // let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    // if role_prive && user_id.is_some() {
    //     let user_id_str = user_id.as_ref().expect("user_id");
    //     let cuuid = commande.cuuid.as_str();
    //     let tuuids: Vec<&str> = commande.retirer_tuuids.iter().map(|t| t.as_str()).collect();
    //     let err_reponse = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
    //     if err_reponse.is_some() {
    //         return Ok(err_reponse)
    //     }
    // } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
    //     // Ok
    // } else {
    //     Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    // }
    //
    // // Traiter la transaction
    // Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

#[derive(Deserialize)]
struct CommandeSupprimerV2 {
    tuuids: Vec<String>,
}

#[derive(Serialize)]
struct CommandeSupprimerTuuidsIndex {
    tuuids: Vec<String>
}

async fn commande_supprimer_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_documents Consommer commande : {:?}", & m.type_message);
    let commande: CommandeSupprimerV2 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            return Ok(Some(middleware.reponse_err(Some(401), None, Some("User_id not included in certificate"))?))
        }
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        let tuuids: Vec<&str> = commande.tuuids.iter().map(|t| t.as_str()).collect();
        let resultat = verifier_autorisation_usager(middleware, user_id.as_str(), Some(&tuuids), None::<String>).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commande_supprimer_documents: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Separate the directories from the files.
    let collection_fichierrep =
        middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc!{"tuuid": {"$in": &commande.tuuids}};
    let mut cursor = collection_fichierrep.find_with_session(filtre, None, session).await?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut tuuids_by_cuuid: HashMap<String, Vec<String>> = HashMap::new();
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if row.user_id != user_id.as_str() {
            warn!("commande_supprimer_documents Deleting file with wrong user_id, SKIPPING");
            continue
        }
        if row.type_node == TypeNode::Fichier.to_str() {
            files.push(row.tuuid.to_owned());
        } else {
            directories.push(row.tuuid.to_owned());
        }

        // Map all tuuids for post-transaction cleanup (search index, events)
        let cuuid = match row.path_cuuids {
            Some(path_cuuids) => match path_cuuids.get(0) {
                Some(cuuid) => *cuuid,
                None => user_id.as_str(),
            },
            None => user_id.as_str()
        };
        match tuuids_by_cuuid.get_mut(cuuid) {
            Some(tuuids) => tuuids.push(row.tuuid.to_owned()),
            None => {
                tuuids_by_cuuid.insert(cuuid.to_owned(), vec![row.tuuid.to_owned()]);
            }
        }
    }

    // Make a list of all subdirectories to delete.
    // Only include subdirectories that are not already deleted.
    let mut subdirectories = Vec::new();
    let filtre = doc!{
        "path_cuuids": {"$in": &directories},
        "type_node": TypeNode::Repertoire.to_str(),
        "supprime": false
    };
    let mut cursor = collection_fichierrep.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if row.user_id != user_id.as_str() {
            warn!("commande_supprimer_documents Deleting directory with wrong user_id, SKIPPING");
            continue
        }
        subdirectories.push(row.tuuid.to_owned());

        // Add all directory tuuids for post-transaction cleanup (search index, events)
        let cuuid = match row.path_cuuids {
            Some(path_cuuids) => match path_cuuids.get(0) {
                Some(cuuid) => *cuuid,
                None => user_id.as_str(),
            },
            None => user_id.as_str()
        };
        match tuuids_by_cuuid.get_mut(cuuid) {
            Some(tuuids) => tuuids.push(row.tuuid.to_owned()),
            None => {
                tuuids_by_cuuid.insert(cuuid.to_owned(), vec![row.tuuid.to_owned()]);
            }
        }
    }

    // Make a list of all files that will be affected. This is for post-transaction cleanup (search index, events).
    let filtre = doc!{
        "path_cuuids": {"$in": &directories},
        "type_node": TypeNode::Fichier.to_str(),
        "supprime": false
    };
    let mut cursor = collection_fichierrep.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if row.user_id != user_id.as_str() {
            warn!("commande_supprimer_documents Deleting directory with wrong user_id, SKIPPING");
            continue
        }
        let cuuid = match row.path_cuuids {
            Some(path_cuuids) => match path_cuuids.get(0) {
                Some(cuuid) => *cuuid,
                None => user_id.as_str(),
            },
            None => user_id.as_str()
        };
        match tuuids_by_cuuid.get_mut(cuuid) {
            Some(tuuids) => tuuids.push(row.tuuid.to_owned()),
            None => {
                tuuids_by_cuuid.insert(cuuid.to_owned(), vec![row.tuuid.to_owned()]);
            }
        }
    }

    // Create a new transaction with information to process
    let result = {
        let mut command_owned = m.message.parse_to_owned()?;
        command_owned.certificat = None;
        let transaction = TransactionDeleteV2 {
            command: command_owned,
            directories: match directories.len() {
                0 => None,
                _ => Some(directories)
            },
            subdirectories: match subdirectories.len() {
                0 => None,
                _ => Some(subdirectories)
            },
            files: match files.len() {
                0 => None,
                _ => Some(files)
            },
            user_id: Some(user_id.clone()),
        };

        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_DELETE_V2).await?.0
    };

    // Commit, DB work is done. Only external events left to do (not a big deal if they fail).
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    debug!("commande_supprimer_documents Post transaction cleanup for : {:?}", tuuids_by_cuuid);

    // Emettre evenements supprime par cuuid
    for (cuuid, liste) in tuuids_by_cuuid.into_iter() {
        let mut evenement = EvenementContenuCollection::new(cuuid);
        evenement.retires = Some(liste.clone());
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;

        // Cleanup of the search index. The list may be large and take a while to process.
        // Just let it go after a short wait, not a big deal if it fails. It can be cleaned-up by reindexing the DB.
        let routage = RoutageMessageAction::builder("solrrelai", "supprimerTuuids", vec![Securite::L3Protege])
            .timeout_blocking(300)
            .build();
        let commande_index = CommandeSupprimerTuuidsIndex { tuuids: liste };
        match middleware.transmettre_commande(routage.clone(), commande_index).await {
            Ok(inner) => match inner {
                Some(result) => {
                    if !verifier_reponse_ok(&result) {
                        warn!("commande_supprimer_documents Error remove tuuids from index (solr error) : {:?}", result);
                    }
                },
                None => info!("commande_supprimer_documents No response from search index (short wait), moving on to next batch")
            },
            Err(_) => {
                info!("commande_supprimer_documents No response from search index (short wait), moving on to next batch")
            }
        }
    }

    Ok(result)
}

#[derive(Clone, Debug, Deserialize)]
struct RowFuuids {
    fuuids: Option<Vec<String>>
}

async fn commande_recuperer_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_recuperer_documents Consommer commande : {:?}", & m.type_message);
    let commande: TransactionListeDocuments = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };
    // let commande: TransactionListeDocuments = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_recuperer_documents versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let tuuids: Vec<&str> = commande.tuuids.iter().map(|t| t.as_str()).collect();
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Emettre une commande de reactivation a fichiers (consignation)
    // Attendre 1 succes, timeout 10 secondes pour echec
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS, COMMANDE_FICHIERS_REACTIVER, vec![Securite::L2Prive])
        .timeout_blocking(5_000)
        .build();

    // Recuperer les fuuids pour tous les tuuids
    let filtre = match user_id.as_ref() {
        Some(u) => doc! { CHAMP_USER_ID: u, CHAMP_TUUID: {"$in": &commande.tuuids} },
        None => doc! { CHAMP_TUUID: {"$in": &commande.tuuids} }
    };
    let projection = doc!{ CHAMP_FUUIDS: true };
    let options = FindOptions::builder().projection(projection).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fuuids = Vec::new();
    let mut curseur = collection.find_with_session(filtre, Some(options), session).await?;
    while let Some(r) = curseur.next(session).await {
        let row: RowFuuids = convertir_bson_deserializable(r?)?;
        if let Some(fr) = row.fuuids {
            fuuids.extend(fr.into_iter());
        }
    }

    debug!("commande_recuperer_documents Liste fuuids a recuperer : {:?}", fuuids);

    let commande = json!({ "fuuids": fuuids });
    match middleware.transmettre_commande(routage, &commande).await {
        Ok(r) => match r {
            Some(r) => match r {
                TypeMessage::Valide(reponse) => {
                    // Traiter la transaction
                    debug!("commande_recuperer_documents Reponse recuperer document OK : {:?}", reponse);
                    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
                },
                _ => {
                    debug!("commande_recuperer_documents Reponse recuperer document est invalide");
                    // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichiers supprimes"}), None)?))
                    Ok(Some(middleware.reponse_err(None, None, Some("Fichiers supprimes"))?))
                }
            },
            None => {
                debug!("commande_recuperer_documents Reponse recuperer : reponse vide");
                // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Reponse des serveurs de fichiers vide (aucun contenu)"}), None)?))
                Ok(Some(middleware.reponse_err(None, None, Some("Reponse des serveurs de fichiers vide (aucun contenu)"))?))
            }
        },
        Err(e) => {
            debug!("commande_recuperer_documents Reponse recuperer document erreur : {:?}", e);
            // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichiers supprimes/timeout"}), None)?))
            Ok(Some(middleware.reponse_err(None, None, Some("Fichiers supprimes/timeout"))?))
        }
    }
}

#[derive(Deserialize)]
struct ReponseRecupererFichiers {
    errors: Option<Vec<String>>,
    inconnus: Option<Vec<String>>,
    recuperes: Option<Vec<String>>,
}

async fn commande_recuperer_documents_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_recuperer_documents Consommer commande : {:?}", & m.type_message);
    let commande: TransactionRecupererDocumentsV2 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commandes.commande_recuperer_documents_v2 User_id absent du certificat"))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_recuperer_documents_v2: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let mut tuuids = HashSet::new();
    for (cuuid, liste) in &commande.items {
        debug!("commande_recuperer_documents_v2 Ajouter tuuids {:?} sous cuuid {}", liste, cuuid);
        tuuids.insert(cuuid);
        if let Some(liste) = liste {
            tuuids.extend(liste);
            // for tuuid in liste {
            //     tuuids.insert(tuuid);
            // }
        }
    }
    let tuuids: Vec<&str> = tuuids.iter().map(|t| t.as_str()).collect();
    let resultat = verifier_autorisation_usager(middleware, user_id, Some(&tuuids), None::<String>).await?;
    if let Some(erreur) = resultat.erreur {
        return Ok(Some(erreur.try_into()?))
    }

    // debug!("commande_recuperer_documents_v2 Verification autorisation fichiers : {:?}", resultat);

    if resultat.fuuids.len() == 0 {
        debug!("commande_recuperer_documents_v2 Aucuns fichiers a restaurer - juste des repertoires. Aucunes verifications additionnelles requises");
        return Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
    }

    // Emettre une commande de reactivation a fichiers (consignation)
    // Attendre 1 succes, timeout 5 secondes pour echec
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS, COMMANDE_FICHIERS_REACTIVER, vec![Securite::L2Prive])
        .timeout_blocking(5_000)
        .build();

    let commande = json!({ "fuuids": resultat.fuuids });
    match middleware.transmettre_commande(routage, &commande).await {
        Ok(r) => match r {
            Some(r) => match r {
                TypeMessage::Valide(reponse) => {
                    // Traiter la transaction
                    debug!("commande_recuperer_documents_v2 Reponse recuperer document OK : {:?}", reponse);
                    let parsed: ReponseRecupererFichiers = {
                        let reponse_ref = reponse.message.parse()?;
                        reponse_ref.contenu()?.deserialize()?
                    };
                    let mut inconnus = 0;
                    let mut errors = 0;
                    if let Some(inconnus_vec) = parsed.inconnus.as_ref() {
                        inconnus = inconnus_vec.len();
                    }
                    if let Some(errors_vec) = parsed.errors.as_ref() {
                        errors = errors_vec.len();
                    }
                    if inconnus > 0 || errors > 0 {
                        let reponse = json!({
                            "ok": false,
                            "err": "Au moins 1 fichier supprime Fichiers supprimes",
                            "recuperes": parsed.recuperes,
                            "inconnus": parsed.inconnus,
                            "errors": parsed.errors,
                        });
                        // return Ok(Some(middleware.formatter_reponse(&reponse, None)?))
                        return Ok(Some(middleware.build_reponse(reponse)?.0))
                    }
                    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
                },
                _ => {
                    debug!("commande_recuperer_documents_v2 Reponse recuperer document est invalide");
                    // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichiers supprimes"}), None)?))
                    Ok(Some(middleware.reponse_err(None, None, Some("Fichiers supprimes"))?))
                }
            },
            None => {
                debug!("commande_recuperer_documents_v2 Reponse recuperer : reponse vide");
                // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Reponse des serveurs de fichiers vide (aucun contenu)"}), None)?))
                Ok(Some(middleware.reponse_err(None, None, Some("Reponse des serveurs de fichiers vide (aucun contenu)"))?))
            }
        },
        Err(e) => {
            debug!("commande_recuperer_documents_v2 Reponse recuperer document erreur : {:?}", e);
            // Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichiers supprimes/timeout"}), None)?))
            Ok(Some(middleware.reponse_err(None, None, Some("Fichiers supprimes/timeout"))?))
        }
    }
}

async fn commande_decrire_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_decrire_collection Consommer commande : {:?}", & m.type_message);
    let commande: TransactionDecrireCollection = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("grosfichiers.consommer_commande: User_id not provided in certificate"))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        let user_id_str = user_id.as_str();
        let tuuids = vec![commande.tuuid.clone()];
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), None::<String>).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Traiter la transaction
    let result = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Declencher indexation
    let tuuid = &commande.tuuid;
    if let Some(metadata) = commande.metadata {
        if metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
            let user_id = user_id.as_str();
            let cle_id = metadata.cle_id.expect("cle_id");
            let format = metadata.format.expect("format");
            let nonce = metadata.nonce.expect("nonce");
            let filehost_ids: Vec<&str> = Vec::new();
            let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, "", &filehost_ids, cle_id, format, nonce);
            sauvegarder_job_index(middleware, &job, session).await?;
        }
    }

    let filtre = doc! { CHAMP_TUUID: tuuid };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.find_one_with_session(filtre, None, session).await {
        Ok(inner) => {
            debug!("transactions.transaction_decrire_collection Update description : {:?}", inner);
            if let Some(d) = inner {
                // Emettre evenement de maj contenu sur chaque cuuid
                match convertir_bson_deserializable::<FichierDetail>(d) {
                    Ok(fichier) => {
                        if let Some(favoris) = fichier.favoris {
                            if favoris {
                                let mut evenement = EvenementContenuCollection::new(user_id.clone());
                                // evenement.cuuid = Some(u);
                                evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                            }
                        }
                        if let Some(path_cuuids) = fichier.path_cuuids {
                            if let Some(cuuid) = path_cuuids.first() {
                                let mut evenement = EvenementContenuCollection::new(cuuid);
                                evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                            }
                        }
                    },
                    Err(e) => warn!("transaction_decrire_collection Erreur conversion a FichierDetail : {:?}", e)
                }
            }
        },
        Err(e) => Err(format!("transactions.transaction_decrire_collection Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid, user_id, session).await?;

    Ok(result)
}

// commande_copier_fichier_tiers est OBSOLETE
// async fn commande_copier_fichier_tiers<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
//     -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
//     where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
// {
//     debug!("commande_copier_fichier_tiers Consommer commande : {:?}", & m.type_message);
//     let commande: CommandeCopierFichierTiers = m.message.get_msg().map_contenu()?;
//     debug!("commande_copier_fichier_tiers parsed : {:?}", commande);
//     // debug!("Commande en json (DEBUG) : \n{:?}", serde_json::to_string(&commande));
//
//     let fingerprint_client = match &m.message.certificat {
//         Some(inner) => inner.fingerprint.clone(),
//         None => Err(format!("commande_copier_fichier_tiers Envelopppe manquante"))?
//     };
//
//     let user_id = match m.get_user_id() {
//         Some(inner) => inner,
//         None => Err(format!("commande_copier_fichier_tiers Enveloppe sans user_id"))?
//     };
//
//     // Verifier aupres du maitredescles si les cles sont valides
//     let reponse_preuves = {
//         let requete_preuves = json!({"fingerprint": fingerprint_client, "preuves": &commande.preuves});
//         let routage_maitrecles = RoutageMessageAction::builder(
//             DOMAINE_NOM_MAITREDESCLES, REQUETE_MAITREDESCLES_VERIFIER_PREUVE)
//             .exchanges(vec![Securite::L4Secure])
//             .build();
//         debug!("commande_copier_fichier_tiers Requete preuve possession cles : {:?}", requete_preuves);
//         let reponse_preuve = match middleware.transmettre_requete(routage_maitrecles, &requete_preuves).await? {
//             TypeMessage::Valide(m) => {
//                 match m.message.certificat.as_ref() {
//                     Some(c) => {
//                         if c.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
//                             debug!("commande_copier_fichier_tiers Reponse preuve : {:?}", m);
//                             let preuve_value: ReponsePreuvePossessionCles = m.message.get_msg().map_contenu()?;
//                             Ok(preuve_value)
//                         } else {
//                             Err(format!("commandes.commande_copier_fichier_tiers Erreur chargement certificat de reponse verification preuve, certificat n'est pas de role maitre des cles"))
//                         }
//                     },
//                     None => Err(format!("commandes.commande_copier_fichier_tiers Erreur chargement certificat de reponse verification preuve, certificat inconnu"))
//                 }
//             },
//             m => Err(format!("commandes.commande_copier_fichier_tiers Erreur reponse message verification cles, mauvais type : {:?}", m))
//         }?;
//         debug!("commande_copier_fichier_tiers Reponse verification preuve : {:?}", reponse_preuve);
//
//         reponse_preuve.verification
//     };
//
//     let mut resultat_fichiers = HashMap::new();
//     for mut fichier in commande.fichiers {
//         let fuuid = fichier.fuuid.as_str();
//
//         let mut etat_cle = false;
//         if Some(&true) == reponse_preuves.get(fuuid) {
//             etat_cle = true;
//         } else {
//             // Tenter de sauvegarder la cle
//             if let Some(cle) = commande.cles.get(fuuid) {
//                 debug!("commande_copier_fichier_tiers Sauvegarder cle fuuid {} : {:?}", fuuid, cle);
//                 let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
//                     .exchanges(vec![Securite::L4Secure])
//                     .timeout_blocking(5000)
//                     .build();
//                 let reponse_cle = middleware.transmettre_commande(routage, &cle, true).await?;
//                 debug!("commande_copier_fichier_tiers Reponse sauvegarde cle : {:?}", reponse_cle);
//                 if let Some(reponse) = reponse_cle {
//                     if let TypeMessage::Valide(mva) = reponse {
//                         debug!("Reponse valide : {:?}", mva);
//                         let reponse_mappee: ReponseCle = mva.message.get_msg().map_contenu()?;
//                         etat_cle = true;
//                     }
//                 }
//             } else {
//                 debug!("commande_copier_fichier_tiers Aucune cle trouvee pour fuuid {} : {:?}", fuuid, commande.cles);
//             }
//         }
//
//         if etat_cle {
//             debug!("commande_copier_fichier_tiers Fuuid {} preuve OK", fuuid);
//
//             // Injecter le user_id du certificat recu
//             fichier.user_id = Some(user_id.clone());
//
//             // Convertir le fichier en transaction
//             let transaction_copier_message = middleware.formatter_message(
//                 MessageKind::Commande, &fichier, DOMAINE_NOM.into(), "copierFichierTiers".into(), None::<&str>, None::<&str>, None, false)?;
//             let transaction_copier_message = MessageSerialise::from_parsed(transaction_copier_message)?;
//
//             let mva = MessageValide::new(
//                 transaction_copier_message,
//                 m.q.clone(),
//                 "transaction.GrosFichiers.copierFichierTiers".into(),
//                 m.domaine.clone(),
//                 "copierFichierTiers".into(),
//                 m.type_message.clone()
//             );
//
//             // Conserver transaction
//             match sauvegarder_traiter_transaction(middleware, mva, gestionnaire).await {
//                 Ok(r) => {
//                     debug!("commande_copier_fichier_tiers Reponse sauvegarde fichier {} : {:?}", fuuid, r);
//                     resultat_fichiers.insert(fuuid.to_string(), true);
//
//                     // Demander visite de presence du fichier par consignation_fichiers
//                     let params = json!({ "visiter": true, "fuuids": vec![&fuuid] });
//                     debug!("commande_copier_fichier_tiers Emettre demande visite fichier {}", fuuid);
//                     let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, "fuuidVerifierExistance")
//                         .exchanges(vec![Securite::L2Prive])
//                         .build();
//                     if let Err(e) = middleware.transmettre_requete(routage, &params).await {
//                         info!("commande_copier_fichier_tiers Erreur visite fichier {} : {:?}", fuuid, e);
//                     }
//                 },
//                 Err(e) => {
//                     error!("commande.commande_copier_fichier_tiers Erreur sauvegarder_traiter_transaction {} : {:?}", fuuid, e);
//                     resultat_fichiers.insert(fuuid.to_string(), false);
//                 }
//             }
//
//         } else {
//             warn!("commande_copier_fichier_tiers Fuuid {} preuve refusee ou cle inconnue", fuuid);
//             resultat_fichiers.insert(fuuid.to_string(), false);
//         }
//     }
//
//     let reponse = json!({"resultat": resultat_fichiers});
//     Ok(Some(middleware.formatter_reponse(&reponse, None)?))
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeCopierFichierTiers {
    pub cles: HashMap<String, CommandeSauvegarderCle>,
    pub fichiers: Vec<TransactionCopierFichierTiers>,
    pub preuves: HashMap<String, PreuvePossessionCles>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreuvePossessionCles {
    pub preuve: String,
    pub date: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponsePreuvePossessionCles {
    pub verification: HashMap<String, bool>,
}

async fn commande_reindexer<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    // Autorisation : doit etre un message provenant d'un usager avec delegation globale
    // Verifier si on a un certificat delegation globale
    match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => Ok(()),
        false => Err(format!("commandes.commande_reindexer: Commande autorisation invalide pour message {:?}", m.type_message)),
    }?;

    // Reset tous les fichiers, demarre re-indexation
    reset_flag_indexe(middleware, gestionnaire, session).await
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeIndexerContenu {
    reset: Option<bool>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct ReponseCommandeReindexer {
    tuuids: Option<Vec<String>>,
    ok: bool,
}

async fn commande_completer_previews<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_completer_previews Consommer commande : {:?}", & m.type_message);
    let commande: CommandeCompleterPreviews = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation : doit etre un message provenant d'un usager avec acces prive ou delegation globale
    // Verifier si on a un certificat delegation globale ou prive
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            warn!("commande_completer_previews User_id n'est pas fourni, commande refusee");
            // let reponse = middleware.formatter_reponse(json!({"ok": false, "err": "Acces refuse (user_id)"}), None)?;
            // return Ok(Some(reponse))
            return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (user_id)"))?))
        }
    };

    // Parcourir tous les fuuids demandes pour le user_id
    let filtre = match commande.fuuids {
        Some(fuuids) => {
            doc! {CHAMP_FUUID: {"$in": fuuids}}
        },
        None => {
            warn!("commande_completer_previews Aucuns fuuids, pas d'effet.");
            // let reponse = middleware.formatter_reponse(json!({"ok": true, "message": "Aucun effet (pas de fuuids fournis)"}), None)?;
            // return Ok(Some(reponse))
            return Ok(Some(middleware.reponse_err(None, None, Some("Aucun effet (pas de fuuids fournis)"))?))
        }
    };

    let collection_reps = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;

    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection_versions.find_with_session(filtre, None, session).await?;
    while curseur.advance(session).await? {
        let fichier_version = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                error!("commande_completer_previews Erreur mapping fichier version, SKIP");
                continue
            }
        };

        let fuuid = fichier_version.fuuid;
        let mimetype= fichier_version.mimetype;

        let filtre_rep = doc!{"fuuids_versions": fuuid, "user_id": &user_id};
        let file_rep = match collection_reps.find_one_with_session(filtre_rep, None, session).await? {
            Some(inner) => inner,
            None => {
                info!("No matching file_rep for fuuid:{}/user_id:{} - SKIP", fuuid, user_id);
                continue
            }
        };
        let tuuid = file_rep.tuuid;

        if fichier_version.cle_id.is_some() && fichier_version.format.is_some() && fichier_version.nonce.is_some() {
            let cle_id = fichier_version.cle_id.expect("cle_id");
            let format: &str = fichier_version.format.expect("format").into();
            let nonce = fichier_version.nonce.expect("nonce");
            let filehost_ids: Vec<&String> = fichier_version.visites.keys().collect();
            let job = BackgroundJob::new(tuuid, fuuid, mimetype, &filehost_ids, cle_id, format, nonce);
            sauvegarder_job_images(middleware, &job, session).await?;
        }
    }

    // Reponse generer preview
    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Deserialize)]
struct RowTuuid {
    tuuid: String,
    fuuid: Option<String>,
    fuuids: Option<Vec<String>>,
    mimetype: Option<String>,
    // visites: Option<HashMap<String, i64>>,
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeCompleterPreviews {
    reset: Option<bool>,
    limit: Option<i64>,
    fuuids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
struct ReponseCompleterPreviews {
    tuuids: Option<Vec<String>>,
}

async fn commande_confirmer_fichier_indexe<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_confirmer_fichier_indexe Consommer commande : {:?}", & m.type_message);
    let commande: ParametresConfirmerJobIndexation = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation : doit etre un message provenant d'un composant protege
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        true => Ok(()),
        false => Err(format!("commandes.commande_completer_previews: Commande autorisation invalide pour message {:?}", m.type_message)),
    }?;

    let job_id = commande.job_id.as_str();
    let tuuid = commande.tuuid.as_str();
    let fuuid = match commande.fuuid.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None};
    if let Err(e) = set_flag_index_traite(middleware, job_id, tuuid, fuuid, session).await {
        error!("commande_confirmer_fichier_indexe Erreur traitement flag : {:?}", e);
    }

    Ok(None)
}

#[derive(Serialize)]
struct CommandeVideoConvertirReponse {
    ok: bool,
    job_id: Option<String>,
}

async fn commande_video_convertir<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_video_convertir Consommer commande : {:?}", & m.type_message);
    let commande: CommandeVideoConvertir = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let fuuid = commande.fuuid.as_str();
    let tuuid = commande.tuuid.as_str();

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => return Ok(Some(middleware.reponse_err(None, None, Some("Certificate has no user_id"))?))
    };

    // Verifier si le fichier a deja un video correspondant
    let bitrate_quality = match &commande.quality_video {
        Some(q) => q.to_owned(),
        None => match &commande.bitrate_video {
            Some(b) => b.to_owned() as i32,
            None => 0,
        }
    };
    let mut cle_video = format!("{};{};{}p;{}", commande.mimetype, commande.codec_video, commande.resolution_video, bitrate_quality);
    if let Some(inner) = commande.audio_stream_idx.as_ref() {
        if *inner != 0 {
            cle_video = format!("{};a{}", cle_video, inner);
        }
    }
    if let Some(inner) = commande.subtitle_stream_idx.as_ref() {
        cle_video = format!("{};s{}", cle_video, inner);
    }

    {   // Verify access rights
        let filtre_rep = doc! { "fuuids_versions": fuuid, "user_id": &user_id };
        let collection_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let count = collection_rep.count_documents_with_session(filtre_rep, None, session).await?;
        if count == 0 {
            info!("commande_video_convertir User_id {} does not have access to fuuid {}", user_id, fuuid);
            return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
        }
    }

    let filtre_fichier = doc! { CHAMP_FUUID: fuuid };
    let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let version_courante = match collection.find_one_with_session(filtre_fichier, None, session).await {
        Ok(inner) => match inner {
            Some(inner) => inner,
            None => {
                info!("commande_video_convertir find_one : Fichier inconnu {}", fuuid);
                return Ok(Some(middleware.reponse_err(Some(404), None, Some("Fichier inconnu"))?))
            }
        },
        Err(e) => {
            error!("commande_video_convertir find_one : Erreur chargement/conversion {} : {:?}", fuuid, e);
            return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement/conversion"))?))
        }
    };

    // Ensure no video exists with those parameters
    let filtre_media = doc!{ CHAMP_FUUID: fuuid, "user_id": &user_id };
    let collection_media = middleware.get_collection_typed::<MediaOwnedRow>(NOM_COLLECTION_MEDIA)?;
    if let Some(media) = collection_media.find_one(filtre_media, None).await? {
        if let Some(video) = media.video {
            if let Some(_) = video.get(cle_video.as_str()) {
                info!("commande_video_convertir Video file already exists with parameters {} for file {}", cle_video, fuuid);
                return Ok(Some(middleware.reponse_err(Some(409), None, Some("A video with the same parameters already exists"))?))
            }
        }
    }

    // Conserver l'information de conversion, emettre nouveau message de job
    if version_courante.cle_id.is_some() && version_courante.format.is_some() && version_courante.nonce.is_some() {
        let cle_id = version_courante.cle_id.expect("cle_id");
        let format: &str = version_courante.format.expect("format").into();
        let nonce = version_courante.nonce.expect("nonce");
        let mimetype = version_courante.mimetype;
        let filehost_ids: Vec<&String> = version_courante.visites.keys().collect();

        let mut job = BackgroundJob::new(tuuid, fuuid, mimetype, &filehost_ids, cle_id, format, nonce);
        let reponse = CommandeVideoConvertirReponse {ok: true, job_id: Some(job.job_id.clone())};

        job.user_id = Some(user_id.clone());
        let params = BackgroundJobParams {
            defaults: None,
            thumbnails: None,
            mimetype: Some(commande.mimetype),
            codec_video: Some(commande.codec_video),
            codec_audio: Some(commande.codec_audio),
            resolution_video: Some(commande.resolution_video),
            quality_video: commande.quality_video,
            bitrate_video: commande.bitrate_video,
            bitrate_audio: Some(commande.bitrate_audio),
            preset: commande.preset,
            audio_stream_idx: commande.audio_stream_idx,
            subtitle_stream_idx: commande.subtitle_stream_idx,
        };
        job.params = Some(params);
        sauvegarder_job_video(middleware, &job, session).await?;

        Ok(Some(middleware.build_reponse(reponse)?.0))
    } else {
        Ok(Some(middleware.reponse_err(Some(2), None, Some("Information de chiffrage manquante"))?))
    }

}

// async fn commande_image_get_job<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
//     -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
//     where M: GenerateurMessages + MongoDao + ValidateurX509,
// {
//     debug!("commande_image_get_job Consommer commande : {:?}", m.type_message);
//     let commande: CommandeImageGetJob = {
//         let message_ref = m.message.parse()?;
//         message_ref.contenu()?.deserialize()?
//     };
//
//     let certificat = m.certificat.as_ref();
//
//     // Verifier autorisation
//     if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
//         info!("commande_image_get_job Exchange n'est pas de niveau 3 ou 4");
//         // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
//         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (exchange)"))?))
//     }
//     if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
//         info!("commande_image_get_job Role n'est pas media");
//         // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre media)"}), None)?))
//         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (role doit etre media)"))?))
//     }
//
//     let commande_get_job = CommandeGetJob { filehost_id: commande.filehost_id, fallback: None };
//     let reponse_prochaine_job = gestionnaire.image_job_handler.get_prochaine_job(
//         middleware, certificat, commande_get_job).await?;
//
//     debug!("commande_image_get_job Prochaine job : tuuid {:?}", reponse_prochaine_job.tuuid);
//     let reponse_chiffree = middleware.build_reponse_chiffree(reponse_prochaine_job, m.certificat.as_ref())?.0;
//     debug!("commande_image_get_job Reponse chiffree\n{}", from_utf8(reponse_chiffree.buffer.as_slice())?);
//     Ok(Some(reponse_chiffree))
// }

// async fn commande_video_get_job<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
//     -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
//     where M: GenerateurMessages + MongoDao + ValidateurX509,
// {
//     debug!("commande_video_get_job Consommer commande : {:?}", & m.type_message);
//     let commande: CommandeVideoGetJob = {
//         let message_ref = m.message.parse()?;
//         message_ref.contenu()?.deserialize()?
//     };
//
//     let certificat = m.certificat.as_ref();
//
//     // Verifier autorisation
//     if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
//         info!("commande_video_get_job Exchange n'est pas de niveau 3 ou 4");
//         // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
//         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (exchange)"))?))
//     }
//     if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
//         info!("commande_video_get_job Role n'est pas media");
//         // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre media)"}), None)?))
//         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (role doit etre media)"))?))
//     }
//
//     let commande_get_job = CommandeGetJob { filehost_id: commande.filehost_id, fallback: commande.fallback };
//     let reponse_prochaine_job = gestionnaire.video_job_handler.get_prochaine_job(
//         middleware, certificat, commande_get_job).await?;
//
//     debug!("commande_video_get_job Prochaine job : {:?}", reponse_prochaine_job.tuuid);
//     Ok(Some(middleware.build_reponse_chiffree(reponse_prochaine_job, m.certificat.as_ref())?.0))
// }

async fn commande_supprimer_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_video Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerVideo = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let admin_account = m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    let private_account = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if !admin_account && !private_account {
        Err("Certificate is not for a private user account/admin, access refused")?
    }

    let fuuid_video = &commande.fuuid_video;
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => {
            inner
        },
        None => Err("commande_supprimer_video User_id missing from certificate")?
    };

    // Find original fuuid for this video
    let filtre_fichier = doc!{"fuuids_reclames": fuuid_video};
    let collection_fichier_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let file_version = match collection_fichier_versions.find_one_with_session(filtre_fichier, None, session).await? {
        Some(inner) => inner,
        None => Err("commande_supprimer_video Erreur chargement info document, aucun match")?
    };
    let fuuid_original = file_version.fuuid.as_str();

    // Ensure access
    let filtre_rep = doc!{"fuuids_versions": fuuid_original, "user_id": &user_id};
    let collection_rep = middleware.get_collection_typed::<NodeFichierRepRow>(NOM_COLLECTION_FICHIERS_REP)?;
    let mut cursor = collection_rep.find_with_session(filtre_rep, None, session).await?;
    let mut tuuids = Vec::new();
    while cursor.advance(session).await ? {
        let row = cursor.deserialize_current()?;
        tuuids.push(row.tuuid);
    }
    if tuuids.is_empty() {
        debug!("Access refused for user_id:{} to fuuid_video:{}", user_id, fuuid_video);
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access refused"))?))
    }

    // Process transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    // Work done, commit before emitting events
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    // Emit event
    for tuuid in tuuids {
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, tuuid, EVENEMENT_FUUID_ASSOCIER_VIDEO, session).await {
            warn!("commande_supprimer_video Erreur emettre_evenement_maj_fichier : {:?}", e);
        }
    }

    Ok(response)
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeAjouterContactLocal {
    nom_usager: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ReponseChargerUserIdParNomUsager {
    usagers: Option<HashMap<String, Option<String>>>
}

#[derive(Serialize)]
struct CommandeAjouterContactLocalReponse {
    ok: bool,
    nom_usager: String,
    user_id: String,
    contact_id: String
}

async fn commande_ajouter_contact_local<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_ajouter_contact Consommer commande : {:?}", & m.type_message);
    let commande: CommandeAjouterContactLocal = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("commande_ajouter_contact_local user_id absent, SKIP");;
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant du certificat"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("User id manquant du certificat"))?))
        }
    };

    // Identifier le user_id de l'usager a ajouter
    let user_contact_id = {
        let routage = RoutageMessageAction::builder(
            DOMAINE_NOM_MAITREDESCOMPTES, "getUserIdParNomUsager", vec![Securite::L3Protege])
            .timeout_blocking(4_000)
            .build();
        let requete = json!({ "noms_usagers": [commande.nom_usager] });
        match middleware.transmettre_requete(routage, &requete).await {
            Ok(inner) => match inner {
                Some(inner) => match inner {
                    TypeMessage::Valide(r) => {
                        let reponse_mappee: ReponseChargerUserIdParNomUsager = {
                            let reponse_ref = r.message.parse()?;
                            reponse_ref.contenu()?.deserialize()?
                        };
                        match reponse_mappee.usagers {
                            Some(mut inner) => {
                                match inner.remove(commande.nom_usager.as_str()) {
                                    Some(inner) => match inner {
                                        Some(inner) => inner,
                                        None => {
                                            debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (usager inconnu - 1), SKIP");
                                            ;
                                            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                                            return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                                        }
                                    },
                                    None => {
                                        debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (usager inconnu - 2), SKIP");
                                        ;
                                        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                                        return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                                    }
                                }
                            },
                            None => {
                                debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (reponse sans liste usagers), SKIP");
                                ;
                                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                                return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                            }
                        }
                    },
                    _ => {
                        debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (mauvais type reponse), SKIP");
                        ;
                        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                        return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                    }
                },
                None => {
                    debug!("commande_ajouter_contact_local Aucune reponse pour chargement user_id pour contact, SKIP");;
                    return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                }
        },
            Err(e) => {
                warn!("commande_ajouter_contact_local Erreur chargement user_id pour contact, SKIP : {:?}", e);;
                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
            }
        }
    };

    if user_contact_id == user_id {
        debug!("commande_ajouter_contact_local Usager (courant) tente de s'ajouter a ses propres contacts, SKIP");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Usager courant ne peut etre ajoute au contacts"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Usager courant ne peut etre ajoute au contacts"))?))
    }

    // Check if contact already exists
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    let filtre_current = doc!{CHAMP_USER_ID: &user_id, "contact_user_id": &user_contact_id};
    if collection.find_one(filtre_current, None).await?.is_some() {
        debug!("Share already exists for user_id: {}, contact user id: {}", user_id, user_contact_id);
        return Ok(Some(middleware.reponse_err(Some(409), None, Some("Share already exists"))?));
    }

    // Convertir en transaction
    let transaction = TransactionAjouterContactLocal { user_id, contact_user_id: user_contact_id };

    // Traiter la transaction
    sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_AJOUTER_CONTACT_LOCAL).await?;

    // Respond with transaction information
    let response = CommandeAjouterContactLocalReponse {
        ok: true,
        nom_usager: commande.nom_usager,
        user_id: transaction.user_id,
        contact_id: transaction.contact_user_id
    };
    Ok(Some(middleware.build_reponse(response)?.0))
}

async fn commande_supprimer_contacts<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_contacts Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerContacts = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("commande_supprimer_contacts user_id absent, SKIP");
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant du certificat"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("User id manquant du certificat"))?))
        }
    };

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
}

async fn commande_partager_collections<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_partager_collections Consommer commande : {:?}", & m.type_message);
    let commande: TransactionPartagerCollections = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("commande_partager_collections user_id absent, SKIP");
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant du certificat"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("User id manquant du certificat"))?))
        }
    };

    // Confirmer que l'usager controle tous les cuuids
    let mut cuuids_manquants: HashSet<&String> = HashSet::from_iter(commande.cuuids.iter());
    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_TUUID: {"$in": &commande.cuuids}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let options = FindOptions::builder().projection(doc!{CHAMP_TUUID: 1}).build();
    let mut curseur = collection.find_with_session(filtre, options, session).await?;
    while let Some(r) = curseur.next(session).await {
        let row: RowTuuid = convertir_bson_deserializable(r?)?;
        cuuids_manquants.remove(&row.tuuid);
    }

    if cuuids_manquants.len() > 0 {
        error!("commande_partager_collections Il y a au moins un cuuid non couvert pour l'usager, SKIP");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Au moins un repertoire est invalide"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Au moins un repertoire est invalide"))?))
    }

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
}

async fn commande_supprimer_partage_usager<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_partage_usager Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerPartageUsager = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("commande_supprimer_partage_usager user_id absent, SKIP");
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant du certificat"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("User id manquant du certificat"))?))
        }
    };

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
}

async fn commande_supprimer_orphelins<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_orphelins Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerOrphelins = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    todo!("fix me")
    // let resultat = trouver_orphelins_supprimer(middleware, &commande, session).await?;
    // debug!("commande_supprimer_orphelins Versions supprimees : {:?}, fuuids a conserver : {:?}",
    //     resultat.versions_supprimees, resultat.fuuids_a_conserver);
    //
    // let mut fuuids_supprimes = 0;
    // for (fuuid, supprime) in &resultat.versions_supprimees {
    //     if *supprime { fuuids_supprimes += 1; };
    // }
    //
    // // Determiner si on repond immediatement ou si on procede vers la transaction
    // if fuuids_supprimes > 0 {
    //     // On execute la transaction pour supprimer les fichiers dans la base de donnes
    //     debug!("commande_supprimer_orphelins Au moins une version supprimer (count: {}), executer la transaction", fuuids_supprimes);
    //     sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;
    // }
    //
    // let reponse = ReponseSupprimerOrphelins { ok: true, err: None, fuuids_a_conserver: resultat.fuuids_a_conserver };
    // Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn transmettre_cle_attachee<M>(middleware: &M, cle: Value)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;

    let mut routage_builder = RoutageMessageAction::builder(
        // DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public]
    )
        .correlation_id(&message_cle.id);

    let routage = routage_builder
        .timeout_blocking(3_000)
        .build();
    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;
    let reponse = match middleware.emettre_message(type_message, buffer_message).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("transmettre_cle_attachee Erreur sauvegarde cle : {:?}", e);
            return Ok(Some(middleware.reponse_err(4, None, Some(format!("Erreur: {:?}", e).as_str()))?))
        }
    };

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("Cle sauvegardee ok");
                    Ok(None)
                } else {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Mauvais type de reponse");
                Ok(Some(middleware.reponse_err(2, None, Some("Erreur sauvegarde cle"))?))
            }
        },
        None => {
            error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Timeout sur confirmation de sauvegarde");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}

async fn transmettre_cle_attachee_domaines<M>(middleware: &M, cle: Value)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public])
        .correlation_id(&message_cle.id)
        .timeout_blocking(5_000)
        .build();

    let type_message = TypeMessageOut::Commande(routage);
    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;

    debug!("transmettre_cle_attachee_domaines Emettre cle attachee, attendre reponse");

    let reponse = middleware.emettre_message(type_message, buffer_message).await?;

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("Cle sauvegardee ok");
                    Ok(None)
                } else {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Mauvais type de reponse");
                Ok(Some(middleware.reponse_err(2, None, Some("Erreur sauvegarde cle"))?))
            }
        },
        None => {
            error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Timeout sur confirmation de sauvegarde");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}

#[derive(Deserialize)]
struct CommandeGetJobKey {
    job_id: String,
    queue: String,
}

async fn commande_get_job_key<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media, RolesCertificats::SolrRelai])? {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let commande: CommandeGetJobKey = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let (collection_name, timeout) = match commande.queue.as_str() {
        "image" => (NOM_COLLECTION_IMAGES_JOBS, 180),
        "video" => (NOM_COLLECTION_VIDEO_JOBS, 600),
        "index" => (NOM_COLLECTION_INDEXATION_JOBS, 180),
        _ => return Ok(Some(middleware.reponse_err(Some(2), None, Some("Unsupported processing queue"))?))
    };

    let expired = Utc::now() - chrono::Duration::new(timeout, 0).expect("duration");

    let collection = middleware.get_collection_typed::<BackgroundJob>(collection_name)?;
    let filtre = doc! {
        "job_id": &commande.job_id,
        "$or": [
            {"etat": VIDEO_CONVERSION_ETAT_PENDING},
            {"etat": VIDEO_CONVERSION_ETAT_RUNNING, "date_maj": {"$lte": expired}},
        ]
    };
    let ops = doc! {
        "$set": {"etat": VIDEO_CONVERSION_ETAT_RUNNING},
        "$currentDate": {"date_maj": true, CHAMP_MODIFICATION: true}
    };
    let job = collection.find_one_and_update_with_session(filtre, ops, None, session).await?;

    match job {
        Some(inner) => {
            // Job exists. Request key from MaitreDesCles, redirect to requestor.
            let cle_id = inner.cle_id;
            let requete = RequeteDechiffrage {
                domaine: DOMAINE_NOM.to_string(),
                liste_hachage_bytes: None,
                cle_ids: Some(vec![cle_id]),
                certificat_rechiffrage: Some(m.certificat.chaine_pem()?),
                inclure_signature: None,
            };

            let (reply_q, correlation_id) = get_replyq_correlation!(m.type_message);

            let routage = RoutageMessageAction::builder(
                DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
            )
                .reply_to(reply_q)
                .correlation_id(correlation_id)
                .blocking(false)
                .build();

            middleware.transmettre_requete(routage, &requete).await?;

            Ok(None)  // The response is handled by MaitreDesCles
        },
        None => {
            Ok(Some(middleware.reponse_err(Some(1), None, Some("Unknown job"))?))
        }
    }
}

#[derive(Deserialize)]
pub struct CommandRecycleItemsV3 {
    tuuids: Vec<String>
}

async fn command_recycle_items_v3<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let command: CommandRecycleItemsV3 = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commandes.command_recycle_items_v3 User_id missing from certificate"))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        debug!("commandes.command_recycle_items_v3: Access denied {:?}", m.type_message);
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?));
    }

    // Ensure that all tuuids are delete directly (supprime_indirect == false) and that they
    // are part of a hierarchy that is not deleted.
    let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fuuids = Vec::new();
    let mut file_tuuids = Vec::new();
    let mut directory_tuuids = Vec::new();
    for tuuid in command.tuuids {
        let filtre = doc!{CHAMP_TUUID: &tuuid, CHAMP_USER_ID: &user_id};
        match collection.find_one_with_session(filtre, None, session).await? {
            Some(item) => {
                // To recycle a file/directory, it must have been deleted directly (supprime == true, supprime_indirect == false)
                if !(item.supprime == true && item.supprime_indirect == false) {
                    let message = format!("Item tuuid:{} not in proper state to recycle", tuuid);
                    debug!("commandes.command_recycle_items_v3 {}", message);
                    return Ok(Some(middleware.reponse_err(Some(1), None, Some(message.as_str()))?));
                }

                let type_node = match TypeNode::try_from(item.type_node.as_str()) {
                    Ok(inner) => inner,
                    Err(e) => {
                        let message = format!("Item tuuid:{} not a supported node type", item.type_node);
                        debug!("commandes.command_recycle_items_v3 {}", message);
                        return Ok(Some(middleware.reponse_err(Some(2), None, Some(message.as_str()))?));
                    }
                };

                match type_node {
                    TypeNode::Fichier => {
                        match item.fuuids_versions {
                            Some(fuuids_versions) => {
                                file_tuuids.push(tuuid.clone());
                                fuuids.extend(fuuids_versions);
                            }
                            None => {
                                let message = format!("File tuuid:{} has no fuuids", tuuid);
                                debug!("commandes.command_recycle_items_v3 {}", message);
                                return Ok(Some(middleware.reponse_err(Some(3), None, Some(message.as_str()))?));
                            }
                        }
                    }
                    _ => {directory_tuuids.push(tuuid.clone());}
                }

                // To recycle a file/directory, its hierarchy must not be deleted.
                if let Some(cuuids) = item.path_cuuids {
                    let filtre = doc!{
                        CHAMP_TUUID: {"$in": cuuids}, CHAMP_USER_ID: &user_id
                    };
                    let mut cursor = collection.find(filtre, None).await?;
                    while cursor.advance().await? {
                        let row = cursor.deserialize_current()?;
                        if row.supprime {
                            let message = format!("File tuuid:{} is under a deleted path", tuuid);
                            debug!("commandes.command_recycle_items_v3 {}", message);
                            return Ok(Some(middleware.reponse_err(Some(4), None, Some(message.as_str()))?));
                        }
                    }
                };
            },
            None => {
                let message = format!("Item tuuid:{} not found", tuuid);
                debug!("commandes.command_recycle_items_v3 {}", message);
                return Ok(Some(middleware.reponse_err(Some(5), None, Some(message.as_str()))?));
            }
        }
    }

    let type_node_fichier: &str = TypeNode::Fichier.into();
    let type_node_directory: &str = TypeNode::Repertoire.into();
    let type_node_collection: &str = TypeNode::Collection.into();

    // Make a list of all fuuids indirectly deleted under directories to restore.
    let fuuids_claims = claim_files_under_cuuids(middleware, session, &user_id, &directory_tuuids).await?;
    fuuids.extend(fuuids_claims);

    // List all subdirectories with supprime_indirect == true.
    let filtre = doc!{
        CHAMP_PATH_CUUIDS: {"$in": &directory_tuuids},
        CHAMP_TYPE_NODE: {"$in": vec![type_node_directory, type_node_collection]},
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: true,
        CHAMP_SUPPRIME_INDIRECT: true,
    };
    let mut cursor = collection.find(filtre, None).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        directory_tuuids.push(row.tuuid);
    }

    // Build the Recycle transaction
    let mut original_command = m.message.parse_to_owned()?;
    original_command.certificat = None;
    let transaction = TransactionRecycleItemsV3 {
        command: original_command,
        user_id: user_id.clone(),
        file_tuuids,
        directory_tuuids,
    };

    debug!("command_recycle_items_v3 Transaction\n{}", serde_json::to_string(&transaction)?);

    sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_RECYCLE_ITEMS_V3).await?;

    // Commit, DB work is done. Only external events left to do (not a big deal if they fail).
    session.commit_transaction().await?;
    start_transaction_regular(session).await?;

    debug!("command_recycle_items_v3 Post transaction cleanup");
    // Emit recycle events for each file by cuuid.
    {
        let mut files_by_cuuid = HashMap::new();
        let filtre = doc! {
            CHAMP_TUUID: {"$in": &transaction.file_tuuids},
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
            CHAMP_TYPE_NODE: type_node_fichier,
        };
        let mut cursor = collection.find_with_session(filtre, None, session).await?;
        while cursor.advance(session).await? {
            let row = cursor.deserialize_current()?;
            let cuuid = match row.path_cuuids {
                Some(mut path_cuuids) => {
                    match path_cuuids.first() {
                        Some(inner) => inner.to_owned(),
                        None => user_id.clone(),
                    }
                }
                None => user_id.clone()
            };
            let list = match files_by_cuuid.get_mut(&cuuid) {
                Some(list) => list,
                None => {
                    files_by_cuuid.insert(cuuid.clone(), Vec::new());
                    files_by_cuuid.get_mut(&cuuid).unwrap()
                },
            };
            list.push(row.tuuid);
        }

        for (cuuid, files) in files_by_cuuid {
            let mut evenement = EvenementContenuCollection::new(cuuid);
            evenement.fichiers_ajoutes = Some(files);
            emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
        }
    }

    if transaction.directory_tuuids.len() > 0 {
        // List all immediate files/subdirectories
        let filtre = doc! {
            CHAMP_TUUID: {"$in": &transaction.directory_tuuids},
            format!("{}.0", CHAMP_PATH_CUUIDS): {"$exists": false},
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
        };
        let mut tuuids_collection = Vec::new();
        let mut cursor = collection.find_with_session(filtre, None, session).await?;
        while cursor.advance(session).await? {
            let row = cursor.deserialize_current()?;
            tuuids_collection.push(row.tuuid);
        }
        if tuuids_collection.len() > 0 {
            let mut evenement = EvenementContenuCollection::new(user_id.clone());
            evenement.collections_modifiees = Some(tuuids_collection);
            emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
        }
    }

    // Emit event for each recycled directory
    for cuuid in transaction.directory_tuuids.into_iter() {
        let mut evenement = EvenementContenuCollection::new(cuuid.clone());
        let mut fichiers_ajoutes = Vec::new();
        let mut collections_ajoutees = Vec::new();

        // List all immediate files/subdirectories
        let filtre = doc!{
            format!("{}.0", CHAMP_PATH_CUUIDS): &cuuid,
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
        };
        let mut cursor = collection.find_with_session(filtre, None, session).await?;
        while cursor.advance(session).await? {
            let row = cursor.deserialize_current()?;
            let type_node = TypeNode::try_from(row.type_node.as_str())?;
            match type_node {
                TypeNode::Fichier => fichiers_ajoutes.push(row.tuuid),
                _ => collections_ajoutees.push(row.tuuid),
            }
        }

        evenement.fichiers_ajoutes = Some(fichiers_ajoutes);
        evenement.collections_ajoutees = Some(collections_ajoutees);

        // Update the directory itself (deleted flags)
        emettre_evenement_maj_collection(middleware, gestionnaire, cuuid, &user_id, session).await?;

        // Update content (files and sub-directories)
        emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn claim_files_under_cuuids<M,S>(middleware: &M, session: &mut ClientSession, user_id: &String, directory_tuuids: &[S])
    -> Result<Vec<String>, CommonError>
    where M: GenerateurMessages + MongoDao, S: AsRef<str>
{
    let directory_tuuids: Vec<&str> = directory_tuuids.iter().map(|s| s.as_ref()).collect();
    let type_node_fichier: &str = TypeNode::Fichier.to_str();

    let mut fuuids = HashSet::new();

    let collection =
        middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;

    let filtre = doc! {
        CHAMP_PATH_CUUIDS: {"$in": &directory_tuuids},
        CHAMP_USER_ID: &user_id,
        CHAMP_TYPE_NODE: type_node_fichier,
        CHAMP_SUPPRIME: true,
        CHAMP_SUPPRIME_INDIRECT: true,
    };
    let mut cursor = collection.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if let Some(fuuids_versions) = row.fuuids_versions {
            fuuids.extend(fuuids_versions);
        }
    }

    // Issue a claim command for all fuuids to restore to CoreTopologie. Ensure none have been deleted.
    let fuuids: Vec<String> = fuuids.into_iter().collect();
    for fuuid_batch in fuuids.chunks(100) {
        debug!("Check batch of fuuids to restore: {:?}", fuuid_batch);
        claim_files_by_fuuids(middleware, fuuid_batch).await?;
    }

    Ok(fuuids)
}

async fn claim_files<M>(middleware: &M, session: &mut ClientSession, user_id: &str, tuuid_batch: &[String]) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao
{
    let mut fuuids = HashSet::new();

    let collection =
        middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;

    let filtre = doc! {
        CHAMP_TUUID: {"$in": &tuuid_batch},
        CHAMP_USER_ID: user_id,
    };
    let mut cursor = collection.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let row = cursor.deserialize_current()?;
        if let Some(fuuids_versions) = row.fuuids_versions {
            fuuids.extend(fuuids_versions);
        }
    }

    let fuuids: Vec<String> = fuuids.into_iter().collect();
    claim_files_by_fuuids(middleware, &fuuids).await?;

    Ok(())
}

async fn claim_files_by_fuuids<M>(middleware: &M, fuuid_batch: &[String]) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao
{
    match verifier_visites_topologies(middleware, fuuid_batch).await {
        Ok(response) => {
            if response.ok != true {
                Err(format!("commandes.command_recycle_items_v3 Error verifying presence of files - server error: {:?}", response.err))?
            }
            // Claim completed. This will prevent the files from being deleted for a while.
            // Check that all files were found. Fail if at least 1 file was already permanently deleted.
            debug!("Batch size: {}", fuuid_batch.len());
            if let Some(v) = response.visits {
                debug!("Response visits: {}", v.len());
                if v.len() < fuuid_batch.len() {
                    Err(format!("commandes.command_recycle_items_v3 Error verifying presence of files (A) - some files have been permanently deleted: {:?}", response.err))?
                }
            }
            if let Some(unknown) = response.unknown {
                debug!("Response unknown: {}", unknown.len());
                if unknown.len() > 0 {
                    Err(format!("commandes.command_recycle_items_v3 Error verifying presence of files (B) - some files have been permanently deleted: {:?}", response.err))?;
                }
            }
        }
        Err(e) => {
            Err(format!("commandes.command_recycle_items_v3 Error verifying presence of files - timeout or other issue: {:?}", e))?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct VisitWorkRow {
    fuuid: String,
    filehost_id: Option<String>,
    #[serde(with="opt_chrono_datetime_as_bson_datetime")]
    visit_time: Option<DateTime<Utc>>,
}

async fn command_receive_visits<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    if ! m.certificat.verifier_domaines(vec![DOMAINE_TOPOLOGIE.to_string()])? {
        Err("command_receive_visits Domain is not CoreTopologie, ignoring")?;
    }

    let collection = middleware.get_collection(NOM_COLLECTION_TEMP_VISITS)?;
    let command: RequeteGetVisitesFuuidsResponse = deser_message_buffer!(m.message);
    if let Some(visits) = command.visits {
        debug!("Received {} visit entries", visits.len());
        let mut batch = Vec::with_capacity(visits.len());
        for visit in visits {
            for (filehost_id, timestamp) in visit.visits {
                let visit_date = DateTime::from_timestamp(timestamp, 0).expect("visit_date from_timestamp");
                let row = VisitWorkRow { fuuid: visit.fuuid.clone(), filehost_id: Some(filehost_id), visit_time: Some(visit_date) };
                batch.push(convertir_to_bson(row)?);
            }
        }
        if ! batch.is_empty() {
            collection.insert_many(batch, None).await?;
        }
    }

    if let Some(unknowns) = command.unknown {
        debug!("Received {} unknwown fuuid claims responses", unknowns.len());
        let mut batch = Vec::with_capacity(unknowns.len());
        for fuuid in unknowns {
            let row = VisitWorkRow { fuuid, filehost_id: None, visit_time: None };
            batch.push(convertir_to_bson(row)?);
        }
        if ! batch.is_empty() {
            collection.insert_many(batch, None).await?;
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}
