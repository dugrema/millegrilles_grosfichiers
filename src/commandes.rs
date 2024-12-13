use std::collections::{HashMap, HashSet};
use std::iter::Map;
use std::str::from_utf8;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{chrono, get_replyq_correlation, serde_json, serde_json::json};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::{DateTime, Utc};
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
use crate::domain_manager::GrosFichiersDomainManager;
use crate::evenements::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, evenement_fichiers_syncpret, EvenementContenuCollection};

use crate::grosfichiers_constantes::*;
use crate::requetes::{ContactRow, mapper_fichier_db, verifier_acces_usager, verifier_acces_usager_tuuids};
use crate::traitement_index::{reset_flag_indexe, sauvegarder_job_index, set_flag_index_traite};
use crate::traitement_jobs::{BackgroundJob, BackgroundJobParams, JobHandler, JobHandlerVersions, ParametresConfirmerJobIndexation};
use crate::traitement_media::{commande_supprimer_job_image, commande_supprimer_job_image_v2, commande_supprimer_job_video, commande_supprimer_job_video_v2, sauvegarder_job_images, sauvegarder_job_video, set_flag_image_traitee, set_flag_video_traite};
use crate::transactions::*;

const REQUETE_MAITREDESCLES_VERIFIER_PREUVE: &str = "verifierPreuve";

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.type_message);

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
        TRANSACTION_DECRIRE_FICHIER => commande_decrire_fichier(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_DECRIRE_COLLECTION => commande_decrire_collection(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_VIDEO => commande_supprimer_video(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_SUPPRIMER_ORPHELINS => commande_supprimer_orphelins(middleware, m, gestionnaire, &mut session).await,

        // Sync
        COMMANDE_RECLAMER_FUUIDS => evenement_fichiers_syncpret(middleware, m, &mut session).await,

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
        let fichier_rep = match NodeFichierRepOwned::from_nouvelle_version(
            middleware, &commande, uuid_transaction, &user_id, session).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierRepOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
        };
        let tuuid = fichier_rep.tuuid.clone();
        let fichier_version = match NodeFichierVersionOwned::from_nouvelle_version(
            &commande, &tuuid, &user_id).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
        };

        let fuuid = fichier_version.fuuid.as_str();
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
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        let tuuids = vec![&commande.tuuid];
        let resultat = verifier_autorisation_usager(middleware, user_id.as_str(), Some(&tuuids), None::<String>).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let (changement_media, fuuid) = match commande.mimetype.as_ref() {
        Some(mimetype) => {
            debug!("commande_decrire_fichier Verifier si le mimetype du fichier a change (nouveau: {})", mimetype);
            let filtre = doc!{CHAMP_TUUID: &commande.tuuid, CHAMP_USER_ID: &user_id};
            let collection = middleware.get_collection_typed::<NodeFichierRepVersionCouranteOwned>(
                NOM_COLLECTION_FICHIERS_REP)?;
            if let Some(fichier) = collection.find_one_with_session(filtre, None, session).await? {
                if fichier.mimetype != commande.mimetype {
                    debug!("commande_decrire_fichier Le mimetype a change de {:?} vers {:?}, reset traitement media de {}", fichier.mimetype, commande.mimetype, commande.tuuid);
                    match fichier.fuuids_versions {
                        Some(mut inner) => {
                            if let Some(fuuid) = inner.pop() {
                                (true, Some(fuuid))
                            } else {
                                (false, None)
                            }
                        },
                        None => (false, None)
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        },
        None => (false, None),
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

    if changement_media {
        if let Some(mimetype) = commande.mimetype.as_ref() {
            if fuuid.is_some() {
                // Ajouter flags media au fichier si approprie
                let (flag_media_traite, flag_video_traite, flag_media) = NodeFichierVersionOwned::get_flags_media(
                    mimetype.as_str());
                let filtre = doc! {CHAMP_TUUID: &commande.tuuid, CHAMP_USER_ID: &user_id};
                let ops = doc! {
                    "$set": {
                        CHAMP_FLAG_MEDIA: flag_media,
                        CHAMP_FLAG_MEDIA_TRAITE: flag_media_traite,
                        CHAMP_FLAG_VIDEO_TRAITE: flag_video_traite,
                    },
                    "$currentDate": {CHAMP_MODIFICATION: true}
                };
                debug!("commande_decrire_fichier Reset flags media sur changement mimetype pour {} : {:?}", commande.tuuid, ops);
                let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(
                    NOM_COLLECTION_VERSIONS)?;
                let fichier_version = match collection.find_one_and_update_with_session(filtre.clone(), ops, None, session).await? {
                    Some(inner) => inner,
                    None => Err(CommonError::Str("commande_decrire_fichier Erreur maj fichier, non trouve"))?
                };

                let cle_id = match fichier_version.cle_id {
                    Some(inner) => inner,
                    None => fichier_version.fuuid
                };

                let mut champs_cles = HashMap::new();
                champs_cles.insert("tuuid".to_string(), commande.tuuid.clone());
                champs_cles.insert("mimetype".to_string(), mimetype.to_owned());

                let mut champs_parametres = HashMap::new();
                champs_parametres.insert("cle_id".to_string(), Bson::String(cle_id.to_string()));
            } else {
                warn!("commande_decrire_fichier Erreur utilisation fuuid sur changement (None)");
            }
        } else {
            warn!("commande_decrire_fichier Erreur utilisation mimetype sur changement (None)");
        }
    }

    // Declencher indexation
    let tuuid = &commande.tuuid;
    if let Some(fuuid) = fuuid.as_ref() {
        let filtre = doc!{CHAMP_TUUID: &commande.tuuid, CHAMP_USER_ID: &user_id};
        let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
        if let Some(fichier) = collection.find_one_with_session(filtre, None, session).await? {
            if fichier.cle_id.is_some() && fichier.format.is_some() && fichier.nonce.is_some() {
                let cle_id = fichier.cle_id.expect("cle_id");
                let format: &str = fichier.format.expect("format").into();
                let nonce = fichier.nonce.expect("nonce");
                let mimetype = fichier.mimetype;
                let filehost_ids: Vec<&String> = fichier.visites.keys().collect();
                let job = BackgroundJob::new_index(tuuid, Some(fuuid), user_id, mimetype, &filehost_ids, cle_id, format, nonce);
                sauvegarder_job_index(middleware, &job, session).await?;
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
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
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
    if user_id.is_some() && metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
        let user_id = user_id.as_ref().expect("user_id");
        let cle_id = metadata.cle_id.expect("cle_id");
        let format = metadata.format.expect("format");
        let nonce = metadata.nonce.expect("nonce");
        let filehost_ids: Vec<&str> = Vec::new();
        let job = BackgroundJob::new_index(tuuid, None::<&str>, user_id, "", &filehost_ids, cle_id, format, nonce);
        sauvegarder_job_index(middleware, &job, session).await?;
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid, session).await?;
    {
        // let mut evenement_contenu = EvenementContenuCollection::new();
        let mut evenement_contenu = match cuuid.as_ref() {
            Some(cuuid) => Ok(EvenementContenuCollection::new(cuuid.clone())),
            None => match user_id {
                Some(inner) => Ok(EvenementContenuCollection::new(inner.clone())),
                None => Err(format!("cuuid et user_id sont None, erreur event emettre_evenement_contenu_collection"))
            }
        };
        match evenement_contenu {
            Ok(mut inner) => {
                inner.collections_ajoutees = Some(vec![tuuid.clone()]);
                emettre_evenement_contenu_collection(middleware, gestionnaire, inner).await?;
            },
            Err(e) => error!("transaction_nouvelle_collection {}", e)
        }
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
    debug!("Commande commande_associer_conversions versions parsed : {:?}", commande);

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
        // while let Some(row) = curseur_docs.next().await {
        //     let row = row?;
        //     // let tuuid_doc = d_result.get_str("tuuid")?;
        //     tuuids_set.remove(row.tuuid);
        //     let type_node = TypeNode::try_from(row.type_node)?;
        //     match type_node {
        //         TypeNode::Fichier => {
        //             reponse.tuuids_fichiers.push(row.tuuid.to_owned());
        //         },
        //         TypeNode::Collection | TypeNode::Repertoire => {
        //             reponse.tuuids_repertoires.push(row.tuuid.to_owned());
        //         }
        //     }
        // }

        if tuuids_set.len() > 0 {
            // Certains tuuids n'appartiennent pas a l'usager
            // let cuuids: Vec<String> = tuuids_set.into_iter().map(|c| c.to_owned()).collect();
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

async fn commande_ajouter_fichiers_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_ajouter_fichiers_collection Consommer commande : {:?}", & m.type_message);
    let commande: TransactionAjouterFichiersCollection = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // let commande: TransactionAjouterFichiersCollection = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_ajouter_fichiers_collection versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if let Some(contact_id) = commande.contact_id.as_ref() {
        debug!("Verifier que le contact_id est valide (correspond aux tuuids)");
        let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
        let filtre = doc!{CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: user_id.as_ref()};
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
    } else if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let cuuid = commande.cuuid.as_str();
        let tuuids: Vec<&str> = commande.inclure_tuuids.iter().map(|t| t.as_str()).collect();
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&tuuids), Some(cuuid)).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

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
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
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
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Traiter la transaction
    let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

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

#[derive(Serialize)]
struct CommandeSupprimerTuuidsIndex {
    tuuids: Vec<String>
}

async fn commande_supprimer_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_documents Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerDocuments = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // let commande: TransactionSupprimerDocuments = m.message.get_msg().map_contenu()?;
    debug!("Commande commande_supprimer_documents versions parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let mut tuuids: Vec<&str> = commande.tuuids.iter().map(|t| t.as_str()).collect();
        if let Some(t) = commande.cuuid.as_ref() {
            if t != "" {
                tuuids.push(t.as_str());
            }
        }
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

    let routage = RoutageMessageAction::builder("solrrelai", "supprimerTuuids", vec![Securite::L3Protege])
        .timeout_blocking(1_500)
        .build();
    let commande_index = CommandeSupprimerTuuidsIndex { tuuids: commande.tuuids.clone() };
    match middleware.transmettre_commande(routage.clone(), commande_index).await? {
        Some(result) => {
            if ! verifier_reponse_ok(&result) {
                warn!("Erreur suppression tuuids:{:?} de l'index (err solr) : {:?}", commande.tuuids, result);
            }
        },
        None => warn!("Erreur suppression tuuids:{:?} de l'index - aucune reponse", commande.tuuids)
    }

    // TODO - mettre evenements ici (liste generee dans transaction)
    // debug!("transaction_supprimer_documents Emettre messages pour tuuids retires : {:?}", tuuids_retires_par_cuuid);
    //
    // // Emettre evenements supprime par cuuid
    // for (cuuid, liste) in tuuids_retires_par_cuuid {
    //     let mut evenement = EvenementContenuCollection::new(cuuid);
    //     evenement.retires = Some(liste);
    //     emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
    // }

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
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
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
        if user_id.is_some() && metadata.cle_id.is_some() && metadata.format.is_some() && metadata.nonce.is_some() {
            let user_id = user_id.as_ref().expect("user_id");
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
                            if let Some(u) = user_id {
                                if favoris {
                                    let mut evenement = EvenementContenuCollection::new(u);
                                    // evenement.cuuid = Some(u);
                                    evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                    emettre_evenement_contenu_collection(middleware, gestionnaire, evenement).await?;
                                }
                            }
                        }
                        if let Some(cuuids) = fichier.cuuids {
                            for cuuid in cuuids {
                                let mut evenement = EvenementContenuCollection::new(cuuid);
                                // evenement.cuuid = Some(cuuid);
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
    emettre_evenement_maj_collection(middleware, gestionnaire, &tuuid, session).await?;

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
            doc! {CHAMP_USER_ID: &user_id, CHAMP_FUUID: {"$in": fuuids}}
        },
        None => {
            warn!("commande_completer_previews Aucuns fuuids, pas d'effet.");
            // let reponse = middleware.formatter_reponse(json!({"ok": true, "message": "Aucun effet (pas de fuuids fournis)"}), None)?;
            // return Ok(Some(reponse))
            return Ok(Some(middleware.reponse_err(None, None, Some("Aucun effet (pas de fuuids fournis)"))?))
        }
    };

    let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection.find_with_session(filtre, None, session).await?;
    while curseur.advance(session).await? {
        let fichier_version = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                error!("commande_completer_previews Erreur mapping fichier version, SKIP");
                continue
            }
        };

        let tuuid = fichier_version.tuuid;
        let fuuid = fichier_version.fuuid;
        let mimetype= fichier_version.mimetype;

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
    visites: Option<HashMap<String, i64>>,
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

    let filtre_fichier = doc! { CHAMP_TUUID: &tuuid, CHAMP_FUUID: fuuid, CHAMP_USER_ID: &user_id };
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

    match version_courante.video {
        Some(v) => {
            match v.get(cle_video.as_str()) { // Verifier si le video existe deja
                Some(v) => {
                    info!("commande_video_convertir Fichier video existe deja {} pour {}", cle_video, fuuid);
                    return Ok(Some(middleware.reponse_err(Some(409), None, Some("Video dans ce format existe deja"))?))
                },
                None => ()  // Ok, le video n'existe pas
            }
        },
        None => ()  // Ok, aucuns videos existant
    };

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

    // let insert_ops = doc! {
    //     "tuuid": &commande.tuuid,
    //     CHAMP_FUUID: fuuid,
    //     CHAMP_USER_ID: &user_id,
    //     CHAMP_MIMETYPE: commande.mimetype,
    //     "codecVideo": commande.codec_video,
    //     "codecAudio": commande.codec_audio,
    //     "qualityVideo": commande.quality_video,
    //     "resolutionVideo": commande.resolution_video,
    //     "bitrateVideo": commande.bitrate_video,
    //     "bitrateAudio": commande.bitrate_audio,
    //     "preset": commande.preset,
    //     "etat": 1,  // Pending
    // };
    // let set_ops = doc! {
    //     CHAMP_FLAG_DB_RETRY: 0,  // Reset le retry count automatique
    // };
    // let ops = doc! {
    //     "$set": set_ops,
    //     "$setOnInsert": insert_ops,
    //     "$currentDate": {CHAMP_MODIFICATION: true},
    // };
    // let filtre_video = doc! {CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video};
    // let collection_video = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    // let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    // let emettre_job = match collection_video.find_one_and_update(filtre_video, ops, options).await? {
    //     Some(d) => {
    //         debug!("commande_video_convertir Etat precedent : {:?}", d);
    //         // Verifier l'etat du document precedent (e.g. pending, erreur, en cours, etc)
    //
    //         true  // Emettre la job
    //     },
    //     None => true  // Nouvelle entree, emettre la nouvelle job.
    // };

    // if emettre_job {
    //     // Faire la liste des consignations avec le fichier disponible
    //     let consignation_disponible: Vec<&String> = version_courante.visites.keys().into_iter().collect();
    //
    //     for consignation in consignation_disponible {
    //         let routage = RoutageMessageAction::builder(DOMAINE_MEDIA_NOM, COMMANDE_VIDEO_DISPONIBLE, vec![Securite::L2Prive])
    //             .partition(consignation)
    //             .blocking(false)
    //             .build();
    //         let commande_fichiers = json!({CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video});
    //         middleware.transmettre_commande(routage, &commande_fichiers).await?;
    //     }
    //
    //     // Emettre evenement pour clients
    //     let evenement = json!({
    //         CHAMP_CLE_CONVERSION: &cle_video,
    //         CHAMP_FUUID: fuuid,
    //         "tuuid": &commande.tuuid,
    //     });
    //     let routage = RoutageMessageAction::builder(DOMAINE_NOM, "jobAjoutee", vec![Securite::L2Prive])
    //         .partition(&user_id)
    //         .build();
    //     middleware.emettre_evenement(routage, &evenement).await?;
    // }
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
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

    let fuuid = &commande.fuuid_video;
    let user_id = m.certificat.get_user_id()?;

    {   // Verifier acces
        let delegation_globale = m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
        if delegation_globale || m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
            // Ok
        } else if user_id.is_some() {
            let u = user_id.as_ref().expect("commande_video_convertir user_id");
            let resultat = verifier_acces_usager(middleware, &u, vec![fuuid]).await?;
            if ! resultat.contains(fuuid) {
                debug!("commande_video_convertir verifier_exchanges : Usager n'a pas acces a fuuid {}", fuuid);;
                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
                return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
            }
        } else {
            debug!("commande_video_convertir verifier_exchanges : Certificat n'a pas l'acces requis (securite 2,3,4 ou user_id avec acces fuuid)");
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
        }
    }

    let filtre_fichier = doc!{CHAMP_FUUIDS: fuuid, CHAMP_USER_ID: user_id.as_ref()};
    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let result = collection.count_documents_with_session(filtre_fichier, None, session).await?;

    if result > 0 {
        // Recuperer information - utilisee pour emettre evenement apres transactions
        let filtre = doc!{CHAMP_FUUIDS: fuuid, CHAMP_USER_ID: user_id.as_ref()};
        let collection_fichier_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
        let doc_video = match collection_fichier_versions.find_one(filtre.clone(), None).await {
            Ok(d) => match d {
                Some(d) => d,
                None => Err(format!("transaction_supprimer_video Erreur chargement info document, aucun match"))?
            },
            Err(e) => Err(format!("transaction_supprimer_video Erreur chargement info document : {:?}", e))?
        };

        // Traiter la transaction
        let response = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;

        // Emettre fichier pour que tous les clients recoivent la mise a jour
        let tuuid = doc_video.tuuid;
        if let Err(e) = emettre_evenement_maj_fichier(middleware, gestionnaire, &tuuid, EVENEMENT_FUUID_ASSOCIER_VIDEO, session).await {
            warn!("transaction_favoris_creerpath Erreur emettre_evenement_maj_fichier : {:?}", e);
        }

        Ok(response)
    } else {
        Ok(Some(middleware.reponse_ok(None, None)?))
    }
}

#[derive(Clone, Debug, Deserialize)]
struct CommandeAjouterContactLocal {
    nom_usager: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ReponseChargerUserIdParNomUsager {
    usagers: Option<HashMap<String, Option<String>>>
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

    // Convertir en transaction
    let transaction = TransactionAjouterContactLocal { user_id, contact_user_id: user_contact_id };

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_AJOUTER_CONTACT_LOCAL).await?.0)
    // Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

    let resultat = trouver_orphelins_supprimer(middleware, &commande, session).await?;
    debug!("commande_supprimer_orphelins Versions supprimees : {:?}, fuuids a conserver : {:?}",
        resultat.versions_supprimees, resultat.fuuids_a_conserver);

    let mut fuuids_supprimes = 0;
    for (fuuid, supprime) in &resultat.versions_supprimees {
        if *supprime { fuuids_supprimes += 1; };
    }

    // Determiner si on repond immediatement ou si on procede vers la transaction
    if fuuids_supprimes > 0 {
        // On execute la transaction pour supprimer les fichiers dans la base de donnes
        debug!("commande_supprimer_orphelins Au moins une version supprimer (count: {}), executer la transaction", fuuids_supprimes);
        sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?;
    }

    let reponse = ReponseSupprimerOrphelins { ok: true, err: None, fuuids_a_conserver: resultat.fuuids_a_conserver };
    Ok(Some(middleware.build_reponse(reponse)?.0))
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
