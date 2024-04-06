use std::collections::{HashMap, HashSet};
use std::iter::Map;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L4Secure};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;

use crate::evenements::evenement_fichiers_syncpret;

use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, EvenementContenuCollection, GestionnaireGrosFichiers};
use crate::grosfichiers_constantes::*;
use crate::requetes::{ContactRow, mapper_fichier_db, verifier_acces_usager, verifier_acces_usager_tuuids};
use crate::traitement_index::{commande_indexation_get_job, reset_flag_indexe};
use crate::traitement_jobs::{CommandeGetJob, JobHandler, JobHandlerFichiersRep, JobHandlerVersions, ParametresConfirmerJobIndexation, ReponseJob};
use crate::traitement_media::{commande_supprimer_job_image, commande_supprimer_job_video};
use crate::transactions::*;

const REQUETE_MAITREDESCLES_VERIFIER_PREUVE: &str = "verifierPreuve";

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.type_message);

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

    match action.as_str() {
        // Commandes standard
        TRANSACTION_NOUVELLE_VERSION => commande_nouvelle_version(middleware, m, gestionnaire).await,
        TRANSACTION_NOUVELLE_COLLECTION => commande_nouvelle_collection(middleware, m, gestionnaire).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => commande_associer_conversions(middleware, m, gestionnaire).await,
        TRANSACTION_ASSOCIER_VIDEO => commande_associer_video(middleware, m, gestionnaire).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => commande_ajouter_fichiers_collection(middleware, m, gestionnaire).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => commande_deplacer_fichiers_collection(middleware, m, gestionnaire).await,
        // TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => commande_retirer_documents_collection(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => commande_supprimer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENTS => commande_recuperer_documents(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENTS_V2 => commande_recuperer_documents_v2(middleware, m, gestionnaire).await,
        TRANSACTION_ARCHIVER_DOCUMENTS => commande_archiver_documents(middleware, m, gestionnaire).await,
        // TRANSACTION_CHANGER_FAVORIS => commande_changer_favoris(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_FICHIER => commande_decrire_fichier(middleware, m, gestionnaire).await,
        TRANSACTION_DECRIRE_COLLECTION => commande_decrire_collection(middleware, m, gestionnaire).await,
        // TRANSACTION_COPIER_FICHIER_TIERS => commande_copier_fichier_tiers(middleware, m, gestionnaire).await,
        // TRANSACTION_FAVORIS_CREERPATH => commande_favoris_creerpath(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_VIDEO => commande_supprimer_video(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_ORPHELINS => commande_supprimer_orphelins(middleware, m, gestionnaire).await,

        // Sync
        COMMANDE_RECLAMER_FUUIDS => evenement_fichiers_syncpret(middleware, m).await,

        COMMANDE_COMPLETER_PREVIEWS => commande_completer_previews(middleware, m, gestionnaire).await,
        COMMANDE_NOUVEAU_FICHIER => commande_nouveau_fichier(middleware, m, gestionnaire).await,
        // COMMANDE_GET_CLE_JOB_CONVERSION => commande_get_cle_job_conversion(middleware, m, gestionnaire).await,

        COMMANDE_IMAGE_GET_JOB => commande_image_get_job(middleware, m, gestionnaire).await,
        TRANSACTION_IMAGE_SUPPRIMER_JOB => commande_supprimer_job_image(middleware, m, gestionnaire).await,

        // Video
        COMMANDE_VIDEO_TRANSCODER => commande_video_convertir(middleware, m, gestionnaire).await,
        // COMMANDE_VIDEO_ARRETER_CONVERSION => commande_video_arreter_conversion(middleware, m, gestionnaire).await,
        COMMANDE_VIDEO_GET_JOB => commande_video_get_job(middleware, m, gestionnaire).await,
        TRANSACTION_VIDEO_SUPPRIMER_JOB => commande_supprimer_job_video(middleware, m, gestionnaire).await,

        // Indexation
        COMMANDE_REINDEXER => commande_reindexer(middleware, m, gestionnaire).await,
        COMMANDE_INDEXATION_GET_JOB => commande_indexation_get_job(middleware, m, gestionnaire).await,
        TRANSACTION_CONFIRMER_FICHIER_INDEXE => commande_confirmer_fichier_indexe(middleware, m, gestionnaire).await,

        // Partage de collections
        TRANSACTION_AJOUTER_CONTACT_LOCAL => commande_ajouter_contact_local(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_CONTACTS => commande_supprimer_contacts(middleware, m, gestionnaire).await,
        TRANSACTION_PARTAGER_COLLECTIONS => commande_partager_collections(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_PARTAGE_USAGER => commande_supprimer_partage_usager(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    }
}

async fn commande_nouvelle_version<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let mut message_owned = m.message.parse_to_owned()?;
    let uuid_transaction = message_owned.id.as_str();
    debug!("commande_nouvelle_version Consommer commande : {:?}", & m.type_message);
    let commande: TransactionNouvelleVersion = message_owned.deserialize()?;

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
    {
        let fichier_rep = match NodeFichierRepOwned::from_nouvelle_version(
            middleware, &commande, uuid_transaction, &user_id).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierRepOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
        };
        let tuuid = fichier_rep.tuuid.clone();
        let fichier_version = match NodeFichierVersionOwned::from_nouvelle_version(
            &commande, &tuuid, &user_id).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("grosfichiers.NodeFichierVersionOwned.transaction_nouvelle_version Erreur from_nouvelle_version : {:?}", e))?
        };
    }

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
                // return Ok(Some(middleware.build_reponse(json!({"ok": false, "err": "Cle manquante"}))?.0));
            }
        },
        None => {
            error!("Cle de nouvelle version manquante (2)");
            return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?));
            // return Ok(Some(middleware.build_reponse(json!({"ok": false, "err": "Cle manquante"}))?.0));
        }
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_decrire_fichier<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
            if let Some(fichier) = collection.find_one(filtre, None).await? {
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
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    if changement_media {
        if let Some(mimetype) = commande.mimetype.as_ref() {
            if let Some(fuuid) = fuuid {
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
                let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
                collection.update_one(filtre.clone(), ops, None).await?;

                let mut champs_cles = HashMap::new();
                champs_cles.insert("tuuid".to_string(), commande.tuuid.clone());
                champs_cles.insert("mimetype".to_string(), mimetype.to_owned());

                // Creer jobs de conversion
                if flag_media_traite == false {
                    if let Err(e) = gestionnaire.image_job_handler.sauvegarder_job(
                        middleware, &fuuid, &user_id, None,
                        Some(champs_cles.clone()), None, true).await {
                        error!("commande_decrire_fichier Erreur image sauvegarder_job : {:?}", e);
                    }
                }

                if flag_video_traite == false {
                    if let Err(e) = gestionnaire.video_job_handler.sauvegarder_job(
                        middleware, fuuid, user_id, None,
                        Some(champs_cles), None, false).await {
                        error!("commande_decrire_fichier Erreur video sauvegarder_job : {:?}", e);
                    }
                }
            } else {
                warn!("commande_decrire_fichier Erreur utilisation fuuid sur changement (None)");
            }
        } else {
            warn!("commande_decrire_fichier Erreur utilisation mimetype sur changement (None)");
        }
    }

    Ok(resultat)
}

async fn commande_nouvelle_collection<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_nouvelle_collection Consommer commande : {:?}", & m.type_message);
    let mut message_owned = m.message.parse_to_owned()?;
    let commande: TransactionNouvelleCollection = message_owned.deserialize()?;
    debug!("Commande commande_nouvelle_collection versions parsed : {:?}", commande);

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
                if let Some(reponse) = transmettre_cle_attachee(middleware, cle).await? {
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
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_associer_conversions<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

    if commande.user_id.is_none() {
        Err(format!("grosfichiers.commande_associer_conversions: User_id obligatoire depuis version 2023.6 {:?}", m.type_message))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_associer_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

async fn commande_ajouter_fichiers_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
        let contact = match collection.find_one(filtre, None).await? {
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
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_deplacer_fichiers_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_retirer_documents_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

async fn commande_supprimer_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

#[derive(Clone, Debug, Deserialize)]
struct RowFuuids {
    fuuids: Option<Vec<String>>
}

async fn commande_recuperer_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
    let mut curseur = collection.find(filtre, Some(options)).await?;
    while let Some(r) = curseur.next().await {
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
                    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

async fn commande_recuperer_documents_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
        return Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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
                    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

async fn commande_archiver_documents<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_archiver_documents Consommer commande : {:?}", & m.type_message);
    let commande: TransactionListeDocuments = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

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
        Err(format!("commandes.commande_archiver_documents: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_changer_favoris<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_changer_favoris Consommer commande : {:?}", & m.type_message);
    let commande: TransactionChangerFavoris = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        let user_id_str = user_id.as_ref().expect("user_id");
        let keys: Vec<String> = commande.favoris.keys().cloned().collect();
        let resultat = verifier_autorisation_usager(middleware, user_id_str, Some(&keys), None::<String>).await?;
        if let Some(erreur) = resultat.erreur {
            return Ok(Some(erreur.try_into()?))
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_decrire_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
        let tuuids = vec![commande.tuuid];
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
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

// commande_copier_fichier_tiers est OBSOLETE
// async fn commande_copier_fichier_tiers<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

async fn commande_reindexer<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_reindexer Consommer commande : {:?}", & m.type_message);
    let commande: CommandeIndexerContenu = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation : doit etre un message provenant d'un usager avec delegation globale
    // Verifier si on a un certificat delegation globale
    match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => Ok(()),
        false => Err(format!("commandes.commande_reindexer: Commande autorisation invalide pour message {:?}", m.type_message)),
    }?;

    reset_flag_indexe(middleware, gestionnaire, &gestionnaire.indexation_job_handler).await?;

    let reponse = ReponseCommandeReindexer {ok: true, tuuids: None};
    Ok(Some(middleware.build_reponse(reponse)?.0))
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

async fn commande_completer_previews<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

    // let autorisation_valide = match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
    //     true => true,
    //     false => {
    //         let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    //         match user_id.as_ref() {
    //             Some(u) => {
    //                 if role_prive == true {
    //                     match commande.fuuids.as_ref() {
    //                         Some(f) => {
    //                             // Verifier que l'usager a les droits d'acces a tous les tuuids
    //
    //                             // Creer un set et retirer les tuuids trouves pour l'usager
    //                             let mut set_fuuids: HashSet<&String> = HashSet::new();
    //                             set_fuuids.extend(f.iter());
    //
    //                             // Parcourir les fichiers de l'usager, retirer tuuids trouves
    //                             let filtre = doc! {CHAMP_USER_ID: u, CHAMP_FUUIDS: {"$in": f}};
    //                             let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    //                             let mut curseur = collection.find(filtre, None).await?;
    //                             while let Some(d) = curseur.next().await {
    //                                 let fichier: RowTuuid = convertir_bson_deserializable(d?)?;
    //                                 // Retirer tous les fuuids (usager a acces)
    //                                 if let Some(f) = fichier.fuuids {
    //                                     for fuuid in f {
    //                                         set_fuuids.remove(&fuuid);
    //                                     }
    //                                 }
    //                             }
    //
    //                             // Verifier que tous les tuuids sont representes (set est vide)
    //                             set_fuuids.is_empty()  // Retourne true si tous les tuuids ont ete trouves pour l'usager
    //                         },
    //                         None => false  // Un usager doit fournir une liste de tuuids
    //                     }
    //                 } else {
    //                     false
    //                 }
    //             },
    //             None => false
    //         }
    //     },
    // };

    // if ! autorisation_valide {
    //     Err(format!("commandes.commande_completer_previews: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    // }

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

    let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(d) = curseur.next().await {
        let fichier: RowTuuid = convertir_bson_deserializable(d?)?;
        if let Some(fuuid) = fichier.fuuid {
            if let Some(mimetype) = fichier.mimetype {
                let mut champs_cles = HashMap::new();
                champs_cles.insert("tuuid".to_string(), fichier.tuuid);
                champs_cles.insert("mimetype".to_string(), mimetype);

                // Prendre une instance au hasard si present
                let instances = match fichier.visites {
                    Some(visites) => {
                        Some(visites.into_keys().collect::<Vec<String>>())
                    },
                    None => None
                };

                gestionnaire.image_job_handler.sauvegarder_job(
                    middleware, fuuid, &user_id,
                    instances, Some(champs_cles), None, true).await?;
            }
        }

    }

    // let reset = match commande.reset {
    //     Some(b) => b,
    //     None => false
    // };

    // Reponse generer preview
    let reponse = json!({ "ok": true });
    Ok(Some(middleware.build_reponse(reponse)?.0))
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

async fn commande_confirmer_fichier_indexe<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_confirmer_fichier_indexe Consommer commande : {:?}", & m.type_message);
    let commande: ParametresConfirmerJobIndexation = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation : doit etre un message provenant d'un composant protege
    match m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("commandes.commande_completer_previews: Commande autorisation invalide pour message {:?}", m.type_message)),
    }?;

    // Traiter la commande
    // let tuuid = match commande.tuuid {
    //     Some(inner) => inner,
    //     None => Err(format!("commande_confirmer_fichier_indexe Tuuid manquant de la commande pour {:?}", commande))?
    // };
    let tuuid = commande.tuuid;
    if let Err(e) = gestionnaire.indexation_job_handler.set_flag(
        middleware, tuuid, Some(commande.user_id), None, true).await {
        error!("commande_confirmer_fichier_indexe Erreur traitement flag : {:?}", e);
    }

    Ok(None)
}

/// Commande qui indique la creation _en cours_ d'un nouveau fichier. Permet de creer un
/// placeholder a l'ecran en attendant le traitement du fichier.
async fn commande_nouveau_fichier<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_nouveau_fichier Consommer commande : {:?}", & m.type_message);
    let commande: TransactionNouvelleVersion = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    let delegation_proprietaire = m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    if ! (role_prive || delegation_proprietaire) && user_id.is_none() {
        let reponse = json!({"ok": false, "err": "Non autorise"});
        return Ok(Some(middleware.build_reponse(&reponse)?.0));
    }

    let fuuid = commande.fuuid;
    let mimetype = commande.mimetype;
    let tuuid = match commande.tuuid {
        Some(t) => t,
        None => {
            let reponse = json!({"ok": false, "err": "tuuid manquant"});
            return Ok(Some(middleware.build_reponse(&reponse)?.0));
        }
    };
    let cuuid = commande.cuuid;
    // let nom_fichier = commande.nom;

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": &fuuid};
    // Ajouter collection au besoin
    // if let Some(c) = cuuid.as_ref() {
    //     add_to_set.insert("cuuids", c);
    // }
    todo!("fix me - get path_cuuids");
    //add_to_set.insert("path_cuuids", cuuid.to_owned());
    //add_to_set.insert("cuuids", cuuid.to_owned());

    let ops = doc! {
        "$set": {
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            // "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
            CHAMP_USER_ID: &user_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    debug!("commande_nouveau_fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("commande_nouveau_fichier.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("commande_nouveau_fichier Resultat transaction update : {:?}", resultat);

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, gestionnaire, tuuid.as_str(), EVENEMENT_AJOUTER_FICHIER).await?;
    //if let Some(c) = cuuid.as_ref() {
        let mut event = EvenementContenuCollection::new(cuuid.to_string());
        let fichiers_ajoutes = vec![tuuid.to_owned()];
        // event.cuuid = cuuid.into();
        event.fichiers_ajoutes = Some(fichiers_ajoutes);
        emettre_evenement_contenu_collection(middleware, gestionnaire, event).await?;
    //}

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_favoris_creerpath<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_favoris_creerpath Consommer commande : {:?}", & m.type_message);
    let commande: TransactionFavorisCreerpath = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Autorisation : si user_id fourni dans la commande, on verifie que le certificat est 4.secure ou delegation globale
    let user_id = {
        match commande.user_id {
            Some(user_id) => {
                // S'assurer que le certificat permet d'utiliser un user_id fourni (4.secure ou delegation globale)
                match m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
                    true => user_id,
                    false => {
                        match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                            true => user_id,
                            false => Err(format!("commandes.commande_completer_previews: Utilisation user_id refusee pour message {:?}", m.type_message))?
                        }
                    },
                }
            },
            None => {
                // Utiliser le user_id du certificat
                match &m.certificat.get_user_id()? {
                    Some(c) => c.to_owned(),
                    None => Err(format!("commandes.commande_favoris_creerpath: Certificat non charge pour message {:?}", m.type_message))?
                }
            }
        }
    };

    debug!("commande_favoris_creerpath Utiliser user_id {}", user_id);

    // Verifier si le path existe deja
    let tuuid_favoris = format!("{}_{}", user_id, commande.favoris_id);
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let filtre_favoris = doc!{
        CHAMP_USER_ID: &user_id,
        CHAMP_TUUID: &tuuid_favoris,
        CHAMP_SUPPRIME: false,
        CHAMP_FAVORIS: true
    };
    debug!("commande_favoris_creerpath Filtre doc favoris : {:?}", filtre_favoris);
    let doc_favoris_opt = collection.find_one(filtre_favoris, None).await?;
    let mut tuuid_leaf = None;

    debug!("commande_favoris_creerpath Doc_favoris_opt trouve : {:?}", doc_favoris_opt);
    match doc_favoris_opt {
        Some(doc_favoris) => {
            match commande.path_collections {
                Some(path_collections) => {
                    let mut trouve = true;
                    let mut cuuid_courant = tuuid_favoris.clone();
                    for path_col in path_collections {
                        let filtre_info_collection = doc!{
                            CHAMP_USER_ID: &user_id,
                            CHAMP_CUUIDS: &cuuid_courant,
                            CHAMP_NOM: &path_col,
                            CHAMP_SUPPRIME: false,
                        };
                        let doc_info_collection = collection.find_one(filtre_info_collection, None).await?;
                        match doc_info_collection {
                            Some(inner_doc) => {
                                let collection_info: InformationCollection = match convertir_bson_deserializable(inner_doc) {
                                    Ok(inner_collection) => Ok(inner_collection),
                                    Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion bson path {} : {:?}", path_col, e))
                                }?;
                                cuuid_courant = collection_info.tuuid.clone();
                            },
                            None => {
                                // Collection manquante, executer la transaction
                                trouve = false;
                                break
                            }
                        }
                        debug!("transaction_favoris_creerpath Path tuuid : {:?}", cuuid_courant);
                    }

                    if trouve {
                        tuuid_leaf = Some(cuuid_courant)
                    }
                },
                None => {
                    tuuid_leaf = Some(tuuid_favoris)
                }
            }
        },
        None => ()
    }

    if tuuid_leaf.is_some() {
        // Retourner le tuuid comme reponse, aucune transaction necessaire
        debug!("commande_favoris_creerpath Path trouve, tuuid {:?}", tuuid_leaf);
        let reponse = json!({CHAMP_TUUID: &tuuid_leaf});
        Ok(Some(middleware.build_reponse(reponse)?.0))
    } else {
        // Poursuivre le traitement sous forme de transaction
        debug!("commande_favoris_creerpath Path incomplet, poursuivre avec la transaction");
        Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
    }
}

async fn commande_video_convertir<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_video_convertir Consommer commande : {:?}", & m.type_message);
    let commande: CommandeVideoConvertir = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let fuuid = commande.fuuid.as_str();

    let user_id = if let Some(user_id) = m.certificat.get_user_id()? {
        user_id
    } else {
        let delegation_globale = m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
        if delegation_globale || m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
            // Ok, on utilise le user_id de la commande
            match commande.user_id {
                Some(inner) => {
                    // Remplacer user_id pour celui demande
                    inner
                },
                None => {
                    debug!("commande_video_convertir verifier_exchanges : User id manquant pour fuuid {}", fuuid);
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("User id manquant"))?))
                }
            }
        } else {
            debug!("commande_video_convertir verifier_exchanges : Certificat n'a pas l'acces requis (securite 2,3,4 ou user_id avec acces fuuid)");
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
        }
    };
    //     if delegation_globale || m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
    //         // Ok, on utilise le user_id de la commande
    //         match commande.user_id {
    //             Some(inner) => {
    //                 // Remplacer user_id pour celui demande
    //                 inner
    //             },
    //             None => {
    //                 debug!("commande_video_convertir verifier_exchanges : User id manquant pour fuuid {}", fuuid);;
    //                 return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User id manquant"}), None)?))
    //             }
    //         }
    //     } else if user_id.is_some() {
    //         let u = user_id.as_ref().expect("commande_video_convertir user_id");
    //         let resultat = verifier_acces_usager(middleware, u, vec![fuuid]).await?;
    //         if ! resultat.contains(&commande.fuuid) {
    //             debug!("commande_video_convertir verifier_exchanges : Usager n'a pas acces a fuuid {}", fuuid);;
    //             return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
    //         }
    //         u.to_owned()
    //     } else {
    //         debug!("commande_video_convertir verifier_exchanges : Certificat n'a pas l'acces requis (securite 2,3,4 ou user_id avec acces fuuid)");
    //         return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
    //     }
    // };

    // Verifier si le fichier a deja un video correspondant
    let bitrate_quality = match &commande.quality_video {
        Some(q) => q.to_owned(),
        None => match &commande.bitrate_video {
            Some(b) => b.to_owned() as i32,
            None => 0,
        }
    };
    let cle_video = format!("{};{};{}p;{}", commande.mimetype, commande.codec_video, commande.resolution_video, bitrate_quality);
    // let filtre_fichier = doc!{CHAMP_FUUIDS: fuuid};
    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    // let info_fichier: FichierDetail = match collection.find_one(filtre_fichier, None).await? {
    //     Some(f) => convertir_bson_deserializable(f)?,
    //     None => {
    //         info!("commande_video_convertir verifier_exchanges : Fichier inconnu {}", fuuid);
    //         return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichier inconnu"}), None)?))
    //     }
    // };

    // let version_courante = match info_fichier.version_courante {
    //     Some(v) => v,
    //     None => {
    //         info!("commande_video_convertir Fichier video en etat incorrect (version_courante manquant) {}", fuuid);
    //         return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Information fichier corrompue"}), None)?))
    //     }
    // };

    let filtre_fichier = doc! { CHAMP_USER_ID: &user_id, CHAMP_FUUID: fuuid };
    let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let version_courante = match collection.find_one(filtre_fichier, None).await {
        Ok(inner) => match inner {
            Some(inner) => inner,
            None => {
                info!("commande_video_convertir find_one : Fichier inconnu {}", fuuid);
                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Fichier inconnu"}), None)?))
                return Ok(Some(middleware.reponse_err(None, None, Some("Fichier inconnu"))?))
            }
        },
        Err(e) => {
            error!("commande_video_convertir find_one : Erreur chargement/conversion {} : {:?}", fuuid, e);
            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement/conversion"}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement/conversion"))?))
        }
    };

    match version_courante.video {
        Some(v) => {
            // Verifier si le video existe deja
            match v.get(cle_video.as_str()) {
                Some(v) => {
                    info!("commande_video_convertir Fichier video existe deja {} pour {}", cle_video, fuuid);
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Video dans ce format existe deja"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("Video dans ce format existe deja"))?))
                },
                None => ()  // Ok, le video n'existe pas
            }
        },
        None => ()  // Ok, aucuns videos existant
    };

    // Conserver l'information de conversion, emettre nouveau message de job
    // Note : job lock fait plus tard avant conversion, duplication de messages est OK
    let insert_ops = doc! {
        "tuuid": &commande.tuuid,
        CHAMP_FUUID: fuuid,
        CHAMP_USER_ID: &user_id,
        CHAMP_MIMETYPE: commande.mimetype,
        "codecVideo": commande.codec_video,
        "codecAudio": commande.codec_audio,
        "qualityVideo": commande.quality_video,
        "resolutionVideo": commande.resolution_video,
        "bitrateVideo": commande.bitrate_video,
        "bitrateAudio": commande.bitrate_audio,
        "preset": commande.preset,
        "etat": 1,  // Pending
    };
    let set_ops = doc! {
        CHAMP_FLAG_DB_RETRY: 0,  // Reset le retry count automatique
    };
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": insert_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre_video = doc! {CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video};
    let collection_video = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let emettre_job = match collection_video.find_one_and_update(filtre_video, ops, options).await? {
        Some(d) => {
            debug!("commande_video_convertir Etat precedent : {:?}", d);
            // Verifier l'etat du document precedent (e.g. pending, erreur, en cours, etc)

            true  // Emettre la job
        },
        None => true  // Nouvelle entree, emettre la nouvelle job.
    };

    if emettre_job {
        // Faire la liste des consignations avec le fichier disponible
        let consignation_disponible: Vec<&String> = version_courante.visites.keys().into_iter().collect();

        for consignation in consignation_disponible {
            let routage = RoutageMessageAction::builder(DOMAINE_MEDIA_NOM, COMMANDE_VIDEO_DISPONIBLE, vec![Securite::L2Prive])
                .partition(consignation)
                .blocking(false)
                .build();
            let commande_fichiers = json!({CHAMP_FUUID: fuuid, CHAMP_CLE_CONVERSION: &cle_video});
            middleware.transmettre_commande(routage, &commande_fichiers).await?;
        }

        // Emettre evenement pour clients
        let evenement = json!({
            CHAMP_CLE_CONVERSION: &cle_video,
            CHAMP_FUUID: fuuid,
            "tuuid": &commande.tuuid,
        });
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, "jobAjoutee", vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage, &evenement).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_image_get_job<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_image_get_job Consommer commande : {:?}", m.type_message);
    let commande: CommandeImageGetJob = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let certificat = m.certificat.as_ref();

    // Verifier autorisation
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        info!("commande_image_get_job Exchange n'est pas de niveau 3 ou 4");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (exchange)"))?))
    }
    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
        info!("commande_image_get_job Role n'est pas media");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre media)"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (role doit etre media)"))?))
    }

    let commande_get_job = CommandeGetJob { instance_id: commande.instance_id, fallback: None };
    let reponse_prochaine_job = gestionnaire.image_job_handler.get_prochaine_job(
        middleware, certificat, commande_get_job).await?;

    debug!("commande_image_get_job Prochaine job : {:?}", reponse_prochaine_job);
    Ok(Some(middleware.build_reponse(reponse_prochaine_job)?.0))
}

async fn commande_video_get_job<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_video_get_job Consommer commande : {:?}", & m.type_message);
    let commande: CommandeVideoGetJob = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let certificat = m.certificat.as_ref();

    // Verifier autorisation
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        info!("commande_video_get_job Exchange n'est pas de niveau 3 ou 4");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (exchange)"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (exchange)"))?))
    }
    if ! m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
        info!("commande_video_get_job Role n'est pas media");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces refuse (role doit etre media)"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse (role doit etre media)"))?))
    }

    let commande_get_job = CommandeGetJob { instance_id: commande.instance_id, fallback: commande.fallback };
    let reponse_prochaine_job = gestionnaire.video_job_handler.get_prochaine_job(
        middleware, certificat, commande_get_job).await?;

    debug!("commande_video_get_job Prochaine job : {:?}", reponse_prochaine_job);
    Ok(Some(middleware.build_reponse(reponse_prochaine_job)?.0))
}

async fn commande_supprimer_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
    let result = collection.count_documents(filtre_fichier, None).await?;

    if result > 0 {
        // Traiter la transaction
        Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

async fn commande_ajouter_contact_local<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCOMPTES, "getUserIdParNomUsager", vec![Securite::L4Secure])
            .build();
        let requete = json!({ "noms_usagers": [commande.nom_usager] });
        match middleware.transmettre_requete(routage, &requete).await {
            Ok(inner) => match inner {
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
                                        debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (usager inconnu - 1), SKIP");;
                                        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                                        return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                                    }
                                },
                                None => {
                                    debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (usager inconnu - 2), SKIP");;
                                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                                    return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                                }
                            }
                        },
                        None => {
                            debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (reponse sans liste usagers), SKIP");;
                            // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                            return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                        }
                    }
                },
                _ => {
                    debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact (mauvais type reponse), SKIP");;
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Erreur chargement user_id pour contact local"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("Erreur chargement user_id pour contact local"))?))
                }
            },
            Err(e) => {
                debug!("commande_ajouter_contact_local Erreur chargement user_id pour contact, SKIP : {:?}", e);;
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
    Ok(sauvegarder_traiter_transaction_serializable(
        middleware, &transaction, gestionnaire, DOMAINE_NOM, TRANSACTION_AJOUTER_CONTACT_LOCAL).await?)
    // Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_contacts<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_partager_collections<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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
    let mut curseur = collection.find(filtre, options).await?;
    while let Some(r) = curseur.next().await {
        let row: RowTuuid = convertir_bson_deserializable(r?)?;
        cuuids_manquants.remove(&row.tuuid);
    }

    if cuuids_manquants.len() > 0 {
        error!("commande_partager_collections Il y a au moins un cuuid non couvert pour l'usager, SKIP");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Au moins un repertoire est invalide"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Au moins un repertoire est invalide"))?))
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_partage_usager<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
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

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_orphelins<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_orphelins Consommer commande : {:?}", & m.type_message);
    let commande: TransactionSupprimerOrphelins = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let resultat = trouver_orphelins_supprimer(middleware, &commande).await?;
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
        sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;
    }

    let reponse = ReponseSupprimerOrphelins { ok: true, err: None, fuuids_a_conserver: resultat.fuuids_a_conserver };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn transmettre_cle_attachee<M>(middleware: &M, cle: Value) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;

    let mut routage_builder = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
        .correlation_id(&message_cle.id)
        .partition("all");

    match message_cle.attachements.take() {
        Some(inner) => {
            if let Some(partition) = inner.get("partition") {
                if let Some(partition) = partition.as_str() {
                    // Override la partition
                    routage_builder = routage_builder.partition(partition);
                }
            }
        },
        None => ()
    }

    let routage = routage_builder.build();
    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;
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

// async fn trouver_orphelins_supprimer<M>(middleware: &M, commande: &TransactionSupprimerOrphelins)
//     -> Result<ResultatVerifierOrphelins, CommonError>
//     where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
// {
//     let mut versions_supprimees = HashMap::new();
//     let mut fuuids_a_conserver = Vec::new();
//
//     let fuuids_commande = {
//         let mut set_fuuids = HashSet::new();
//         for fuuid in &commande.fuuids { set_fuuids.insert(fuuid.as_str()); }
//         set_fuuids
//     };
//
//     // S'assurer qu'au moins un fuuid peut etre supprime.
//     // Extraire les fuuids qui doivent etre conserves
//     let filtre = doc! {
//         CHAMP_FUUIDS: {"$in": &commande.fuuids},
//     };
//     let collection = middleware.get_collection_typed::<NodeFichierVersionBorrowed>(
//         NOM_COLLECTION_VERSIONS)?;
//     debug!("commande_supprimer_partage_usager Filtre requete orphelins : {:?}", filtre);
//     let mut curseur = collection.find(filtre, None).await?;
//     while curseur.advance().await? {
//         let doc_mappe = curseur.deserialize_current()?;
//         let fuuids_version = &doc_mappe.fuuids;
//         let fuuid_fichier = doc_mappe.fuuid;
//         let supprime = doc_mappe.supprime;
//
//         if supprime {
//             // Verifier si l'original est l'orphelin a supprimer
//             if fuuids_commande.contains(fuuid_fichier) {
//                 if !versions_supprimees.contains_key(fuuid_fichier) {
//                     // S'assurer de ne pas faire d'override si le fuuid est deja present avec false
//                     versions_supprimees.insert(fuuid_fichier.to_string(), true);
//                 }
//             }
//         } else {
//             if fuuids_commande.contains(fuuid_fichier) {
//                 // Override, s'assurer de ne pas supprimer le fichier si au moins 1 usager le conserve
//                 versions_supprimees.insert(fuuid_fichier.to_string(), false);
//             }
//
//             // Pas supprime localement, ajouter tous les fuuids qui sont identifies comme orphelins
//             for fuuid in fuuids_version {
//                 if fuuids_commande.contains(*fuuid) {
//                     fuuids_a_conserver.push(fuuid.to_string());
//                 }
//             }
//         }
//     }
//
//     debug!("commande_supprimer_partage_usager Versions supprimees : {:?}, fuuids a conserver : {:?}", versions_supprimees, fuuids_a_conserver);
//     let resultat = ResultatVerifierOrphelins { versions_supprimees, fuuids_a_conserver };
//     Ok(resultat)
// }
