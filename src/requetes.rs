use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use std::str::from_utf8;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::bson::serde_helpers::deserialize_chrono_datetime_from_bson_datetime;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::{InformationDechiffrage, InformationDechiffrageV2, ReponseDechiffrage, ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L3Protege, L4Secure};
use millegrilles_common_rust::dechiffrage::{DataChiffre, DataChiffreBorrow};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::jwt_handler::{generer_jwt, verify_jwt};
use millegrilles_common_rust::messages_generiques::CommandeDechiffrerCle;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::redis::Commands;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::optionformatchiffragestr;
use crate::domain_manager::GrosFichiersDomainManager;
use crate::grosfichiers_constantes::*;
use crate::traitement_index::{ParametresGetClesStream, ParametresGetPermission, ParametresRecherche, ResultatHits, ResultatHitsDetail};
use crate::traitement_media::requete_jobs_video;
use crate::transactions::*;

const CONST_LIMITE_TAILLE_ZIP: u64 = 1024 * 1024 * 1024 * 100;   // Limite 100 GB
const CONST_LIMITE_NOMBRE_ZIP: u64 = 1_000;
const CONST_LIMITE_NOMBRE_SOUS_REPERTOIRES: u64 = 10_000;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GrosFichiersDomainManager) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer requete : {:?}", &message.type_message);

    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let (domaine, action) = match &message.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            error!("Message requete/domaine inconnu : {:?}. Message dropped.", message.type_message);
            return Ok(None)
        }
    };

    // let domaine = message.domaine.as_str();
    if domaine.as_str() != DOMAINE_NOM {
        error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
        return Ok(None)
    }

    if role_prive && user_id.is_some() {
        match action.as_str() {
            REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
            REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
            // REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            // REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
            REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_TUUIDS => requete_verifier_acces_tuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            // REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_JOBS_VIDEO => requete_jobs_video(middleware, message, gestionnaire).await,
            REQUETE_CHARGER_CONTACTS => requete_charger_contacts(middleware, message, gestionnaire).await,
            REQUETE_PARTAGES_USAGER => requete_partages_usager(middleware, message, gestionnaire).await,
            REQUETE_PARTAGES_CONTACT => requete_partages_contact(middleware, message, gestionnaire).await,
            REQUETE_INFO_STATISTIQUES => requete_info_statistiques(middleware, message, gestionnaire).await,
            REQUETE_STRUCTURE_REPERTOIRE => requete_structure_repertoire(middleware, message, gestionnaire).await,
            REQUETE_JWT_STREAMING => requete_creer_jwt_streaming(middleware, message, gestionnaire).await,
            REQUETE_SOUS_REPERTOIRES => requete_sous_repertoires(middleware, message, gestionnaire).await,
            REQUETE_RECHERCHE_INDEX => requete_recherche_index(middleware, message, gestionnaire).await,
            REQUETE_INFO_VIDEO => requete_info_video(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue (1): '{}'. Message dropped.", action);
                Ok(None)
            }
        }
    } else if message.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        match action.as_str() {
            REQUETE_CONFIRMER_ETAT_FUUIDS => requete_confirmer_etat_fuuids(middleware, message, gestionnaire).await,
            // REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_STREAM => requete_get_cles_stream(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            //REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CUUIDS => requete_sync_cuuids(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue pour exchanges 3.protege/4.secure : '{}'. Message dropped.", action);
                Ok(None)
            }
        }
    } else if message.certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        match action.as_str() {
            REQUETE_CONFIRMER_ETAT_FUUIDS => requete_confirmer_etat_fuuids(middleware, message, gestionnaire).await,
            // REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_TUUIDS => requete_verifier_acces_tuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CUUIDS => requete_sync_cuuids(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_STREAM => requete_get_cles_stream(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue pour exchange 2.prive : '{}'. Message dropped.", action);
                Ok(None)
            }
        }
    } else if message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        match action.as_str() {
            REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
            REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
            REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
            // REQUETE_DOCUMENTS_PAR_FUUID => requete_documents_par_fuuid(middleware, message, gestionnaire).await,
            // REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
            REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
            REQUETE_GET_CLES_FICHIERS => requete_get_cles_fichiers(middleware, message, gestionnaire).await,
            REQUETE_VERIFIER_ACCES_FUUIDS => requete_verifier_acces_fuuids(middleware, message, gestionnaire).await,
            REQUETE_SYNC_COLLECTION => requete_sync_collection(middleware, message, gestionnaire).await,
            // REQUETE_SYNC_RECENTS => requete_sync_plusrecent(middleware, message, gestionnaire).await,
            REQUETE_SYNC_CORBEILLE => requete_sync_corbeille(middleware, message, gestionnaire).await,
            REQUETE_JOBS_VIDEO => requete_jobs_video(middleware, message, gestionnaire).await,
            REQUETE_CHARGER_CONTACTS => requete_charger_contacts(middleware, message, gestionnaire).await,
            REQUETE_PARTAGES_USAGER => requete_partages_usager(middleware, message, gestionnaire).await,
            REQUETE_PARTAGES_CONTACT => requete_partages_contact(middleware, message, gestionnaire).await,
            REQUETE_INFO_STATISTIQUES => requete_info_statistiques(middleware, message, gestionnaire).await,
            REQUETE_STRUCTURE_REPERTOIRE => requete_structure_repertoire(middleware, message, gestionnaire).await,
            REQUETE_JWT_STREAMING => requete_creer_jwt_streaming(middleware, message, gestionnaire).await,
            REQUETE_SOUS_REPERTOIRES => requete_sous_repertoires(middleware, message, gestionnaire).await,
            REQUETE_RECHERCHE_INDEX => requete_recherche_index(middleware, message, gestionnaire).await,
            REQUETE_INFO_VIDEO => requete_info_video(middleware, message, gestionnaire).await,
            _ => {
                error!("Message requete/action inconnue (delegation globale): '{}'. Message dropped.", action);
                Ok(None)
            }
        }
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

}

async fn requete_activite_recente<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_activite_recente Message : {:?}", & m.type_message);
    let requete: RequetePlusRecente = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = m.certificat.get_user_id()?;
    if user_id.is_none() {
        // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
    }

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
        .limit(limit)
        .skip(skip)
        .build();
    let filtre = doc!{CHAMP_SUPPRIME: false, CHAMP_USER_ID: user_id};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn mapper_fichiers_curseur(mut curseur: Cursor<Document>) -> Result<Value, CommonError> {
    let mut fichiers_mappes = Vec::new();

    while let Some(fresult) = curseur.next().await {
        let fcurseur = fresult?;
        let fichier_db = mapper_fichier_db(fcurseur)?;
        fichiers_mappes.push(fichier_db);
    }

    // Convertir fichiers en Value (serde pour reponse json)
    Ok(serde_json::to_value(fichiers_mappes)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequetePlusRecente {
    limit: Option<i64>,
    skip: Option<u64>,
}

pub fn mapper_fichier_db(fichier: Document) -> Result<FichierDetail, CommonError> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    debug!("Ficher charge : {:?}", fichier);
    let mut fichier_mappe: FichierDetail = convertir_bson_deserializable(fichier)?;
    fichier_mappe.date_creation = Some(date_creation.to_chrono());
    fichier_mappe.derniere_modification = Some(date_modification.to_chrono());
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

async fn requete_favoris<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_favoris Message : {:?}", & m.type_message);
    //let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let projection = doc! {CHAMP_NOM: true, CHAMP_TITRE: true, CHAMP_SECURITE: true, CHAMP_TUUID: true, "_mg-creation": true};
    let filtre = doc! { CHAMP_FAVORIS: true, CHAMP_USER_ID: user_id };
    let hint = Hint::Name("collections_favoris".into());
    let opts = FindOptions::builder().projection(projection).hint(hint).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let favoris_mappes = {
        let mut favoris_mappes = Vec::new();
        let mut curseur = collection.find(filtre, opts).await?;
        while let Some(c) = curseur.next().await {
            let favori_doc = c?;
            let favori_mappe: Favoris = convertir_bson_deserializable(favori_doc)?;
            favoris_mappes.push(favori_mappe);
        }
        favoris_mappes
    };

    let reponse = json!({ "favoris": favoris_mappes });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Favoris {
    nom: String,
    tuuid: String,
    securite: Option<String>,
    // #[serde(rename(deserialize = "_mg-creation"))]
    // date_creation: Option<DateTime<Utc>>,
    // titre: Option<HashMap<String, CommonError>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReponseFichierRepVersion {
    pub tuuid: String,
    pub user_id: String,
    pub type_node: String,
    pub supprime: bool,
    pub supprime_indirect: bool,
    pub metadata: DataChiffre,

    // Champs pour type_node Fichier
    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    /// Fuuids des versions en ordre (plus recent en dernier)
    #[serde(skip_serializing_if="Option::is_none")]
    pub fuuids_versions: Option<Vec<String>>,

    // Champs pour type_node Fichiers/Repertoires
    /// Path des cuuids parents (inverse, parent immediat est index 0)
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_cuuids: Option<Vec<String>>,

    // Champs recuperes a partir de la version courante
    #[serde(skip_serializing_if="Option::is_none")]
    pub version_courante: Option<NodeFichierVersionOwned>,

    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    pub derniere_modification: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    pub date_creation: Option<DateTime<Utc>>,

    // Information de chiffrage symmetrique (depuis 2024.3.0)
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio_stream_info: Option<Vec<AudioStreamInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitle_stream_info: Option<Vec<SubtitleStreamInfo>>,
}

impl From<NodeFichierRepOwned> for ReponseFichierRepVersion {
    fn from(mut value: NodeFichierRepOwned) -> Self {
        // value.map_date_modification();
        Self {
            tuuid: value.tuuid,
            user_id: value.user_id,
            type_node: value.type_node,
            supprime: value.supprime,
            supprime_indirect: value.supprime_indirect,
            metadata: value.metadata,
            mimetype: value.mimetype,
            fuuids_versions: value.fuuids_versions,
            path_cuuids: value.path_cuuids,
            version_courante: None,
            derniere_modification: value.derniere_modification,
            date_creation: value.date_creation,
            cle_id: None,
            format: None,
            nonce: None,
            verification: None,
            audio_stream_info: None,
            subtitle_stream_info: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ReponseDocumentsParTuuid {
    fichiers: Vec<ReponseFichierRepVersion>
}

async fn requete_documents_par_tuuid<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.type_message);
    let requete: RequeteDocumentsParTuuids = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("requetes.requete_documents_par_tuuid: User_id manquant pour message {:?}", m.type_message))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("requetes.requete_documents_par_tuuid: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let (user_id, filtre) = if let Some(true) = requete.partage {
        // Pre-filtrage pour le partage. Charger les tuuids partages avec le user_id.
        let mut user_id = user_id;
        let contact_ids = {
            let mut contact_ids = Vec::new();

            let mut filtre_contacts = doc!( CHAMP_CONTACT_USER_ID: &user_id );
            if let Some(contact_id) = requete.contact_id.as_ref() {
                filtre_contacts.insert("contact_id", contact_id);
            }
            let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let mut curseur = collection.find(filtre_contacts, None).await?;
            while curseur.advance().await? {
                let row = curseur.deserialize_current()?;
                contact_ids.push(row.contact_id);

                if requete.contact_id.is_some() {
                    // Remplacer le user_id de l'usager par celui qui a partage la collection
                    user_id = row.user_id;
                    break;  // On a un seul contact
                }
            }

            contact_ids
        };

        // Trouver les tuuids partages pour les contact_ids
        let filtre_tuuids = doc! { CHAMP_CONTACT_ID: {"$in": contact_ids} };
        let collection = middleware.get_collection_typed::<RowPartagesUsager>(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
        let mut curseur = collection.find(filtre_tuuids, None).await?;
        let mut tuuids_partages = Vec::new();
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            tuuids_partages.push(row.tuuid);
        }

        // Faire une requete pour les tuuids et leurs sous-repertoires
        (
            user_id,
            doc! {
                CHAMP_TUUID: {"$in": requete.tuuids_documents},
                "$or": [
                    { CHAMP_TUUID: {"$in": &tuuids_partages} },
                    { CHAMP_PATH_CUUIDS: {"$in": &tuuids_partages} }
                ]
            }
        )
    } else {
        (
            user_id.clone(),
            doc! {
                CHAMP_TUUID: {"$in": requete.tuuids_documents},
                CHAMP_USER_ID: &user_id,
            }
        )
    };

    debug!("requete_documents_par_tuuid Filtre {:?}", serde_json::to_string(&filtre)?);

    let collection_typed = middleware.get_collection_typed::<NodeFichierRepOwned>(
        NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection_typed.find(filtre, None).await?;
    let mut reponse = ReponseDocumentsParTuuid { fichiers: Vec::new() };
    let mut map_fichiers_par_fuuid: HashMap<String, ReponseFichierRepVersion> = HashMap::new();
    {
        while let Some(r) = curseur.next().await {
            let mut row = r?;
            // row.map_date_modification();
            let type_node = TypeNode::try_from(row.type_node.as_str())?;
            match type_node {
                TypeNode::Fichier => {
                    // Conserver le fichier separement pour requete sur versions
                    let fuuid: Option<&String> = match row.fuuids_versions.as_ref() {
                        Some(inner) => inner.get(0),
                        None => None
                    };
                    if let Some(fuuid) = fuuid {
                        map_fichiers_par_fuuid.insert(fuuid.clone(), row.into());
                    } else {
                        reponse.fichiers.push(row.into());
                    }
                },
                TypeNode::Collection | TypeNode::Repertoire => {
                    reponse.fichiers.push(row.into());
                }
            }
        }
    };

    debug!("requete_documents_par_tuuid Fichiers trouves : {:?}", reponse.fichiers);

    // Recuperer l'information de versions de tous les fichiers
    let fuuids_fichiers: Vec<&str> = map_fichiers_par_fuuid.keys().map(|s| s.as_str()).collect();
    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_FUUID: {"$in": fuuids_fichiers} };
    let options = FindOptions::builder()
        .hint(Hint::Name(String::from("fuuid_user_id")))
        .build();
    let collection_versions = middleware.get_collection_typed::<NodeFichierVersionOwned>(
        NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection_versions.find(filtre, options).await?;
    while let Some(r) = curseur.next().await {
        let row = r?;
        match map_fichiers_par_fuuid.remove(row.fuuid.as_str()) {
            Some(mut inner) => {
                inner.version_courante = Some(row);
                reponse.fichiers.push(inner);  // Transferer vers la liste de reponses
            },
            None => {
                warn!("requetes.requete_documents_par_tuuid Recu version {} qui ne match aucun element en memoire", row.tuuid);
            }
        }
    }

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Serialize)]
struct ReponseVerifierAccesFuuids {
    fuuids_acces: Vec<String>,
    acces_tous: bool,
    user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteVerifierAccesTuuids {
    user_id: Option<String>,
    tuuids: Vec<String>,
    contact_id: Option<String>,
}

#[derive(Serialize)]
struct ReponseVerifierAccesTuuids {
    tuuids_acces: Vec<String>,
    acces_tous: bool,
    user_id: String,
}

/// Requete pour verifier si un contact_id ou user_id a acces aux tuuids listes.
async fn requete_verifier_acces_tuuids<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_verifier_acces_tuuids Message : {:?}", & m.type_message);
    let requete: RequeteVerifierAccesTuuids = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => {
            if ! m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "acces refuse"}), None)?))
                return Ok(Some(middleware.reponse_err(None, None, Some("acces refuse"))?))
            }
            match requete.user_id.as_ref() {
                Some(u) => u.to_owned(),
                None => {
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User_id manquant"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant"))?))
                }
            }
        }
    };

    let user_id = match requete.contact_id.as_ref() {
        Some(contact_id) => {
            // Verifier que le contact_id et les contact_user_id correspondent, extraire user_id partage
            let filtre = doc! { CHAMP_CONTACT_ID: &contact_id, CHAMP_CONTACT_USER_ID: user_id };
            let collection = middleware.get_collection_typed::<RowPartageContactOwned>(
                NOM_COLLECTION_PARTAGE_CONTACT)?;
            let contact = match collection.find_one(filtre, None).await? {
                Some(inner) => inner,
                None => {
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "contact_id et user_id mismatch ou manquant"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("contact_id et user_id mismatch ou manquant"))?))
                }
            };
            // Ok, le contact est valide. Retourner user_id de l'usager qui a fait le partage.
            contact.user_id
        },
        None => user_id.to_owned()
    };

    debug!("requete_verifier_acces_tuuids user_id {} utilise pour verifier acces tuuids sur {:?}", user_id, requete.tuuids);

    let resultat = verifier_acces_usager_tuuids(middleware, &user_id, &requete.tuuids).await?;

    let acces_tous = resultat.len() == requete.tuuids.len();

    debug!("requete_verifier_acces_tuuids user_id {} : acces tous {:?}, acces {:?}", user_id, acces_tous, resultat);

    let reponse = ReponseVerifierAccesTuuids {
        tuuids_acces: resultat,
        acces_tous,
        user_id,
    };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn requete_verifier_acces_fuuids<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_verifier_acces_fuuids Message : {:?}", & m.type_message);
    let requete: RequeteVerifierAccesFuuids = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => {
            if ! m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
                // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "acces refuse"}), None)?))
                return Ok(Some(middleware.reponse_err(None, None, Some("acces refuse"))?))
            }
            match requete.user_id.as_ref() {
                Some(u) => u.to_owned(),
                None => {
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "User_id manquant"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant"))?))
                }
            }
        }
    };

    let user_id = match requete.contact_id.as_ref() {
        Some(contact_id) => {
            // Verifier que le contact_id et les contact_user_id correspondent, extraire user_id partage
            let filtre = doc! { CHAMP_CONTACT_ID: &contact_id, CHAMP_CONTACT_USER_ID: user_id };
            let collection = middleware.get_collection_typed::<RowPartageContactOwned>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let contact = match collection.find_one(filtre, None).await? {
                Some(inner) => inner,
                None => {
                    // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "contact_id et user_id mismatch ou manquant"}), None)?))
                    return Ok(Some(middleware.reponse_err(None, None, Some("contact_id et user_id mismatch ou manquant"))?))
                }
            };
            // Ok, le contact est valide. Retourner user_id de l'usager qui a fait le partage.
            contact.user_id
        },
        None => user_id.to_owned()
    };

    let resultat = verifier_acces_usager(middleware, &user_id, &requete.fuuids).await?;

    let acces_tous = resultat.len() == requete.fuuids.len();

    // let reponse = json!({ "fuuids_acces": resultat , "acces_tous": acces_tous, "user_id": user_id });
    let reponse = ReponseVerifierAccesFuuids {
        fuuids_acces: resultat,
        acces_tous,
        user_id,
    };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Serialize)]
struct ReponseCreerJwtStreaming {
    ok: bool,
    err: Option<String>,
    jwt_token: Option<String>,
}

async fn requete_creer_jwt_streaming<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_verifier_acces_fuuids Message : {:?}\n{}", &m.type_message, from_utf8(m.message.buffer.as_slice())?);
    let requete: RequeteGenererJwtStreaming = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => {
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant"))?))
        }
    };

    let user_id = match requete.contact_id.as_ref() {
        Some(contact_id) => {
            // Verifier que le contact_id et les contact_user_id correspondent, extraire user_id partage
            let filtre = doc! { CHAMP_CONTACT_ID: &contact_id, CHAMP_CONTACT_USER_ID: user_id };
            let collection = middleware.get_collection_typed::<RowPartageContactOwned>(NOM_COLLECTION_PARTAGE_CONTACT)?;
            let contact = match collection.find_one(filtre, None).await? {
                Some(inner) => inner,
                None => {
                    return Ok(Some(middleware.reponse_err(None, None, Some("contact_id et user_id mismatch ou manquant"))?))
                }
            };
            // Ok, le contact est valide. Retourner user_id de l'usager qui a fait le partage.
            contact.user_id
        },
        None => user_id.to_owned()
    };

    // Verifier si l'usager a acces aux fuuids demandes
    let mut fuuids = Vec::new();
    fuuids.push(requete.fuuid.as_str());
    if let Some(fuuid) = requete.fuuid_ref.as_ref() {
        fuuids.push(fuuid.as_str());
    }
    let resultat = verifier_acces_usager(middleware, &user_id, &fuuids).await?;
    if resultat.len() != fuuids.len() {
        warn!("requete_verifier_acces_fuuids Mismatch, l'usager n'a pas acces aux fuuids demandes");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Acces aux fichiers est refuse"}), None)?))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces aux fichiers est refuse"))?))
    }

    // L'acces aux fuuids est OK. Charger l'information de dechiffrage.
    debug!("requete_verifier_acces_fuuids Charger information de dechiffrage pour {}", requete.fuuid);
    let info_stream = get_information_fichier_stream(middleware, &user_id, &requete.fuuid, requete.fuuid_ref.as_ref()).await?;
    let jwt_token = generer_jwt(middleware, &user_id, &requete.fuuid, info_stream.mimetype, info_stream.dechiffrage)?;

    // let reponse = json!({ "fuuids_acces": resultat , "acces_tous": acces_tous, "user_id": user_id });
    let reponse = ReponseCreerJwtStreaming {
        ok: true,
        err: None,
        jwt_token: Some(jwt_token)
    };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

struct InformationFichierStream {
    mimetype: String,
    dechiffrage: InformationDechiffrageV2,
}

async fn get_information_fichier_stream<M,U,S,R>(middleware: &M, user_id: U, fuuid: S, fuuid_ref_in: Option<R>)
    -> Result<InformationFichierStream, CommonError>
    where
        M: GenerateurMessages + MongoDao,
        U: AsRef<str>, S: AsRef<str>, R: AsRef<str>
{
    let user_id = user_id.as_ref();
    let fuuid = fuuid.as_ref();
    let fuuid_ref = match fuuid_ref_in.as_ref() { Some(inner) => Some(inner.as_ref()), None => None };

    let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FUUIDS: fuuid };
    let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(
        NOM_COLLECTION_VERSIONS)?;
    let fichier = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => Err(format!("requetes.get_information_fichier_stream Fuuid inconnu {} pour user_id {}", fuuid, user_id))?
    };

    let resultat = match fuuid_ref {
        Some(fuuid_ref) => {
            // On a un fuuid de reference (video transcode) - l'information de dechiffrage est
            // dans la collection VERSIONS (deja charge).
            if fuuid_ref != fichier.fuuid.as_str() {
                Err(format!("requetes.get_information_fichier_stream Mismatch fuuid_ref {} et fichier trouve (db) {}", fuuid_ref, fichier.fuuid))?
            }

            // Trouver video correspondant au fuuid.
            let video = match fichier.video {
                Some(inner) => {
                    let mut video_trouve: Vec<TransactionAssocierVideoVersionDetail> = inner.into_iter()
                        .filter(|f| f.1.fuuid_video.as_str() == fuuid)
                        .map(|f| f.1)
                        .collect();
                    match video_trouve.pop() {
                        Some(inner) => inner,
                        None => Err(format!("requetes.get_information_fichier_stream Aucun video avec fuuid {} pour fuuid_ref {}", fuuid, fuuid_ref))?
                    }
                },
                None => Err(format!("requetes.get_information_fichier_stream Aucuns videos pour fuuid_ref {}", fuuid_ref))?
            };

            let format = match video.format.as_ref() {
                Some(inner) => FormatChiffrage::try_from(inner.as_str())?,
                None => Err(format!("requetes.get_information_fichier_stream Format chiffrage video manquant pour fuuid {}", fuuid))?
            };

            let cle_id = match video.cle_id {
                Some(inner) => inner,
                None => fuuid_ref.to_owned()
            };

            let nonce = match video.nonce {
                Some(inner) => Some(inner),
                None => match video.header {
                    Some(inner) => Some(inner[1..].to_string()),
                    None => None
                }
            };

            let info_dechiffrage = InformationDechiffrageV2 {
                cle_id,
                format,
                nonce,
                verification: None,
                fuuid: Some(fuuid_ref.to_owned()),  // Reference au fichier video, requis pour JWT
            };

            InformationFichierStream {
                mimetype: video.mimetype,
                dechiffrage: info_dechiffrage,
            }
        },
        None => {
            // On n'a pas de fuuid de reference - video original

            // Verifier si on a l'ancien ou le nouveau format de chiffrage symmetrique (V2)
            match fichier.cle_id {
                Some(cle_id) => {
                    // Nouveau format, toute l'information est deja disponible
                    let format = match fichier.format {
                        Some(inner) => inner,
                        None => Err(Error::Str("requetes.get_information_fichier_stream Format de chiffrage manquant"))?
                    };
                    let info_dechiffrage = InformationDechiffrageV2 {
                        cle_id,
                        format,
                        nonce: fichier.nonce,
                        verification: fichier.verification,
                        fuuid: None,
                    };
                    InformationFichierStream {
                        mimetype: fichier.mimetype,
                        dechiffrage: info_dechiffrage,
                    }
                },
                None => {
                    // Ancien format, on doit recuperer l'information aupres du maitre des cles
                    let requete = RequeteDechiffrage {
                        domaine: DOMAINE_NOM.to_string(),
                        liste_hachage_bytes: None,
                        cle_ids: Some(vec![fuuid.to_string()]),
                        certificat_rechiffrage: None,
                        inclure_signature: None,
                    };
                    let routage = RoutageMessageAction::builder(
                        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
                    )
                        .build();
                    debug!("requetes.get_information_fichier_stream Transmettre requete permission dechiffrage cle : {:?}", requete);
                    let reponse = middleware.transmettre_requete(routage, &requete).await?;
                    let info_dechiffrage = if let Some(TypeMessage::Valide(reponse)) = reponse {
                        debug!("requetes.get_information_fichier_stream Reponse dechiffrage\n{}", from_utf8(reponse.message.buffer.as_slice())?);
                        let message_ref = reponse.message.parse()?;
                        let enveloppe_privee = middleware.get_enveloppe_signature();
                        // let mut reponse_dechiffrage: ReponseDechiffrage = deser_message_buffer!(reponse.message);
                        let mut reponse_dechiffrage: ReponseRequeteDechiffrageV2 = message_ref.dechiffrer(enveloppe_privee.as_ref())?;
                        let cle = match reponse_dechiffrage.cles.take() {
                            Some(mut inner) => inner.remove(0),
                            None => Err(format!("requetes.get_information_fichier_stream Cle fuuid {} manquante", fuuid))?
                        };
                        let info = InformationDechiffrageV2 {
                            format: match cle.format.as_ref() { Some(inner) => inner.clone(), None => FormatChiffrage::MGS4 },
                            cle_id: match cle.cle_id.as_ref() { Some(inner) => inner.to_string(), None => fuuid.to_string() },
                            nonce: match cle.nonce.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                            verification: match cle.verification.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                            fuuid: None,
                        };

                        debug!("requetes.get_information_fichier_stream Information dechiffrage recue : {:?}", info);

                        info
                    } else {
                        Err(format!("requetes.get_information_fichier_stream Erreur requete information dechiffrage {}, reponse invalide", fuuid))?
                    };
                    InformationFichierStream {
                        mimetype: fichier.mimetype,
                        dechiffrage: info_dechiffrage,
                    }
                }
            }

            // let requete = RequeteDechiffrage {
            //     domaine: DOMAINE_NOM.to_string(),
            //     liste_hachage_bytes: None,
            //     cle_ids: Some(vec![fuuid.to_string()]),
            //     certificat_rechiffrage: None,
            // };
            // let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE, vec![Securite::L4Secure])
            //     .build();

            // debug!("Transmettre requete permission dechiffrage cle : {:?}", requete);
            // let reponse = middleware.transmettre_requete(routage, &requete).await?;
            // let info_dechiffrage = if let Some(TypeMessage::Valide(reponse)) = reponse {
            //     debug!("Reponse dechiffrage : {:?}", reponse);
            //     let mut reponse_dechiffrage: ReponseDechiffrage = deser_message_buffer!(reponse.message);
            //     let cle = match reponse_dechiffrage.cles.remove(fuuid) {
            //         Some(inner) => inner,
            //         None => Err(format!("requetes.get_information_fichier_stream Cle fuuid {} manquante", fuuid))?
            //     };
            //     InformationDechiffrage {
            //         format: match cle.format.as_ref() { Some(inner) => Some(FormatChiffrage::try_from(inner.as_str())?), None => None },
            //         cle_id: None,
            //         ref_hachage_bytes: None,
            //         header: cle.header,
            //         tag: cle.tag,
            //     }
            // } else {
            //     Err(format!("Erreur requete information dechiffrage {}, reponse invalide", fuuid))?
            // };
            // InformationFichierStream {
            //     mimetype: fichier.mimetype,
            //     dechiffrage: info_dechiffrage,
            // }
        }
    };

    Ok(resultat)
}

async fn requete_get_corbeille<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_corbeille Message : {:?}", & m.type_message);
    let requete: RequetePlusRecente = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("grosfichiers.consommer_commande: User_id absent du certificat pour commande {:?}", m.type_message))?
    };
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_activite_recente_2")))
        .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
        .limit(limit)
        .skip(skip)
        .build();
    let filtre = doc!{
        CHAMP_USER_ID: &user_id,
        "$or": [
            {CHAMP_SUPPRIME: true},
            {CHAMP_SUPPRIME_INDIRECT: true}
        ]
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct RowPartageContactOwned {
    contact_id: String,
    contact_user_id: String,
    user_id: String,
}

async fn get_contacts_user<M,U>(middleware: &M, user_id: U) -> Result<Vec<RowPartageContactOwned>, CommonError>
    where M: MongoDao, U: AsRef<str>
{
    let user_id = user_id.as_ref();

    let mut contacts = Vec::new();
    let collection = middleware.get_collection_typed::<RowPartageContactOwned>(
        NOM_COLLECTION_PARTAGE_CONTACT)?;
    let filtre = doc! { CHAMP_CONTACT_USER_ID: user_id };
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        contacts.push(row);
    }

    Ok(contacts)
}

#[derive(Deserialize)]
struct RowPartageContactBorrowed<'a> {
    #[serde(borrow)]
    contact_id: &'a str,
    #[serde(borrow)]
    contact_user_id: &'a str,
    #[serde(borrow)]
    user_id: &'a str,
}

#[derive(Deserialize)]
struct RowPartageCollection<'a> {
    #[serde(borrow)]
    contact_id: &'a str,
    #[serde(borrow)]
    tuuid: &'a str,
    #[serde(borrow)]
    user_id: &'a str,
}

async fn get_tuuids_partages_user<M,U>(middleware: &M, user_id: U) -> Result<Vec<String>, CommonError>
    where M: MongoDao, U: AsRef<str>
{
    let mut tuuids_partages = Vec::new();

    let user_id = user_id.as_ref();

    let mut contact_ids = Vec::new();
    let collection = middleware.get_collection_typed::<RowPartageContactBorrowed>(
        NOM_COLLECTION_PARTAGE_CONTACT)?;
    let filtre = doc! { CHAMP_CONTACT_USER_ID: user_id };
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        contact_ids.push(row.contact_id.to_string());
    }

    let filtre = doc! { CHAMP_CONTACT_ID: {"$in": contact_ids} };
    let collection = middleware.get_collection_typed::<RowPartageCollection>(
        NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        tuuids_partages.push(row.tuuid.to_string());
    }

    Ok(tuuids_partages)
}

async fn requete_get_cles_fichiers<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_cles_fichiers Message : {:?}", &m.type_message);
    let requete: ParametresGetPermission = {
        let message_ref = m.message.parse()?;
        match message_ref.contenu()?.deserialize() {
            Ok(inner) => inner,
            Err(e) => {
                error!("requete_get_cles_fichiers Erreur mapping message\n{}", from_utf8(m.message.buffer.as_slice())?);
                Err(e)?
            }
        }
    };

    // Faire une requete pour confirmer que l'usager a acces aux fuuids
    let mut filtre_and = vec![
        doc!{"$or":[
            {CHAMP_FUUIDS_VERSIONS: { "$in": &requete.fuuids }},
            {"metadata.ref_hachage_bytes": { "$in": &requete.fuuids }},
            {"metadata.cle_id": { "$in": &requete.fuuids }},
        ]}
    ];

    let mut filtre = doc! {};

    if let Some(tuuids) = requete.tuuids {
        filtre.insert("tuuid".to_string(), doc!{"$in": tuuids});
    }

    if let Some(user_id) = m.certificat.get_user_id()? {
        if Some(true) == requete.partage {
            // Requete de cles sur partage - permettre de charger les tuuids de tous les partages
            let tuuids_partages = get_tuuids_partages_user(middleware, user_id.as_str()).await?;
            filtre_and.push(doc!{"$or": [
                doc!{CHAMP_PATH_CUUIDS: {"$in": &tuuids_partages}},
                doc!{CHAMP_TUUID: {"$in": tuuids_partages}}
            ]});
        } else {
           filtre.insert(CHAMP_USER_ID, user_id);
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L4Secure])? && m.certificat.verifier_roles(vec![RolesCertificats::Media])? {
        // Ok, aucunes limitations
    } else if m.certificat.verifier_exchanges(vec![Securite::L2Prive])? && m.certificat.verifier_roles(vec![RolesCertificats::Stream])? {
        // filtre.insert(CHAMP_MIMETYPE, doc! {"mimetype": {"$regex": "video\\/"}} );
        filtre.insert(CHAMP_MIMETYPE, doc! {
            "mimetype": {
                "$or": [
                    {"$regex": "video\\/"},
                    "application/vnd\\.rn-realmedia",
		            "application/vnd\\.rn-realplayer",
		            "application/x-mplayer2",
		            "application/x-shockwave-flash"
                ]
            }
        });
    } else {
        return Ok(Some(middleware.reponse_err(None, None, Some("user_id n'est pas dans le certificat/certificat n'est pas de role media/stream"))?))
        // return Ok(Some(middleware.formatter_reponse(
        //     json!({"err": true, "message": "user_id n'est pas dans le certificat/certificat n'est pas de role media/stream"}),
        //     None)?)
        // )
    }

    // Ajouter section $and au filtre suite au ajouts pour le partage
    filtre.insert("$and", filtre_and);

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage = m.certificat.chaine_pem()?;

    debug!("requete_get_cles_fichiers Filtre : {:?}", serde_json::to_string(&filtre)?);
    let projection = doc! { CHAMP_FUUIDS_VERSIONS: true, CHAMP_TUUID: true, CHAMP_METADATA: true };
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection_typed::<ResultatDocsPermission>(
        NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre.clone(), Some(opts)).await?;

    let liste_cle_ids = match requete.cle_ids {
        Some(inner) => inner,
        None => match requete.fuuids {
            Some(inner) => inner,
            None => {
                warn!("requete_get_cles_fichiers Aucun cle_ids ni fuuids dans la requete");
                return Ok(Some(middleware.reponse_err(1, None, Some("Aucune cle_ids ni fuuids recus"))?))
            }
        }
    };

    let mut cle_ids_demandes = HashSet::new();
    cle_ids_demandes.extend(liste_cle_ids.iter().map(|s|s.as_str()));

    let mut cle_ids_approuves = Vec::new();
    while curseur.advance().await? {
    // while let Some(fresult) = curseur.next().await {
        let doc_mappe = curseur.deserialize_current()?;
        debug!("requete_get_cles_fichiers document trouve pour permission cle : {:?}", doc_mappe);
        // let doc_mappe: ResultatDocsPermission = convertir_bson_deserializable(fresult?)?;
        if let Some(fuuids) = doc_mappe.fuuids_versions {
            for d in fuuids {
                if cle_ids_demandes.remove(d) {
                    cle_ids_approuves.push(d.to_owned());
                }
            }
        }
        if let Some(metadata) = doc_mappe.metadata {
            if let Some(ref_hachage_bytes) = metadata.ref_hachage_bytes {
                if cle_ids_demandes.remove(ref_hachage_bytes) {
                    cle_ids_approuves.push(ref_hachage_bytes.to_owned());
                }
            }
            if let Some(cle_id) = metadata.cle_id {
                if cle_ids_demandes.remove(cle_id) {
                    cle_ids_approuves.push(cle_id.to_owned());
                }
            }
        }
    }

    if cle_ids_demandes.len() > 0 {
        warn!("requete_get_cles_fichiers Acces cles suivantes refuse pour user_id {:?} (partage: {:?}) : {:?}\nFiltre: {:?}",
            m.certificat.get_user_id()?, requete.partage, cle_ids_demandes, serde_json::to_string(&filtre));
    }

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(cle_ids_approuves),
        certificat_rechiffrage: Some(pem_rechiffrage),
        inclure_signature: None,
    };

    // Emettre requete de rechiffrage de cle, reponse acheminee directement au demandeur
    let (reply_to, correlation_id) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_to = match r.reply_to.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_get_permission Reply_to manquant"))?
            };
            let correlation_id = match r.correlation_id.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_get_permission Correlation_id manquant"))?
            };
            (reply_to, correlation_id)
        }
        _ => {
            Err(CommonError::Str("requetes.requete_get_permission Mauvais type message, doit etre requete"))?
        }
    };

    let routage = match requete.version {
        Some(2) => {
            RoutageMessageAction::builder(
                DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
                .reply_to(reply_to)
                .correlation_id(correlation_id)
                .blocking(false)
                .build()
        },
        None | Some(1) => {
            RoutageMessageAction::builder(
                DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE, vec![Securite::L3Protege])
                .reply_to(reply_to)
                .correlation_id(correlation_id)
                .blocking(false)
                .build()
        },
        _ => Err(Error::Str("Version de reponse non supportee"))?
    };

    debug!("Transmettre requete permission dechiffrage cle Routage {:?}\n{:?}", routage, permission);

    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

async fn requete_get_cles_stream<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_get_cles_stream Message : {:?}", &m.type_message);
    let requete: ParametresGetClesStream = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Stream])? {
        // let reponse = json!({"err": true, "message": "certificat doit etre de role stream"});
        // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, None, Some("certificat doit etre de role stream"))?))
    }

    let jwt_token = match requete.jwt {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": true, "message": "jwt absent"});
            // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("jwt absent"))?))
        }
    };

    let resultat_jwt = verify_jwt(middleware, jwt_token.as_str()).await?;

    let user_id = match resultat_jwt.user_id {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": true, "message": "jwt invalide - user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("jwt invalide - user_id manquant"))?))
        }
    };
    let fuuid = match resultat_jwt.fuuid {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": true, "message": "jwt invalide - subject (sub) manquant"});
            // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("jwt invalide - subject (sub) manquant"))?))
        }
    };

    // let user_id = requete.user_id;

    // let mut hachage_bytes = Vec::new();
    // let mut hachage_bytes_demandes = HashSet::new();
    // hachage_bytes_demandes.extend(requete.fuuids.iter().map(|f| f.to_string()));

    let filtre = doc!{
        "fuuids": { "$in": vec![&fuuid] },
        "user_id": &user_id,
        "$or": [
            {"mimetype": {"$regex": "(video\\/|audio\\/)"}},
            {"mimetype": {"$in": [
                "application/vnd.rn-realmedia",
                "application/vnd.rn-realplayer",
                "application/x-mplayer2",
                "application/x-shockwave-flash"
            ]}}
        ]
    };

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage = m.certificat.chaine_pem()?;

    debug!("requete_get_cles_stream Filtre : {:?}", filtre);
    let projection = doc! { CHAMP_FUUID: true, CHAMP_FUUIDS: true, CHAMP_METADATA: true, "cle_id": true };
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection_typed::<ResultatDocsVersionsFuuidsBorrow>(
        NOM_COLLECTION_VERSIONS)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes_demandes = HashSet::new();
    hachage_bytes_demandes.extend(requete.fuuids.iter().map(|f| f.to_string()));
    let mut hachage_bytes = Vec::new();
    while curseur.advance().await? {
        let doc_mappe = curseur.deserialize_current()?;
        debug!("requete_get_cles_stream document trouve pour permission cle : {:?}", doc_mappe);
        match doc_mappe.cle_id {
            Some(inner) => {
                // Nouvelle approche chiffrage V2
                hachage_bytes.push(inner.to_owned());
            },
            None => {
                // Ancienne approche
                // let doc_mappe: ResultatDocsPermission = convertir_bson_deserializable(fresult?)?;
                if let Some(fuuids) = doc_mappe.fuuids {
                    for d in fuuids {
                        if hachage_bytes_demandes.remove(d) {
                            hachage_bytes.push(d.to_owned());
                        }
                    }
                }
                if let Some(metadata) = doc_mappe.metadata {
                    if let Some(ref_hachage_bytes) = metadata.ref_hachage_bytes {
                        if hachage_bytes_demandes.remove(ref_hachage_bytes) {
                            hachage_bytes.push(ref_hachage_bytes.to_owned());
                        }
                    }
                }
            }
        }
    }

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(hachage_bytes),
        certificat_rechiffrage: Some(pem_rechiffrage),
        inclure_signature: None,
    };

    // let permission = json!({
    //     "liste_hachage_bytes": hachage_bytes,
    //     "certificat_rechiffrage": pem_rechiffrage,
    // });

    // Emettre requete de rechiffrage de cle, reponse acheminee directement au demandeur
    let (reply_to, correlation_id) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_to = match r.reply_to.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_recherche_index Reply_to manquant"))?
            };
            let correlation_id = match r.correlation_id.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_recherche_index Correlation_id manquant"))?
            };
            (reply_to, correlation_id)
        }
        _ => {
            Err(CommonError::Str("requetes.requete_recherche_index Mauvais type message, doit etre requete"))?
        }
    };

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    debug!("requete_get_cles_stream Transmettre requete permission dechiffrage cle : {:?}", permission);

    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

async fn mapper_fichiers_resultat<M>(middleware: &M, resultats: Vec<ResultatHitsDetail>, user_id: Option<String>)
    -> Result<Vec<ResultatDocumentRecherche>, CommonError>
    where M: MongoDao
{
    // Generer liste de tous les fichiers par version
    let (resultat_par_fuuid, fuuids) = {
        let mut map = HashMap::new();
        let mut fuuids = Vec::new();
        for r in &resultats {
            map.insert(r.id_.as_str(), r);
            fuuids.push(r.id_.clone());
        }
        (map, fuuids)
    };

    debug!("requete.mapper_fichiers_resultat resultat par fuuid : {:?}", resultat_par_fuuid);

    let mut fichiers_par_tuuid = {
        let mut filtre = doc! { CHAMP_FUUIDS: {"$in": &fuuids} };
        if user_id.is_some() {
            filtre.insert(String::from("user_id"), user_id.expect("user_id"));
        }
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection.find(filtre, None).await?;

        let mut fichiers: HashMap<String, Vec<ResultatDocumentRecherche>> = HashMap::new();
        while let Some(c) = curseur.next().await {
            // let fichier: DBFichierVersionDetail = convertir_bson_deserializable(c?)?;
            let fcurseur = c?;
            let fichier = mapper_fichier_db(fcurseur)?;

            if fichier.fuuid_v_courante.is_none() {
                warn!("Fichier tuuid={} sans fuuid_v_courante", fichier.tuuid);
                continue  // Skip le mapping
            }

            let fuuid = match fichier.fuuid_v_courante.as_ref() {
                Some(f) => f.to_owned(),
                None => {
                    warn!("mapper_fichiers_resultat Erreur mapping fichier tuuid={} sans fuuid", fichier.tuuid);
                    continue;
                }
            };

            let resultat = resultat_par_fuuid.get(fuuid.as_str()).expect("resultat");
            // let fichier_resultat = ResultatDocumentRecherche::new(fichier, *resultat)?;
            let fichier_resultat = match ResultatDocumentRecherche::new_fichier(fichier, *resultat) {
                Ok(fichier_resultat) => fichier_resultat,
                Err(e) => {
                    warn!("mapper_fichiers_resultat Erreur mapping fichier fuuid={}: {:?}", fuuid, e);
                    continue  // Skip le mapping
                }
            };
            let tuuid = fichier_resultat.tuuid.clone();
            match fichiers.get_mut(&tuuid) {
                Some(mut inner) => { inner.push(fichier_resultat); },
                None => { fichiers.insert(tuuid, vec![fichier_resultat]); }
            }

        }

        fichiers
    };

    debug!("requete.mapper_fichiers_resultat Fichiers par tuuid : {:?}", fichiers_par_tuuid);

    // Charger les details "courants" pour les fichiers
    {
        let tuuids: Vec<String> = fichiers_par_tuuid.keys().map(|k| k.clone()).collect();
        let filtre = doc! { CHAMP_TUUID: {"$in": tuuids} };
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(c) = curseur.next().await {
            let fichier: FichierDetail = convertir_bson_deserializable(c?)?;
            let tuuid = &fichier.tuuid;
            if let Some(mut fichier_resultat) = fichiers_par_tuuid.get_mut(tuuid) {
                for f in fichier_resultat {
                    f.nom = fichier.nom.clone();
                    f.titre = fichier.titre.clone();
                    f.description = fichier.description.clone();
                    f.date_creation = fichier.date_creation.clone();
                    f.date_modification = fichier.derniere_modification.clone();
                }
            }
        }
    };

    // Generer liste de fichiers en reponse, garder l'ordre des fuuid
    let mut fichiers_par_fuuid: HashMap<String, ResultatDocumentRecherche> = HashMap::new();
    for (_, vec_fichiers) in fichiers_par_tuuid.into_iter() {
        for f in vec_fichiers {
            fichiers_par_fuuid.insert(f.fuuid.clone(), f);
        }
    }

    let mut liste_reponse = Vec::new();
    for fuuid in &fuuids {
        if let Some(f) = fichiers_par_fuuid.remove(fuuid) {
            liste_reponse.push(f);
        }
    }

    debug!("requete.mapper_fichiers_resultat Liste response hits : {:?}", liste_reponse);

    Ok(liste_reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocumentRecherche {
    tuuid: String,
    fuuid: String,
    nom: Option<String>,
    supprime: Option<bool>,
    archive: Option<bool>,
    nom_version: Option<String>,
    taille: u64,
    mimetype: String,
    date_creation: Option<DateTime<Utc>>,
    date_modification: Option<DateTime<Utc>>,
    date_version: Option<DateTime<Utc>>,
    titre: Option<HashMap<String, String>>,
    description: Option<HashMap<String, String>>,

    version_courante: Option<DBFichierVersionDetail>,

    // Thumbnail
    thumb_hachage_bytes: Option<String>,
    thumb_data: Option<String>,

    // Info recherche
    score: f32,
}

impl ResultatDocumentRecherche {
    fn new(value: DBFichierVersionDetail, resultat: &ResultatHitsDetail) -> Result<Self, CommonError> {

        let (thumb_hachage_bytes, thumb_data) = match value.images {
            Some(mut images) => {
                match images.remove("thumb") {
                    Some(inner) => {
                        (Some(inner.hachage), inner.data_chiffre)
                    },
                    None => (None, None)
                }
            },
            None => (None, None)
        };

        Ok(ResultatDocumentRecherche {
            tuuid: value.tuuid.expect("tuuid"),
            fuuid: value.fuuid.expect("fuuid"),
            nom: value.nom.clone(),
            supprime: None,
            archive: None,
            nom_version: value.nom,
            taille: value.taille as u64,
            mimetype: value.mimetype,
            date_creation: None,
            date_modification: None,
            date_version: value.date_fichier,
            titre: None,
            description: None,

            version_courante: None,

            // Thumbnail
            thumb_hachage_bytes,
            thumb_data,

            // Info recherche
            score: resultat.score,
        })
    }

    fn new_fichier(value: FichierDetail, resultat: &ResultatHitsDetail) -> Result<Self, CommonError> {

        let (thumb_hachage_bytes, thumb_data, mimetype, taille) = match &value.version_courante {
            Some(v) => {
                let taille = v.taille as u64;
                let mimetype = v.mimetype.to_owned();
                match &v.images {
                    Some(images) => {
                        match images.get("thumb") {
                            Some(inner) => {
                                (Some(inner.hachage.clone()), inner.data_chiffre.clone(), mimetype, taille)
                            },
                            None => (None, None, mimetype, taille)
                        }
                    },
                    None => (None, None, mimetype, taille)
                }
            },
            None => (None, None, String::from("application/data"), 0)
        };

        let fuuid = match value.fuuid_v_courante { Some(t) => t, None => Err(format!("Resultat sans tuuid"))? };

        let date_version = match value.derniere_modification {
            Some(d) => d,
            None => Err(format!("Resultat sans date de derniere_modification"))?
        };

        Ok(ResultatDocumentRecherche {
            tuuid: value.tuuid,
            fuuid,
            nom: value.nom.clone(),
            supprime: value.supprime,
            archive: value.archive,
            nom_version: value.nom,
            taille,
            mimetype,
            date_creation: value.date_creation,
            date_modification: Some(date_version.clone()),
            date_version: Some(date_version),
            titre: value.titre,
            description: value.description,

            version_courante: value.version_courante,

            // Thumbnail
            thumb_hachage_bytes,
            thumb_data,

            // Info recherche
            score: resultat.score,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParTuuids {
    tuuids_documents: Vec<String>,
    partage: Option<bool>,       // Flag qui indique qu'on utilise une permission (contact partage)
    contact_id: Option<String>,  // Identificateur de contact direct
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParFuuids {
    fuuids_documents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteVerifierAccesFuuids {
    user_id: Option<String>,
    fuuids: Vec<String>,
    contact_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGenererJwtStreaming {
    fuuid: String,
    fuuid_ref: Option<String>,
    contact_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteContenuCollection {
    tuuid_collection: String,
    limit: Option<i64>,
    skip: Option<u64>,
    sort_keys: Option<Vec<SortKey>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SortKey {
    colonne: String,
    ordre: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocsPermission<'a> {
    tuuid: &'a str,
    #[serde(borrow)]
    fuuids_versions: Option<Vec<&'a str>>,
    #[serde(borrow)]
    metadata: Option<DataChiffreBorrow<'a>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocsVersionsFuuidsBorrow<'a> {
    fuuid: &'a str,
    fuuids: Option<Vec<&'a str>>,
    metadata: Option<DataChiffreBorrow<'a>>,
    cle_id: Option<&'a str>,
}

async fn requete_confirmer_etat_fuuids<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    if ! m.certificat.verifier_exchanges(vec![L2Prive, L3Protege, L4Secure])? {
        error!("requetes.requete_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", m.type_message);
        return Ok(None)
    }

    debug!("requete_confirmer_etat_fuuids Message : {:?}", & m.type_message);
    let requete: RequeteConfirmerEtatFuuids = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let mut fuuids = HashSet::new();
    for fuuid in &requete.fuuids {
        fuuids.insert(fuuid.clone());
    }

    let projection = doc! {
        "fuuids": 1,
        "supprime": 1,
    };

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .build();
    let mut filtre = doc!{"fuuids": {"$in": requete.fuuids}};

    let collection = middleware.get_collection_typed::<RowEtatFuuid>(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = Vec::new();
    let mut curseur = collection.find(filtre, opts).await?;
    //while let Some(d) = curseur.next().await {
    while curseur.advance().await? {
        // let record: RowEtatFuuid = convertir_bson_deserializable(d?)?;
        let row = curseur.deserialize_current()?;
        for fuuid in row.fuuids.into_iter() {
            if fuuids.remove(fuuid) {
            //if fuuids.contains(fuuid) {
            //    fuuids.remove(fuuid);
                fichiers_confirmation.push( ConfirmationEtatFuuid { fuuid: fuuid.to_owned(), supprime: row.supprime } );
            }
        }
    }

    // Ajouter tous les fuuids manquants (encore dans le set)
    // Ces fichiers sont inconnus et presumes supprimes
    for fuuid in fuuids.into_iter() {
        fichiers_confirmation.push( ConfirmationEtatFuuid { fuuid, supprime: true } );
    }

    let confirmation = ReponseConfirmerEtatFuuids { fichiers: fichiers_confirmation };
    let reponse = json!({ "confirmation": confirmation });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn verifier_acces_usager<M,S,T,V>(middleware: &M, user_id_in: S, fuuids_in: V)
    -> Result<Vec<String>, CommonError>
    where M: GenerateurMessages + MongoDao,
          S: AsRef<str>,
          T: AsRef<str>,
          V: AsRef<Vec<T>>
{
    let user_id = user_id_in.as_ref();
    let fuuids: Vec<&str> = fuuids_in.as_ref().iter().map(|s| s.as_ref()).collect();

    let mut filtre = doc! {
        CHAMP_FUUIDS: { "$in": &fuuids },
        CHAMP_USER_ID: user_id,
        CHAMP_SUPPRIME: false,
    };

    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection = middleware.get_collection_typed::<RowEtatFuuid>(NOM_COLLECTION_VERSIONS)?;
    let options = FindOptions::builder()
        .projection(doc!{CHAMP_FUUIDS: 1, CHAMP_SUPPRIME: 1})
        //.projection(doc!{CHAMP_FUUIDS: 1})
        .hint(Hint::Name("Versions_fuuids".into()))
        .build();
    let mut curseur = collection.find(filtre, Some(options)).await?;

    let mut fuuids_acces = HashSet::new();

    //while let Some(row) = curseur.next().await {
    while curseur.advance().await? {
        let doc_map = curseur.deserialize_current()?;
        // let doc_row = row?;
        // let doc_map: RowEtatFuuid = convertir_bson_deserializable(doc_row)?;
        fuuids_acces.extend(doc_map.fuuids.into_iter().map(|s| s.to_owned()));
    }

    let hashset_requete = HashSet::from_iter(fuuids);
    let mut hashset_acces = HashSet::new();
    for fuuid in &fuuids_acces {
        hashset_acces.insert(fuuid.as_str());
    }

    let resultat: Vec<&&str> = hashset_acces.intersection(&hashset_requete).collect();

    // String to_owned
    Ok(resultat.into_iter().map(|s| s.to_string()).collect())
}

pub async fn verifier_acces_usager_tuuids<M,S,T,V>(middleware: &M, user_id_in: S, tuuids_in: V)
    -> Result<Vec<String>, CommonError>
    where M: GenerateurMessages + MongoDao,
          S: AsRef<str>,
          T: AsRef<str>,
          V: AsRef<Vec<T>>
{
    let user_id = user_id_in.as_ref();
    let tuuids: Vec<&str> = tuuids_in.as_ref().iter().map(|s| s.as_ref()).collect();

    let mut filtre = doc! {
        CHAMP_TUUID: { "$in": &tuuids },
        CHAMP_USER_ID: user_id,
        CHAMP_SUPPRIME: false,
    };

    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let collection = middleware.get_collection_typed::<RowEtatTuuid>(NOM_COLLECTION_FICHIERS_REP)?;
    let options = FindOptions::builder()
        .projection(doc!{CHAMP_TUUID: 1, CHAMP_SUPPRIME: 1})
        .hint(Hint::Name("fichiers_tuuid".into()))
        .build();
    let mut curseur = collection.find(filtre, Some(options)).await?;

    let mut tuuids_acces = HashSet::new();

    while curseur.advance().await? {
        let doc_map = curseur.deserialize_current()?;
        tuuids_acces.insert(doc_map.tuuid.to_owned());
    }

    let hashset_requete = HashSet::from_iter(tuuids);
    let mut hashset_acces = HashSet::new();
    for tuuid in &tuuids_acces {
        hashset_acces.insert(tuuid.as_str());
    }

    let resultat: Vec<&&str> = hashset_acces.intersection(&hashset_requete).collect();

    // String to_owned
    Ok(resultat.into_iter().map(|s| s.to_string()).collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseConfirmerEtatFuuids {
    fichiers: Vec<ConfirmationEtatFuuid>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowEtatFuuid<'a> {
    #[serde(borrow)]
    fuuids: Vec<&'a str>,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowEtatTuuid<'a> {
    #[serde(borrow)]
    tuuid: &'a str,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfirmationEtatFuuid {
    fuuid: String,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncCollection {
    cuuid: Option<String>,
    user_id: Option<String>,
    skip: Option<u64>,
    limit: Option<i64>,

    /// Contact_id du partage comme autorisation
    contact_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncIntervalle {
    user_id: Option<String>,
    // debut: DateTime<Utc>,
    // fin: Option<DateTime<Utc>>,
    skip: Option<u64>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSyncCuuids {
    user_id: Option<String>,
    skip: Option<u64>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichierSync {
    tuuid: String,
    // #[serde(with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification", skip_serializing)]
    // map_derniere_modification: DateTime<Utc>,
    #[serde(default,
    rename(deserialize="_mg-derniere-modification"),
    serialize_with = "optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    derniere_modification: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if="Option::is_none")]
    favoris: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    supprime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    supprime_indirect: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CuuidsSync {
    tuuid: String,
    // #[serde(with="millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime", rename="_mg-derniere-modification", skip_serializing)]
    // map_derniere_modification: DateTime<Utc>,
    #[serde(default,
    rename(deserialize="_mg-derniere-modification"),
    serialize_with = "optionepochseconds::serialize",
    deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    derniere_modification: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if="Option::is_none")]
    favoris: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    supprime: Option<bool>,
    metadata: DataChiffre,
    user_id: String,
    // cuuids: Option<Vec<String>>,
    cuuid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseRequeteSyncCollection {
    complete: bool,
    liste: Vec<FichierSync>
}

async fn requete_sync_collection<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_confirmer_etat_fuuids Message : {:?}", & m.type_message);
    let requete: RequeteSyncCollection = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = {
        match m.certificat.get_user_id()? {
            Some(u) => u,
            None => {
                if m.certificat.verifier_exchanges(vec![L3Protege, L4Secure])? {
                    match requete.user_id {
                        Some(u) => u,
                        None => {
                            error!("requete_sync_collection L3Protege/L4Secure user_id manquant");
                            return Ok(None)
                        }
                    }
                } else {
                    error!("requetes.requete_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", m.type_message);
                    return Ok(None)
                }
            }
        }
    };

    let user_id = if let Some(contact_id) = requete.contact_id {
        // Determiner le user_id effectif pour la requete en confirmant le droit d'acces via contact
        let filtre = doc!{ CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id };
        let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
        match collection.find_one(filtre, None).await? {
            Some(inner) => {
                inner.user_id   // User id du proprietaire des fichiers
            },
            None => {
                error!("requetes.requete_confirmer_etat_fuuids Acces refuse, mauvais contact_id : {:?}", m.type_message);
                return Ok(None)
            }
        }
    } else {
        user_id
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        // .hint(Hint::Name("fichiers_cuuid".into()))
        .build();

    let mut filtre = doc!{"user_id": user_id};
    match requete.cuuid {
        Some(cuuid) => {
            filtre.insert("path_cuuids.0", cuuid);
            // filtre.insert("$or", vec![
            //     doc!{ "cuuids": &cuuid},
            //     doc!{"cuuid": &cuuid }
            // ]);
        },
        None => {
            // Requete sur les Collections
            filtre.insert(CHAMP_TYPE_NODE, TypeNode::Collection.to_str());
            // filtre.insert("favoris", true);
        }
    }
    debug!("requete_sync_collection Filtre {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_fichiers(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCollection { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn requete_sync_corbeille<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_sync_corbeille Message : {:?}", & m.type_message);
    let requete: RequeteSyncIntervalle = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = {
        match m.certificat.get_user_id()? {
            Some(u) => u,
            None => {
                if m.certificat.verifier_exchanges(vec![L3Protege, L4Secure])? {
                    match requete.user_id {
                        Some(u) => u,
                        None => {
                            error!("requete_sync_corbeille L3Protege/L4Secure user_id manquant");
                            return Ok(None)
                        }
                    }
                } else {
                    error!("requetes.requete_sync_corbeille Acces refuse, certificat n'est pas d'un exchange L2+ : {:?}", m.type_message);
                    return Ok(None)
                }
            }
        }
    };

    let limit = requete.limit.unwrap_or_else(|| 1000);
    let skip = requete.skip.unwrap_or_else(|| 0);

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_CREATION: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
        CHAMP_SUPPRIME_INDIRECT: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        // .hint(Hint::Name("path_cuuids".into()))
        .build();
    // let date_debut = requete.debut.get_datetime();
    let filtre = doc! {"user_id": user_id, "supprime": true};

    debug!("requete_sync_corbeille Requete fichiers filtre : {:?}", filtre);

    let mut fichiers_confirmation = find_sync_fichiers(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCollection { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseRequeteSyncCuuids {
    complete: bool,
    liste: Vec<CuuidsSync>
}

async fn requete_sync_cuuids<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    let certificat = m.certificat.as_ref();

    if ! certificat.verifier_domaines(vec!["GrosFichiers".to_string()])? {
        error!("requete_sync_cuuids Permission refusee (domaines cert != GrosFichiers)");
        return Ok(None)
    }

    debug!("requete_sync_cuuids Message : {:?}", & m.type_message);
    let requete: RequeteSyncCuuids = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let sort = doc! {CHAMP_CREATION: 1, CHAMP_TUUID: 1};
    let projection = doc! {
        CHAMP_TUUID: 1,
        CHAMP_CREATION: 1,
        CHAMP_MODIFICATION: 1,
        CHAMP_FAVORIS: 1,
        CHAMP_SUPPRIME: 1,
        CHAMP_METADATA: 1,
        CHAMP_USER_ID: 1,
        CHAMP_CUUID: 1,
    };
    let opts = FindOptions::builder()
        .projection(projection)
        .sort(sort)
        .skip(skip)
        .limit(limit.clone())
        .build();

    let type_node_repertoire: &str = TypeNode::Repertoire.into();
    let type_node_collection: &str = TypeNode::Collection.into();
    let mut filtre = doc! {
        "type_node": {"$in": [type_node_repertoire, type_node_collection]},
        "supprime": false,
        "metadata": {"$exists": true}
    };

    debug!("requete_sync_cuuids filtre : {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = find_sync_cuuids(middleware, filtre, opts).await?;
    let complete = fichiers_confirmation.len() < limit as usize;

    let reponse = ReponseRequeteSyncCuuids { complete, liste: fichiers_confirmation };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn find_sync_fichiers<M>(middleware: &M, filtre: Document, opts: FindOptions) -> Result<Vec<FichierSync>, CommonError>
    where M: MongoDao
{
    let collection = middleware.get_collection_typed::<FichierSync>(NOM_COLLECTION_FICHIERS_REP)?;

    let mut curseur = collection.find(filtre, opts).await?;
    let mut fichiers_confirmation = Vec::new();
    // while let Some(d) = curseur.next().await {
    while curseur.advance().await? {
        let mut row = curseur.deserialize_current()?;
        // let mut record: FichierSync = convertir_bson_deserializable(d?)?;
        // row.derniere_modification = Some(row.map_derniere_modification.clone());
        fichiers_confirmation.push(row);
    }

    Ok(fichiers_confirmation)
}

async fn find_sync_cuuids<M>(middleware: &M, filtre: Document, opts: FindOptions) -> Result<Vec<CuuidsSync>, CommonError>
    where M: MongoDao
{
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let mut curseur = collection.find(filtre, opts).await?;
    let mut cuuids_confirmation = Vec::new();
    while let Some(d) = curseur.next().await {
        let mut record: CuuidsSync = convertir_bson_deserializable(d?)?;
        // record.derniere_modification = Some(record.map_derniere_modification.clone());
        cuuids_confirmation.push(record);
    }

    Ok(cuuids_confirmation)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteChargerContacts {}

#[derive(Deserialize)]
pub struct ContactRow { pub contact_id: String, pub user_id: String, pub contact_user_id: String }

#[derive(Serialize, Deserialize)]
struct ReponseUsager {
    #[serde(rename(deserialize = "userId"))]
    user_id: String,
    #[serde(rename(deserialize = "nomUsager"))]
    nom_usager: String,
}

#[derive(Deserialize)]
struct ReponseUsagers {
    usagers: Vec<ReponseUsager>,
}

#[derive(Serialize)]
struct ReponseContact {
    #[serde(rename(deserialize = "contactId"))]
    contact_id: String,
    #[serde(rename(deserialize = "userId"))]
    user_id: String,
    #[serde(rename(deserialize = "nomUsager"))]
    nom_usager: String,
}

#[derive(Serialize)]
struct ReponseContacts {
    contacts: Vec<ReponseContact>,
}

async fn map_user_ids_nom_usager<M,U>(middleware: &M, user_ids_in: &Vec<U>) -> Result<Vec<ReponseUsager>, CommonError>
    where M: GenerateurMessages, U: AsRef<str>
{
    let user_ids: Vec<&str> = user_ids_in.iter().map(|s| s.as_ref()).collect();
    debug!("map_user_ids_nom_usager Pour user_ids {:?}", user_ids);

    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCOMPTES, "getListeUsagers", vec![Securite::L3Protege])
        .build();

    let requete = json!({"liste_userids": user_ids});
    let reponse = match middleware.transmettre_requete(routage, &requete).await? {
        Some(inner) => match inner {
            TypeMessage::Valide(inner) => {
                let reponse_ref = inner.message.parse()?;
                let reponse: ReponseUsagers = reponse_ref.contenu()?.deserialize()?;
                reponse
            },
            _ => {
                debug!("requete_charger_contacts Mauvais type de reponse");
                Err(format!("requetes.map_user_ids_nom_usager Erreur chargement liste usagers"))?
            }
        },
        None => {
            debug!("requete_charger_contacts Aucune reponse");
            Err(format!("requetes.map_user_ids_nom_usager Erreur chargement liste usagers"))?
        }
    };

    Ok(reponse.usagers)
}

async fn requete_charger_contacts<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_charger_contacts Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_charger_contacts user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let commande: RequeteChargerContacts = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let contacts = {
        let mut user_ids = HashMap::new();
        let filtre = doc! { CHAMP_USER_ID: &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(d) = curseur.next().await {
            let row: ContactRow = convertir_bson_deserializable(d?)?;
            user_ids.insert(row.contact_user_id.clone(), row);
        }

        // Faire une requete aupres de MaitreDesComptes pour mapper le user_id avec le nom_usager courant
        let vec_user_ids: Vec<&String> = user_ids.keys().map(|u|u).collect();
        let reponse_usagers = map_user_ids_nom_usager(middleware, &vec_user_ids).await?;

        // Mapper contact_id et nom_usager
        let mut contacts = Vec::new();
        for usager in reponse_usagers {
            let contact_id = match user_ids.remove(usager.user_id.as_str()) {
                Some(inner) => {
                    inner.contact_id
                },
                None => {
                    debug!("Mismatch user_id {}, SKIP", usager.user_id);
                    continue;
                }
            };
            let contact = ReponseContact {
                contact_id,
                user_id: usager.user_id,
                nom_usager: usager.nom_usager,
            };
            contacts.push(contact);
        }

        contacts
    };

    let reponse = ReponseContacts { contacts };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct RequetePartagesUsager { contact_id: Option<String> }

#[derive(Serialize, Deserialize)]
struct RowPartagesUsager {
    tuuid: String,
    user_id: String,
    contact_id: String,
}

#[derive(Serialize)]
struct ReponsePartagesUsager {
    ok: bool,
    partages: Vec<RowPartagesUsager>,
    usagers: Option<Vec<ReponseUsager>>,
}

async fn requete_partages_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_partages_usager Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_partages_usager user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequetePartagesUsager = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let mut filtre = doc! { CHAMP_USER_ID: &user_id };
    if let Some(inner) = requete.contact_id.as_ref() {
        filtre.insert(CHAMP_CONTACT_ID, inner );
    }
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut partages = Vec::new();
    while let Some(r) = curseur.next().await {
        let row: RowPartagesUsager = convertir_bson_deserializable(r?)?;
        partages.push(row);
    }

    let reponse = ReponsePartagesUsager { ok: true, partages, usagers: None };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequetePartagesContact { user_id: Option<String> }

/// Retourne la liste de tuuids partages avec l'usager qui fait la requete
async fn requete_partages_contact<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_partages_usager Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_partages_usager user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequetePartagesContact = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // Charger la liste des contact_id qui correspondent a l'usager courant
    let contacts = get_contacts_user(middleware, user_id).await?;

    // Faire une requete pour obtenir tous les partages associes aux contacts
    let contact_ids: Vec<&str> = contacts.iter().map(|c| c.contact_id.as_str()).collect();
    let filtre = doc! {
        CHAMP_CONTACT_ID: { "$in": contact_ids },
    };
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
    let mut curseur = collection.find(filtre, None).await?;
    let partages = {
        let mut partages = Vec::new();
        while let Some(r) = curseur.next().await {
            let row: RowPartagesUsager = convertir_bson_deserializable(r?)?;
            partages.push(row);
        }
        partages
    };

    // Faire une requete pour obtenir l'information des usagers. Dedupe avec HashSet
    let mut user_ids = HashSet::new();
    user_ids.extend(partages.iter().map(|s| s.user_id.as_str()));
    let user_ids: Vec<&str> = user_ids.into_iter().collect();

    let usagers = map_user_ids_nom_usager(middleware, &user_ids).await?;

    let reponse = ReponsePartagesUsager { ok: true, partages, usagers: Some(usagers) };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteInfoStatistiques {
    /// Collection / repertoire a utiliser comme top de l'arborescence
    cuuid: Option<String>,
    contact_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ResultatStatistiquesRow {
    #[serde(alias="_id")]
    type_node: String,
    taille: usize,
    count: usize,
}

#[derive(Serialize)]
struct ReponseInfoStatistiques {
    info: Vec<ResultatStatistiquesRow>,
}

async fn requete_info_statistiques<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_info_statistiques Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_info_statistiques user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequeteInfoStatistiques = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let user_id = if let Some(contact_id) = requete.contact_id {
        // Determiner le user_id effectif pour la requete en confirmant le droit d'acces via contact
        let filtre = doc!{ CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id };
        let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
        match collection.find_one(filtre, None).await? {
            Some(inner) => {
                inner.user_id   // User id du proprietaire des fichiers
            },
            None => {
                error!("requetes.requete_verifier_acces_fuuids Acces refuse, mauvais contact_id");
                return Ok(None)
            }
        }
    } else {
        user_id
    };

    let filtre = match requete.cuuid.as_ref() {
        Some(cuuid) => {
            doc! {
                CHAMP_USER_ID: &user_id,
                CHAMP_SUPPRIME: false,
                CHAMP_SUPPRIME_INDIRECT: false,
                "$or": [
                    {CHAMP_TUUID: cuuid},
                    {CHAMP_PATH_CUUIDS: cuuid}
                ]
            }
        },
        None => doc! {
            CHAMP_USER_ID: &user_id,
            CHAMP_SUPPRIME: false,
            CHAMP_SUPPRIME_INDIRECT: false,
        }
    };

    let pipeline = vec![
        doc! { "$match": filtre },
        doc! { "$project": {CHAMP_TYPE_NODE: 1, CHAMP_PATH_CUUIDS: 1, CHAMP_FUUIDS_VERSIONS: 1} },
        doc! { "$lookup": {
            "from": NOM_COLLECTION_VERSIONS,
            "localField": "fuuids_versions",
            "foreignField": "fuuid",
            // "let": { "fuuid": "zSEfXUAKuWwK4NeWAGX573uCTCCG4xak1DEWCzk4JqcRjc6h25d2ov74c93pATRxbcCxQToY7kU3drygxWREuRkb7MCKET" },
            "pipeline": [
                // {"$match": { CHAMP_USER_ID: &user_id, CHAMP_FUUID: "$fuuid"}},
                {"$match": { CHAMP_USER_ID: &user_id }},
                {"$project": {CHAMP_TAILLE: 1, CHAMP_USER_ID: 1, CHAMP_FUUID: 1}},
                { "$group": {
                        "_id": "$user_id",
                        "taille": {"$sum": "$taille"}
                    }
                }
            ],
            "as": "versions",
        }},
        doc! { "$replaceRoot": { "newRoot": {"$mergeObjects": [ {"$arrayElemAt": ["$versions", 0] }, "$$ROOT" ]}}},
        doc! { "$group": {
                "_id": "$type_node",
                "taille": {"$sum": "$taille"},
                "count": {"$count": {}},
            }
        }
    ];

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut cursor = collection.aggregate(pipeline, None).await?;
    let mut resultat = Vec::new();
    while let Some(d) = cursor.next().await {
        let data = d?;
        // debug!("Data : {:?}", data);
        let row: ResultatStatistiquesRow = convertir_bson_deserializable(data)?;
        resultat.push(row);
    }

    let reponse = ReponseInfoStatistiques { info: resultat };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteStructureRepertoire {
    cuuid: Option<String>,
    // limite_bytes: Option<u64>,
    limite_nombre: Option<u64>,
    contact_id: Option<String>,
}

// #[derive(Serialize)]
// struct ReponseStructureRepertoireItem {
//     tuuid: String,
//     type_node: String,
//     metadata: DataChiffre,
//     path_cuuids: Option<Vec<String>>,
//     fuuids_versions: Option<Vec<String>>,
// }
//
// impl<'a> From<NodeFichierRepBorrowed<'a>> for ReponseStructureRepertoireItem {
//     fn from(value: NodeFichierRepBorrowed<'a>) -> Self {
//         let path_cuuids = match value.path_cuuids {
//             Some(inner) => Some(inner.into_iter().map(|s| s.to_owned()).collect()),
//             None => None
//         };
//         let fuuids_versions = match value.fuuids_versions {
//             Some(inner) => Some(inner.into_iter().map(|s| s.to_owned()).collect()),
//             None => None,
//         };
//
//         Self {
//             tuuid: value.tuuid.to_owned(),
//             type_node: value.type_node.to_owned(),
//             metadata: value.metadata.into(),
//             path_cuuids,
//             fuuids_versions,
//         }
//     }
// }

#[derive(Serialize)]
struct ReponseStructureRepertoire {
    ok: bool,
    #[serde(skip_serializing_if="Option::is_none")]
    err: Option<String>,
    liste: Vec<NodeFichierRepVersionCouranteOwned>,
}

async fn requete_structure_repertoire<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_info_statistiques Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_info_statistiques user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequeteStructureRepertoire = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    // let limite_bytes = match requete.limite_bytes { Some(inner) => inner, None => CONST_LIMITE_TAILLE_ZIP};
    let limite_nombre = match requete.limite_nombre { Some(inner) => inner, None => CONST_LIMITE_NOMBRE_ZIP};

    let user_id = if let Some(contact_id) = requete.contact_id {
        // Determiner le user_id effectif pour la requete en confirmant le droit d'acces via contact
        let filtre = doc!{ CHAMP_CONTACT_ID: contact_id, CHAMP_CONTACT_USER_ID: &user_id };
        let collection = middleware.get_collection_typed::<ContactRow>(NOM_COLLECTION_PARTAGE_CONTACT)?;
        match collection.find_one(filtre, None).await? {
            Some(inner) => {
                inner.user_id   // User id du proprietaire des fichiers
            },
            None => {
                error!("requetes.requete_verifier_acces_fuuids Acces refuse, mauvais contact_id");
                return Ok(None)
            }
        }
    } else {
        user_id
    };

    let mut filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: false,
    };

    // Ajouter le filtre sur le cuuid (si cuuid est None, la requete est sur tous les fichiers)
    if let Some(cuuid) = requete.cuuid.as_ref() {
        filtre.insert("$or", vec![
            doc!{ CHAMP_PATH_CUUIDS: cuuid },
            doc!{ CHAMP_TUUID: cuuid }
        ]);
    }

    let pipeline = vec![
        doc! { "$match": filtre },
        doc! { "$project": {
            CHAMP_TUUID: 1, CHAMP_USER_ID: 1, CHAMP_TYPE_NODE: 1, CHAMP_PATH_CUUIDS: 1,
            CHAMP_FUUIDS_VERSIONS: 1, CHAMP_METADATA: 1, CHAMP_MIMETYPE: 1,
            CHAMP_SUPPRIME: 1, CHAMP_SUPPRIME_INDIRECT: 1,
        }},
        doc! { "$lookup": {
            "from": NOM_COLLECTION_VERSIONS,
            "localField": "fuuids_versions.0",
            "foreignField": "fuuid",
            // "let": { "fuuid": "zSEfXUAKuWwK4NeWAGX573uCTCCG4xak1DEWCzk4JqcRjc6h25d2ov74c93pATRxbcCxQToY7kU3drygxWREuRkb7MCKET" },
            "pipeline": [
                // {"$match": { CHAMP_USER_ID: &user_id, CHAMP_FUUID: "$fuuid"}},
                {"$match": { CHAMP_USER_ID: &user_id }},
                {"$project": {
                    CHAMP_TAILLE: 1, CHAMP_USER_ID: 1, CHAMP_FUUID: 1,
                    // Dechiffrage V2
                    "cle_id": 1, "nonce": 1, "format": 1,
                }},
                // { "$group": {
                //         "_id": "$user_id",
                //         "taille": {"$sum": "$taille"}
                //     }
                // }
            ],
            "as": "versions",
        }},
        // doc! { "$replaceRoot": { "newRoot": {"$mergeObjects": [ {"$arrayElemAt": ["$version_courante", 0] }, "$$ROOT" ]}}},
    ];

    let mut reponse = ReponseStructureRepertoire { ok: true, err: None, liste: Vec::new() };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut cursor = collection.aggregate(pipeline, None).await?;
    while let Some(d) = cursor.next().await {
        let data = d?;
        debug!("Data : {:?}", data);
        let row: NodeFichierRepVersionCouranteOwned = convertir_bson_deserializable(data)?;
        debug!("Data row mappe : {:?}", row);
        reponse.liste.push(row);
    }

    // let options = FindOptions::builder()
    //     .projection(doc!{
    //         CHAMP_TUUID: 1, CHAMP_USER_ID: 1, CHAMP_TYPE_NODE: 1, CHAMP_PATH_CUUIDS: 1,
    //         CHAMP_FUUIDS_VERSIONS: 1, CHAMP_METADATA: 1,
    //         CHAMP_SUPPRIME: 1, CHAMP_SUPPRIME_INDIRECT: 1
    //     })
    //     .limit((limite_nombre + 1) as i64)
    //     .build();
    // let collection = middleware.get_collection_typed::<NodeFichierRepBorrowed>(NOM_COLLECTION_FICHIERS_REP)?;
    // let mut curseur = collection.find(filtre, options).await?;
    // while curseur.advance().await? {
    //     let row = curseur.deserialize_current()?;
    //     reponse.liste.push(row.into());
    // }

    let reponse = if reponse.liste.len() <= limite_nombre as usize {
        middleware.build_reponse(reponse)?.0
    } else {
        // On a depasser la limite, retourner une erreur
        reponse.liste.clear();
        reponse.err = Some("Limite nombre atteinte".into());
        reponse.ok = false;
        middleware.build_reponse(reponse)?.0
    };

    Ok(Some(reponse))
}

#[derive(Deserialize)]
struct RequeteSousRepertoires {
    cuuid: String,
    limite_nombre: Option<u64>,
}

#[derive(Serialize)]
struct ReponseSousRepertoires {
    ok: bool,
    #[serde(skip_serializing_if="Option::is_none")]
    err: Option<String>,
    cuuid: String,
    liste: Vec<NodeFichierRepOwned>,
}

async fn requete_sous_repertoires<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_sous_repertoires Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_sous_repertoires user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequeteSousRepertoires = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };

    let limite_nombre = match requete.limite_nombre { Some(inner) => inner, None => CONST_LIMITE_NOMBRE_SOUS_REPERTOIRES };

    let mut filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: false,
        CHAMP_TYPE_NODE: TypeNode::Repertoire.to_str(),
        CHAMP_PATH_CUUIDS: &requete.cuuid,
    };

    let mut reponse = ReponseSousRepertoires { ok: true, err: None, cuuid: requete.cuuid, liste: Vec::new() };
    let collection = middleware.get_collection_typed::<NodeFichierRepOwned>(NOM_COLLECTION_FICHIERS_REP)?;
    let limite_1 = (&limite_nombre + 1) as i64;
    let options = FindOptions::builder().limit(limite_1).build();
    let mut curseur = collection.find(filtre, options).await?;
    while curseur.advance().await? {
        let doc_rep = curseur.deserialize_current()?;
        reponse.liste.push(doc_rep);
    }

    let reponse = if reponse.liste.len() <= limite_nombre as usize {
        middleware.build_reponse(reponse)?.0
    } else {
        // On a depasser la limite, retourner une erreur
        reponse.liste.clear();
        reponse.err = Some("Limite nombre atteinte".into());
        reponse.ok = false;
        middleware.build_reponse(reponse)?.0
    };

    Ok(Some(reponse))
}

#[derive(Deserialize)]
struct RequeteRechercheIndex {
    query: String,
    start: Option<i64>,
    limit: Option<i64>,
    inclure_partages: Option<bool>,
}

#[derive(Serialize)]
struct TransfertRequeteRechercheIndex {
    user_id: String,
    query: String,
    start: Option<i64>,
    limit: Option<i64>,
    cuuids_partages: Option<Vec<String>>,
}

impl TransfertRequeteRechercheIndex {
    fn new<S>(user_id: S, value: RequeteRechercheIndex) -> Self
        where S: ToString
    {
        Self {
            user_id: user_id.to_string(),
            query: value.query,
            start: value.start,
            limit: value.limit,
            cuuids_partages: None
        }
    }
}

pub async fn requete_recherche_index<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_recherche_index Consommer commande : {:?}", & m.type_message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_recherche_index user_id manquant du certificat");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "User_id manquant du certificat"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let (reply_to, correlation_id) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_to = match r.reply_to.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_recherche_index Reply_to manquant"))?
            };
            let correlation_id = match r.correlation_id.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(CommonError::Str("requetes.requete_recherche_index Correlation_id manquant"))?
            };
            (reply_to, correlation_id)
        }
        _ => {
            Err(CommonError::Str("requetes.requete_recherche_index Mauvais type message, doit etre requete"))?
        }
    };

    let requete: RequeteRechercheIndex = {
        let message_ref = m.message.parse()?;
        message_ref.contenu()?.deserialize()?
    };
    let inclure_partages = match requete.inclure_partages.as_ref() { Some(true) => true, _ => false};

    let mut requete_transfert = TransfertRequeteRechercheIndex::new(
        &user_id, requete);

    // Recuperer la liste des partages si necessaire
    if inclure_partages {
        // Charger la liste des contact_id qui correspondent a l'usager courant
        let contacts = get_contacts_user(middleware, user_id).await?;

        // Faire une requete pour obtenir tous les partages associes aux contacts
        let contact_ids: Vec<&str> = contacts.iter().map(|c| c.contact_id.as_str()).collect();
        let filtre = doc! {CHAMP_CONTACT_ID: {"$in": contact_ids}};
        let collection = middleware.get_collection_typed::<RowPartagesUsager>(
            NOM_COLLECTION_PARTAGE_COLLECTIONS)?;
        let mut curseur = collection.find(filtre, None).await?;

        // Conserver les tuuids (cuuids partages)
        let mut cuuids = HashSet::new();
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            cuuids.insert(row.tuuid.to_owned());
        }

        // Convertir en vec
        let cuuids: Vec<String> = cuuids.into_iter().collect();
        requete_transfert.cuuids_partages = Some(cuuids);
    };

    let domaine: &str = RolesCertificats::SolrRelai.into();
    let action = "fichiers";
    let routage = RoutageMessageAction::builder(domaine, action, vec![Securite::L3Protege])
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();
    middleware.transmettre_requete(routage, &requete_transfert).await?;

    Ok(None)
}

#[derive(Deserialize)]
struct RequeteInfoVideo {fuuid: String}

#[derive(Serialize)]
struct RequeteInfoVideoResponse {
    fuuid: String,
    tuuid: String,
    audio: Option<Vec<NodeFichierVersionAudioOwned>>,
    subtitles: Option<Vec<NodeFichierVersionSubtitlesOwned>>,
}

async fn requete_info_video<M>(middleware: &M, m: MessageValide, gestionnaire: &GrosFichiersDomainManager)
                               -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            debug!("requete_recherche_index user_id manquant du certificat");
            return Ok(Some(middleware.reponse_err(None, None, Some("User_id manquant du certificat"))?))
        }
    };

    let requete: RequeteInfoVideo = deser_message_buffer!(m.message);

    let collection = middleware.get_collection_typed::<NodeFichierVersionOwned>(NOM_COLLECTION_VERSIONS)?;
    let filtre = doc!{"user_id": &user_id, "fuuid": &requete.fuuid};
    match collection.find_one(filtre, None).await? {
        Some(fichier) => {
            let response = RequeteInfoVideoResponse {
                fuuid: fichier.fuuid,
                tuuid: fichier.tuuid,
                audio: fichier.audio,
                subtitles: fichier.subtitles,
            };
            Ok(Some(middleware.build_reponse(response)?.0))
        },
        None => Ok(Some(middleware.reponse_err(Some(404), None, Some("File not found"))?))
    }
}

pub async fn get_decrypted_keys<M>(middleware: &M, cle_ids: Vec<String>) -> Result<Vec<ResponseRequestDechiffrageV2Cle>, CommonError>
    where M: GenerateurMessages
{
    let requete = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(cle_ids),
        certificat_rechiffrage: None,
        inclure_signature: None,
    };
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
    ).build();

    debug!("get_decrypted_keys Transmettre requete permission dechiffrage cle : {:?}", requete);
    let response_message = middleware.transmettre_requete(routage, &requete).await?;
    let decrypted_response = if let Some(TypeMessage::Valide(response)) = response_message {
        debug!("get_decrypted_keys Response\n{}", from_utf8(response.message.buffer.as_slice())?);
        let message_ref = response.message.parse()?;
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let decrypted_response: ReponseRequeteDechiffrageV2 = message_ref.dechiffrer(enveloppe_privee.as_ref())?;
        decrypted_response
    } else {
        Err(format!("get_decrypted_keys Error getting keys from keymaster: {:?}", response_message))?
    };

    match decrypted_response.cles {
        Some(cles) => Ok(cles),
        None => Err("get_decrypted_keys No keys were received")?
    }

    // let mut decrypted_key_response = Vec::new();
    // for key in keys {
    //     if let Some(cle_id) = key.cle_id {
    //         let key_info = InformationDechiffrageV2 {
    //             format: key.format.unwrap_or_else(|| FormatChiffrage::MGS4),
    //             cle_id,
    //             nonce: key.nonce,
    //             verification: key.verification,
    //             fuuid: None,
    //         };
    //         decrypted_key_response.push(key_info);
    //     }
    // }
    //
    // Ok(decrypted_key_response)
}
