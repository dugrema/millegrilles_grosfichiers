use std::collections::HashMap;
use std::error::Error;
use std::convert::{TryFrom, TryInto};

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::grosfichiers_constantes::*;
use crate::transactions::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    match message.verifier_exchanges(vec![Securite::L3Protege]) {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))
            }
        }
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
                REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
                REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
                REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
                REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn requete_activite_recente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_activite_recente Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu(None)?;
    debug!("requete_activite_recente cle parsed : {:?}", requete);
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
    let filtre = doc!{CHAMP_SUPPRIME: false};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn mapper_fichiers_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
    let mut fichiers_mappes = Vec::new();

    while let Some(fresult) = curseur.next().await {
        let fcurseur = fresult?;
        let fichier_db = mapper_fichier_db(fcurseur)?;
        let fichier_mappe: FichierVersionCourante = fichier_db.try_into()?;
        fichiers_mappes.push(fichier_mappe);
    }

    // Convertir fichiers en Value (serde pour reponse json)
    Ok(serde_json::to_value(fichiers_mappes)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequetePlusRecente {
    limit: Option<i64>,
    skip: Option<u64>,
}

fn mapper_fichier_db(fichier: Document) -> Result<FichierVersionCourante, Box<dyn Error>> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    let mut fichier_mappe: FichierVersionCourante = convertir_bson_deserializable(fichier)?;
    fichier_mappe.date_creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
    fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichierVersionCourante {
    tuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    cuuids: Option<Vec<String>>,
    nom: String,
    titre: Option<HashMap<String, String>>,

    fuuid_v_courante: Option<String>,
    version_courante: Option<DBFichierVersion>,

    favoris: Option<bool>,

    date_creation: Option<DateEpochSeconds>,
    derniere_modification: Option<DateEpochSeconds>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DBFichierVersion {
    nom_fichier: String,
    mimetype: String,
    taille: usize,
    #[serde(rename="dateFichier")]
    date_fichier: DateEpochSeconds,
    #[serde(skip_serializing_if="Option::is_none")]
    height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    weight: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    images: Option<HashMap<String, ImageConversion>>,
    #[serde(skip_serializing_if="Option::is_none")]
    anime: Option<bool>,

}

async fn requete_favoris<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_favoris Message : {:?}", & m.message);
    //let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let projection = doc! {CHAMP_NOM: true, CHAMP_TITRE: true, CHAMP_SECURITE: true, CHAMP_TUUID: true};
    let filtre = doc! { CHAMP_FAVORIS: true };
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
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Favoris {
    nom: String,
    tuuid: String,
    securite: Option<String>,
    // titre: Option<HashMap<String, String>>,
}

async fn requete_documents_par_tuuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.message);
    let requete: RequeteDocumentsParTuuids = m.message.get_msg().map_contenu(None)?;
    debug!("requete_documents_par_tuuid cle parsed : {:?}", requete);

    let filtre = doc! { CHAMP_TUUID: {"$in": &requete.tuuids_documents} };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let curseur = collection.find(filtre, None).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers":  fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_contenu_collection<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_contenu_collection Message : {:?}", & m.message);
    let requete: RequeteContenuCollection = m.message.get_msg().map_contenu(None)?;
    debug!("requete_contenu_collection cle parsed : {:?}", requete);

    let skip = match requete.skip { Some(s) => s, None => 0 };
    let limit = match requete.limit { Some(l) => l, None => 50 };
    let filtre_collection = doc! { CHAMP_TUUID: &requete.tuuid_collection, CHAMP_SUPPRIME: false };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut doc_info_collection = match collection.find_one(filtre_collection, None).await? {
        Some(c) => c,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Collection introuvable"}), None)?))
    };
    filtrer_doc_id(&mut doc_info_collection);

    let sort = match requete.sort_keys {
        Some(s) => {
            let mut doc_sort = doc!();
            for k in s {
                doc_sort.insert(k, 1);
            }
            doc_sort
        },
        None => doc!{"nom": 1}
    };
    let filtre_fichiers = doc! { CHAMP_CUUIDS: {"$all": [&requete.tuuid_collection]}, CHAMP_SUPPRIME: false };
    let ops_fichiers = FindOptions::builder()
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .build();
    let curseur = collection.find(filtre_fichiers, Some(ops_fichiers)).await?;
    let fichiers_reps = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({
        "collection": doc_info_collection,
        "documents": fichiers_reps,
    });

    // if permission is not None:
    //     permission[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES] = extra_out[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS]
    //     permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)
    //     reponse['permission'] = permission

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_get_corbeille<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_corbeille Message : {:?}", & m.message);
    let requete: RequetePlusRecente = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_corbeille cle parsed : {:?}", requete);
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
    let filtre = doc!{CHAMP_SUPPRIME: true};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDocumentsParTuuids {
    tuuids_documents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteContenuCollection {
    tuuid_collection: String,
    limit: Option<i64>,
    skip: Option<u64>,
    sort_keys: Option<Vec<String>>,
}
