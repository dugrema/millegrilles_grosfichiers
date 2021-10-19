use std::collections::HashMap;
use std::error::Error;

use log::{debug, error, warn};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongodb::options::UpdateOptions;

use crate::grosfichiers_constantes::*;

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("grosfichiers.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        // TRANSACTION_CLE  => {
        //     sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
        //     Ok(None)
        // },
        _ => Err(format!("grosfichiers.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

pub async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(middleware, transaction).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, transaction).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, transaction).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => transaction_retirer_documents_collection(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, transaction).await,
        TRANSACTION_CHANGER_FAVORIS => transaction_changer_favoris(middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleVersion {
    fuuid: String,
    cuuid: Option<String>,
    tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    nom_fichier: String,
    mimetype: String,
    taille: u64,
    #[serde(rename="dateFichier")]
    date_fichier: DateEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleCollection {
    nom: String,
    cuuid: Option<String>,  // Insertion dans collection destination
    securite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterFichiersCollection {
    cuuid: String,  // Collection qui recoit les documents
    inclure_tuuids: Vec<String>,  // Fichiers/rep a ajouter a la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRetirerDocumentsCollection {
    cuuid: String,  // Collection qui recoit les documents
    retirer_tuuids: Vec<String>,  // Fichiers/rep a retirer de la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerDocuments {
    tuuids: Vec<String>,  // Fichiers/rep a supprimer
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionChangerFavoris {
    favoris: HashMap<String, bool>,
}

async fn transaction_nouvelle_version<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_nouvelle_version Consommer transaction : {:?}", &transaction);
    let transaction_fichier: TransactionNouvelleVersion = match transaction.clone().convertir::<TransactionNouvelleVersion>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction : {:?}", e))?
    };

    // Determiner tuuid - si non fourni, c'est l'uuid-transaction (implique un nouveau fichier)
    let tuuid = match &transaction_fichier.tuuid {
        Some(t) => t.clone(),
        None => String::from(transaction.get_uuid_transaction())
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    };

    let fuuid = transaction_fichier.fuuid;
    let cuuid = transaction_fichier.cuuid;
    let nom_fichier = transaction_fichier.nom_fichier;
    let mimetype = transaction_fichier.mimetype;

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert("tuuid", &tuuid);
        doc_version.insert("fuuids", vec![&fuuid]);
        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            doc_version.insert("flag_media", "image");
            doc_version.insert("flag_media_traite", false);
        } else if mimetype.starts_with("video") {
            doc_version.insert("flag_media", "video");
            doc_version.insert("flag_media_traite", false);
        } else if mimetype =="application/pdf" {
            doc_version.insert("flag_indexe", false);
        }
        match collection.insert_one(doc_version, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur insertion nouvelle version {} : {:?}", fuuid, e))?
        }
    }

    // Retirer champs cles - ils sont inutiles dans la version
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": &fuuid};
    // Ajouter collection au besoin
    if let Some(c) = cuuid {
        add_to_set.insert("cuuids", c);
    }

    let ops = doc! {
        "$set": {
            "version_courante": doc_bson_transaction,
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    debug!("nouveau fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("nouveau fichier Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_nouvelle_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_nouvelle_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionNouvelleCollection = match transaction.clone().convertir::<TransactionNouvelleCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_collection) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion transaction en bson : {:?}", e))?
    };

    let tuuid = transaction.get_uuid_transaction().to_owned();
    let cuuid = transaction_collection.cuuid;
    let nom_collection = transaction_collection.nom;
    let date_courante = millegrilles_common_rust::bson::DateTime::now();
    let securite = match transaction_collection.securite {
        Some(s) => s,
        None => SECURITE_3_PROTEGE.to_owned()
    };

    // Creer document de collection (fichiersRep)
    let mut doc_collection = doc! {
        CHAMP_TUUID: &tuuid,
        CHAMP_NOM: nom_collection,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        CHAMP_SECURITE: &securite,
        CHAMP_SUPPRIME: false,
    };
    debug!("grosfichiers.transaction_nouvelle_collection Ajouter nouvelle collection doc : {:?}", doc_collection);

    // Ajouter collection parent au besoin
    if let Some(c) = cuuid {
        let mut arr = millegrilles_common_rust::bson::Array::new();
        arr.push(millegrilles_common_rust::bson::Bson::String(c));
        doc_collection.insert("cuuids", arr);
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.insert_one(doc_collection, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_nouvelle_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_ajouter_fichiers_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_ajouter_fichiers_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionAjouterFichiersCollection = match transaction.clone().convertir::<TransactionAjouterFichiersCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let add_to_set = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid};
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.inclure_tuuids}};
    let ops = doc! {
        "$addToSet": add_to_set,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_ajouter_fichiers_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_retirer_documents_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_retirer_documents_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionRetirerDocumentsCollection = match transaction.clone().convertir::<TransactionRetirerDocumentsCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let pull_from_array = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid};
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.retirer_tuuids}};
    let ops = doc! {
        "$pull": pull_from_array,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_retirer_documents_collection Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_supprimer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerDocuments = match transaction.clone().convertir::<TransactionSupprimerDocuments>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_supprimer_documents Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_recuperer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_recuperer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerDocuments = match transaction.clone().convertir::<TransactionSupprimerDocuments>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur conversion transaction : {:?}", e))?
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let ops = doc! {
        "$set": {CHAMP_SUPPRIME: false},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_recuperer_documents Resultat transaction update : {:?}", resultat);

    middleware.reponse_ok()
}

async fn transaction_changer_favoris<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_changer_favoris Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionChangerFavoris = match transaction.clone().convertir::<TransactionChangerFavoris>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur conversion transaction : {:?}", e))?
    };

    let (tuuids_set, tuuids_reset) = {
        let mut tuuids_set = Vec::new();
        let mut tuuids_reset = Vec::new();

        // Split en deux requetes - une pour favoris = true, l'autre pour false
        for (key, value) in transaction_collection.favoris.iter() {
            if *value == true {
                tuuids_set.push(key.to_owned());
            } else {
                tuuids_reset.push(key.to_owned());
            }
        }
        (tuuids_set, tuuids_reset)
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    // Faire 2 requetes, une pour favoris=true, l'autre false
    if ! tuuids_reset.is_empty() {
        let filtre_reset = doc! {CHAMP_TUUID: {"$in": &tuuids_reset}};
        let ops_reset = doc! { "$set": {CHAMP_FAVORIS: false}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_reset, ops_reset, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many reset sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update reset : {:?}", resultat);
    }

    if ! tuuids_set.is_empty() {
        let filtre_set = doc! {CHAMP_TUUID: {"$in": &tuuids_set}};
        let ops_set = doc! { "$set": {CHAMP_FAVORIS: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_set, ops_set, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many set sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update set : {:?}", resultat);
    }

    middleware.reponse_ok()
}
