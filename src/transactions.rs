use std::collections::HashMap;
use std::error::Error;
use std::convert::TryInto;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Bson, bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_transaction_recue;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::transactions::Transaction;
use crate::grosfichiers::{emettre_evenement_maj_collection, emettre_evenement_maj_fichier, GestionnaireGrosFichiers};

use crate::grosfichiers_constantes::*;
use crate::traitement_media::emettre_commande_media;
use crate::traitement_index::emettre_commande_indexation;

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation
    match m.action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_NOUVELLE_VERSION |
        TRANSACTION_NOUVELLE_COLLECTION |
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION |
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION |
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION |
        TRANSACTION_SUPPRIMER_DOCUMENTS |
        TRANSACTION_RECUPERER_DOCUMENTS |
        TRANSACTION_CHANGER_FAVORIS |
        TRANSACTION_DECRIRE_FICHIER |
        TRANSACTION_DECRIRE_COLLECTION |
        TRANSACTION_COPIER_FICHIER_TIERS => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)"))
            }?;
        },
        // 3.protege ou 4.secure
        TRANSACTION_ASSOCIER_CONVERSIONS |
        TRANSACTION_ASSOCIER_VIDEO => {
            match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;

    Ok(None)
}

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(gestionnaire, middleware, transaction).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, transaction).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, transaction).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => transaction_deplacer_fichiers_collection(middleware, transaction).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => transaction_retirer_documents_collection(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, transaction).await,
        TRANSACTION_CHANGER_FAVORIS => transaction_changer_favoris(middleware, transaction).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => transaction_associer_conversions(middleware, transaction).await,
        TRANSACTION_ASSOCIER_VIDEO => transaction_associer_video(middleware, transaction).await,
        TRANSACTION_DECRIRE_FICHIER => transaction_decire_fichier(middleware, transaction).await,
        TRANSACTION_DECRIRE_COLLECTION => transaction_decire_collection(middleware, transaction).await,
        TRANSACTION_COPIER_FICHIER_TIERS => transaction_copier_fichier_tiers(gestionnaire, middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleVersion {
    fuuid: String,
    cuuid: Option<String>,
    tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    nom: String,
    mimetype: String,
    taille: u64,
    #[serde(rename="dateFichier")]
    date_fichier: DateEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireFichier {
    pub tuuid: String,
    nom: Option<String>,
    titre: Option<HashMap<String, String>>,
    description: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireCollection {
    pub tuuid: String,
    nom: Option<String>,
    titre: Option<HashMap<String, String>>,
    description: Option<HashMap<String, String>>,
    securite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleCollection {
    nom: String,
    pub cuuid: Option<String>,  // Insertion dans collection destination
    securite: Option<String>,
    favoris: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterFichiersCollection {
    pub cuuid: String,  // Collection qui recoit les documents
    pub inclure_tuuids: Vec<String>,  // Fichiers/rep a ajouter a la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDeplacerFichiersCollection {
    pub cuuid_origine: String,          // Collection avec les documents (source)
    pub cuuid_destination: String,      // Collection qui recoit les documents
    pub inclure_tuuids: Vec<String>,    // Fichiers/rep a ajouter a la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRetirerDocumentsCollection {
    pub cuuid: String,  // Collection qui recoit les documents
    pub retirer_tuuids: Vec<String>,  // Fichiers/rep a retirer de la collection
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionListeDocuments {
    pub tuuids: Vec<String>,  // Fichiers/rep a supprimer
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionChangerFavoris {
    pub favoris: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCopierFichierTiers {
    pub fuuid: String,
    pub cuuid: String,
    pub nom: String,
    pub mimetype: String,
    pub taille: u64,
    #[serde(rename="dateFichier")]
    pub date_fichier: DateEpochSeconds,
    pub images: Option<HashMap<String, ImageInfo>>,
    pub video: Option<HashMap<String, VideoInfo>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub hachage: String,
    pub resolution: Option<u32>,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub taille: Option<u64>,
    pub mimetype: Option<String>,
    pub data_chiffre: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoInfo {
    pub hachage: String,
    pub resolution: Option<u32>,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub taille: Option<u64>,
    pub mimetype: Option<String>,
}

async fn transaction_nouvelle_version<M, T>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
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
    let nom_fichier = transaction_fichier.nom;
    let mimetype = transaction_fichier.mimetype;

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => {
            e.get_user_id()?.to_owned()
        },
        None => None
    };

    doc_bson_transaction.insert(CHAMP_FUUID_MIMETYPES, doc! {&fuuid: &mimetype});

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    let mut flag_media = false;

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert(CHAMP_TUUID, &tuuid);
        doc_version.insert(CHAMP_FUUIDS, vec![&fuuid]);

        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "image");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
        } else if mimetype.starts_with("video") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "video");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
        } else if mimetype =="application/pdf" {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "poster");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
        }
        doc_version.insert(CHAMP_FLAG_INDEXE, false);

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
            CHAMP_USER_ID: &user_id,
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

    if flag_media == true {
        debug!("Emettre une commande de conversion pour media {}", fuuid);
        match emettre_commande_media(middleware, &tuuid, &fuuid, &mimetype).await {
            Ok(()) => (),
            Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
        }
    }

    debug!("Emettre une commande d'indexation pour {}", fuuid);
    match emettre_commande_indexation(gestionnaire, middleware, &tuuid, &fuuid).await {
        Ok(()) => (),
        Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid).await?;

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

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let tuuid = transaction.get_uuid_transaction().to_owned();
    let cuuid = transaction_collection.cuuid;
    let nom_collection = transaction_collection.nom;
    let date_courante = millegrilles_common_rust::bson::DateTime::now();
    let securite = match transaction_collection.securite {
        Some(s) => s,
        None => SECURITE_3_PROTEGE.to_owned()
    };
    let favoris = match transaction_collection.favoris {
        Some(f) => f,
        None => false
    };

    // Creer document de collection (fichiersRep)
    let mut doc_collection = doc! {
        CHAMP_TUUID: &tuuid,
        CHAMP_NOM: nom_collection,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        CHAMP_SECURITE: &securite,
        CHAMP_USER_ID: user_id,
        CHAMP_SUPPRIME: false,
        CHAMP_FAVORIS: favoris,
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

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, &tuuid).await?;

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
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_fichiers_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_ajouter_fichiers_collection Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid).await?;
    }

    middleware.reponse_ok()
}

async fn transaction_deplacer_fichiers_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_deplacer_fichiers_collection Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionDeplacerFichiersCollection = match transaction.clone().convertir::<TransactionDeplacerFichiersCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur conversion transaction : {:?}", e))?
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.inclure_tuuids}};
    { // Ajouter dans la destination
        let add_to_set = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid_destination};
        let ops = doc! {
            "$addToSet": &add_to_set,
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let resultat = match collection.update_many(filtre.clone(), ops, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur update_one sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_deplacer_fichiers_collection Resultat transaction update : {:?}", resultat);
    }
    { // Retirer de l'origine
        let pull_from_array = doc! {CHAMP_CUUIDS: &transaction_collection.cuuid_origine};
        let ops = doc! {
            "$pull": &pull_from_array,
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let resultat = match collection.update_many(filtre, ops, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_deplacer_fichiers_collection Erreur update_one sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_deplacer_fichiers_collection Resultat transaction update : {:?}", resultat);
    }

    for tuuid in &transaction_collection.inclure_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid).await?;
    }

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
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_retirer_documents_collection Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_retirer_documents_collection Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.retirer_tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid).await?;
    }

    middleware.reponse_ok()
}

async fn transaction_supprimer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionListeDocuments = match transaction.clone().convertir::<TransactionListeDocuments>() {
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
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_supprimer_documents Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        match emettre_evenement_maj_fichier(middleware, &tuuid).await {
            Ok(()) => (),
            Err(e) => {
                // Peut-etre une collection
                emettre_evenement_maj_fichier(middleware, &tuuid).await?;
            }
        }
    }

    middleware.reponse_ok()
}

async fn transaction_recuperer_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_recuperer_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionListeDocuments = match transaction.clone().convertir::<TransactionListeDocuments>() {
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
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_recuperer_documents Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("grosfichiers.transaction_recuperer_documents Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid).await?;
    }

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

        for tuuid in &tuuids_reset {
            // Emettre fichier pour que tous les clients recoivent la mise a jour
            emettre_evenement_maj_collection(middleware, &tuuid).await?;
        }

    }

    if ! tuuids_set.is_empty() {
        let filtre_set = doc! {CHAMP_TUUID: {"$in": &tuuids_set}};
        let ops_set = doc! { "$set": {CHAMP_FAVORIS: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        let resultat = match collection.update_many(filtre_set, ops_set, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_changer_favoris Erreur update_many set sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_changer_favoris Resultat transaction update set : {:?}", resultat);

        for tuuid in &tuuids_set {
            // Emettre fichier pour que tous les clients recoivent la mise a jour
            emettre_evenement_maj_collection(middleware, &tuuid).await?;
        }
    }

    middleware.reponse_ok()
}

async fn transaction_associer_conversions<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_associer_conversions Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionAssocierConversions = match transaction.clone().convertir::<TransactionAssocierConversions>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_associer_conversions Erreur conversion transaction : {:?}", e))?
    };

    let tuuid = transaction_mappee.tuuid.clone();

    let doc_images = match convertir_to_bson(transaction_mappee.images.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur conversion images en bson : {:?}", e))?
    };

    // Mapper tous les fuuids avec leur mimetype
    let (fuuids, fuuid_mimetypes) = {
        let mut fuuids = Vec::new();
        let mut fuuid_mimetypes = HashMap::new();
        fuuids.push(transaction_mappee.fuuid.clone());
        if let Some(mimetype) = &transaction_mappee.mimetype {
            fuuid_mimetypes.insert(transaction_mappee.fuuid.clone(), mimetype.clone());
        }
        for (_, image) in transaction_mappee.images.iter() {
            fuuids.push(image.hachage.to_owned());
            if let Some(mimetype) = &image.mimetype {
                fuuid_mimetypes.insert(image.hachage.to_owned(), mimetype.clone());
            }
        }

        (fuuids, fuuid_mimetypes)
    };

    // MAJ de la version du fichier
    {
        let filtre = doc! { CHAMP_FUUID: &transaction_mappee.fuuid };
        let mut set_ops = doc! {
            "images": &doc_images,
            "flag_media_traite": true,
        };
        if let Some(inner) = transaction_mappee.anime {
            set_ops.insert("anime", inner);
        }
        if let Some(inner) = &transaction_mappee.mimetype {
            set_ops.insert("mimetype", inner);
        }
        if let Some(inner) = transaction_mappee.width {
            set_ops.insert("width", inner);
        }
        if let Some(inner) = transaction_mappee.height {
            set_ops.insert("height", inner);
        }
        for (fuuid, mimetype) in fuuid_mimetypes.iter() {
            set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        }

        let add_to_set = doc! {CHAMP_FUUIDS: {"$each": &fuuids}};

        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }
    }

    // S'assurer d'appliquer le fitre sur la version courante
    {
        let filtre = doc! {
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_FUUID_V_COURANTE: &transaction_mappee.fuuid,
        };

        let mut set_ops = doc! {
            "version_courante.images": &doc_images,
        };
        if let Some(inner) = &transaction_mappee.anime {
            set_ops.insert("version_courante.anime", inner);
        }
        if let Some(inner) = &transaction_mappee.mimetype {
            set_ops.insert("version_courante.mimetype", inner);
        }
        if let Some(inner) = &transaction_mappee.width {
            set_ops.insert("version_courante.width", inner);
        }
        if let Some(inner) = &transaction_mappee.height {
            set_ops.insert("version_courante.height", inner);
        }
        for (fuuid, mimetype) in fuuid_mimetypes.iter() {
            set_ops.insert(format!("version_courante.{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        }

        // Combiner les fuuids hors de l'info de version
        let add_to_set = doc! {CHAMP_FUUIDS: {"$each": &fuuids}};

        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid).await?;

    middleware.reponse_ok()
}

async fn transaction_associer_video<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_associer_conversions Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionAssocierVideo = match transaction.clone().convertir::<TransactionAssocierVideo>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_associer_video Erreur conversion transaction : {:?}", e))?
    };

    let tuuid = transaction_mappee.tuuid.clone();

    let doc_video = match convertir_to_bson(transaction_mappee.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion images en bson : {:?}", e))?
    };

    // Mapper tous les fuuids avec leur mimetype
    let (fuuids, fuuid_mimetypes) = {
        let mut fuuids = Vec::new();
        let mut fuuid_mimetypes = HashMap::new();
        fuuids.push(transaction_mappee.fuuid_video.clone());
        fuuid_mimetypes.insert(transaction_mappee.fuuid_video.clone(), transaction_mappee.mimetype.clone());

        (fuuids, fuuid_mimetypes)
    };

    let resolution = match transaction_mappee.height {
        Some(inner) => inner,
        None => 240
    };
    let cle_video = format!("{};{};{}", &transaction_mappee.mimetype, resolution, &transaction_mappee.bitrate);

    // MAJ de la version du fichier
    {
        let filtre = doc! { CHAMP_FUUID: &transaction_mappee.fuuid };
        let mut set_ops = doc! {
            format!("video.{}", &cle_video): &doc_video,
        };
        for (fuuid, mimetype) in fuuid_mimetypes.iter() {
            set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        }
        let add_to_set = doc! {CHAMP_FUUIDS: {"$each": &fuuids}};
        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }
    }

    // S'assurer d'appliquer le fitre sur la version courante
    {
        let filtre = doc! {
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_FUUID_V_COURANTE: &transaction_mappee.fuuid,
        };

        let mut set_ops = doc! {
            format!("version_courante.video.{}", &cle_video): &doc_video,
        };
        for (fuuid, mimetype) in fuuid_mimetypes.iter() {
            set_ops.insert(format!("version_courante.{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        }

        // Combiner les fuuids hors de l'info de version
        let add_to_set = doc! {CHAMP_FUUIDS: {"$each": &fuuids}};

        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid).await?;

    middleware.reponse_ok()
}

async fn transaction_decire_fichier<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_decire_fichier Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionDecrireFichier = match transaction.clone().convertir::<TransactionDecrireFichier>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion transaction : {:?}", e))?
    };

    let tuuid = transaction_mappee.tuuid.as_str();
    let filtre = doc! { CHAMP_TUUID: tuuid };

    let mut set_ops = doc! {};

    // Modifier champ nom si present
    if let Some(nom) = &transaction_mappee.nom {
        set_ops.insert("nom", nom);
    }

    // Modifier champ titre si present
    if let Some(titre) = &transaction_mappee.titre {
        let titre_bson = match bson::to_bson(titre) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion titre vers bson : {:?}", e))?
        };
        set_ops.insert("titre", titre_bson);
    }

    // Modifier champ description si present
    if let Some(description) = &transaction_mappee.description {
        let description_bson = match bson::to_bson(description) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion titre vers bson : {:?}", e))?
        };
        set_ops.insert("description", description_bson);
    }

    let ops = doc! {
        "$set": set_ops,
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(inner) => debug!("transactions.transaction_decire_fichier Update description : {:?}", inner),
        Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid).await?;

    middleware.reponse_ok()
}

async fn transaction_decire_collection<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_decire_collection Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionDecrireCollection = match transaction.clone().convertir::<TransactionDecrireCollection>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion transaction : {:?}", e))?
    };

    let tuuid = transaction_mappee.tuuid.as_str();
    let filtre = doc! { CHAMP_TUUID: tuuid };

    let mut set_ops = doc! {};

    // Modifier champ nom si present
    if let Some(nom) = &transaction_mappee.nom {
        set_ops.insert("nom", nom);
    }

    // Modifier champ titre si present
    if let Some(titre) = &transaction_mappee.titre {
        let titre_bson = match bson::to_bson(titre) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion titre vers bson : {:?}", e))?
        };
        set_ops.insert("titre", titre_bson);
    }

    // Modifier champ securite si present
    if let Some(securite) = &transaction_mappee.securite {
        // Valider le champ securite
        let _: Securite = match securite.as_str().try_into() {
            Ok(s) => s,
            Err(e) => Err(format!("transactions.transaction_decire_collection Champ securite invalide '{}' : {:?}", securite, e))?
        };

        let titre_bson = match bson::to_bson(securite) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion securite vers bson : {:?}", e))?
        };
        set_ops.insert("securite", titre_bson);
    }

    // Modifier champ description si present
    if let Some(description) = &transaction_mappee.description {
        let description_bson = match bson::to_bson(description) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion titre vers bson : {:?}", e))?
        };
        set_ops.insert("description", description_bson);
    }

    let ops = doc! {
        "$set": set_ops,
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(inner) => debug!("transactions.transaction_decire_collection Update description : {:?}", inner),
        Err(e) => Err(format!("transactions.transaction_decire_collection Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_collection(middleware, &tuuid).await?;

    middleware.reponse_ok()
}

async fn transaction_copier_fichier_tiers<M, T>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_copier_fichier_tiers Consommer transaction : {:?}", &transaction);
    let transaction_fichier: TransactionCopierFichierTiers = match transaction.clone().convertir::<TransactionCopierFichierTiers>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur conversion transaction : {:?}", e))?
    };

    // Nouveau tuuid, utiliser uuid_transaction
    let tuuid = transaction.get_uuid_transaction();

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    };

    let fuuid = transaction_fichier.fuuid;
    let cuuid = transaction_fichier.cuuid;
    let nom_fichier = transaction_fichier.nom;
    let mimetype = transaction_fichier.mimetype;

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => {
            match e.get_user_id()? {
                Some(u) => u.to_owned(),
                None => Err(format!("transactions.transaction_copier_fichier_tiers Le certificat n'a pas de user_id"))?
            }
        },
        None => Err(format!("transactions.transaction_copier_fichier_tiers Certificat n'est pas charge"))?
    };

    let fuuids_mimetype = {
        let mut fuuids_mimetype = Document::new();
        fuuids_mimetype.insert(fuuid.clone(), mimetype.clone());

        // Ajouter fuuids video, images
        if let Some(images) = transaction_fichier.images {
            for img in images.values() {
                let mimetype = img.mimetype.as_ref();
                let fuuid = &img.hachage;
                if let Some(mt) = mimetype {
                    fuuids_mimetype.insert(fuuid.to_owned(), mt.to_owned());
                }
            }
        }

        if let Some(videos) = transaction_fichier.video {
            for vid in videos.values() {
                let mimetype = vid.mimetype.as_ref();
                let fuuid = &vid.hachage;
                if let Some(mt) = mimetype {
                    fuuids_mimetype.insert(fuuid.to_owned(), mt.to_owned());
                }
            }
        }

        fuuids_mimetype
    };

    let fuuids: Vec<&String> = fuuids_mimetype.keys().collect();

    doc_bson_transaction.insert(CHAMP_FUUID_MIMETYPES, &fuuids_mimetype);

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    let mut flag_media = false;

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert(CHAMP_TUUID, &tuuid);
        doc_version.insert(CHAMP_FUUIDS, &fuuids);

        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "image");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, true);
        } else if mimetype.starts_with("video") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "video");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, true);
        } else if mimetype =="application/pdf" {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "poster");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, true);
        }
        doc_version.insert(CHAMP_FLAG_INDEXE, false);

        // Champs date
        doc_version.insert(CHAMP_CREATION, Utc::now());

        let ops = doc! {
            "$setOnInsert": doc_version,
            "$currentDate": {CHAMP_MODIFICATION: true}
        };

        let filtre = doc! {
            "fuuid": &fuuid,
        };
        let options = UpdateOptions::builder()
            .upsert(true)
            .build();

        match collection.update_one(filtre, ops, options).await {
            Ok(resultat_update) => {
                if resultat_update.upserted_id.is_none() && resultat_update.matched_count != 1 {
                   Err(format!("Erreur mise a jour versionsFichiers, echec insertion document (updated count == 0)"))?;
                }
            },
            Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur update versionFichiers : {:?}", e))?
        }
    }

    // Retirer champs cles - ils sont inutiles dans la version
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{"fuuids": {"$each": &fuuids}};

    // Ajouter collection
    add_to_set.insert("cuuids", cuuid);

    let ops = doc! {
        "$set": {
            "version_courante": doc_bson_transaction,
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
            CHAMP_FUUID_MIMETYPES: &fuuids_mimetype,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
            CHAMP_USER_ID: &user_id,
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

    // if flag_media == true {
    //     debug!("Emettre une commande de conversion pour media {}", fuuid);
    //     match emettre_commande_media(middleware, &tuuid, &fuuid, &mimetype).await {
    //         Ok(()) => (),
    //         Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
    //     }
    // }

    debug!("Emettre une commande d'indexation pour {}", fuuid);
    match emettre_commande_indexation(gestionnaire, middleware, &tuuid, &fuuid).await {
        Ok(()) => (),
        Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid).await?;

    middleware.reponse_ok()
}