use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::TryInto;

use log::{debug, info, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Bson, bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::grosfichiers::{emettre_evenement_contenu_collection, emettre_evenement_maj_collection, emettre_evenement_maj_fichier, EvenementContenuCollection, GestionnaireGrosFichiers};

use crate::grosfichiers_constantes::*;
use crate::requetes::verifier_acces_usager;
use crate::traitement_jobs::JobHandler;
// use crate::traitement_media::emettre_commande_media;
// use crate::traitement_index::emettre_commande_indexation;

pub async fn consommer_transaction<M>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
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
        TRANSACTION_ARCHIVER_DOCUMENTS |
        TRANSACTION_CHANGER_FAVORIS |
        TRANSACTION_DECRIRE_FICHIER |
        TRANSACTION_DECRIRE_COLLECTION |
        TRANSACTION_COPIER_FICHIER_TIERS |
        TRANSACTION_FAVORIS_CREERPATH |
        TRANSACTION_SUPPRIMER_VIDEO |
        TRANSACTION_ASSOCIER_CONVERSIONS |
        TRANSACTION_ASSOCIER_VIDEO |
        TRANSACTION_IMAGE_SUPPRIMER_JOB |
        TRANSACTION_VIDEO_SUPPRIMER_JOB => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: pas 4.secure"))
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    // sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireGrosFichiers, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    let action = match transaction.get_routage().action.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(format!("transactions.aiguillage_transaction Transaction sans action : {:?}", transaction))?
    };

    match action {
        TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(gestionnaire, middleware, transaction).await,
        TRANSACTION_NOUVELLE_COLLECTION => transaction_nouvelle_collection(middleware, transaction).await,
        TRANSACTION_AJOUTER_FICHIERS_COLLECTION => transaction_ajouter_fichiers_collection(middleware, transaction).await,
        TRANSACTION_DEPLACER_FICHIERS_COLLECTION => transaction_deplacer_fichiers_collection(middleware, transaction).await,
        TRANSACTION_RETIRER_DOCUMENTS_COLLECTION => transaction_retirer_documents_collection(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENTS => transaction_supprimer_documents(middleware, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENTS => transaction_recuperer_documents(middleware, transaction).await,
        TRANSACTION_ARCHIVER_DOCUMENTS => transaction_archiver_documents(middleware, transaction).await,
        TRANSACTION_CHANGER_FAVORIS => transaction_changer_favoris(middleware, transaction).await,
        TRANSACTION_ASSOCIER_CONVERSIONS => transaction_associer_conversions(middleware, gestionnaire, transaction).await,
        TRANSACTION_ASSOCIER_VIDEO => transaction_associer_video(middleware, gestionnaire, transaction).await,
        TRANSACTION_DECRIRE_FICHIER => transaction_decire_fichier(middleware, gestionnaire, transaction).await,
        TRANSACTION_DECRIRE_COLLECTION => transaction_decire_collection(middleware, transaction).await,
        TRANSACTION_COPIER_FICHIER_TIERS => transaction_copier_fichier_tiers(gestionnaire, middleware, transaction).await,
        TRANSACTION_FAVORIS_CREERPATH => transaction_favoris_creerpath(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_VIDEO => transaction_supprimer_video(middleware, transaction).await,
        TRANSACTION_IMAGE_SUPPRIMER_JOB => transaction_supprimer_job_image(middleware, gestionnaire, transaction).await,
        TRANSACTION_VIDEO_SUPPRIMER_JOB => transaction_supprimer_job_video(middleware, gestionnaire, transaction).await,
        TRANSACTION_AJOUTER_CONTACT_LOCAL => transaction_ajouter_contact_local(middleware, gestionnaire, transaction).await,
        TRANSACTION_SUPPRIMER_CONTACTS => transaction_supprimer_contacts(middleware, gestionnaire, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), action)),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffre {
    pub data_chiffre: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub ref_hachage_bytes: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub hachage_bytes: Option<String>,
    pub format: Option<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleVersion {
    pub fuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cuuid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
    #[serde(skip_serializing_if="Option::is_none")]
    pub nom: Option<String>,
    pub mimetype: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    pub taille: u64,
    #[serde(rename="dateFichier", skip_serializing_if="Option::is_none")]
    pub date_fichier: Option<DateEpochSeconds>,
    // #[serde(rename = "_cle", skip_serializing_if = "Option::is_none")]
    // pub cle: Option<MessageMilleGrille>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireFichier {
    pub tuuid: String,
    // nom: Option<String>,
    // titre: Option<HashMap<String, String>>,
    metadata: Option<DataChiffre>,
    // description: Option<HashMap<String, String>>,
    mimetype: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDecrireCollection {
    pub tuuid: String,
    // nom: Option<String>,
    metadata: Option<DataChiffre>,
    // titre: Option<HashMap<String, String>>,
    // description: Option<HashMap<String, String>>,
    // securite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionNouvelleCollection {
    // nom: Option<String>,
    pub metadata: DataChiffre,
    pub cuuid: Option<String>,  // Insertion dans collection destination
    // securite: Option<String>,
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
    pub tuuids: Vec<String>,  // Fichiers/rep a supprimer, archiver, etc
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerDocuments {
    pub tuuids: Vec<String>,    // Fichiers/rep a supprimer
    pub cuuid: Option<String>,  // Collection a retirer des documents (suppression conditionnelle)
    pub cuuids_path: Option<Vec<String>>,  // Path du fichier lors de la suppression (breadcrumb)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionChangerFavoris {
    pub favoris: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCopierFichierTiers {
    pub fuuid: String,
    pub cuuid: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub metadata: Option<DataChiffre>,
    pub mimetype: String,
    pub user_id: Option<String>,
    pub taille: u64,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, VideoInfo>>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub hachage: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resolution: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub taille: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub data_chiffre: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoInfo {
    pub fuuid: String,
    pub tuuid: String,
    pub fuuid_video: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resolution: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub taille_fichier: Option<u64>,
    pub mimetype: String,
    pub codec: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub bitrate: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub quality: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionFavorisCreerpath {
    pub favoris_id: String,
    pub user_id: Option<String>,
    pub path_collections: Option<Vec<String>>,
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
    // let nom_fichier = transaction_fichier.nom;
    let mimetype = transaction_fichier.mimetype;

    let enveloppe = match transaction.get_enveloppe_certificat() {
        Some(inner) => inner,
        None => Err(format!("grosfichiers.transaction_nouvelle_version Certificat absent (enveloppe)"))?
    };

    let user_id = match enveloppe.get_user_id() {
        Ok(inner) => match inner {
            Some(user) => user.to_owned(),
            None => Err(format!("grosfichiers.transaction_nouvelle_version User_id absent du certificat"))?
        },
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur get_user_id() : {:?}", e))?
    };

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    let mut flag_media = false;
    let mut flag_duplication = false;

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert(CHAMP_TUUID, &tuuid);
        doc_version.insert(CHAMP_USER_ID, &user_id);
        doc_version.insert(CHAMP_FUUIDS, vec![&fuuid]);
        doc_version.insert(CHAMP_FUUIDS_RECLAMES, vec![&fuuid]);

        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "image");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
        } else if mimetype.starts_with("video") {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "video");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
            doc_version.insert(CHAMP_FLAG_VIDEO_TRAITE, false);
        } else if mimetype =="application/pdf" {
            flag_media = true;
            doc_version.insert(CHAMP_FLAG_MEDIA, "poster");
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
        }
        doc_version.insert(CHAMP_FLAG_INDEX, false);

        match collection.insert_one(doc_version, None).await {
            Ok(_) => (),
            Err(e) => {
                flag_duplication = verifier_erreur_duplication_mongo(&*e.kind);
                if(flag_duplication) {
                    // Ok, on va traiter la version meme si elle est deja conservee (idempotent)
                    info!("transaction_nouvelle_version Recu transaction deja presente dans versionsFichiers (fuuid: {}), on traite sans inserer", fuuid);
                    ()
                } else {
                    Err(format!("transaction_nouvelle_version Erreur insertion nouvelle version {} : {:?}", fuuid, e))?
                }
            }
        }
    }

    // Retirer champs cles - ils sont inutiles dans la version
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{
        CHAMP_FUUIDS: &fuuid,
        CHAMP_FUUIDS_RECLAMES: &fuuid,
    };
    // Ajouter collection au besoin
    if let Some(c) = cuuid.as_ref() {
        add_to_set.insert(CHAMP_CUUIDS, c);
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
            // "nom": &nom_fichier,
            "tuuid": &tuuid,
            CHAMP_CREATION: Utc::now(),
            CHAMP_USER_ID: &user_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    debug!("transaction_nouvelle_version nouveau fichier update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("grosfichiers.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("transaction_nouvelle_version nouveau fichier Resultat transaction update : {:?}", resultat);

    if flag_duplication == false {
        // On emet les messages de traitement uniquement si la transaction est nouvelle
        // if flag_media == true {
        //     debug!("Emettre une commande de conversion pour media {}", fuuid);
        //     match emettre_commande_media(middleware, &tuuid, &fuuid, &mimetype, false).await {
        //         Ok(()) => (),
        //         Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
        //     }
        // }

        // debug!("Emettre une commande d'indexation pour {}", fuuid);
        // match emettre_commande_indexation(gestionnaire, middleware, &tuuid, &fuuid).await {
        //     Ok(()) => (),
        //     Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
        // }

        // Conserver information pour indexer le fichier
        let mut parametres = HashMap::new();
        parametres.insert("mimetype".to_string(), Bson::String(mimetype.clone()));
        if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
            middleware, &fuuid, &user_id, None,
            None, Some(parametres), false).await {
            error!("transaction_nouvelle_version Erreur ajout_job_indexation : {:?}", e);
        }
        // if let Err(e) = ajout_job_indexation(middleware, &tuuid, &fuuid, &user_id, &mimetype).await {
        //     error!("transaction_nouvelle_version Erreur ajout_job_indexation : {:?}", e);
        // }

        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await?;

        if let Some(cuuid) = cuuid.as_ref() {
            let mut evenement_contenu = EvenementContenuCollection::new();
            evenement_contenu.cuuid = Some(cuuid.clone());
            evenement_contenu.fichiers_ajoutes = Some(vec![tuuid.clone()]);
            emettre_evenement_contenu_collection(middleware, evenement_contenu).await?;
        }
    }

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
    // let nom_collection = transaction_collection.nom;
    let metadata = match convertir_to_bson(&transaction_collection.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_collection Erreur conversion metadata chiffre en bson {:?}", e))?
    };

    let date_courante = millegrilles_common_rust::bson::DateTime::now();
    // let securite = match transaction_collection.securite {
    //     Some(s) => s,
    //     None => SECURITE_3_PROTEGE.to_owned()
    // };
    let favoris = match transaction_collection.favoris {
        Some(f) => f,
        None => false
    };

    // Creer document de collection (fichiersRep)
    let mut doc_collection = doc! {
        CHAMP_TUUID: &tuuid,
        // CHAMP_NOM: nom_collection,
        CHAMP_METADATA: metadata,
        CHAMP_CREATION: &date_courante,
        CHAMP_MODIFICATION: &date_courante,
        // CHAMP_SECURITE: &securite,
        CHAMP_USER_ID: &user_id,
        CHAMP_SUPPRIME: false,
        CHAMP_FAVORIS: favoris,
    };
    debug!("grosfichiers.transaction_nouvelle_collection Ajouter nouvelle collection doc : {:?}", doc_collection);

    // Ajouter collection parent au besoin
    if let Some(c) = cuuid.as_ref() {
        let mut arr = millegrilles_common_rust::bson::Array::new();
        arr.push(millegrilles_common_rust::bson::Bson::String(c.clone()));
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
    {
        let mut evenement_contenu = EvenementContenuCollection::new();
        match cuuid.as_ref() {
            Some(cuuid) => evenement_contenu.cuuid = Some(cuuid.clone()),
            None => evenement_contenu.cuuid = user_id.clone()
        }
        evenement_contenu.collections_ajoutees = Some(vec![tuuid.clone()]);
        emettre_evenement_contenu_collection(middleware, evenement_contenu).await?;
    }

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
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_AJOUTER_FICHIER_COLLECTION).await?;
    }

    {
        let mut evenement_contenu = EvenementContenuCollection::new();
        evenement_contenu.cuuid = Some(transaction_collection.cuuid.clone());
        evenement_contenu.fichiers_ajoutes = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, evenement_contenu).await?;
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
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_DEPLACER_FICHIER_COLLECTION).await?;
    }

    {
        let mut evenement_source = EvenementContenuCollection::new();
        evenement_source.cuuid = Some(transaction_collection.cuuid_origine.clone());
        evenement_source.retires = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, evenement_source).await?;

        let mut evenement_destination = EvenementContenuCollection::new();
        evenement_destination.cuuid = Some(transaction_collection.cuuid_destination.clone());
        evenement_destination.fichiers_ajoutes = Some(transaction_collection.inclure_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, evenement_destination).await?;
    }

    middleware.reponse_ok()
}

/// Obsolete - conserver pour support legacy
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
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_RETIRER_COLLECTION).await?;
    }

    {
        let mut evenement_contenu = EvenementContenuCollection::new();
        evenement_contenu.cuuid = Some(transaction_collection.cuuid.clone());
        evenement_contenu.retires = Some(transaction_collection.retirer_tuuids.clone());
        emettre_evenement_contenu_collection(middleware, evenement_contenu).await?;
    }

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

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(c) => c.get_user_id()?.to_owned(),
        None => None
    };

    // Conserver liste de tuuids par cuuid, utilise pour evenement
    let mut tuuids_retires_par_cuuid: HashMap<String, Vec<String>> = HashMap::new();
    // Liste de tuuids qui vont etre marques comme supprimes=true
    let mut tuuids_supprimes: Vec<String> = Vec::new();
    // Liste de tuuids encore valides (plusieurs cuuids). On va juste retirer le cuuid en parametre.
    let mut tuuids_retires: Vec<String> = Vec::new();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let filtre = doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}};
    let mut curseur = match collection.find(filtre, None).await {
        Ok(c) => c,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur preparation curseur : {:?}", e))?
    };
    while let Some(r) = curseur.next().await {
        if let Ok(d) = r {
            let fichier: FichierDetail = match convertir_bson_deserializable(d) {
                Ok(f) => f,
                Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur mapping FichierDetail : {:?}", e))?
            };
            let tuuid = fichier.tuuid;
            match fichier.cuuids.as_ref() {
                Some(cuuids) => {
                    if cuuids.len() == 0 {
                        // Document sans collection - traiter comme un favoris
                        tuuids_supprimes.push(tuuid.clone());

                        // Ajouter dans la liste de suppression des favoris (cuuid = user_id)
                        if let Some(u) = user_id.as_ref() {
                            match tuuids_retires_par_cuuid.get_mut(u) {
                                Some(tuuids_supprimes) => {
                                    tuuids_supprimes.push(tuuid.clone());
                                },
                                None => {
                                    tuuids_retires_par_cuuid.insert(u.clone(), vec![tuuid.clone()]);
                                }
                            }
                        }
                    } else if cuuids.len() == 1 {
                        let cuuid: &String = cuuids.get(0).expect("cuuid");

                        // Ajouter dans la liste de suppression du cuuid (evenement)
                        match tuuids_retires_par_cuuid.get_mut(cuuid) {
                            Some(tuuids_supprimes) => {
                                tuuids_supprimes.push(tuuid.clone());
                            },
                            None => {
                                tuuids_retires_par_cuuid.insert(cuuid.clone(), vec![tuuid.clone()]);
                            }
                        }

                        // Ajouter a la liste de documents a marquer supprime=true
                        tuuids_supprimes.push(tuuid);
                    } else {
                        // Plusieurs cuuids - on retire celui qui est demande seulement
                        match transaction_collection.cuuid.as_ref() {
                            Some(cuuid) => {
                                // Supprimer seulement le cuuid demande
                                tuuids_retires.push(tuuid.clone());

                                // Ajouter a la liste des tuuids supprimes par cuuid
                                match tuuids_retires_par_cuuid.get_mut(cuuid) {
                                    Some(tuuids_supprimes) => {
                                        tuuids_supprimes.push(tuuid.clone());
                                    },
                                    None => {
                                        tuuids_retires_par_cuuid.insert(cuuid.clone(), vec![tuuid.clone()]);
                                    }
                                }
                            },
                            None => {
                                // Aucun cuuid en parametre - on supprime le document de tous les cuuids
                                // Ajouter a la liste de documents a marquer supprime=true
                                tuuids_supprimes.push(tuuid.clone());

                                // Conserver le tuuid dans la liste pour les cuuids
                                for cuuid in cuuids {
                                    // Ajouter dans la liste de suppression du cuuid (evenement)
                                    match tuuids_retires_par_cuuid.get_mut(cuuid) {
                                        Some(tuuids_supprimes) => {
                                            tuuids_supprimes.push(tuuid.clone());
                                        },
                                        None => {
                                            tuuids_retires_par_cuuid.insert(cuuid.clone(), vec![tuuid.clone()]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                None => {
                    // Document sans collection - traiter comme un favoris
                    tuuids_supprimes.push(tuuid.clone());

                    // Ajouter dans la liste de suppression des favoris (cuuid = user_id)
                    if let Some(u) = user_id.as_ref() {
                        match tuuids_retires_par_cuuid.get_mut(u) {
                            Some(tuuids_supprimes) => {
                                tuuids_supprimes.push(tuuid.clone());
                            },
                            None => {
                                tuuids_retires_par_cuuid.insert(u.clone(), vec![tuuid.clone()]);
                            }
                        }
                    }
                }
            }
        }
    }

    if tuuids_supprimes.len() > 0 {
        // Marquer tuuids supprime=true
        let filtre = doc! {CHAMP_TUUID: {"$in": &tuuids_supprimes}};
        let ops = doc! {
            "$set": {
                CHAMP_SUPPRIME: true,
                CHAMP_SUPPRIME_PATH: transaction_collection.cuuids_path,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let resultat = match collection.update_many(filtre, ops, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur update_many supprimer=true sur transaction : {:?}", e))?
        };
        debug!("grosfichiers.transaction_supprimer_documents Resultat transaction update : {:?}", resultat);
    }

    if tuuids_retires.len() > 0 {
        if let Some(cuuid) = transaction_collection.cuuid.as_ref() {
            // Retirer cuuid
            let filtre = doc! {CHAMP_TUUID: {"$in": &tuuids_retires}};
            let ops = doc! {
                "$pull": {CHAMP_CUUIDS: cuuid},
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            let resultat = match collection.update_many(filtre, ops, None).await {
                Ok(r) => r,
                Err(e) => Err(format!("grosfichiers.transaction_supprimer_documents Erreur update_many pour pull cuuid : {:?}", e))?
            };
            debug!("transaction_supprimer_documents Resultat transaction update : {:?}", resultat);
        }
    }

    debug!("transaction_supprimer_documents Emettre messages pour tuuids retires : {:?}", tuuids_retires_par_cuuid);

    // Emettre evenements supprime par cuuid
    for (cuuid, liste) in tuuids_retires_par_cuuid {
        let mut evenement = EvenementContenuCollection::new();
        evenement.cuuid = Some(cuuid);
        evenement.retires = Some(liste);
        emettre_evenement_contenu_collection(middleware, evenement).await?;
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
        "$set": {CHAMP_SUPPRIME: false, CHAMP_ARCHIVE: false},
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
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_RECUPERER).await?;
    }

    middleware.reponse_ok()
}

async fn transaction_archiver_documents<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_archiver_documents Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionListeDocuments = match transaction.clone().convertir::<TransactionListeDocuments>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_archiver_documents Erreur conversion transaction : {:?}", e))?
    };

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let filtre = match user_id.as_ref() {
        Some(u) => doc! {CHAMP_USER_ID: u, CHAMP_TUUID: {"$in": &transaction_collection.tuuids}},
        None => doc! {CHAMP_TUUID: {"$in": &transaction_collection.tuuids}}
    };
    let ops = doc! {
        "$set": {CHAMP_ARCHIVE: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let resultat = match collection.update_many(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transactions.transaction_archiver_documents Erreur update_many sur transcation : {:?}", e))?
    };
    debug!("transaction_archiver_documents Resultat transaction update : {:?}", resultat);

    for tuuid in &transaction_collection.tuuids {
        // Emettre fichier pour que tous les clients recoivent la mise a jour
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_ARCHIVER).await?;
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

async fn transaction_associer_conversions<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
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
    let user_id = match transaction_mappee.user_id.as_ref() {
        Some(inner) => Some(inner.as_str()),
        None => None
    };
    let fuuid = transaction_mappee.fuuid.as_str();

    let doc_images = match convertir_to_bson(transaction_mappee.images.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur conversion images en bson : {:?}", e))?
    };

    // Mapper tous les fuuids avec leur mimetype
    let (fuuids, fuuids_reclames) = {
        let mut fuuids = Vec::new();
        let mut fuuids_reclames = Vec::new();
        fuuids.push(transaction_mappee.fuuid.clone());
        for (_, image) in transaction_mappee.images.iter() {
            fuuids.push(image.hachage.to_owned());
            if image.data_chiffre.is_none() {
                fuuids_reclames.push(image.hachage.to_owned());
            }
        }
        (fuuids, fuuids_reclames)
    };

    // MAJ de la version du fichier
    {
        let mut filtre = doc! { CHAMP_FUUID: &transaction_mappee.fuuid };
        if let Some(inner) = user_id {
            // Note : legacy, supporte ancienne transaction (pre 2023.6) qui n'avait pas le user_id
            filtre.insert(CHAMP_USER_ID, inner);
        }
        let mut set_ops = doc! {};

        // Si on a le thumbnail, on va marquer media_traite
        debug!("Traiter images : {:?}", transaction_mappee.images);
        set_ops.insert(CHAMP_FLAG_MEDIA_TRAITE, true);

        // Inserer images par cle dans set_ops
        for (k, v) in &doc_images {
            debug!("Traiter image {} : {:?}", k, v);
            let cle_image = format!("images.{}", k);
            set_ops.insert(cle_image, v.to_owned());
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
        if let Some(inner) = transaction_mappee.video_codec.as_ref() {
            set_ops.insert("videoCodec", inner);
        }
        if let Some(inner) = transaction_mappee.duration.as_ref() {
            set_ops.insert("duration", inner);
        }
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }

        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids_reclames},
        };

        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        debug!("transactions.transaction_associer_conversions set ops versions : {:?}", ops);
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transactions.transaction_associer_conversions Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_conversions Erreur maj versions : {:?}", e))?
        }

        if let Err(e) = gestionnaire.image_job_handler.set_flag(middleware, fuuid, user_id, None, true).await {
            error!("Erreur set flag true pour traitement job images {:?}/{} : {:?}", user_id, fuuid, e);
        }
    }

    // S'assurer d'appliquer le fitre sur la version courante
    {
        let filtre = doc! {
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_FUUID_V_COURANTE: &transaction_mappee.fuuid,
        };

        let mut set_ops = doc! {};

        // Inserer images par cle dans set_ops
        for (k, v) in doc_images {
            let cle_image = format!("version_courante.images.{}", k);
            set_ops.insert(cle_image, v);
        };

        if let Some(inner) = &transaction_mappee.anime {
            set_ops.insert("version_courante.anime", inner);
        }
        if let Some(inner) = &transaction_mappee.mimetype {
            set_ops.insert("mimetype", inner);
            set_ops.insert("version_courante.mimetype", inner);
        }
        if let Some(inner) = &transaction_mappee.width {
            set_ops.insert("version_courante.width", inner);
        }
        if let Some(inner) = &transaction_mappee.height {
            set_ops.insert("version_courante.height", inner);
        }
        if let Some(inner) = transaction_mappee.video_codec.as_ref() {
            set_ops.insert("version_courante.videoCodec", inner);
        }
        if let Some(inner) = transaction_mappee.duration.as_ref() {
            set_ops.insert("version_courante.duration", inner);
        }
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("version_courante.{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }

        // Combiner les fuuids hors de l'info de version
        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids_reclames},
        };

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
    emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_ASSOCIER_CONVERSION).await?;

    middleware.reponse_ok()
}

async fn transaction_associer_video<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_associer_video Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionAssocierVideo = match transaction.clone().convertir::<TransactionAssocierVideo>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion transaction : {:?}", e))?
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

    let cle_video = match transaction_mappee.cle_conversion {
        Some(inner) => inner,  // Nouveau avec 2023.7.4
        None => {
            // Note : avant 2023.7.4 (et media 2023.7.4), la cle_video n'etait pas fournie
            //        cause un probleme avec les videos verticaux.
            let resolution = match transaction_mappee.height {
                Some(height) => match transaction_mappee.width {
                    Some(width) => {
                        // La resolution est le plus petit des deux nombres
                        if width < height {
                            width
                        } else {
                            height
                        }
                    },
                    None => height,
                },
                None => 0
            };
            let bitrate_quality = {
                match &transaction_mappee.quality {
                    Some(q) => q.to_owned(),
                    None => match &transaction_mappee.bitrate {
                        Some(b) => b.to_owned() as i32,
                        None => 0
                    }
                }
            };
            format!("{};{};{}p;{}", &transaction_mappee.mimetype, &transaction_mappee.codec, resolution, bitrate_quality)
        }
    };

    // Appliquer le filtre sur la version courante (pour l'usager si applicable)
    let mut fuuid_video_existant = None;
    {
        let mut filtre = doc! {
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_FUUID_V_COURANTE: &transaction_mappee.fuuid,
            CHAMP_USER_ID: &transaction_mappee.user_id,
        };

        // if let Some(user_id) = transaction_mappee.user_id.as_ref() {
        //     // Utiliser un filtre pour un usager
        //     filtre.insert(CHAMP_USER_ID, user_id.to_owned());
        // }

        // Verifier si le video existe deja - retirer le fuuid_video si c'est le cas
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        {
            let doc_existant: Option<FichierDetail> = match collection.find_one(filtre.clone(), None).await {
                Ok(d) => match d {
                    Some(d) => match convertir_bson_deserializable(d) {
                        Ok(d) => d,
                        Err(e) => Err(format!("transactions.transaction_associer_video Erreur conversion bson fichier (video) : {:?}", e))?
                    },
                    None => None
                },
                Err(e) => Err(format!("transaction_associer_video Erreur chargement fichier (video) : {:?}", e))?
            };
            if let Some(d) = doc_existant {
                if let Some(version_courante) = d.version_courante {
                    if let Some(v) = version_courante.video {
                        if let Some(video) = v.get(cle_video.as_str()) {
                            fuuid_video_existant = Some(video.fuuid_video.to_owned());
                        }
                    }
                }
            }
        }

        if let Some(fuuid_video) = fuuid_video_existant.as_ref() {
            let ops = doc! {
                "$pull": {
                    CHAMP_FUUIDS: &fuuid_video,
                    CHAMP_FUUIDS_RECLAMES: &fuuid_video
                },
                // "$unset": {format!("version_courante.fuuidMimetypes.{}", fuuid_video): true},
            };
            match collection.update_many(filtre.clone(), ops, None).await {
                Ok(inner) => debug!("transaction_associer_video Suppression video : {:?}", inner),
                Err(e) => Err(format!("transactions.transaction_associer_video Erreur suppression video existant : {:?}", e))?
            }
        }

        let mut set_ops = doc! {
            format!("version_courante.video.{}", &cle_video): &doc_video,
        };
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("version_courante.{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }

        // Combiner les fuuids hors de l'info de version
        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids},
        };

        let mut ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };

        match collection.update_many(filtre, ops, None).await {
            Ok(inner) => debug!("transaction_associer_video Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_video Erreur maj versions : {:?}", e))?
        }
    }

    // MAJ de la version du fichier
    {
        let filtre = doc! {
            CHAMP_FUUID: &transaction_mappee.fuuid,
            CHAMP_TUUID: &transaction_mappee.tuuid,
            CHAMP_USER_ID: &transaction_mappee.user_id,
        };

        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;

        if let Some(fuuid_video) = fuuid_video_existant.as_ref() {
            let ops = doc! {
                "$pull": {
                    CHAMP_FUUIDS: &fuuid_video,
                    CHAMP_FUUIDS_RECLAMES: &fuuid_video,
                },
                // "$unset": {format!("fuuidMimetypes.{}", fuuid_video): true},
            };
            match collection.update_many(filtre.clone(), ops, None).await {
                Ok(inner) => debug!("transaction_associer_video Suppression video : {:?}", inner),
                Err(e) => Err(format!("transactions.transaction_associer_video Erreur suppression video existant : {:?}", e))?
            }
        }

        let mut set_ops = doc! {
            CHAMP_FLAG_VIDEO_TRAITE: true,
            format!("video.{}", &cle_video): &doc_video,
        };
        // for (fuuid, mimetype) in fuuid_mimetypes.iter() {
        //     set_ops.insert(format!("{}.{}", CHAMP_FUUID_MIMETYPES, fuuid), mimetype);
        // }
        let add_to_set = doc! {
            CHAMP_FUUIDS: {"$each": &fuuids},
            CHAMP_FUUIDS_RECLAMES: {"$each": &fuuids},
        };
        let ops = doc! {
            "$set": set_ops,
            "$addToSet": add_to_set,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        match collection.update_one(filtre, ops, None).await {
            Ok(inner) => debug!("transaction_associer_video Update versions : {:?}", inner),
            Err(e) => Err(format!("transactions.transaction_associer_video Erreur maj versions : {:?}", e))?
        }
    }

    {   // Supprimer job dans table videos
        // Traiter la commande
        let mut cles_supplementaires = HashMap::new();
        cles_supplementaires.insert(CHAMP_CLE_CONVERSION.to_string(), cle_video.clone());
        if let Err(e) = gestionnaire.video_job_handler.set_flag(
            middleware, &transaction_mappee.fuuid, Some(&transaction_mappee.user_id), Some(cles_supplementaires), true).await {
            error!("transaction_associer_video Erreur traitement flag : {:?}", e);
        }

        // let collection_video = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
        // let filtre = doc! {CHAMP_FUUID: &transaction_mappee.fuuid, CHAMP_CLE_CONVERSION: &cle_video};
        // if let Err(e) = collection_video.delete_one(filtre, None).await {
        //     error!("transactions.transaction_associer_conversions Erreur suppression job video fuuid {:?} cle {} : {:?}",
        //         &transaction_mappee.fuuid, &cle_video, e);
        // }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    //if let Some(t) = tuuid.as_ref() {
        emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_ASSOCIER_VIDEO).await?;
    //}

    middleware.reponse_ok()
}

async fn transaction_decire_fichier<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_decire_fichier Consommer transaction : {:?}", &transaction);
    let transaction_mappee: TransactionDecrireFichier = match transaction.clone().convertir::<TransactionDecrireFichier>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion transaction : {:?}", e))?
    };

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let tuuid = transaction_mappee.tuuid.as_str();
    let mut filtre = doc! { CHAMP_TUUID: tuuid };
    if let Some(inner) = &user_id {
        filtre.insert("user_id", inner);
    }

    // {
    //     // Reset flag indexe
    //     let collection_versions = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
    //     let ops = doc! {
    //         "$set": { CHAMP_FLAG_INDEX: false },
    //         "$unset": { CHAMP_FLAG_INDEX_ERREUR: true },
    //         "$currentDate": { CHAMP_MODIFICATION: true },
    //     };
    //     if let Err(e) = collection_versions.update_one(filtre.clone(), ops, None).await {
    //         Err(format!("transactions.transaction_decire_collection Erreur maj versions fichiers tuuid {} : {:?}", tuuid, e))?
    //     }
    // }

    let mut set_ops = doc! {};

    // Modifier metadata
    if let Some(metadata) = transaction_mappee.metadata {
        let metadata_bson = match bson::to_bson(&metadata) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion metadata vers bson : {:?}", e))?
        };
        set_ops.insert("version_courante.metadata", metadata_bson);
    }

    if let Some(mimetype) = transaction_mappee.mimetype {
        set_ops.insert("mimetype", &mimetype);
        set_ops.insert("version_courante.mimetype", &mimetype);
    }

    // Modifier champ nom si present
    // if let Some(nom) = &transaction_mappee.nom {
    //     set_ops.insert("nom", nom);
    // }

    // Modifier champ titre si present
    // if let Some(titre) = &transaction_mappee.titre {
    //     let titre_bson = match bson::to_bson(titre) {
    //         Ok(inner) => inner,
    //         Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion titre vers bson : {:?}", e))?
    //     };
    //     set_ops.insert("titre", titre_bson);
    // }

    // Modifier champ description si present
    // if let Some(description) = &transaction_mappee.description {
    //     let description_bson = match bson::to_bson(description) {
    //         Ok(inner) => inner,
    //         Err(e) => Err(format!("transactions.transaction_decire_fichier Erreur conversion titre vers bson : {:?}", e))?
    //     };
    //     set_ops.insert("description", description_bson);
    // }

    let ops = doc! {
        "$set": set_ops,
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => {
            debug!("transaction_decire_fichier Update description : {:?}", inner);
            if let Some(doc_fichier) = inner {
                if let Ok(inner) = convertir_bson_deserializable::<FichierDetail>(doc_fichier) {
                    if let Some(user_id) = inner.user_id {
                        if let Some(fuuid) = inner.fuuid_v_courante {
                            if let Some(mimetype) = inner.mimetype {
                                let mut champs_cles = HashMap::new();
                                champs_cles.insert("tuuid".to_string(), tuuid.to_string());
                                champs_cles.insert("mimetype".to_string(), mimetype.to_string());
                                if let Err(e) = gestionnaire.indexation_job_handler.sauvegarder_job(
                                    middleware, fuuid, user_id, None,
                                    Some(champs_cles), None, false).await {
                                    error!("transaction_decire_fichier Erreur ajout_job_indexation : {:?}", e);
                                }
                                // if let Err(e) = ajout_job_indexation(middleware, tuuid, fuuid, user_id, mimetype).await {
                                //     error!("transaction_decire_fichier Erreur ajout_job_indexation : {:?}", e);
                                // }
                            }
                        }
                    }
                }
            }
            // if let Some(d) = inner {
            //     // Emettre evenement de maj contenu sur chaque cuuid
            //     match convertir_bson_deserializable::<FichierDetail>(d) {
            //         Ok(fichier) => {
            //             if let Some(favoris) = fichier.favoris {
            //                 if let Some(u) = user_id {
            //                     if favoris {
            //                         let mut evenement = EvenementContenuCollection::new();
            //                         evenement.cuuid = Some(u);
            //                         evenement.fichiers_modifies = Some(vec![tuuid.to_owned()]);
            //                         emettre_evenement_contenu_collection(middleware, evenement).await?;
            //                     }
            //                 }
            //             }
            //             if let Some(cuuids) = fichier.cuuids {
            //                 for cuuid in cuuids {
            //                     let mut evenement = EvenementContenuCollection::new();
            //                     evenement.cuuid = Some(cuuid);
            //                     evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
            //                     emettre_evenement_contenu_collection(middleware, evenement).await?;
            //                 }
            //             }
            //         },
            //         Err(e) => warn!("transaction_decire_fichier Erreur conversion a FichierDetail : {:?}", e)
            //     }
            // }
        },
        Err(e) => Err(format!("transaction_decire_fichier Erreur update description : {:?}", e))?
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_DECRIRE_FICHIER).await?;

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

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let tuuid = transaction_mappee.tuuid.as_str();
    let filtre = doc! { CHAMP_TUUID: tuuid };

    let doc_metadata = match convertir_to_bson(&transaction_mappee.metadata) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.transaction_decire_collection Erreur conversion transaction : {:?}", e))?
    };

    let mut set_ops = doc! {
        "metadata": doc_metadata,
    };

    let ops = doc! {
        "$set": set_ops,
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => {
            debug!("transactions.transaction_decire_collection Update description : {:?}", inner);
            if let Some(d) = inner {
                // Emettre evenement de maj contenu sur chaque cuuid
                match convertir_bson_deserializable::<FichierDetail>(d) {
                    Ok(fichier) => {
                        if let Some(favoris) = fichier.favoris {
                            if let Some(u) = user_id {
                                if favoris {
                                    let mut evenement = EvenementContenuCollection::new();
                                    evenement.cuuid = Some(u);
                                    evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                    emettre_evenement_contenu_collection(middleware, evenement).await?;
                                }
                            }
                        }
                        if let Some(cuuids) = fichier.cuuids {
                            for cuuid in cuuids {
                                let mut evenement = EvenementContenuCollection::new();
                                evenement.cuuid = Some(cuuid);
                                evenement.collections_modifiees = Some(vec![tuuid.to_owned()]);
                                emettre_evenement_contenu_collection(middleware, evenement).await?;
                            }
                        }
                    },
                    Err(e) => warn!("transaction_decire_collection Erreur conversion a FichierDetail : {:?}", e)
                }
            }
        },
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

    let user_id = match transaction_fichier.user_id.as_ref() {
        Some(inner) => inner,
        None => Err(format!("transactions.transaction_copier_fichier_tiers user_id manquant"))?
    };

    // Detecter si le fichier existe deja pour l'usager (par fuuid)
    let tuuid = {
        let filtre = doc!{CHAMP_USER_ID: &user_id, CHAMP_FUUIDS: &transaction_fichier.fuuid};
        let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
        match collection.find_one(filtre, None).await {
            Ok(inner) => {
                match inner {
                    Some(doc) => {
                        // Le document existe deja, reutiliser le tuuid et ajouter au nouveau cuuid
                        let fichier: FichierDetail = match convertir_bson_deserializable(doc) {
                            Ok(inner) => inner,
                            Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur mapping a FichierDetail : {:?}", e))?
                        };
                        fichier.tuuid
                    },
                    None => {
                        // Nouveau fichier, utiliser uuid_transaction pour le tuuid
                        transaction.get_uuid_transaction().to_string()
                    }
                }
            },
            Err(e) => Err(format!("transactions.transaction_copier_fichier_tiers Erreur verification fuuid existant : {:?}", e))?
        }
    };

    // Conserver champs transaction uniquement (filtrer champs meta)
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
        Ok(d) => d,
        Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
    };

    debug!("transaction_copier_fichier_tiers Tuuid {} Doc bson : {:?}", tuuid, doc_bson_transaction);

    let fuuid = transaction_fichier.fuuid;
    let cuuid = transaction_fichier.cuuid;
    let metadata = transaction_fichier.metadata;
    let mimetype = transaction_fichier.mimetype;

    let mut fuuids = HashSet::new();
    let mut fuuids_reclames = HashSet::new();
    fuuids.insert(fuuid.as_str());
    fuuids_reclames.insert(fuuid.as_str());
    let images_presentes = match &transaction_fichier.images {
        Some(images) => {
            let presentes = ! images.is_empty();
            for image in images.values() {
                fuuids.insert(image.hachage.as_str());
                if image.data_chiffre.is_none() {
                    fuuids_reclames.insert(image.hachage.as_str());
                }
            }
            presentes
        },
        None => false
    };
    let videos_presents = match &transaction_fichier.video {
        Some(videos) => {
            let presents = ! videos.is_empty();
            for video in videos.values() {
                fuuids.insert(video.fuuid_video.as_str());
                fuuids_reclames.insert(video.fuuid_video.as_str());
            }
            presents
        },
        None => false
    };

    let fuuids: Vec<&str> = fuuids.into_iter().collect();  // Convertir en vec
    let fuuids_reclames: Vec<&str> = fuuids_reclames.into_iter().collect();  // Convertir en vec

    debug!("Fuuids fichier : {:?}", fuuids);
    doc_bson_transaction.insert(CHAMP_FUUIDS, &fuuids);
    doc_bson_transaction.insert(CHAMP_FUUIDS_RECLAMES, &fuuids_reclames);

    // Retirer champ CUUID, pas utile dans l'information de version
    doc_bson_transaction.remove(CHAMP_CUUID);

    // Inserer document de version
    {
        let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        let mut doc_version = doc_bson_transaction.clone();
        doc_version.insert(CHAMP_TUUID, &tuuid);
        doc_version.insert(CHAMP_FUUIDS, &fuuids);
        doc_version.insert(CHAMP_FUUIDS_RECLAMES, &fuuids_reclames);

        // Information optionnelle pour accelerer indexation/traitement media
        if mimetype.starts_with("image") {
            doc_version.insert(CHAMP_FLAG_MEDIA, "image");

            // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);
        } else if mimetype.starts_with("video") {
            doc_version.insert(CHAMP_FLAG_MEDIA, "video");

            // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);

            // Si au moins 1 video est present dans l'entree, on ne fait pas de traitements supplementaires
            doc_version.insert(CHAMP_FLAG_VIDEO_TRAITE, videos_presents);
        } else if mimetype =="application/pdf" {
            doc_version.insert(CHAMP_FLAG_MEDIA, "poster");

            // Si au moins 1 image est presente dans l'entree, on ne fait pas de traitements supplementaires
            doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, images_presentes);
        }
        doc_version.insert(CHAMP_FLAG_INDEX, false);

        // Champs date
        doc_version.insert(CHAMP_CREATION, Utc::now());

        let ops = doc! {
            "$setOnInsert": doc_version,
            "$currentDate": {CHAMP_MODIFICATION: true}
        };

        let filtre = doc! { "fuuid": &fuuid, "tuuid": &tuuid };
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

    // Retirer champs cles - ils sont inutiles dans la version_courante
    doc_bson_transaction.remove(CHAMP_TUUID);
    doc_bson_transaction.remove(CHAMP_FUUID);
    doc_bson_transaction.remove(CHAMP_METADATA);
    doc_bson_transaction.remove(CHAMP_FUUIDS);
    doc_bson_transaction.remove(CHAMP_FUUIDS_RECLAMES);
    doc_bson_transaction.remove(CHAMP_USER_ID);

    let filtre = doc! {CHAMP_TUUID: &tuuid};
    let mut add_to_set = doc!{
        "fuuids": {"$each": &fuuids},
        "fuuids_reclames": {"$each": &fuuids_reclames},
    };

    // Ajouter collection
    add_to_set.insert("cuuids", cuuid);

    let metadata = match metadata {
        Some(inner) => match convertir_to_bson(inner) {
            Ok(metadata) => Some(metadata),
            Err(e) => Err(format!("Erreur conversion metadata a bson : {:?}", e))?
        },
        None => None
    };

    let ops = doc! {
        "$set": {
            "version_courante": doc_bson_transaction,
            CHAMP_FUUID_V_COURANTE: &fuuid,
            CHAMP_MIMETYPE: &mimetype,
            CHAMP_SUPPRIME: false,
        },
        "$addToSet": add_to_set,
        "$setOnInsert": {
            CHAMP_TUUID: &tuuid,
            CHAMP_CREATION: Utc::now(),
            CHAMP_USER_ID: &user_id,
            CHAMP_METADATA: metadata,
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

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_COPIER_FICHIER_TIERS).await?;

    middleware.reponse_ok()
}

async fn transaction_favoris_creerpath<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_favoris_creerpath Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionFavorisCreerpath = match transaction.clone().convertir::<TransactionFavorisCreerpath>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion transaction : {:?}", e))?
    };
    let uuid_transaction = transaction.get_uuid_transaction();

    let user_id = match &transaction_collection.user_id {
        Some(u) => Ok(u.to_owned()),
        None => {
            match transaction.get_enveloppe_certificat() {
                Some(c) => {
                    match c.get_user_id()? {
                        Some(u) => Ok(u.to_owned()),
                        None => Err(format!("grosfichiers.transaction_favoris_creerpath user_id manquant"))
                    }
                },
                None => Err(format!("grosfichiers.transaction_favoris_creerpath Certificat non charge"))
            }
        }
    }?;

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;

    let date_courante = Utc::now();
    let tuuid_favoris = format!("{}_{}", &user_id, &transaction_collection.favoris_id);

    {
        let ops_favoris = doc! {
            "$setOnInsert": {
                CHAMP_TUUID: &tuuid_favoris,
                CHAMP_NOM: &transaction_collection.favoris_id,
                CHAMP_CREATION: &date_courante,
                CHAMP_MODIFICATION: &date_courante,
                CHAMP_SECURITE: SECURITE_3_PROTEGE,
                CHAMP_USER_ID: &user_id,
            },
            "$set": {
                CHAMP_SUPPRIME: false,
                CHAMP_FAVORIS: true,
            }
        };
        let filtre_favoris = doc! {CHAMP_TUUID: &tuuid_favoris};
        let options_favoris = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let doc_favoris_opt = match collection.find_one_and_update(
            filtre_favoris, ops_favoris, Some(options_favoris)).await {
            Ok(f) => Ok(f),
            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur find_one_and_update doc favoris : {:?}", e))
        }?;

        if doc_favoris_opt.is_none() {
            Err(format!("grosfichiers.transaction_favoris_creerpath Erreur creation document favoris"))?;
        }
    }

    let mut cuuid_courant = tuuid_favoris.clone();
    let mut idx = 0;
    let tuuid_leaf = match transaction_collection.path_collections {
        Some(path_collections) => {
            for path_col in path_collections {
                idx = idx+1;
                // Trouver ou creer favoris
                let filtre = doc!{
                    CHAMP_CUUIDS: &cuuid_courant,
                    CHAMP_USER_ID: &user_id,
                    CHAMP_NOM: &path_col,
                };
                let doc_path = match collection.find_one(filtre, None).await {
                    Ok(d) => Ok(d),
                    Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur creation doc collection path {} : {:?}", path_col, e))
                }?;
                match doc_path {
                    Some(d) => {
                        debug!("grosfichiers.transaction_favoris_creerpath Mapper info collection : {:?}", d);
                        let collection_info: InformationCollection = match convertir_bson_deserializable(d) {
                            Ok(inner_collection) => Ok(inner_collection),
                            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion bson path {} : {:?}", path_col, e))
                        }?;
                        cuuid_courant = collection_info.tuuid.clone();

                        let flag_supprime = match collection_info.supprime {
                            Some(f) => f,
                            None => true
                        };

                        if flag_supprime {
                            // MAj collection, flip flags
                            let filtre = doc!{CHAMP_TUUID: &collection_info.tuuid};
                            let ops = doc!{
                                "$set": {CHAMP_SUPPRIME: false},
                                "$currentDate": {CHAMP_MODIFICATION: true}
                            };
                            match collection.update_one(filtre, ops, None).await {
                                Ok(_) => (),
                                Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur flip flag supprime de tuuid={} : {:?}", &collection_info.tuuid, e))?
                            }
                        }
                    },
                    None => {
                        // Creer la nouvelle collection
                        let tuuid = format!("{}_{}", uuid_transaction, idx);
                        let collection_info = doc!{
                            CHAMP_TUUID: &tuuid,
                            CHAMP_NOM: &path_col,
                            CHAMP_CREATION: &date_courante,
                            CHAMP_MODIFICATION: &date_courante,
                            CHAMP_SECURITE: SECURITE_3_PROTEGE,
                            CHAMP_USER_ID: &user_id,
                            CHAMP_SUPPRIME: false,
                            CHAMP_FAVORIS: false,
                            CHAMP_CUUIDS: vec![cuuid_courant]
                        };
                        match collection.insert_one(collection_info, None).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur insertion collection path {} : {:?}", path_col, e))
                        }?;
                        cuuid_courant = tuuid.clone();
                    }
                }
            }

            // Retourner le dernier identifcateur de collection (c'est le tuuid)
            cuuid_courant
        },
        None => tuuid_favoris
    };

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    let reponse = match middleware.formatter_reponse(json!({CHAMP_TUUID: &tuuid_leaf}), None) {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }?;

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationCollection {
    pub tuuid: String,
    pub nom: String,
    pub cuuids: Option<Vec<String>>,
    pub user_id: String,
    pub supprime: Option<bool>,
    pub favoris: Option<bool>,
}

async fn transaction_supprimer_video<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_video Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerVideo = match transaction.clone().convertir::<TransactionSupprimerVideo>() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur conversion transaction : {:?}", e))?
    };

    let fuuid = &transaction_collection.fuuid_video;

    let enveloppe = match transaction.get_enveloppe_certificat() {
        Some(e) => e,
        None => Err(format!("transaction_supprimer_video Certificat inconnu, transaction ignoree"))?
    };
    let user_id = enveloppe.get_user_id()?;

    // {   // Verifier acces
    //     let delegation_globale = enveloppe.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);
    //     if delegation_globale || enveloppe.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
    //         // Ok
    //     } else if user_id.is_some() {
    //         let u = user_id.expect("commande_video_convertir user_id");
    //         let resultat = verifier_acces_usager(middleware, &u, vec![fuuid]).await?;
    //         if ! resultat.contains(fuuid) {
    //             debug!("commande_video_convertir verifier_exchanges : Usager n'a pas acces a fuuid {}", fuuid);;
    //             return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
    //         }
    //     } else {
    //         debug!("commande_video_convertir verifier_exchanges : Certificat n'a pas l'acces requis (securite 2,3,4 ou user_id avec acces fuuid)");
    //         return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Access denied"}), None)?))
    //     }
    // }

    let mut labels_videos = Vec::new();
    let filtre = doc!{CHAMP_FUUIDS: fuuid, CHAMP_USER_ID: user_id.as_ref()};
    let collection_fichier_rep = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let doc_video: FichierDetail = match collection_fichier_rep.find_one(filtre.clone(), None).await {
        Ok(d) => match d {
            Some(d) => match convertir_bson_deserializable(d) {
                Ok(d) => match d {
                    Some(d) => d,
                    None => Err(format!("transaction_supprimer_video Erreur chargement info document, aucun match"))?,
                },
                Err(e) => Err(format!("transaction_supprimer_video Erreur conversion info document : {:?}", e))?
            },
            None => Err(format!("transaction_supprimer_video Erreur chargement info document, aucun match"))?
        },
        Err(e) => Err(format!("transaction_supprimer_video Erreur chargement info document : {:?}", e))?
    };

    let tuuid = doc_video.tuuid.as_str();

    {
        debug!("Information doc videos a supprimer : {:?}", doc_video);
        let mut ops_unset = doc!{};
        if let Some(version_courante) = doc_video.version_courante {
            if let Some(map_video) = version_courante.video {
                for (label, video) in map_video {
                    if &video.fuuid_video == fuuid {
                        ops_unset.insert(format!("version_courante.video.{}", label), true);
                        labels_videos.push(label);
                    }
                }
            }
        }

        ops_unset.insert(format!("version_courante.fuuidMimetypes.{}", fuuid), true);

        let ops = doc! {
            "$pull": {"fuuids": fuuid},
            "$unset": ops_unset,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        debug!("transaction_supprimer_video Ops supprimer video fichier_rep : {:?}", ops);
        match collection_fichier_rep.update_one(filtre.clone(), ops, None).await {
            Ok(_r) => (),
            Err(e) => Err(format!("transaction_supprimer_video Erreur update_one collection fichiers rep : {:?}", e))?
        }
    }

    {
        let filtre = doc!{CHAMP_FUUIDS: fuuid};
        let mut ops_unset = doc!{format!("fuuidMimetypes.{}", fuuid): true};
        for label in labels_videos {
            ops_unset.insert(format!("video.{}", label), true);
        }

        let ops = doc! {
            "$pull": {"fuuids": fuuid},
            "$unset": ops_unset,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let collection_version_fichier = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
        match collection_version_fichier.update_one(filtre, ops, None).await {
            Ok(_r) => (),
            Err(e) => Err(format!("transaction_supprimer_video Erreur update_one collection fichiers rep : {:?}", e))?
        }
    }

    // Emettre fichier pour que tous les clients recoivent la mise a jour
    emettre_evenement_maj_fichier(middleware, &tuuid, EVENEMENT_FUUID_NOUVELLE_VERSION).await?;

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok() {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}


async fn transaction_supprimer_job_image<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_job_image Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerJobImage = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_job_image Erreur conversion transaction : {:?}", e))?
    };

    let fuuid = &transaction_collection.fuuid;
    let user_id = &transaction_collection.user_id;

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = gestionnaire.image_job_handler.set_flag(middleware, fuuid, Some(user_id),None, true).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag image : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok() {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("transactions.transaction_supprimer_job_image Erreur formattage reponse"))
    }
}

async fn transaction_supprimer_job_video<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_job_video Consommer transaction : {:?}", &transaction);
    let transaction_collection: TransactionSupprimerJobVideo = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_job_image Erreur conversion transaction : {:?}", e))?
    };

    let fuuid = &transaction_collection.fuuid;
    let user_id = &transaction_collection.user_id;
    let mut cles_supplementaires = HashMap::new();
    cles_supplementaires.insert("cle_conversion".to_string(), transaction_collection.cle_conversion.clone());

    // Indiquer que la job a ete completee et ne doit pas etre redemarree.
    if let Err(e) = gestionnaire.video_job_handler.set_flag(middleware, fuuid, Some(user_id),Some(cles_supplementaires), true).await {
        Err(format!("transactions.transaction_supprimer_job_image Erreur set_flag video : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok() {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("grosfichiers.transaction_favoris_creerpath Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterContactLocal {
    /// Usager du carnet
    pub user_id: String,
    /// Contact local ajoute
    pub contact_user_id: String,
}

async fn transaction_ajouter_contact_local<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_ajouter_contact_local Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let transaction_mappee: TransactionAjouterContactLocal = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc! {
        CHAMP_ID_CONTACT: uuid_transaction,
        CHAMP_USER_ID: &transaction_mappee.user_id,
        "contact_user_id": &transaction_mappee.contact_user_id,
    };
    let ops = doc! {
        "$setOnInsert": {
            CHAMP_USER_ID: transaction_mappee.user_id,
            "contact_user_id": transaction_mappee.contact_user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    if let Err(e) = collection.update_one(filtre, ops, options).await {
        Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur sauvegarde contact : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok() {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("grosfichiers.transaction_ajouter_contact_local Erreur formattage reponse"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerContacts {
    pub contact_ids: Vec<String>,
}

async fn transaction_supprimer_contacts<M, T>(middleware: &M, gestionnaire: &GestionnaireGrosFichiers, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_supprimer_contacts Consommer transaction : {:?}", &transaction);
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(inner) => match inner.get_user_id()? {
            Some(inner) => inner.to_owned(),
            None => Err(format!("grosfichiers.transaction_supprimer_contacts User_id manquant du certificat"))?
        },
        None => Err(format!("grosfichiers.transaction_supprimer_contacts Erreur enveloppe manquante"))?
    };

    let transaction_mappee: TransactionSupprimerContacts = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_contacts Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc! {
        CHAMP_USER_ID: &user_id,
        CHAMP_ID_CONTACT: {"$in": transaction_mappee.contact_ids},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_PARTAGE_CONTACT)?;
    if let Err(e) = collection.delete_many(filtre, None).await {
        Err(format!("grosfichiers.transaction_supprimer_contacts Erreur suppression contacts : {:?}", e))?
    }

    // Retourner le tuuid comme reponse, aucune transaction necessaire
    match middleware.reponse_ok() {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("grosfichiers.transaction_supprimer_contacts Erreur formattage reponse"))
    }
}
