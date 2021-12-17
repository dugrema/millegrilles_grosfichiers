use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
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
use crate::traitement_index::{ElasticSearchDao, ParametresGetPermission, ParametresRecherche, ResultatHits, ResultatHitsDetail};
use crate::transactions::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else if message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege]) {
        // Autorisation : On accepte les requetes de 3.protege ou 4.secure
        // Ok
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
                REQUETE_FAVORIS => requete_favoris(middleware, message, gestionnaire).await,
                REQUETE_DOCUMENTS_PAR_TUUID => requete_documents_par_tuuid(middleware, message, gestionnaire).await,
                REQUETE_CONTENU_COLLECTION => requete_contenu_collection(middleware, message, gestionnaire).await,
                REQUETE_GET_CORBEILLE => requete_get_corbeille(middleware, message, gestionnaire).await,
                REQUETE_RECHERCHE_INDEX => requete_recherche_index(middleware, message, gestionnaire).await,
                REQUETE_GET_PERMISSION => requete_get_permission(middleware, message, gestionnaire).await,
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

    let user_id = m.get_user_id();
    if user_id.is_none() {
        return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
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
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn mapper_fichiers_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
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

pub fn mapper_fichier_db(fichier: Document) -> Result<FichierDetail, Box<dyn Error>> {
    let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
    let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
    let mut fichier_mappe: FichierDetail = convertir_bson_deserializable(fichier)?;
    fichier_mappe.date_creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
    fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
    debug!("Fichier mappe : {:?}", fichier_mappe);
    Ok(fichier_mappe)
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct FichierVersionCourante {
//     tuuid: String,
//     #[serde(skip_serializing_if="Option::is_none")]
//     cuuids: Option<Vec<String>>,
//     nom: String,
//     titre: Option<HashMap<String, String>>,
//
//     fuuid_v_courante: Option<String>,
//     version_courante: Option<DBFichierVersion>,
//
//     favoris: Option<bool>,
//
//     date_creation: Option<DateEpochSeconds>,
//     derniere_modification: Option<DateEpochSeconds>,
//     supprime: Option<bool>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct DBFichierVersion {
//     nom: String,
//     fuuid: String,
//     tuuid: String,
//     mimetype: String,
//     taille: usize,
//     #[serde(rename="dateFichier")]
//     date_fichier: DateEpochSeconds,
//     #[serde(skip_serializing_if="Option::is_none")]
//     height: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     weight: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     images: Option<HashMap<String, ImageConversion>>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     anime: Option<bool>,
// }

async fn requete_favoris<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_favoris Message : {:?}", & m.message);
    //let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
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
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Favoris {
    nom: String,
    tuuid: String,
    securite: Option<String>,
    // #[serde(rename(deserialize = "_mg-creation"))]
    // date_creation: Option<DateEpochSeconds>,
    // titre: Option<HashMap<String, String>>,
}

async fn requete_documents_par_tuuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_documents_par_tuuid Message : {:?}", & m.message);
    let requete: RequeteDocumentsParTuuids = m.message.get_msg().map_contenu(None)?;
    debug!("requete_documents_par_tuuid cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let mut filtre = doc! { CHAMP_TUUID: {"$in": &requete.tuuids_documents} };
    if user_id.is_some() {
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    }
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

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let skip = match requete.skip { Some(s) => s, None => 0 };
    let limit = match requete.limit { Some(l) => l, None => 50 };
    let mut filtre_collection = doc! { CHAMP_TUUID: &requete.tuuid_collection, CHAMP_SUPPRIME: false };
    if user_id.is_some() {
        filtre_collection.insert("user_id", Bson::String(user_id.expect("user_id")));
    }

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

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
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
    let mut filtre = doc!{CHAMP_SUPPRIME: true};
    if user_id.is_some() {
        filtre.insert("user_id", Bson::String(user_id.expect("user_id")));
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;

    let reponse = json!({ "fichiers": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_recherche_index<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_recherche_index Message : {:?}", & m.message);
    let mut requete: ParametresRecherche = m.message.get_msg().map_contenu(None)?;
    debug!("requete_recherche_index cle parsed : {:?}", requete);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive && user_id.is_some() {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("grosfichiers.requete_recherche_index: Autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Ajouter user_id a la requete
    requete.user_id = user_id;

    let info = match gestionnaire.es_rechercher("grosfichiers", &requete).await {
        Ok(resultats) => {
            match resultats.hits {
                Some(inner) => {
                    let total = inner.total.value;
                    match inner.hits {
                        Some(hits) => {
                            let resultats = mapper_fichiers_resultat(middleware, hits).await?;
                            Some((total, resultats))
                        },
                        None => None
                    }
                },
                None => None
            }
        },
        Err(e) => {
            error!("requetes.requete_recherche_index Erreur recherche index grosfichiers : {}", e);
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": e.clone()}), None)?))
        }
    };

    let reponse = match info {
        Some((total, hits)) => {
            json!({"ok": true, "total": total, "hits": hits})
        },
        None => json!({"ok": true, "total": 0})
    };

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_get_permission<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireGrosFichiers)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"err": true, "message": "user_id n'est pas dans le certificat"}), None)?))
    };

    debug!("requete_get_permission Message : {:?}", & m.message);
    let requete: ParametresGetPermission = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_permission cle parsed : {:?}", requete);

    let mut conditions: Vec<Document> = Vec::new();
    if requete.tuuids.is_some() {
        conditions.push(doc!{"tuuid": {"$in": requete.tuuids.expect("tuuids")}});
    }
    if requete.fuuids.is_some() {
        conditions.push(doc!{"fuuids": {"$in": requete.fuuids.expect("fuuids")}});
    }

    let mut filtre = doc!{
        "user_id": user_id,
        "$or": conditions,
    };
    let projection = doc! {"fuuids": true, "tuuid": true};
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes = HashSet::new();
    while let Some(fresult) = curseur.next().await {
        let doc_mappe: ResultatDocsPermission = convertir_bson_deserializable(fresult?)?;
        for d in doc_mappe.fuuids {
            hachage_bytes.insert(d);
        }
    }

    let permission = json!({
        "permission_hachage_bytes": hachage_bytes,
        "permission_duree": 300
    });

    Ok(Some(middleware.formatter_reponse(&permission, None)?))
}

async fn mapper_fichiers_resultat<M>(middleware: &M, resultats: Vec<ResultatHitsDetail>)
    -> Result<Vec<ResultatDocumentRecherche>, Box<dyn Error>>
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
        let filtre = doc! { CHAMP_FUUIDS: {"$in": &fuuids} };
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
    nom: String,
    supprime: Option<bool>,
    nom_version: String,
    taille: u64,
    mimetype: String,
    date_creation: Option<DateEpochSeconds>,
    date_modification: Option<DateEpochSeconds>,
    date_version: DateEpochSeconds,
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
    fn new(value: DBFichierVersionDetail, resultat: &ResultatHitsDetail) -> Result<Self, Box<dyn Error>> {

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

    fn new_fichier(value: FichierDetail, resultat: &ResultatHitsDetail) -> Result<Self, Box<dyn Error>> {

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
            nom_version: value.nom,
            taille,
            mimetype,
            date_creation: value.date_creation,
            date_modification: Some(date_version.clone()),
            date_version,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteContenuCollection {
    tuuid_collection: String,
    limit: Option<i64>,
    skip: Option<u64>,
    sort_keys: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatDocsPermission {
    tuuid: String,
    fuuids: Vec<String>,
}