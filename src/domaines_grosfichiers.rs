//! Module SenseursPassifs de millegrilles installe sur un noeud 3.protege.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono as chrono;
use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::middleware_db::{MiddlewareDb, preparer_middleware_db};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::grosfichiers::GestionnaireGrosFichiers;
use crate::traitement_index::IndexationJobHandler;
use crate::traitement_media::{ImageJobHandler, VideoJobHandler};
// use crate::traitement_index::{ElasticSearchDao, ElasticSearchDaoImpl};

const DUREE_ATTENTE: u64 = 20000;

// Creer espace static pour conserver les gestionnaires

static mut GESTIONNAIRE: TypeGestionnaire = TypeGestionnaire::None;

/// Enum pour distinger les types de gestionnaires.
enum TypeGestionnaire {
    PartitionConsignation(Arc<GestionnaireGrosFichiers>),
    None
}

pub async fn run() {

    // Init gestionnaires ('static)
    let gestionnaire = charger_gestionnaire();

    // Wiring
    let futures = build(gestionnaire).await;

    // Run
    executer(futures).await
}

/// Fonction qui lit le certificat local et extrait les fingerprints idmg et de partition
/// Conserve les gestionnaires dans la variable GESTIONNAIRES 'static
fn charger_gestionnaire() -> &'static TypeGestionnaire {
    // Charger une version simplifiee de la configuration - on veut le certificat associe a l'enveloppe privee
    // let config = charger_configuration().expect("config");
    // let config_noeud = config.get_configuration_noeud();
    // let elastic_search_url = match &config_noeud.elastic_search_url {
    //     Some(inner) => inner,
    //     None => panic!("URL MG_ELASTICSEARCH_URL doit etre fourni")
    // };

    // Index dao
    // let index_dao = Arc::new(ElasticSearchDaoImpl::new(elastic_search_url.as_str()).expect("index"));
    let image_job_handler = ImageJobHandler {};
    let video_job_handler = VideoJobHandler {};
    let indexation_job_handler = IndexationJobHandler {};

    let gestionnaire = Arc::new(GestionnaireGrosFichiers {
        image_job_handler, video_job_handler, indexation_job_handler });

    // Inserer les gestionnaires dans la variable static - permet d'obtenir lifetime 'static
    unsafe {
        GESTIONNAIRE = TypeGestionnaire::PartitionConsignation(gestionnaire);

        // let mut vec_gestionnaires = Vec::new();
        // vec_gestionnaires.extend(&GESTIONNAIRES);
        // vec_gestionnaires
        &GESTIONNAIRE
    }
}

async fn build(gestionnaire: &'static TypeGestionnaire) -> FuturesUnordered<JoinHandle<()>> {
    let middleware_hooks = preparer_middleware_db();
    let middleware = middleware_hooks.middleware;

    // Tester connexion redis
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                info!("redis.liste_certificats_fingerprints Resultat : {:?}", fingerprints_redis);
            },
            Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
        }
    }

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();

    // ** Domaines **
    match gestionnaire {
        TypeGestionnaire::PartitionConsignation(gestionnaire) => {
            futures.extend(gestionnaire.preparer_threads(middleware.clone()).await.expect("preparer_threads"));
        },
        TypeGestionnaire::None => {panic!("Gestionnaire non configure");}
    }

    // ** Thread d'entretien **
    futures.push(spawn(entretien(middleware.clone(), vec![gestionnaire])));

    // Thread ecoute et validation des messages
    info!("domaines_maitredescles.build Ajout {} futures dans middleware_hooks", futures.len());
    for f in middleware_hooks.futures {
        futures.push(f);
    }

    futures
}

async fn executer(mut futures: FuturesUnordered<JoinHandle<()>>) {
    info!("domaines_grosfichiers: Demarrage traitement, top level threads {}", futures.len());
    let arret = futures.next().await;
    info!("domaines_grosfichiers: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Thread d'entretien
async fn entretien<M>(middleware: Arc<M>, gestionnaires: Vec<&'static TypeGestionnaire>)
    where M: Middleware
{
    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = {
        let mut coll_docs_strings = Vec::new();
        for g in &gestionnaires {
            match g {
                TypeGestionnaire::PartitionConsignation(g) => {
                    coll_docs_strings.push(String::from(g.get_collection_transactions().expect("collection transactions")));
                },
                TypeGestionnaire::None => ()
            }
        }
        coll_docs_strings
    };

    let mut rechiffrage_complete = false;

    let mut prochain_chargement_certificats_maitredescles = chrono::Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    let mut prochain_sync = chrono::Utc::now();
    let intervalle_sync = chrono::Duration::hours(6);

    let mut prochaine_confirmation_ca = chrono::Utc::now();
    let intervalle_confirmation_ca = chrono::Duration::minutes(15);

    let mut prochain_chargement_certificats_autres = chrono::Utc::now();
    let intervalle_chargement_certificats_autres = chrono::Duration::minutes(5);

    let mut prochain_entretien_elasticsearch = chrono::Utc::now();
    let intervalle_entretien_elasticsearch = chrono::Duration::minutes(5);

    info!("domaines_grosfichiers.entretien : Debut thread dans 5 secondes");

    // Donner 5 secondes pour que les Q soient pretes (e.g. Q reponse)
    sleep(DurationTokio::new(5, 0)).await;

    loop {
        let maintenant = chrono::Utc::now();
        debug!("domaines_grosfichiers.entretien  Execution task d'entretien Core {:?}", maintenant);

        if prochain_chargement_certificats_maitredescles < maintenant {
            let enveloppe_privee = middleware.get_enveloppe_privee();
            let cert_prive = enveloppe_privee.enveloppe.clone();
            match middleware.charger_certificats_chiffrage(middleware.as_ref()).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                    debug!("Prochain chargement cert maitredescles: {:?}", prochain_chargement_certificats_maitredescles);
                },
                Err(e) => warn!("Erreur chargement certificats de maitre des cles : {:?}", e)
            }
        }

        // Sleep jusqu'au prochain entretien ou evenement MQ (e.g. connexion)
        debug!("domaines_grosfichiers.entretien Fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);
        sleep(duration).await;
        if middleware.get_mode_regeneration() == true {
            debug!("domaines_grosfichiers.entretien Mode regeneration, skip entretien");
            continue;
        }

        middleware.entretien_validateur().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
                &collections_transaction
            ).await;

            match resultat {
                Ok(_) => {
                    prochain_entretien_transactions = maintenant + intervalle_entretien_transactions;
                },
                Err(e) => {
                    warn!("domaines_grosfichiers.entretien Erreur resoumission transactions (entretien) : {:?}", e);
                }
            }
        }

        if certificat_emis == false {
            debug!("domaines_grosfichiers.entretien Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("Erreur emission certificat local : {:?}", e),
            }
            debug!("domaines_grosfichiers.entretien Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }

        for g in &gestionnaires {
            match g {
                TypeGestionnaire::PartitionConsignation(g) => {
                    debug!("Entretien GestionnaireGrosFichiers");
                    // if prochain_entretien_elasticsearch < maintenant {
                    //     prochain_entretien_elasticsearch = maintenant + intervalle_entretien_elasticsearch;
                    //     if !g.es_est_pret() {
                    //         info!("Preparer ElasticSearch");
                    //         match g.es_preparer().await {
                    //             Ok(()) => {
                    //                 info!("Index ElasticSearch prets");
                    //             },
                    //             Err(e) => warn!("domaines_grosfichiers.entretien Erreur preparation ElasticSearch : {:?}", e)
                    //         }
                    //     }
                    // }
                },
                _ => ()
            }
        }

    }

    // panic!("Forcer fermeture");
    info!("domaines_grosfichiers.entretien : Fin thread");
}

async fn consommer(
    _middleware: Arc<impl ValidateurX509 + GenerateurMessages + MongoDao>,
    mut rx: Receiver<TypeMessage>,
    map_senders: HashMap<String, Sender<TypeMessage>>
) {
    info!("domaines_grosfichiers.consommer : Debut thread, mapping : {:?}", map_senders.keys());

    while let Some(message) = rx.recv().await {
        match &message {
            TypeMessage::Valide(m) => {
                warn!("domaines_grosfichiers.consommer: Message valide sans routing key/action : {:?}", m.message);
            },
            TypeMessage::ValideAction(m) => {
                let contenu = &m.message;
                let rk = m.routing_key.as_str();
                let action = m.action.as_str();
                let domaine = m.domaine.as_str();
                let nom_q = m.q.as_str();
                info!("domaines_grosfichiers.consommer: Traiter message valide (action: {}, rk: {}, q: {})", action, rk, nom_q);
                debug!("domaines_grosfichiers.consommer: Traiter message valide contenu {:?}", contenu);

                // Tenter de mapper avec le nom de la Q (ne fonctionnera pas pour la Q de reponse)
                let sender = match map_senders.get(nom_q) {
                    Some(sender) => {
                        debug!("domaines_grosfichiers.consommer Mapping message avec nom_q: {}", nom_q);
                        sender
                    },
                    None => {
                        match map_senders.get(domaine) {
                            Some(sender) => {
                                debug!("domaines_grosfichiers.consommer Mapping message avec domaine: {}", domaine);
                                sender
                            },
                            None => {
                                error!("domaines_grosfichiers.consommer Message de queue ({}) et domaine ({}) inconnu, on le drop", nom_q, domaine);
                                continue  // On skip
                            },
                        }
                    }
                };

                match sender.send(message).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("domaines_grosfichiers.consommer Erreur consommer message {:?}", e)
                    }
                }
            },
            TypeMessage::Certificat(_) => (),  // Rien a faire
            TypeMessage::Regeneration => (),   // Rien a faire
        }
    }

    info!("domaines_grosfichiers.consommer: Fin thread : {:?}", map_senders.keys());
}

// #[cfg(test)]
// mod test_integration {
//     use std::collections::HashMap;
//
//     use millegrilles_common_rust::backup::CatalogueHoraire;
//     use millegrilles_common_rust::chiffrage::Chiffreur;
//     use millegrilles_common_rust::constantes::COMMANDE_SAUVEGARDER_CLE;
//     use millegrilles_common_rust::formatteur_messages::MessageSerialise;
//     use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
//     use millegrilles_common_rust::middleware::IsConfigurationPki;
//     use millegrilles_common_rust::middleware_db::preparer_middleware_db;
//     use millegrilles_common_rust::mongo_dao::convertir_to_bson;
//     use millegrilles_common_rust::tokio as tokio;
//     use millegrilles_common_rust::tokio_stream::StreamExt;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
// // #[tokio::test]
//     // async fn test_sauvegarder_cle() {
//     //     setup("test_sauvegarder_cle");
//     //     let gestionnaires = charger_gestionnaires();
//     //     let (mut futures, middleware) = build(gestionnaires).await;
//     //
//     //     let fingerprint_cert = middleware.get_enveloppe_privee();
//     //     let fingerprint = fingerprint_cert.fingerprint().to_owned();
//     //
//     //     futures.push(tokio::spawn(async move {
//     //
//     //         tokio::time::sleep(tokio::time::Duration::new(4, 0)).await;
//     //
//     //         // S'assurer d'avoir recu le cert de chiffrage
//     //         middleware.charger_certificats_chiffrage().await.expect("certs");
//     //
//     //         let input = b"Allo, le test";
//     //         let mut output = [0u8; 13];
//     //
//     //         let mut cipher = middleware.get_cipher().expect("cipher");
//     //         let output_size = cipher.update(input, &mut output).expect("update");
//     //         let mut output_final = [0u8; 10];
//     //         let output_final_size = cipher.finalize(&mut output_final).expect("final");
//     //         let cipher_keys = cipher.get_cipher_keys().expect("keys");
//     //
//     //         let mut doc_map = HashMap::new();
//     //         doc_map.insert(String::from("test"), String::from("true"));
//     //         let commande = cipher_keys.get_commande_sauvegarder_cles(
//     //             "Test", None, doc_map);
//     //
//     //         debug!("Commande sauvegarder cles : {:?}", commande);
//     //
//     //         let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
//     //             .partition(fingerprint)
//     //             .build();
//     //
//     //         let reponse = middleware.transmettre_commande(routage, &commande, true).await.expect("commande");
//     //         debug!("Reponse commande cle : {:?}", reponse);
//     //
//     //         debug!("Sleep 2 secondes pour attendre fin traitements");
//     //         tokio::time::sleep(tokio::time::Duration::new(2, 0)).await;
//     //
//     //     }));
//     //     // Execution async du test
//     //     futures.next().await.expect("resultat").expect("ok");
//     // }
// }