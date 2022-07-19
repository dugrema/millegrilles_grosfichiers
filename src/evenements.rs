use std::collections::HashSet;
use std::error::Error;
use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::grosfichiers_constantes::*;

pub async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive]) {
        true => Ok(()),
        false => Err(format!("grosfichiers.consommer_evenement: Exchange evenement invalide (pas 2.prive)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_CONFIRMER_ETAT_FUUIDS => {
            evenement_confirmer_etat_fuuids(middleware, m).await?;
            Ok(None)
        },
        EVENEMENT_TRANSCODAGE_PROGRES => evenement_transcodage_progres(middleware, m).await,
        _ => Err(format!("grosfichiers.consommer_evenement: Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

async fn evenement_confirmer_etat_fuuids<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let uuid_transaction = m.correlation_id.clone();

    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", uuid_transaction);
        return Ok(None)
    }

    debug!("evenement_confirmer_etat_fuuids Message : {:?}", & m.message);
    let evenement: EvenementConfirmerEtatFuuids = m.message.get_msg().map_contenu(None)?;
    debug!("evenement_confirmer_etat_fuuids parsed : {:?}", evenement);

    repondre_fuuids(middleware, &evenement.fuuids).await?;

    Ok(None)
}

async fn evenement_transcodage_progres<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let uuid_transaction = m.correlation_id.clone();

    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", uuid_transaction);
        return Ok(None)
    }
    if !m.verifier_roles(vec![RolesCertificats::Media]) {
        error!("evenement_transcodage_progres Acces refuse, certificat n'est pas de role media");
        return Ok(None)
    }

    debug!("evenement_transcodage_progres Message : {:?}", & m.message);
    let evenement: EvenementTranscodageProgres = m.message.get_msg().map_contenu(None)?;
    debug!("evenement_transcodage_progres parsed : {:?}", evenement);

    let height = match evenement.height {
        Some(h) => h,
        None => {
            // Height/resolution n'est pas fourni, rien a faire
            return Ok(None)
        }
    };

    let cle_video = format!("{};{};{}", evenement.mimetype, height, evenement.video_bitrate);
    let filtre = doc! {
        CHAMP_FUUID: &evenement.fuuid,
        CHAMP_CLE_CONVERSION: &cle_video
    };

    let mut ops = doc! {
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    match evenement.pct_progres {
        Some(p) => {
            let set_ops = doc! {"pct_progres": p};
            ops.insert("$set", set_ops);
        },
        None => ()
    }
    let collection = middleware.get_collection(NOM_COLLECTION_VIDEO_JOBS)?;
    collection.update_one(filtre, ops, None).await?;

    Ok(None)
}


async fn repondre_fuuids<M>(middleware: &M, evenement_fuuids: &Vec<String>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let mut fuuids = HashSet::new();
    for fuuid in evenement_fuuids.iter() {
        fuuids.insert(fuuid.clone());
    }

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .build();
    let mut filtre = doc!{"fuuids": {"$in": evenement_fuuids}};

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
    let mut fichiers_confirmation = Vec::new();
    let mut curseur = collection.find(filtre, opts).await?;
    while let Some(d) = curseur.next().await {
        let record: RowEtatFuuid = convertir_bson_deserializable(d?)?;
        for fuuid in record.fuuids.into_iter() {
            if fuuids.contains(&fuuid) {
                fuuids.remove(&fuuid);
                // Note: on ignore les fichiers supprimes == true, on va laisser la chance a
                //       un autre module d'en garder possession.
                if record.supprime == false {
                    fichiers_confirmation.push(ConfirmationEtatFuuid { fuuid, supprime: record.supprime });
                }
            }
        }
    }

    // // Ajouter tous les fuuids manquants (encore dans le set)
    // // Ces fichiers sont inconnus et presumes supprimes
    // for fuuid in fuuids.into_iter() {
    //     fichiers_confirmation.push( ConfirmationEtatFuuid { fuuid, supprime: true } );
    // }

    if fichiers_confirmation.is_empty() {
        debug!("repondre_fuuids Aucuns fuuids connus, on ne repond pas");
        return Ok(());
    }

    let confirmation = ReponseConfirmerEtatFuuids { fuuids: fichiers_confirmation };
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_ACTIVITE_FUUIDS)
        .exchanges(vec![L2Prive])
        .build();
    middleware.transmettre_commande(routage, &confirmation, false).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementTranscodageProgres {
    fuuid: String,
    mimetype: String,
    #[serde(rename="videoBitrate")]
    video_bitrate: u32,
    height: Option<u32>,
    #[serde(rename="pctProgres")]
    pct_progres: Option<i32>,
    passe: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RowEtatFuuid {
    fuuids: Vec<String>,
    supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteConfirmerEtatFuuids {
    fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseConfirmerEtatFuuids {
    fuuids: Vec<ConfirmationEtatFuuid>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfirmationEtatFuuid {
    fuuid: String,
    supprime: bool,
}
