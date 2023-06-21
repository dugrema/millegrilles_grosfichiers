use std::error::Error;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::FindOneOptions;
use serde::Deserialize;

use crate::grosfichiers_constantes::*;

#[async_trait]
pub trait JobHandler: MongoDao + GenerateurMessages {
    /// Nom de la collection ou se trouvent les jobs
    fn get_nom_collection(&self) -> &str;

    /// Retourne le nom du flag de la table GrosFichiers/versionFichiers pour ce type de job.
    fn get_nom_flag(&self) -> &str;

    /// Emettre un evenement de job disponible.
    /// 1 evenement emis pour chaque instance avec au moins 1 job de disponible.
    async fn emettre_evenements_job(&self) -> Result<(), Box<dyn Error>>;

    async fn emettre_trigger<I>(&self, instance: I) -> Result<(), Box<dyn Error>>
    where I: AsRef<str> + Send;

    async fn sauvegarder_job<S,U,V>(&self, fuuid: S, user_id: U, instance: V) -> Result<(), Box<dyn Error>>
    where S: AsRef<str> + Send, U: AsRef<str> + Send, V: AsRef<str> + Send;

    /// Set le flag de traitement complete
    async fn set_flag<S,U>(&self, fuuid: S, user_id: U, valeur: bool) -> Result<(), Box<dyn Error>>
    where S: AsRef<str> + Send, U: AsRef<str> + Send {
        todo!("fix me");
        Ok(())
    }

}

#[derive(Clone, Debug, Deserialize)]
struct DocJob {
    visites: Option<Vec<String>>
}

/// Emet un trigger media image si au moins une job media est due.
pub async fn trouver_jobs_instances<M, T, D, S>(job_handler: &M) -> Result<(), Box<dyn Error>>
    where M: JobHandler, D: AsRef<str> + Send, S: AsRef<str> + Send
{
    let doc_job: Option<DocJob> = {
        let mut filtre = doc! {
            CHAMP_FLAG_INDEX_ETAT: VIDEO_CONVERSION_ETAT_PENDING
        };
        let options = FindOneOptions::builder().projection(doc! {"instances": true}).build();
        let collection = job_handler.get_collection(NOM_COLLECTION_IMAGES_JOBS)?;
        match collection.find_one(filtre, options).await? {
            Some(inner) => Some(convertir_bson_deserializable(inner)?),
            None => None
        }
    };

    if let Some(inner) = doc_job {
        if let Some(visites) = inner.visites {
            for instance in visites {
                job_handler.emettre_trigger(instance).await?;
            }
        }
    }

    Ok(())
}
