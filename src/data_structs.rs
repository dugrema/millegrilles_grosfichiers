use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::millegrilles_cryptographie::serde_dates::mapstringepochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{FormatChiffrage, optionformatchiffragestr};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;

#[derive(Clone, Serialize, Deserialize)]
pub struct MediaOwnedRow {
    pub fuuid: String,
    pub user_id: String,

    // Mapping date
    #[serde(rename="_mg-creation", with="chrono_datetime_as_bson_datetime")]
    pub creation: DateTime<Utc>,
    #[serde(rename="_mg-derniere-modification", with="chrono_datetime_as_bson_datetime")]
    pub derniere_modification: DateTime<Utc>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
    pub anime: bool,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, VideoDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio: Option<Vec<AudioDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitles: Option<Vec<SubtitleDetail>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ImageDetail {
    pub hachage: String,
    pub mimetype: String,

    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub taille: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resolution: Option<u32>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub data_chiffre: Option<String>,

    // Information dechiffrage - note : fuuid_v_courante du fichier -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VideoDetail {
    pub fuuid: String,
    pub fuuid_video: String,
    pub taille_fichier: u64,
    pub mimetype: String,
    pub codec: String,

    /// Fix bug videas verticaux. Ajoute dans version 2023.7.4
    pub cle_conversion: Option<String>,

    // Metadata video transcode
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub bitrate: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub quality: Option<i32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio_stream_idx: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitle_stream_idx: Option<u32>,

    // Information dechiffrage - note : fuuid -> ref_hachage_bytes
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AudioDetail {
    index: u32,
    title: Option<String>,
    language: Option<String>,
    codec_name: Option<String>,
    bit_rate: Option<u32>,
    default: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubtitleDetail {
    index: u32,
    language: Option<String>,
    title: Option<String>,
    codec_name: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ResponseVersionCourante {
    pub fuuid: String,
    pub mimetype: String,
    pub taille: u64,
    pub fuuids_reclames: Vec<String>,

    // pub supprime: bool,
    #[serde(with="mapstringepochseconds")]
    pub visites: HashMap<String, DateTime<Utc>>,

    // Mapping date
    #[serde(default, rename="_mg-derniere-modification", with="optionepochseconds")]
    pub derniere_modification: Option<DateTime<Utc>>,

    // Champs optionnels media
    #[serde(skip_serializing_if="Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub duration: Option<f32>,
    #[serde(rename="videoCodec", skip_serializing_if="Option::is_none")]
    pub video_codec: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub images: Option<HashMap<String, ImageDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub video: Option<HashMap<String, VideoDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub audio: Option<Vec<AudioDetail>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subtitles: Option<Vec<SubtitleDetail>>,

    // Information de chiffrage symmetrique (depuis 2024.3.0)
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<String>,
}
