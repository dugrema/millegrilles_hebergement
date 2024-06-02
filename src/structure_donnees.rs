use millegrilles_common_rust::bson;
use serde::Deserialize;

use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;

#[derive(Deserialize)]
pub struct QuotaClient {

}

#[derive(Deserialize)]
pub struct ClientHebergementRow {
    pub idmg: String,
    pub roles: Option<Vec<String>>,
    pub domaines: Option<Vec<String>>,
    pub contact: Option<String>,
    pub information: Option<String>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub expiration: Option<DateTime<Utc>>,
    pub quota: Option<QuotaClient>,
}

#[derive(Deserialize)]
pub struct FichiersHeberges {
    fuuid: String,
    idmg: String,
    taille_chiffre: i64,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    derniere_reclamation: DateTime<Utc>,
}
