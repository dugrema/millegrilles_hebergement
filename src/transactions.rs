use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::constantes as CommonConstantes;
use millegrilles_common_rust::mongodb::options::UpdateOptions;

use serde::{Deserialize, Serialize};
use crate::constantes;

use crate::domaine_hebergement::GestionnaireDomaineHebergement;

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: TryInto<TransactionValide> + Send
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(Error::Str("aiguillage_transaction Erreur try_into TransactionValide"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.aiguillage_transaction Transaction sans action : {}", transaction.transaction.id))?
        },
        None => Err(format!("transactions.aiguillage_transaction Transaction sans routage : {}", transaction.transaction.id))?
    };

    match action.as_str() {
        constantes::TRANSACTION_SAUVEGARDER_CLIENT => transaction_sauvegarder_client(gestionnaire, middleware, transaction).await,
        _ => Err(format!("transactions.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

#[derive(Deserialize)]
pub struct TransactionSauvegarderClient {
    pub idmg: String,
    pub descriptif: Option<String>,
    #[serde(default, with="optionepochseconds")]
    pub expiration: Option<DateTime<Utc>>,
    pub roles: Option<Vec<String>>,
    pub domaines: Option<Vec<String>>,
    pub data_chiffre: Option<DataChiffre>,
    pub actif: Option<bool>
}

async fn transaction_sauvegarder_client<M>(_gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MongoDao
{
    let message_recu: TransactionSauvegarderClient = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let idmg = message_recu.idmg;

    let filtre = doc! {"idmg": &idmg};
    let expiration = match message_recu.expiration {
        Some(inner) => Some(inner.timestamp()),
        None => None
    };
    let data_chiffre = match message_recu.data_chiffre {
        Some(inner) => Some(convertir_to_bson(inner)?),
        None => None
    };
    let actif = message_recu.actif.unwrap_or_else(|| true);
    let ops = doc!{
        "$setOnInsert": {
            // "idmg": &idmg,
            CommonConstantes::CHAMP_CREATION: Utc::now(),
        },
        "$set": {
            "expiration": expiration,
            "descriptif": message_recu.descriptif,
            "roles": message_recu.roles,
            "domaines": message_recu.domaines,
            "data_chiffre": data_chiffre,
            "actif": actif,
        },
        "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true}
    };
    let collection = middleware.get_collection(constantes::COLLECTION_CLIENTS_NOM)?;
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre, ops, options).await?;

    Ok(None)
}
