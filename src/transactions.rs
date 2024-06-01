use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
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
        // constantes::COMMANDE_POSTER_V1 => transaction_poster_v1(gestionnaire, middleware, transaction).await,
        _ => Err(format!("transactions.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}
