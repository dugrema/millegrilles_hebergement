use std::collections::HashSet;
use std::str::from_utf8;
use log::{debug, error};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite, CHAMP_MODIFICATION, CHAMP_CREATION, DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::mongodb::options::FindOptions;

use serde::{Deserialize, Serialize};
use crate::constantes;
use crate::domaine_hebergement::GestionnaireDomaineHebergement;

pub async fn consommer_requete<M>(gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MiddlewareMessages + MongoDao
{
    debug!("consommer_requete : {:?}", &message.type_message);
    let (_user_id, _role_prive) = verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Requete(r) => r.action.clone(),
        _ => Err(Error::Str("grosfichiers.consommer_requete Mauvais type message, doit etre Requete"))?
    };

    match action.as_str() {
        // Commandes standard
        // constantes::REQUETE_SYNC_MESSAGES => requete_sync_messages(gestionnaire, middleware, message).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_commande: Commande {} inconnue, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }

}

/// Verifier si le message est autorise a etre execute comme requete. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(Option<String>, bool), Error> {
    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, requete usager
    } else {
        match message.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                    true => Ok(()),
                    false => Err(Error::String(format!(
                        "verifier_autorisation: Commande autorisation invalide pour message {:?}",
                        message.type_message))),
                }
            }
        }?;
    }

    Ok((user_id, role_prive))
}

// ********
// Requetes
// ********