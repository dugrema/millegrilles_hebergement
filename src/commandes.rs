use std::collections::{HashMap, HashSet};
use std::str::from_utf8;

use log::{debug, error, warn};
use millegrilles_common_rust::{constantes as CommonConstantes, serde_json};
use millegrilles_common_rust::base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64_nopad};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage};
use millegrilles_common_rust::constantes::{COMMANDE_ACTIVITE_FUUIDS, COMMANDE_AJOUTER_CLE_DOMAINES, DELEGATION_GLOBALE_PROPRIETAIRE, DOMAINE_FICHIERS, DOMAINE_NOM_MAITREDESCLES, DOMAINE_NOM_MAITREDESCOMPTES, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, RolesCertificats, Securite};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{Cipher, CleChiffrageHandler};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher};
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::generer_cle_avec_ca;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, lire_idmg};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tokio::time as tokio_time;
use serde::{Deserialize, Serialize};

use crate::constantes;
use crate::domaine_hebergement::GestionnaireDomaineHebergement;
use crate::structure_donnees::ClientHebergementRow;
use crate::transactions::TransactionSauvegarderClient;

pub async fn consommer_commande<M>(gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("consommer_commande : {:?}", &message.type_message);
    verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Commande(r) => r.action.clone(),
        _ => Err(Error::Str("grosfichiers.consommer_commande Mauvais type message, doit etre Commande"))?
    };

    match action.as_str() {
        // Commandes standard
        constantes::TRANSACTION_SAUVEGARDER_CLIENT => commande_sauvegarder_client(gestionnaire, middleware, message).await,
        // Commande inconnue
        _ => Err(Error::String(format!("consommer_commande: Commande {} inconnue, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }
}

/// Verifier si le message est autorise  a etre execute comme commonde. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(), Error> {
    let user_id = message.certificat.get_user_id()?;

    match message.certificat.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure))? {
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

    Ok(())
}

// *********
// Commandes
// *********
async fn commande_sauvegarder_client<M>(gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_liste_clients Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
    let message_owned = message.message.parse_to_owned()?;

    // Valider structure de la commande
    let commande: TransactionSauvegarderClient = message_owned.deserialize()?;

    // Valider le idmg
    let idmg = commande.idmg;
    let val_idmg = lire_idmg(idmg.as_str())?;
    let now = Utc::now();
    if val_idmg.expiration < now {
        Err(Error::String(format!("commande_sauvegarder_client IDMG {} expire depuis : {:?}", idmg, val_idmg.expiration)))?
    }

    // Verifier si on a une cle a sauvegarder
    if let Some(mut attachements) = message_owned.attachements {
        if let Some(cle) = attachements.remove("cle") {
            todo!("Sauvegarder cle")
        }
    }

    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}
