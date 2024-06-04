use std::collections::HashSet;
use std::str::from_utf8;
use log::{debug, error, warn};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite, CHAMP_MODIFICATION, CHAMP_CREATION, DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable, optionepochseconds};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongodb::options::FindOptions;

use serde::{Deserialize, Serialize};
use crate::constantes;
use crate::constantes::COLLECTION_CLIENTS_NOM;
use crate::domaine_hebergement::GestionnaireDomaineHebergement;
use crate::jwt::generer_jwt_hebergement;
use crate::structure_donnees::{ClientHebergementRow, QuotaClient};

pub async fn consommer_requete<M>(gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MiddlewareMessages + MongoDao
{
    debug!("consommer_requete : {:?}", &message.type_message);
    verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Requete(r) => r.action.clone(),
        _ => Err(Error::Str("grosfichiers.consommer_requete Mauvais type message, doit etre Requete"))?
    };

    match action.as_str() {
        // Commandes standard
        constantes::REQUETE_LISTE_CLIENTS => requete_liste_clients(gestionnaire, middleware, message).await,
        constantes::REQUETE_TOKEN_JWT => requete_token_jwt(gestionnaire, middleware, message).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_requete: Requete {} inconnue, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }

}

/// Verifier si le message est autorise a etre execute comme requete. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(), Error> {
    match message.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                true => Ok(()),
                false => Err(Error::String(format!(
                    "verifier_autorisation: Requete autorisation invalide pour message {:?}",
                    message.type_message))),
            }
        }
    }?;

    Ok(())
}

// ********
// Requetes
// ********
#[derive(Deserialize)]
struct RequeteListeClients {}

#[derive(Serialize)]
struct ReponseClientRow {
    idmg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domaines: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    information: Option<String>,
    #[serde(default, with = "optionepochseconds", skip_serializing_if = "Option::is_none")]
    expiration: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<QuotaClient>,
}

#[derive(Serialize)]
struct ReponseListeClients {
    ok: bool,
    err: Option<String>,
    clients: Vec<ReponseClientRow>,
}

impl From<ClientHebergementRow> for ReponseClientRow {
    fn from(value: ClientHebergementRow) -> Self {
        Self {
            idmg: value.idmg,
            descriptif: value.descriptif,
            roles: value.roles,
            domaines: value.domaines,
            contact: value.contact,
            information: value.information,
            expiration: value.expiration,
            quota: value.quota,
        }
    }
}

async fn requete_liste_clients<M>(_gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_liste_clients Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);

    if !message.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Err(Error::Str("requete_liste_clients Acces refuse (exchange doit etre 3.protege"))?
    }

    let message_ref = message.message.parse()?;
    let requete: RequeteListeClients = message_ref.contenu()?.deserialize()?;

    // let skip = requete.skip.unwrap_or_else(|| 0);
    // let limit = requete.limit.unwrap_or_else(|| 1000);

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("requete_sync_messages Certificat sans user_id"))?
    };

    let filtre = doc! {};
    let options = FindOptions::builder()
        // .skip(skip)
        // .limit(limit)
        // .projection(doc!{"message_id": 1, CHAMP_MODIFICATION: 1, "supprime": 1, "date_traitement": 1})
        // .sort(doc!{CHAMP_CREATION: 1, "_id": 1})
        .build();
    let collection = middleware.get_collection_typed::<ClientHebergementRow>(constantes::COLLECTION_CLIENTS_NOM)?;
    let mut curseur = collection.find(filtre, options).await?;
    // let mut resultat = Vec::with_capacity(limit as usize);
    let mut resultat = Vec::new();
    while curseur.advance().await? {
        let row = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                error!("requete_liste_clients Erreur mapping row message, skip : {:?}", e);
                continue
            }
        };

        let message_sync = ReponseClientRow::from(row);
        resultat.push(message_sync);
    }

    let reponse = ReponseListeClients {
        ok: true,
        err: None,
        clients: resultat,
    };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteTokenJwt {
    requete: MessageMilleGrillesOwned,
    idmg: String,
}

#[derive(Serialize)]
struct ReponseTokenJwt {
    ok: bool,
    err: Option<String>,
    jwt_readonly: Option<String>,
    jwt_readwrite: Option<String>,
}

async fn requete_token_jwt<M>(_gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
                                  -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_liste_clients Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
    let message_ref = message.message.parse()?;
    let requete: RequeteTokenJwt = message_ref.contenu()?.deserialize()?;
    let mut requete_client = requete.requete;
    if ! requete_client.verifier_signature().is_ok() {
        debug!("requete_token_jwt Signature invalide");
        return Ok(Some(middleware.reponse_err(Some(1), None, Some("Signature requete invalide"))?))
    };

    debug!("requete_liste_clients Charger enveloppe IDMG");
    let (enveloppe_idmg, ca_pem) = match requete_client.millegrille.clone() {
        Some(ca_pem) => {
            match middleware.charger_enveloppe(&vec![ca_pem.clone()], None, None).await {
                Ok(inner) => (inner, ca_pem),
                Err(e) => {
                    debug!("requete_token_jwt Certificat IDMG invalide : {:?}", e);
                    return Ok(Some(middleware.reponse_err(Some(4), None, Some("Certificat IDMG invalide"))?))
                }
            }
        },
        None => {
            debug!("requete_token_jwt Certificat IDMG manquant");
            return Ok(Some(middleware.reponse_err(Some(3), None, Some("Certificat IDMG manquant"))?))
        }
    };

    debug!("requete_liste_clients Verifier enveloppe requete");
    let enveloppe_requete = match requete_client.certificat.as_ref() {
        Some(inner) => {
            match middleware.charger_enveloppe(inner, None, Some(ca_pem.as_str())).await {
                Ok(inner) => inner,
                Err(e) => {
                    debug!("requete_token_jwt Certificat requete invalide : {:?}", e);
                    return Ok(Some(middleware.reponse_err(Some(7), None, Some("Certificat requete invalide"))?))
                }
            }
        },
        None => {
            debug!("requete_token_jwt Certificat requete manquant");
            return Ok(Some(middleware.reponse_err(Some(6), None, Some("Certificat requete manquant"))?))
        }
    };

    debug!("requete_liste_clients Verifier enveloppe requete");
    if requete_client.pubkey.as_str() != enveloppe_requete.fingerprint()?.as_str() {
        return Ok(Some(middleware.reponse_err(Some(8), None, Some("Mismatch certificat requete"))?))
    }

    if(!enveloppe_requete.verifier_roles_string(vec!["core".to_string()])?) {
        Err(Error::Str("requete_token_jwt Seul le role core est supporte"))?
    }

    let idmg = enveloppe_idmg.calculer_idmg()?;
    if enveloppe_requete.idmg()? != idmg.as_str() {
        return Ok(Some(middleware.reponse_err(Some(5), None, Some("Mismatch idmg certificat/ca"))?))
    }

    // Verifier la delegation pour ce IDMG
    let filtre = doc!{"idmg": &idmg};
    let collection = middleware.get_collection_typed::<ClientHebergementRow>(COLLECTION_CLIENTS_NOM)?;
    let doc_hebergement = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => {
            debug!("requete_token_jwt Hebergement non disponible pour {}", idmg);
            return Ok(Some(middleware.reponse_err(Some(9), None, Some("Hebergement non configure pour client"))?))
        }
    };

    let roles_heberges = doc_hebergement.roles;
    let domaines_heberges = doc_hebergement.domaines;

    // Generer les JWT
    let jwt_readonly = generer_jwt_hebergement(middleware, &idmg, false, roles_heberges.clone(), domaines_heberges.clone())?;
    let jwt_readwrite = generer_jwt_hebergement(middleware, &idmg, true, roles_heberges, domaines_heberges)?;;

    let reponse = ReponseTokenJwt {
        ok: true,
        err: None,
        jwt_readonly: Some(jwt_readonly),
        jwt_readwrite: Some(jwt_readwrite)
    };

    debug!("requete_token_jwt Repondre avec message chiffre");
    Ok(Some(middleware.build_reponse_chiffree(reponse, enveloppe_requete.as_ref())?.0))
}
