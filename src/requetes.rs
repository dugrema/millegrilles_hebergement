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
use crate::structure_donnees::ClientHebergementRow;

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
        constantes::REQUETE_LISTE_CLIENTS => requete_liste_clients(gestionnaire, middleware, message).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_requete: Requete {} inconnue, **DROPPED**\n{}",
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
                        "verifier_autorisation: Requete autorisation invalide pour message {:?}",
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
#[derive(Deserialize)]
struct RequeteListeClients {}

#[derive(Serialize)]
struct ReponseClientRow {}

#[derive(Serialize)]
struct ReponseListeClients {
    ok: bool,
    err: Option<String>,
    clients: Vec<ReponseClientRow>,
}

impl From<ClientHebergementRow> for ReponseClientRow {
    fn from(value: ClientHebergementRow) -> Self {
        todo!()
    }
}

async fn requete_liste_clients<M>(_gestionnaire: &GestionnaireDomaineHebergement, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_liste_clients Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
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
