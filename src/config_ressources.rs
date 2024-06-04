use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{DEFAULT_Q_TTL, Securite};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use crate::constantes;

use crate::domaine_hebergement::GestionnaireDomaineHebergement;


pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // Requetes
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", constantes::DOMAINE_NOM, constantes::REQUETE_LISTE_CLIENTS), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", constantes::DOMAINE_NOM, constantes::REQUETE_TOKEN_JWT), exchange: Securite::L1Public});

    // Commandes
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", constantes::DOMAINE_NOM, constantes::TRANSACTION_SAUVEGARDER_CLIENT), exchange: Securite::L3Protege});

    // Evenements
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_FICHIERS_SYNCPRET), exchange: Securite::L3Protege});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: constantes::QUEUE_VOLATILS_NOM.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers
    queues.push(QueueType::Triggers (constantes::DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_hebergement<M>(middleware: &M, _gestionnaire: &GestionnaireDomaineHebergement) -> Result<(), Error>
    where M: MongoDao + ConfigMessages
{
    // let options_usagers = IndexOptions {
    //     nom_index: Some(String::from("user_id")),
    //     unique: true,
    // };
    // let champs_index_usagers = vec!(
    //     ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     COLLECTION_USAGERS_NOM,
    //     champs_index_usagers,
    //     Some(options_usagers)
    // ).await?;

    Ok(())
}
