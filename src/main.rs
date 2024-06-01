mod domaine_hebergement;
mod config_ressources;
mod constantes;
mod transactions;
mod commandes;
mod evenements;
mod requetes;

use log::info;
use millegrilles_common_rust::tokio::runtime::Builder;
use crate::domaine_hebergement::run as run_hebergement;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");

    let runtime = Builder::new_multi_thread()
        // .worker_threads(3)  // Utiliser env var TOKIO_WORKER_THREADS
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(run_hebergement());
}
