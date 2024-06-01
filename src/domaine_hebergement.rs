use log::{info, warn};
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::static_cell::StaticCell;

// static GESTIONNAIRE: StaticCell<GestionnaireDomaineHebergement> = StaticCell::new();


pub async fn run() {

    // let (middleware, futures_middleware) = preparer_middleware()
    //     .expect("preparer middleware");
    // let (gestionnaire, futures_domaine) = initialiser(middleware).await
    //     .expect("initialiser domaine");
    //
    // // Tester connexion redis
    // if let Some(redis) = middleware.redis.as_ref() {
    //     match redis.liste_certificats_fingerprints().await {
    //         Ok(fingerprints_redis) => {
    //             info!("redis.liste_certificats_fingerprints Resultat : {} certificats en cache", fingerprints_redis.len());
    //         },
    //         Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
    //     }
    // }
    //
    // // Combiner les JoinHandles recus
    // let mut futures = FuturesUnordered::new();
    // futures.extend(futures_middleware);
    // futures.extend(futures_domaine);
    //
    // // Demarrer thread d'entretien.
    // futures.push(spawn(thread_entretien(gestionnaire, middleware)));
    //
    // // Le "await" maintien l'application ouverte. Des qu'une task termine, l'application arrete.
    // futures.next().await;
    //
    // for f in &futures {
    //     f.abort()
    // }
    //
    // info!("domaine_messages Attendre {} tasks restantes", futures.len());
    // while futures.len() > 0 {
    //     futures.next().await;
    // }
    //
    // info!("domaine_messages Fin execution");
    todo!()
}
