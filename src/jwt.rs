use log::{debug, error, info, warn};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use millegrilles_common_rust::jwt_simple::prelude::*;

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::{InformationDechiffrage, InformationDechiffrageV2};
use millegrilles_common_rust::constantes::{DOMAINE_NOM_GROSFICHIERS, DOMAINE_NOM_MESSAGERIE, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::FormatteurMessage;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::error::Error;

use crate::constantes;

pub const CONST_DUREE_TOKEN_VALIDE: u64 = 60 * 60 * 1;

#[derive(Debug, Serialize, Deserialize)]
struct ClaimsTokenHebergement {
    /// Roles heberges pour le client
    #[serde(skip_serializing_if="Option::is_none")]
    roles: Option<Vec<String>>,

    /// Domaines heberges pour le client
    #[serde(skip_serializing_if="Option::is_none")]
    domaines: Option<Vec<String>>,

    /// True si le JWT supporte read et write. Si false, read-only.
    readwrite: bool,
}

// pub async fn verify_jwt<M,S>(middleware: &M, jwt_token: S) -> Result<FichierClaims, Error>
//     where M: ValidateurX509, S: AsRef<str>
// {
//     let jwt_token = jwt_token.as_ref();
//
//     let metadata = match Token::decode_metadata(&jwt_token) {
//         Ok(inner) => inner,
//         Err(e) => Err(Error::String(format!("Erreur Token::decode_metatada : {:?}", e)))?
//     };
//     let fingerprint = match metadata.key_id() {
//         Some(inner) => inner,
//         None => Err(format!("jwt_handler.verify_jwt fingerprint (kid) manquant du JWT"))?
//     };
//
//     debug!("verify_jwt Token fingerprint (kid) : {}", fingerprint);
//
//     let enveloppe = match middleware.get_certificat(fingerprint).await {
//         Some(inner) => inner,
//         None => Err(format!("jwt_handler.verify_jwt Certificat inconnu pour fingerprint {}", fingerprint))?
//     };
//
//     // Verifier le domaine de l'enveloppe
//     if ! enveloppe.verifier_domaines(vec![DOMAINE_NOM_MESSAGERIE.to_string(), DOMAINE_NOM_GROSFICHIERS.to_string()])? {
//         Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un domaine supporte {}", fingerprint))?
//     }
//     if ! enveloppe.verifier_exchanges(vec![Securite::L4Secure])? {
//         Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un exchange supporte (doit etre 4.secure) {}", fingerprint))?
//     }
//     // // TODO : Fix me - utiliser domaine (GrosFichiers, Messagerie). Pour l'instance c'est le niveau L2Prive ou L4Secure
//     // if ! enveloppe.verifier_exchanges(vec![Securite::L2Prive, Securite::L4Secure]) {
//     //     Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un exchange supporte {}", fingerprint))?
//     // }
//
//     let public_key = enveloppe.pubkey()?;  //cle_publique.as_ref(); //.as_ref();
//     let key_ed25519 = match Ed25519PublicKey::from_bytes(public_key.as_slice()) {
//         Ok(inner) => inner,
//         Err(e) => Err(Error::String(format!("Erreur Ed25519PublicKey::from_bytes {:?}", e)))?
//     };
//     let claims = match key_ed25519.verify_token::<ClaimsTokenFichier>(&jwt_token, None) {
//         Ok(inner) => inner,
//         Err(e) => Err(format!("Erreur key_ed25519.verify_token::<ClaimsTokenFichier> : {:?}",e ))?
//     };
//     debug!("verify_jwt Claims : {:?}", claims);
//
//     let custom = claims.custom;
//
//     Ok(FichierClaims {
//         fuuid: claims.subject,
//         user_id: custom.user_id,
//     })
// }

pub fn generer_jwt_hebergement<M,U>(
    middleware: &M, idmg: U, readwrite: bool, roles_heberges: Option<Vec<String>>,
    domaines_heberges: Option<Vec<String>>
)
    -> Result<String, Error>
    where
        M: FormatteurMessage,
        U: ToString
{
    let idmg = idmg.to_string();

    let info_hebergement = ClaimsTokenHebergement {
        roles: roles_heberges,
        domaines: domaines_heberges,
        readwrite
    };

    let mut claims = Claims::with_custom_claims(
        info_hebergement, Duration::from_secs(CONST_DUREE_TOKEN_VALIDE));
    claims.subject = Some(idmg);

    // Recuperer cle pour signer le token
    let enveloppe = middleware.get_enveloppe_signature();
    claims.issuer = Some(constantes::DOMAINE_NOM.into());
    let cle_privee = enveloppe.cle_privee.private_key_to_der()?;
    let cle_der = match Ed25519KeyPair::from_der(cle_privee.as_slice()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("generer_jwt Ed25519KeyPair::from_der : {:?}",e ))?
    };
    let cle_signature = cle_der.with_key_id(enveloppe.fingerprint()?.as_str());

    // Signer et retourner le nouveau token
    let jwt_token = match cle_signature.sign(claims) {
        Ok(inner) => inner,
        Err(e) => Err(format!("generer_jwt Erreur cle_signature.sign(claims) : {:?}",e ))?
    };
    Ok(jwt_token)
}
