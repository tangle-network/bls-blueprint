//! Distributed key generation on BLS12-381 G1, the path `bls_keygen_protocol` runs.
//!
//! It drives gennaro-dkg's five rounds for a 3-of-5 committee over blsful's
//! `G1Projective`, so a split between the blstrs_plus behind blsful and the one
//! gennaro-dkg implements its traits for fails here before it reaches a deployment.

use blsful::inner_types::{G1Projective, G2Projective, Scalar};
use gennaro_dkg::elliptic_curve_tools_03::legacy::SumOfProducts;
use gennaro_dkg::vsss_rs::elliptic_curve::{Group, group::GroupEncoding};
use gennaro_dkg::vsss_rs::{
    IdentifierPrimeField, ParticipantIdGeneratorCollection, ParticipantIdGeneratorType,
    ReadableShareSet,
};
use gennaro_dkg::*;
use std::num::NonZeroUsize;

type Participant<G> = Box<dyn AnyParticipant<G>>;

#[test]
fn three_of_five_g1_dkg_agrees_and_signs() {
    dkg_agrees_and_signs::<G1Projective>();
}

#[test]
fn three_of_five_g2_dkg_agrees_and_signs() {
    dkg_agrees_and_signs::<G2Projective>();
}

fn dkg_agrees_and_signs<G>()
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Group<Scalar = Scalar> + Default + 'static,
{
    let threshold = NonZeroUsize::new(3).unwrap();
    let limit = NonZeroUsize::new(5).unwrap();
    let ids = vec![ParticipantIdGeneratorType::<
        IdentifierPrimeField<<G as Group>::Scalar>,
    >::sequential(None, None, limit)];
    let parameters = Parameters::<G>::new(threshold, limit, None, None, Some(ids.clone()));
    let mut participants: Vec<Participant<G>> = ParticipantIdGeneratorCollection::from(&ids)
        .iter()
        .map(|id| Box::new(SecretParticipant::<G>::new(id, &parameters).unwrap()) as Participant<G>)
        .collect();

    for _ in [
        Round::One,
        Round::Two,
        Round::Three,
        Round::Four,
        Round::Five,
    ] {
        let outputs: Vec<_> = participants.iter_mut().map(|p| p.run().unwrap()).collect();
        for output in &outputs {
            for ParticipantRoundOutput {
                dst_ordinal,
                dst_id,
                data,
                ..
            } in output.iter()
            {
                if let Some(participant) = participants.get_mut(dst_ordinal) {
                    assert_eq!(participant.get_id(), dst_id);
                    participant.receive(data.as_slice()).unwrap();
                }
            }
        }
    }

    let public_key = participants[0].get_public_key().unwrap();
    assert!(
        participants
            .iter()
            .all(|p| p.get_public_key().unwrap() == public_key)
    );
    assert_eq!(public_key.is_identity().unwrap_u8(), 0);

    // Any threshold of shares reconstructs the secret behind that public key.
    let shares: Vec<_> = participants
        .iter()
        .take(3)
        .map(|p| p.get_secret_share().unwrap())
        .collect();
    let secret = shares.combine().unwrap();
    assert_eq!(G::generator() * *secret, public_key);

    let signing_key = snowbridge_milagro_bls::SecretKey::from_bytes(&secret.to_be_bytes()).unwrap();
    let signing_public_key = snowbridge_milagro_bls::PublicKey::from_secret_key(&signing_key);
    let message = b"dkg-cohort-signing-boundary";
    let signature = snowbridge_milagro_bls::Signature::new(message, &signing_key);
    assert!(signature.verify(message, &signing_public_key));
    assert!(!signature.verify(b"another-message", &signing_public_key));
}
