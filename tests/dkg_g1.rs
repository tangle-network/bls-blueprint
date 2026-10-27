//! Distributed key generation on BLS12-381 G1, the path `bls_keygen_protocol` runs.
//!
//! It drives gennaro-dkg's five rounds for a 3-of-5 committee over blsful's
//! `G1Projective`, so a split between the blstrs_plus behind blsful and the one
//! gennaro-dkg implements its traits for fails here before it reaches a deployment.

use blsful::inner_types::G1Projective;
use gennaro_dkg::vsss_rs::elliptic_curve::Group;
use gennaro_dkg::vsss_rs::{
    IdentifierPrimeField, ParticipantIdGeneratorCollection, ParticipantIdGeneratorType,
    ReadableShareSet,
};
use gennaro_dkg::*;
use std::num::NonZeroUsize;

type Participant = Box<dyn AnyParticipant<G1Projective>>;

#[test]
fn three_of_five_dkg_agrees_on_the_key_its_shares_reconstruct() {
    let threshold = NonZeroUsize::new(3).unwrap();
    let limit = NonZeroUsize::new(5).unwrap();
    let ids = vec![ParticipantIdGeneratorType::<
        IdentifierPrimeField<<G1Projective as Group>::Scalar>,
    >::sequential(None, None, limit)];
    let parameters = Parameters::<G1Projective>::new(threshold, limit, None, None, Some(ids.clone()));
    let mut participants: Vec<Participant> = ParticipantIdGeneratorCollection::from(&ids)
        .iter()
        .map(|id| {
            Box::new(SecretParticipant::<G1Projective>::new(id, &parameters).unwrap()) as Participant
        })
        .collect();

    for _ in [Round::One, Round::Two, Round::Three, Round::Four, Round::Five] {
        let outputs: Vec<_> = participants.iter_mut().map(|p| p.run().unwrap()).collect();
        for output in &outputs {
            for ParticipantRoundOutput { dst_ordinal, dst_id, data, .. } in output.iter() {
                if let Some(participant) = participants.get_mut(dst_ordinal) {
                    assert_eq!(participant.get_id(), dst_id);
                    participant.receive(data.as_slice()).unwrap();
                }
            }
        }
    }

    let public_key = participants[0].get_public_key().unwrap();
    assert!(participants.iter().all(|p| p.get_public_key().unwrap() == public_key));
    assert_eq!(public_key.is_identity().unwrap_u8(), 0);

    // Any threshold of shares reconstructs the secret behind that public key.
    let shares: Vec<_> = participants
        .iter()
        .take(3)
        .map(|p| p.get_secret_share().unwrap())
        .collect();
    let secret = shares.combine().unwrap();
    assert_eq!(G1Projective::generator() * *secret, public_key);
}
