use blsful::inner_types::{G1Projective, Scalar};
use gennaro_dkg::vsss_rs::IdentifierPrimeField;
use gennaro_dkg::{Parameters, SecretParticipant};
use round_based::MessageDestination;
use round_based::rounds_router::{RoundsRouter, simple_store::RoundInput};
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use tracing::info;

use crate::keygen::KeygenError;

/// State persisted after keygen, needed for signing.
/// Stores the secret key scalar and aggregated public key as raw bytes.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct BlsState {
    /// Secret key scalar bytes (32 bytes, big-endian)
    pub secret_key_bytes: Option<Vec<u8>>,
    /// Aggregated uncompressed public key bytes (97 bytes, milagro format)
    pub uncompressed_pk: Option<Vec<u8>>,
    /// The call_id of the keygen job
    pub call_id: u64,
    /// Threshold
    pub t: u16,
}

/// Messages for the BLS keygen protocol.
/// Rounds 1-4: gennaro-dkg protocol (run/receive pattern)
/// Round 5: milagro public key share broadcast + aggregation
#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum KeygenMsg {
    DkgRound1(DkgRound1Msg),
    DkgRound2(DkgRound2Msg),
    DkgRound3(DkgRound3Msg),
    DkgRound4(DkgRound4Msg),
    PkShareBroadcast(PkShareMsg),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DkgRound1Msg {
    pub source: u16,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DkgRound2Msg {
    pub source: u16,
    pub destination: u16,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DkgRound3Msg {
    pub source: u16,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DkgRound4Msg {
    pub source: u16,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PkShareMsg {
    pub source: u16,
    pub data: Vec<u8>,
}

pub trait HasRecipient {
    fn recipient(&self) -> MessageDestination;
}

impl HasRecipient for KeygenMsg {
    fn recipient(&self) -> MessageDestination {
        match self {
            KeygenMsg::DkgRound1(_)
            | KeygenMsg::DkgRound3(_)
            | KeygenMsg::DkgRound4(_)
            | KeygenMsg::PkShareBroadcast(_) => MessageDestination::AllParties,
            KeygenMsg::DkgRound2(msg) => MessageDestination::OneParty(msg.destination),
        }
    }
}

#[tracing::instrument(skip_all)]
pub async fn bls_keygen_protocol<M>(
    party: M,
    i: PartyIndex,
    t: u16,
    n: u16,
    call_id: u64,
) -> Result<BlsState, KeygenError>
where
    M: Mpc<ProtocolMessage = KeygenMsg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // Create gennaro-dkg participant with 1-indexed sequential IDs
    let t_nz = NonZeroUsize::new(t as usize).expect("T > 0");
    let n_nz = NonZeroUsize::new(n as usize).expect("N > 0");
    let parameters = Parameters::new(t_nz, n_nz, None, None, None);

    let my_id = IdentifierPrimeField(Scalar::from((i + 1) as u64));
    let mut participant = SecretParticipant::<G1Projective>::new(my_id, &parameters)
        .map_err(|e| KeygenError::MpcError(e.to_string()))?;

    // Setup round-based router: 4 DKG rounds + 1 PK aggregation round
    let mut rounds = RoundsRouter::builder();
    let r1 = rounds.add_round(RoundInput::<DkgRound1Msg>::broadcast(i, n));
    let r2 = rounds.add_round(RoundInput::<DkgRound2Msg>::p2p(i, n));
    let r3 = rounds.add_round(RoundInput::<DkgRound3Msg>::broadcast(i, n));
    let r4 = rounds.add_round(RoundInput::<DkgRound4Msg>::broadcast(i, n));
    let r5 = rounds.add_round(RoundInput::<PkShareMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // --- DKG Round 1: Broadcast commitment hashes ---
    // NOTE: generator.iter() returns Box<dyn Iterator> which is !Send.
    // We must collect all outputs before any .await to keep the future Send.
    info!("[BLS-DKG] Round 1: commitment hashes");
    let r1_outputs: Vec<_> = {
        let generator = participant.run().map_err(dkg_err)?;
        generator.iter().collect()
    };
    let payload = r1_outputs
        .into_iter()
        .next()
        .ok_or_else(|| KeygenError::MpcError("No round 1 output".into()))?
        .data;
    send_msg::<M>(
        &mut outgoings,
        KeygenMsg::DkgRound1(DkgRound1Msg { source: i, payload }),
    )
    .await?;

    for (_, _, msg) in rounds
        .complete(r1)
        .await
        .map_err(mpc_err)?
        .into_iter_indexed()
    {
        participant.receive(&msg.payload).map_err(dkg_err)?;
    }

    // --- DKG Round 2: P2P shares ---
    info!("[BLS-DKG] Round 2: P2P shares");
    let r2_outputs: Vec<_> = {
        let generator = participant.run().map_err(dkg_err)?;
        generator.iter().collect()
    };
    for output in r2_outputs {
        let msg = KeygenMsg::DkgRound2(DkgRound2Msg {
            source: i,
            destination: output.dst_ordinal as u16,
            payload: output.data,
        });
        send_msg::<M>(&mut outgoings, msg).await?;
    }

    for (_, _, msg) in rounds
        .complete(r2)
        .await
        .map_err(mpc_err)?
        .into_iter_indexed()
    {
        participant.receive(&msg.payload).map_err(dkg_err)?;
    }

    // --- DKG Round 3: Feldman commitments ---
    info!("[BLS-DKG] Round 3: Feldman commitments");
    let r3_outputs: Vec<_> = {
        let generator = participant.run().map_err(dkg_err)?;
        generator.iter().collect()
    };
    let payload = r3_outputs
        .into_iter()
        .next()
        .ok_or_else(|| KeygenError::MpcError("No round 3 output".into()))?
        .data;
    send_msg::<M>(
        &mut outgoings,
        KeygenMsg::DkgRound3(DkgRound3Msg { source: i, payload }),
    )
    .await?;

    for (_, _, msg) in rounds
        .complete(r3)
        .await
        .map_err(mpc_err)?
        .into_iter_indexed()
    {
        participant.receive(&msg.payload).map_err(dkg_err)?;
    }

    // --- DKG Round 4: Transcript verification ---
    info!("[BLS-DKG] Round 4: transcript verification");
    let r4_outputs: Vec<_> = {
        let generator = participant.run().map_err(dkg_err)?;
        generator.iter().collect()
    };
    let payload = r4_outputs
        .into_iter()
        .next()
        .ok_or_else(|| KeygenError::MpcError("No round 4 output".into()))?
        .data;
    send_msg::<M>(
        &mut outgoings,
        KeygenMsg::DkgRound4(DkgRound4Msg { source: i, payload }),
    )
    .await?;

    for (_, _, msg) in rounds
        .complete(r4)
        .await
        .map_err(mpc_err)?
        .into_iter_indexed()
    {
        participant.receive(&msg.payload).map_err(dkg_err)?;
    }

    // --- DKG Round 5: Internal computation (no network) ---
    participant.run().map_err(dkg_err)?;
    assert!(
        participant.completed(),
        "DKG should be complete after round 5"
    );

    // Extract secret share scalar
    let secret_share = participant
        .get_secret_share()
        .ok_or_else(|| KeygenError::MpcError("DKG incomplete: no secret share".into()))?;
    let scalar: Scalar = *secret_share.value;
    let secret_key_bytes = scalar.to_be_bytes().to_vec();

    // --- Round 5 (network): Broadcast milagro pk shares for aggregation ---
    info!("[BLS-DKG] Round 5: PK share broadcast + aggregation");
    let milagro_sk = snowbridge_milagro_bls::SecretKey::from_bytes(&secret_key_bytes)
        .map_err(|e| KeygenError::MpcError(format!("Failed to create milagro SK: {e:?}")))?;
    let pk_share = snowbridge_milagro_bls::PublicKey::from_secret_key(&milagro_sk);
    let my_pk_msg = PkShareMsg {
        source: i,
        data: pk_share.as_uncompressed_bytes().to_vec(),
    };
    send_msg::<M>(
        &mut outgoings,
        KeygenMsg::PkShareBroadcast(my_pk_msg.clone()),
    )
    .await?;

    let pk_received = rounds.complete(r5).await.map_err(mpc_err)?;
    let all_pk_msgs = pk_received.into_vec_including_me(my_pk_msg);
    let all_pk_shares: Result<Vec<_>, _> = all_pk_msgs
        .iter()
        .map(|msg| snowbridge_milagro_bls::PublicKey::from_uncompressed_bytes(&msg.data))
        .collect();
    let all_pk_shares =
        all_pk_shares.map_err(|e| KeygenError::MpcError(format!("Bad pk share: {e:?}")))?;

    let pk_agg = snowbridge_milagro_bls::AggregatePublicKey::aggregate(
        &all_pk_shares.iter().collect::<Vec<_>>(),
    )
    .map_err(|e| KeygenError::MpcError(format!("Failed to aggregate PKs: {e:?}")))?;

    let mut uncompressed_pk = [0u8; 97];
    pk_agg.point.to_bytes(&mut uncompressed_pk, false);

    info!("[BLS-DKG] Keygen complete for party {i}");

    Ok(BlsState {
        secret_key_bytes: Some(secret_key_bytes),
        uncompressed_pk: Some(uncompressed_pk.to_vec()),
        call_id,
        t,
    })
}

fn dkg_err(e: gennaro_dkg::Error) -> KeygenError {
    KeygenError::MpcError(e.to_string())
}

fn mpc_err<E: std::fmt::Display>(e: E) -> KeygenError {
    KeygenError::MpcError(e.to_string())
}

#[tracing::instrument(skip_all)]
pub async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), KeygenError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    let recipient = msg.recipient();
    let msg = round_based::Outgoing { recipient, msg };
    futures::SinkExt::send(tx, msg)
        .await
        .map_err(|e| KeygenError::DeliveryError(e.to_string()))?;
    Ok(())
}

async fn send_msg<M>(
    tx: &mut <<M as Mpc>::Delivery as Delivery<KeygenMsg>>::Send,
    msg: KeygenMsg,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = KeygenMsg>,
{
    send_message::<M, KeygenMsg>(msg, tx).await
}
