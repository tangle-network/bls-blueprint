use blueprint_sdk::crypto::hashing::sha2_256;
use itertools::Itertools;
use round_based::MessageDestination;
use round_based::rounds_router::{RoundsRouter, simple_store::RoundInput};
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use snowbridge_milagro_bls::{PublicKey, SecretKey, Signature};
use std::collections::BTreeMap;

use crate::keygen_state_machine::{BlsState, HasRecipient};
use crate::signing::SigningError;

#[derive(Default, Clone)]
pub struct BlsSigningState {
    pub secret_key: Option<SecretKey>,
    pub signature: Option<Vec<u8>>,
    received_sig_shares: BTreeMap<usize, Signature>,
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum SigningMsg {
    Round1Broadcast(Msg1),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg1 {
    pub sender: u16,
    pub receiver: Option<u16>,
    pub body: Vec<u8>, // signature_share
}

impl HasRecipient for SigningMsg {
    fn recipient(&self) -> MessageDestination {
        match self {
            SigningMsg::Round1Broadcast(..) => MessageDestination::AllParties,
        }
    }
}

pub async fn bls_signing_protocol<M, T>(
    party: M,
    i: PartyIndex,
    n: u16,
    state: &BlsState,
    input_data_to_sign: T,
) -> Result<BlsSigningState, SigningError>
where
    M: Mpc<ProtocolMessage = SigningMsg>,
    T: AsRef<[u8]>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut signing_state = BlsSigningState::default();

    // Extract secret key bytes from state
    let secret_key_bytes = state.secret_key_bytes.as_ref().ok_or_else(|| {
        SigningError::KeyRetrievalError("Secret key not found in state".to_string())
    })?;

    let secret_key = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|e| SigningError::MpcError(format!("Failed to create secret key: {e:?}")))?;

    // Step 1: Generate shares
    let sign_input = sha2_256(input_data_to_sign.as_ref());
    let sig_share = Signature::new(&sign_input, &secret_key);

    let my_msg = Msg1 {
        sender: i,
        receiver: None,
        body: sig_share.as_bytes().to_vec(),
    };
    // Step 2: Broadcast shares
    let msg = SigningMsg::Round1Broadcast(my_msg.clone());

    send_message::<M, SigningMsg>(msg, &mut outgoings)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))?;

    // Step 3: Receive shares until there are t+1 total
    let mut rounds = RoundsRouter::builder();
    let round = rounds.add_round(RoundInput::<Msg1>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let msgs = rounds
        .complete(round)
        .await
        .map_err(|e| SigningError::MpcError(format!("Failed to complete round: {e}")))?;

    for msg in msgs.into_vec_including_me(my_msg) {
        let (sender, sig) = (msg.sender, msg.body);
        let sig = Signature::from_bytes(&sig)
            .map_err(|e| SigningError::MpcError(format!("Failed to create signature: {e:?}")))?;
        signing_state
            .received_sig_shares
            .insert(sender as usize, sig);
    }

    // Step 4: Verify the combined signatures and public keys
    let sig_shares = signing_state
        .received_sig_shares
        .clone()
        .into_iter()
        .sorted_by_key(|r| r.0)
        .map(|r| r.1)
        .collect::<Vec<_>>();

    let combined_signature = snowbridge_milagro_bls::AggregateSignature::aggregate(
        &sig_shares.iter().collect::<Vec<_>>(),
    );

    let uncompressed_pk = state.uncompressed_pk.as_ref().ok_or_else(|| {
        SigningError::KeyRetrievalError("Uncompressed public key not found in state".to_string())
    })?;

    let as_pk = PublicKey::from_uncompressed_bytes(&uncompressed_pk[1..])
        .map_err(|e| SigningError::MpcError(format!("Failed to create public key: {e:?}")))?;

    let as_sig = Signature::from_bytes(&combined_signature.as_bytes())
        .map_err(|e| SigningError::MpcError(format!("Failed to create signature: {e:?}")))?;

    if !as_sig.verify(&sign_input, &as_pk) {
        return Err(SigningError::MpcError(
            "Failed to verify signature locally".to_string(),
        ));
    }

    signing_state.signature = Some(as_sig.as_bytes().to_vec());
    signing_state.secret_key = Some(secret_key);

    Ok(signing_state)
}

async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), SigningError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    crate::keygen_state_machine::send_message::<M, Msg>(msg, tx)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))
}
