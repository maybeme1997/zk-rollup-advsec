use std::error::Error;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, VerifyingKey};
mod mimc;
mod builder;

use std::io;
use std::io::Write;
use std::str::FromStr;
use ark_bn254::Bn254;
use num_bigint;

use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ed25519_dalek::ed25519::signature::rand_core::RngCore;
use num_traits::Num;
use crate::builder::CircomConfig;

type GrothBn = Groth16<Bn254>;

const SENDER_ETH: u32 = 500;
const RECEIVER_ETH: u32 = 0;

fn main() -> Result<(), Box<dyn Error>> {

    // Import inputs.json from the circuit_js folder
    let inputs = include_str!("../circuits/input.json");
    let inputs: serde_json::Value = serde_json::from_str(inputs)?;

    // Get the sender and receiver public keys
    let accounts_root = num_bigint::BigInt::from_str(inputs["accounts_root"].as_str().unwrap())?;
    let intermediate_root = num_bigint::BigInt::from_str(inputs["intermediate_root"].as_str().unwrap())?;

    let sender_pubkey_x = num_bigint::BigInt::from_str(inputs["sender_pubkey"][0].as_str().unwrap())?;
    let sender_pubkey_y = num_bigint::BigInt::from_str(inputs["sender_pubkey"][1].as_str().unwrap())?;

    let receiver_pubkey_x = num_bigint::BigInt::from_str(inputs["receiver_pubkey"][0].as_str().unwrap())?;
    let receiver_pubkey_y = num_bigint::BigInt::from_str(inputs["receiver_pubkey"][1].as_str().unwrap())?;

    let sender_balance = num_bigint::BigInt::from_str(inputs["sender_balance"].as_str().unwrap())?;
    let receiver_balance = num_bigint::BigInt::from_str(inputs["receiver_balance"].as_str().unwrap())?;
    let amount = num_bigint::BigInt::from_str(inputs["amount"].as_str().unwrap())?;

    let signature_r8x = num_bigint::BigInt::from_str(inputs["signature_R8x"].as_str().unwrap())?;
    let signature_r8y = num_bigint::BigInt::from_str(inputs["signature_R8y"].as_str().unwrap())?;
    let signature_s = num_bigint::BigInt::from_str(inputs["signature_S"].as_str().unwrap())?;

    let sender_hash = num_bigint::BigInt::from_str(inputs["sender_proof"][0].as_str().unwrap())?;
    let sender_hash_pos = num_bigint::BigInt::from_str(inputs["sender_proof_pos"][0].as_str().unwrap())?;

    let receiver_hash = num_bigint::BigInt::from_str(inputs["receiver_proof"][0].as_str().unwrap())?;
    let receiver_hash_pos = num_bigint::BigInt::from_str(inputs["receiver_proof_pos"][0].as_str().unwrap())?;


    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(
        "./circuits/circuit_js/circuit.wasm",
        "./circuits/circuit.r1cs",
    )?;

    // Insert our public inputs as key value pairs
    let mut builder = builder::CircomBuilder::new(cfg);
    builder.push_input("accounts_root", accounts_root);
    builder.push_input("intermediate_root", intermediate_root);
    builder.push_input("sender_balance", sender_balance);
    builder.push_input("receiver_balance", receiver_balance);
    builder.push_input("amount", amount);
    builder.push_input("signature_r8x", signature_r8x);
    builder.push_input("signature_r8y", signature_r8y);
    builder.push_input("signature_s", signature_s);

    let mut sender_key = Vec::new();
    sender_key.push(sender_pubkey_x);
    sender_key.push(sender_pubkey_y);
    builder.push_input_vec("sender_pubkey", sender_key);

    let mut receiver_key = Vec::new();
    receiver_key.push(receiver_pubkey_x);
    receiver_key.push(receiver_pubkey_y);
    builder.push_input_vec("receiver_pubkey", receiver_key);

    let mut sender_proof = Vec::new();
    sender_proof.push(sender_hash);
    builder.push_input_vec("sender_proof", sender_proof);

    let mut sender_proof_pos = Vec::new();
    sender_proof_pos.push(num_bigint::BigInt::from(0));
    builder.push_input_vec("sender_proof_pos", sender_proof_pos);

    let mut receiver_proof = Vec::new();
    receiver_proof.push(receiver_hash);
    builder.push_input_vec("receiver_proof", receiver_proof);

    let mut receiver_proof_pos: Vec<num_bigint::BigInt> = Vec::new();
    receiver_proof_pos.push(num_bigint::BigInt::from(1));
    builder.push_input_vec("receiver_proof_pos", receiver_proof_pos);

    builder.push_input("enabled", num_bigint::BigInt::from(1));

    // Create an empty instance for setting it up
    let circom = builder.setup();

    // Run a trusted setup
    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    // Get the populated instance of the circuit with the witness
    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    // Generate the proof
    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    // Check that the proof is valid
    let pvk = GrothBn::process_vk(&params.vk)?;
    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;
    assert!(verified);

    Ok(())
}

fn read_u64_input() -> Result<u32, Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let parsed_input = input.trim().parse()?;
    Ok(parsed_input)
}

fn hash_account(key: &VerifyingKey, balance: u32) -> Result<num_bigint::BigInt, Box<dyn Error>> {
    let mut hasher = mimc::Mimc7::new();
    let mut account_vec: Vec<num_bigint::BigInt> = Vec::new();
    account_vec.push(convert_bytes(key.to_bytes()));
    account_vec.push(num_bigint::BigInt::from(balance));
    Ok(hasher.hash(account_vec)?)
}

fn root_hash(hash1: &num_bigint::BigInt, hash2: &num_bigint::BigInt) -> Result<num_bigint::BigInt, Box<dyn Error>> {
    let mut hasher = mimc::Mimc7::new();
    let account_hashes = vec![hash1.clone(), hash2.clone()];
    Ok(hasher.hash(account_hashes)?)
}

fn hash_transaction(sender_key: &VerifyingKey, receiver_key: &VerifyingKey, amount: u32) -> Result<num_bigint::BigInt, Box<dyn Error>> {
    let mut hasher = mimc::Mimc7::new();
    let mut transaction_vec = Vec::new();
    transaction_vec.push(convert_bytes(sender_key.to_bytes()));
    transaction_vec.push(convert_bytes(receiver_key.to_bytes()));
    transaction_vec.push(num_bigint::BigInt::from(amount));
    Ok(hasher.hash(transaction_vec)?)
}

// Convert this byte array to a BigInt v0.2.6
fn convert_bytes(bytes: [u8; 32]) -> num_bigint::BigInt {
    num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &*bytes.to_vec())
}
