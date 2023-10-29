use std::error::Error;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
mod mimc;
mod builder;

use std::io;
use std::io::Write;
use ark_bn254::Bn254;
use num_bigint;

use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_crypto_primitives::snark::SNARK;
use ark_ff::BigInt;
use ark_groth16::Groth16;
use ed25519_compact::{KeyPair, Seed};
use ed25519_dalek::ed25519::signature::rand_core::RngCore;
use crate::builder::CircomConfig;

type GrothBn = Groth16<Bn254>;

const SENDER_ETH: u32 = 500;
const RECEIVER_ETH: u32 = 0;

fn main() -> Result<(), Box<dyn Error>> {

    let key_pair = KeyPair::from_seed(Seed::default());


    // Generate a sender and receiver keypair
    let mut csprng1 = OsRng;
    let sender_key = SigningKey::generate(&mut csprng1);

    let mut csprng2 = OsRng;
    let receiver_key = SigningKey::generate(&mut csprng2);

    println!("Sender public key: {:?}", convert_bytes(sender_key.verifying_key().to_bytes()).to_string());

    // Ask for the amount of ETH for the transaction
    print!("Sender ETH: {}\n", SENDER_ETH);
    print!("Receiver ETH: {}\n", RECEIVER_ETH);
    print!("Enter the amount of ETH for the transaction: ");
    io::stdout().flush()?;  // Ensure the print! output is displayed immediately
    let send_eth_amount = read_u64_input()?;

    // Hash the sender and receiver accounts and calculate the accounts root
    let sender_hash = hash_account(&sender_key.verifying_key(), SENDER_ETH)?;
    let receiver_hash = hash_account(&receiver_key.verifying_key(), RECEIVER_ETH)?;
    let accounts_root = root_hash(&sender_hash, &receiver_hash)?;

    // Hash the transaction, sign it and verify the signature
    let transaction_arr = hash_transaction(&sender_key.verifying_key(), &receiver_key.verifying_key(), send_eth_amount)?;
    let signature = sender_key.sign(&transaction_arr.to_signed_bytes_be());
    let verified = sender_key.verify(&transaction_arr.to_signed_bytes_be(), &signature);
    println!("Signature verified: {:?}", verified.is_ok());

    // Calculate the new account hashes after the transaction
    let new_sender_hash = hash_account(&sender_key.verifying_key(), SENDER_ETH - send_eth_amount)?;
    let new_receiver_hash = hash_account(&receiver_key.verifying_key(), RECEIVER_ETH + send_eth_amount)?;

    // Calculate the intermediate and new roots
    let intermediate_accounts_root = root_hash(&new_sender_hash, &receiver_hash)?;
    let new_accounts_root = root_hash(&new_sender_hash, &new_receiver_hash)?;

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(
        "./circuits/circuit_js/circuit.wasm",
        "./circuits/circuit.r1cs",
    )?;

    // Insert our public inputs as key value pairs
    let mut builder = builder::CircomBuilder::new(cfg);
    builder.push_input("accounts_root", accounts_root);
    builder.push_input("intermediate_root", intermediate_accounts_root);
    builder.push_input("sender_pubkey", convert_bytes(sender_key.verifying_key().to_bytes()));
    builder.push_input("sender_balance", num_bigint::BigInt::from(SENDER_ETH));
    builder.push_input("receiver_pubkey", convert_bytes(receiver_key.verifying_key().to_bytes()));
    builder.push_input("receiver_balance", num_bigint::BigInt::from(RECEIVER_ETH));
    builder.push_input("amount", num_bigint::BigInt::from(send_eth_amount));
    builder.push_input("signature_R8x", signature.r_bytes());
    // builder.push_input("signature_S", signature.s_bytes().into());


    let mut sender_proof = Vec::new();
    sender_proof.push(sender_hash);
    builder.push_input_vec("sender_proof", sender_proof);

    let mut receiver_proof_pos = Vec::new();
    receiver_proof_pos.push(num_bigint::BigInt::from(0));
    builder.push_input_vec("sender_proof_pos", receiver_proof_pos);

    let mut receiver_proof = Vec::new();
    receiver_proof.push(receiver_hash);
    builder.push_input_vec("receiver_proof", receiver_proof);

    let mut receiver_proof_pos: Vec<num_bigint::BigInt> = Vec::new();
    receiver_proof_pos.push(num_bigint::BigInt::from(1));
    builder.push_input_vec("receiver_proof_pos", receiver_proof_pos);
    builder.push_input("enabled", 1);

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
