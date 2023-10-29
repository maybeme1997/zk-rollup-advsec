/// # Ethereum Zero-Knowledge Proofs Utility
///
/// ## Overview:
/// This program provides a tool for creating a zero-knowledge proof for Ethereum transactions.
/// It utilizes zkSNARKs to demonstrate that a sender has made a transaction without revealing
/// the details of the transaction.
///
/// ## Dependencies:
/// - **std**: Standard library.
/// - **rand**: Random number generation.
/// - **ed25519_dalek**: Ed25519 signing and verifying.
/// - **mimc**: MiMC hash function.
/// - **builder**: Tool for building zkSNARK circuits.
/// - **ark_bn254**: BN-254 elliptic curve.
/// - **num_bigint**: BigInt support library.
/// - **ark_std**: Arkworks library.
/// - **color_eyre**: Error report handler.
/// - **ark_crypto_primitives**: Arkworks crypto primitives.
/// - **ark_ff**: Arkworks field arithmetic.
/// - **ark_groth16**: Groth16 SNARK proof.
/// - **ed25519_compact**: Ed25519 signing and verifying.
///
/// ## Constants:
/// - **SENDER_ETH**: The balance of Ethereum for the sender - 500.
/// - **RECEIVER_ETH**: The balance of Ethereum for the receiver - 0.
///
/// ## Functions:
///
/// 1. **main**:
///    - Initiating our program.
///      - Generate sender and receiver key pairs.
///      - Request the user to input for the transaction.
///      - Hash the sender and receiver accounts and calculate the accounts roots.
///      - Sign and verify the transaction.
///      - Load the zkSNARK circuit and create a proof.
///      - Verify the proof.
///
/// 2. **read_u64_input**:
///    - Reads an input from the console.
///
/// 3. **hash_account**:
///    - Computes the hash of an account given its public key and balance.
///
/// 4. **root_hash**:
///    - Computes the MiMC hash of two combined hashes.
///
/// 5. **hash_transaction**:
///    - Computes the MiMC hash of a transaction given the sender key, receiver key, and amount.
///
/// 6. **convert_bytes**:
///    - Converts a byte array into a `BigInt`.

// External dependencies
use std::error::Error;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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

// Internal modules
mod mimc;
mod builder;
use crate::builder::CircomConfig;

// Type definition for Groth16 using Bn254 curve
type GrothBn = Groth16<Bn254>;

// Initial balances for sender and receiver
const SENDER_ETH: u32 = 500;
const RECEIVER_ETH: u32 = 0;

fn main() -> Result<(), Box<dyn Error>> {
    // Generating a default key pair
    let key_pair = KeyPair::from_seed(Seed::default());

    // Generating sender and receiver key pairs using RNG
    let mut csprng1 = OsRng;
    let sender_key = SigningKey::generate(&mut csprng1);

    let mut csprng2 = OsRng;
    let receiver_key = SigningKey::generate(&mut csprng2);

    // Printing sender public key
    println!("Sender public key: {:?}", convert_bytes(sender_key.verifying_key().to_bytes()).to_string());

    // Display sender and receiver initial balances and get transaction amount from user
    print!("Sender ETH: {}\n", SENDER_ETH);
    print!("Receiver ETH: {}\n", RECEIVER_ETH);
    print!("Enter the amount of ETH for the transaction: ");
    io::stdout().flush()?;  // Ensure the print! output is displayed immediately
    let send_eth_amount = read_u64_input()?;

    // Hash sender and receiver accounts and calculate the accounts root
    let sender_hash = hash_account(&sender_key.verifying_key(), SENDER_ETH)?;
    let receiver_hash = hash_account(&receiver_key.verifying_key(), RECEIVER_ETH)?;
    let accounts_root = root_hash(&sender_hash, &receiver_hash)?;

    // Hash the transaction, sign it, and verify the signature
    let transaction_arr = hash_transaction(&sender_key.verifying_key(), &receiver_key.verifying_key(), send_eth_amount)?;
    let signature = sender_key.sign(&transaction_arr.to_signed_bytes_be());
    let verified = sender_key.verify(&transaction_arr.to_signed_bytes_be(), &signature);
    println!("Signature verified: {:?}", verified.is_ok());

    // Calculate new account hashes post-transaction
    let new_sender_hash = hash_account(&sender_key.verifying_key(), SENDER_ETH - send_eth_amount)?;
    let new_receiver_hash = hash_account(&receiver_key.verifying_key(), RECEIVER_ETH + send_eth_amount)?;

    // Calculate intermediate and new roots post-transaction
    let intermediate_accounts_root = root_hash(&new_sender_hash, &receiver_hash)?;
    let new_accounts_root = root_hash(&new_sender_hash, &new_receiver_hash)?;

    // Load WASM and R1CS files for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(
        "./circuits/circuit_js/circuit.wasm",
        "./circuits/circuit.r1cs",
    )?;

    // Populate zkSNARK circuit with public inputs
    let mut builder = builder::CircomBuilder::new(cfg);
    builder.push_input("accounts_root", accounts_root);
    builder.push_input("intermediate_root", intermediate_accounts_root);
    builder.push_input("sender_pubkey", convert_bytes(sender_key.verifying_key().to_bytes()));
    builder.push_input("sender_balance", num_bigint::BigInt::from(SENDER_ETH));
    builder.push_input("receiver_pubkey", convert_bytes(receiver_key.verifying_key().to_bytes()));
    builder.push_input("receiver_balance", num_bigint::BigInt::from(RECEIVER_ETH));
    builder.push_input("amount", num_bigint::BigInt::from(send_eth_amount));
    builder.push_input("signature_R8x", signature.r_bytes());


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

    // Create empty instance
    let circom = builder.setup();

    // Setup using Groth16
    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    // Add witness to the circuit 
    let circom = builder.build()?;

    // Generate the zero-knowledge proof
    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    // Verify the generated proof
    let pvk = GrothBn::process_vk(&params.vk)?;
    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;
    assert!(verified);

    Ok(())
}

// Reads an input value (u32) from the console.
fn read_u64_input() -> Result<u32, Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let parsed_input = input.trim().parse()?;
    Ok(parsed_input)
}

// Returns the MiMC hash of an account given its verifying key and balance.
fn hash_account(key: &VerifyingKey, balance: u32) -> Result<num_bigint::BigInt, Box<dyn Error>> {
    let mut hasher = mimc::Mimc7::new();
    let mut account_vec: Vec<num_bigint::BigInt> = Vec::new();
    account_vec.push(convert_bytes(key.to_bytes()));
    account_vec.push(num_bigint::BigInt::from(balance));
    Ok(hasher.hash(account_vec)?)
}

// Returns the MiMC hash of two combined hashes.
fn root_hash(hash1: &num_bigint::BigInt, hash2: &num_bigint::BigInt) -> Result<num_bigint::BigInt, Box<dyn Error>> {
    let mut hasher = mimc::Mimc7::new();
    let account_hashes = vec![hash1.clone(), hash2.clone()];
    Ok(hasher.hash(account_hashes)?)
}

// Hashes the details of a transaction using the MiMC hash function.
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
