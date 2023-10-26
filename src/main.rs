use std::error::Error;
use rand::rngs::OsRng;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mimc_rs::Mimc7;

use std::io;
use std::io::Write;
use std::path::Path;
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use num_bigint_1;
use num_bigint_2;

use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use num_bigint_1::{Sign, ToBigInt};

type GrothBn = Groth16<Bn254>;

const SENDER_ETH: u32 = 500;
const RECEIVER_ETH: u32 = 0;

fn main() -> Result<(), Box<dyn Error>> {

    // Generate a sender and receiver keypair
    let mut csprng = OsRng{};
    let sender_key = SigningKey::generate(&mut csprng);
    let receiver_key = SigningKey::generate(&mut csprng);

    println!("Sender public key: {:?}", sender_key.verifying_key().to_bytes().len());

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
    let signature = sender_key.sign(&transaction_arr);
    let verified = sender_key.verify(&transaction_arr, &signature);
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
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("accounts_root", convert_bigint(accounts_root));
    builder.push_input("intermediate_root", convert_bigint(intermediate_accounts_root));
    // builder.push_input("accounts_pubkey", [
    //     convert_bytes(sender_key.verifying_key().to_bytes()),
    //     convert_bytes(receiver_key.verifying_key().to_bytes()),
    // ]);
    // builder.push_input("accounts_balance", [SENDER_ETH, RECEIVER_ETH]);
    // builder.push_input("sender_pubkey", [sender_key.verifying_key().to_bytes().to_vec()].into());
    // builder.push_input("sender_balance", SENDER_ETH.into());
    // builder.push_input("receiver_pubkey", [receiver_key.verifying_key().to_bytes().to_vec()].into());
    // builder.push_input("receiver_balance", RECEIVER_ETH);
    // builder.push_input("amount", send_eth_amount);
    // builder.push_input("signature_R8x", signature.r_bytes().into());
    // builder.push_input("signature_S", signature.s_bytes().into());
    // builder.push_input("sender_proof", [sender_hash].into());
    // builder.push_input("sender_proof_pos", [0].into());
    // builder.push_input("receiver_proof", [receiver_hash].into());
    // builder.push_input("receiver_proof_pos", [1].into());
    // builder.push_input("enabled", 1.into());

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

fn hash_account(key: &VerifyingKey, balance: u32) -> Result<num_bigint_1::BigInt, Box<dyn Error>> {
    let mut hasher = Mimc7::new();
    let mut account_vec = key.to_bytes().iter().map(|&b| b.into()).collect::<Vec<_>>();
    account_vec.push(balance.into());
    Ok(hasher.hash(account_vec)?)
}

fn root_hash(hash1: &num_bigint_1::BigInt, hash2: &num_bigint_1::BigInt) -> Result<num_bigint_1::BigInt, Box<dyn Error>> {
    let mut hasher = Mimc7::new();
    let account_hashes = vec![hash1.clone(), hash2.clone()];
    Ok(hasher.hash(account_hashes)?)
}

fn hash_transaction(sender_key: &VerifyingKey, receiver_key: &VerifyingKey, amount: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hasher = Mimc7::new();
    let mut transaction_vec = sender_key.to_bytes().iter().chain(receiver_key.to_bytes().iter()).map(|&b| num_bigint_1::BigInt::from(b)).collect::<Vec<_>>();
    transaction_vec.push(num_bigint_1::BigInt::from(amount));
    Ok(hasher.hash(transaction_vec).unwrap().to_bytes_be().1)
}

fn convert_bigint(bigint1: num_bigint_1::BigInt) -> num_bigint_2::BigInt {
    num_bigint_2::BigInt::from_signed_bytes_be(&*bigint1.to_signed_bytes_be())
}

// Convert this byte array to a BigInt
fn convert_bytes(bytes: [u8; 32]) -> num_bigint_2::BigInt {
    num_bigint_2::BigInt::from_bytes_be(num_bigint_2::Sign::Plus, &*bytes.to_vec())
}