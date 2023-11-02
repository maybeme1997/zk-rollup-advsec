# Efficient zk-Rollup Implementation in Rust

This repository contains a simple, single transaction, zero-knowledge rollup made in Rust. 
We have combined various open-source libraries/projects that were already available.

This project was part of a university assignment, so this project should not be used in production environments.


## Install & Run 
Make sure that Rust and Node are installed.

First go into to the circuits directory and compile the circuit. Download the latest version of Circom from here https://github.com/iden3/circom

    cd circuits
    npm install
    node generate_input.js
    [your circom executable here] circuit.circom --wasm --r1cs --json

Now go back into the main folder and run:
    
    cargo run

This will set up the proof and verify the proof based on the generated inputs


**Resources used:**
- [1] zk-rollup tutorial, https://github.com/rollupnc/RollupNC
- [2] ark-circom, https://github.com/arkworks-rs/circom-compat
