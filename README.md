# Efficient zk-Rollup Implementation in Rust

This repository contains a simple, single transaction, zero-knowledge rollup made in Rust. 
We have used various open-source libraries/projects that were already available.

This project was part of an university assignment, so this project should not be used in production environments.


## Install & Run 
Make sure that Rust and Node are installed.

First go into to the circuits directory and compile the ciruit. Download the latest version of circom from here https://github.com/iden3/circom

    cd circuits
    npm install
    node generate_input.js
    [your circom executable here] circuit.circom --wasm --r1cs --json

Now go back into the main folder and run:
    
    cargo run

This will set up the proof and verify the proof based on the generated inputs


**References:**
- [1] zero-knowledge rollup, https://ethereum.org/en/developers/docs/scaling/zk-rollups/
- [2] The Rust Programming Language, https://doc.rust-lang.org/book/
- [3] zk-rollup tutorial, https://github.com/rollupnc/RollupNC
