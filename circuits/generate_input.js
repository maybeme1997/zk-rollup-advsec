const fs = require("fs");
const {buildBabyjub, buildMimc7, buildEddsa} = require("circomlibjs");
const wasm_tester = require('circom_tester').wasm
const prompt = require('prompt-sync')();

async function main() {
    const babyJub = await buildBabyjub();
    const mimc7 = await buildMimc7();
    const eddsa = await buildEddsa();
    const F = babyJub.F;

    // setup accounts
    const senderPrvKey = Buffer.from("1".toString().padStart(64, "0"), "hex");
    const receiverPrvKey = Buffer.from("2".toString().padStart(64, "0"), "hex");
    const senderPubKey = eddsa.prv2pub(senderPrvKey);
    const receiverPubKey = eddsa.prv2pub(receiverPrvKey);

    const senderBalance = 500;
    const receiverBalance = 0;

    console.log("Sender balance: ", senderBalance);
    console.log("Receiver balance: ", receiverBalance);

    const val = prompt('Amount of money to transfer:');
    const amount= Number(val);

    // setup accounts and root hash
    const senderHash = mimc7.multiHash(
        [senderPubKey[0], senderPubKey[1], senderBalance],
        1
    );
    const receiverHash = mimc7.multiHash(
        [receiverPubKey[0], receiverPubKey[1], receiverBalance],
        1
    );

    // Print sender hash
    console.log("------------------- Sender and receiver hash -------------------");
    console.log(BigInt(F.toObject(senderHash)).toString());
    console.log(BigInt(F.toObject(receiverHash)).toString());

    const accounts_root = mimc7.multiHash([senderHash, receiverHash], 1);

    // sign transaction
    const txHash = mimc7.multiHash(
        [senderPubKey[0], senderPubKey[1], receiverPubKey[0], receiverPubKey[1], amount],
        1
    );

    const signature = eddsa.signMiMC(senderPrvKey, txHash);


    // New accounts state and root hash
    const newSenderHash = mimc7.multiHash(
        [senderPubKey[0], senderPubKey[1], senderBalance - amount],
        1
    );
    const newReceiverHash = mimc7.multiHash(
        [receiverPubKey[0], receiverPubKey[1], receiverBalance + amount],
        1
    );
    const intermediate_root = mimc7.multiHash([newSenderHash, receiverHash], 1);
    const new_root = mimc7.multiHash([newSenderHash, newReceiverHash], 1);

    const inputs = {
        accounts_root: BigInt(F.toObject(accounts_root)).toString(),
        intermediate_root: BigInt(F.toObject(intermediate_root)).toString(),
        accounts_balance: [senderBalance.toString(), receiverBalance.toString()],
        sender_pubkey: [
            BigInt(F.toObject(senderPubKey[0])).toString(),
            BigInt(F.toObject(senderPubKey[1])).toString(),
        ],
        sender_balance: senderBalance.toString(),
        receiver_pubkey: [
            BigInt(F.toObject(receiverPubKey[0])).toString(),
            BigInt(F.toObject(receiverPubKey[1])).toString(),
        ],
        receiver_balance: receiverBalance.toString(),
        amount: amount.toString(),
        signature_R8x: BigInt(F.toObject(signature.R8[0])).toString(),
        signature_R8y: BigInt(F.toObject(signature.R8[1])).toString(),
        signature_S: BigInt(signature.S).toString(),
        sender_proof: [BigInt(F.toObject(receiverHash)).toString()],
        sender_proof_pos: ["0"],
        receiver_proof: [BigInt(F.toObject(newSenderHash)).toString()],
        receiver_proof_pos: ["1"],
        enabled: "1"
    };

    console.log("------------------- new root hash -------------------");
    console.log(BigInt(F.toObject(new_root)).toString());
    fs.writeFileSync("./input.json", JSON.stringify(inputs), 'utf-8');
}

main();
