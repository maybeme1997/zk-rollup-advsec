const fs = require("fs");
const { buildBabyjub, buildMimc7, buildEddsa } = require("circomlibjs");
const wasm_tester = require('circom_tester').wasm

async function main() {
  const babyJub = await buildBabyjub();
  const mimc7 = await buildMimc7();
  const eddsa = await buildEddsa();
  const F = babyJub.F;
  
  // setup accounts
  const alicePrvKey = Buffer.from("1".toString().padStart(64, "0"), "hex");
  console.log(alicePrvKey);
  const receiverPrvKey = Buffer.from("2".toString().padStart(64, "0"), "hex");

  const senderPubKey = eddsa.prv2pub(alicePrvKey);
  const receiverPubKey = eddsa.prv2pub(receiverPrvKey);


}
main();
