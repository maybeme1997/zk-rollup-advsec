extern crate num_traits;

use tiny_keccak::Keccak;

use num_bigint::{BigInt, Sign};
use num_traits::Zero;

const SEED: &str = "mimc";
const N_ROUNDS: i64 = 91;

pub struct Constants {
    // seed_hash: BigInt,
    // iv: BigInt,
    r: BigInt,
    n_rounds: i64,
    cts: Vec<BigInt>,
}

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub fn generate_constants() -> Constants {
    let r: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
        .unwrap();

    let mut keccak = Keccak::new_keccak256();
    let mut h = [0u8; 32];
    keccak.update(SEED.as_bytes());
    keccak.finalize(&mut h);
    let mut keccak = Keccak::new_keccak256();
    let mut h_iv = [0u8; 32];
    let seed_iv = format!("{}{}", SEED, "_iv");
    keccak.update(seed_iv.as_bytes());
    keccak.finalize(&mut h_iv);

    // let seed_hash: BigInt = BigInt::from_bytes_be(Sign::Plus, &h);
    // let c: BigInt = BigInt::from_bytes_be(Sign::Plus, &h_iv);
    // let iv: BigInt = c % &r;
    let cts = get_constants(&r, SEED, N_ROUNDS);

    Constants {
        // seed_hash: seed_hash,
        // iv: iv,
        r,
        n_rounds: N_ROUNDS,
        cts: cts,
    }
}

pub fn get_constants(r: &BigInt, seed: &str, n_rounds: i64) -> Vec<BigInt> {
    let mut cts: Vec<BigInt> = Vec::new();
    cts.push(Zero::zero());

    let mut keccak = Keccak::new_keccak256();
    let mut h = [0u8; 32];
    keccak.update(seed.as_bytes());
    keccak.finalize(&mut h);

    let mut c = BigInt::from_bytes_be(Sign::Plus, &h);
    for _ in 1..n_rounds {
        let mut keccak = Keccak::new_keccak256();
        let mut h = [0u8; 32];
        let (_, c_bytes) = c.to_bytes_be();
        keccak.update(&c_bytes[..]);
        keccak.finalize(&mut h);
        c = BigInt::from_bytes_be(Sign::Plus, &h);
        let n = modulus(&c, &r);
        cts.push(n);
    }
    cts
}

pub fn mimc7_hash_generic(r: &BigInt, x_in: &BigInt, k: &BigInt, n_rounds: i64) -> BigInt {
    let cts = get_constants(r, SEED, n_rounds);
    let mut h: BigInt = Zero::zero();
    for i in 0..n_rounds as usize {
        let mut t: BigInt;
        if i == 0 {
            t = x_in + k;
        } else {
            t = h + k + &cts[i];
        }
        t = modulus(&t, &r);
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        h = (t4 * t2) * t;
        h = modulus(&h, &r);
    }
    modulus(&(h + k), &r)
}

pub fn hash_generic(iv: BigInt, arr: Vec<BigInt>, r: BigInt, n_rounds: i64) -> BigInt {
    let mut h: BigInt = iv;
    for i in 0..arr.len() {
        h = mimc7_hash_generic(&r, &h, &arr[i], n_rounds);
    }
    h
}

pub fn check_bigint_in_field(a: &BigInt, q: &BigInt) -> bool {
    if a >= q {
        return false;
    }
    true
}

pub fn check_bigint_array_in_field(arr: &Vec<BigInt>, q: &BigInt) -> bool {
    for a in arr {
        if !check_bigint_in_field(a, &q) {
            return false;
        }
    }
    true
}

pub struct Mimc7 {
    constants: Constants,
}

impl Mimc7 {
    pub fn new() -> Mimc7 {
        Mimc7 {
            constants: generate_constants(),
        }
    }

    pub fn hash(&self, arr: Vec<BigInt>) -> Result<BigInt, String> {
        // check if arr elements are inside the Finite Field over R
        if !check_bigint_array_in_field(&arr, &self.constants.r) {
            return Err("elements not inside the finite field over R".to_string());
        }
        let mut h: BigInt = Zero::zero();
        for i in 0..arr.len() {
            h = &h + &arr[i] + self.mimc7_hash(&arr[i], &h);
            h = modulus(&h, &self.constants.r)
        }
        Ok(modulus(&h, &self.constants.r))
    }

    pub fn mimc7_hash(&self, x_in: &BigInt, k: &BigInt) -> BigInt {
        let mut h: BigInt = Zero::zero();
        for i in 0..self.constants.n_rounds as usize {
            let t: BigInt;
            if i == 0 {
                t = x_in + k;
            } else {
                t = h + k + &self.constants.cts[i];
            }
            let t2 = &t * &t;
            let t4 = &t2 * &t2;
            h = (t4 * t2) * t;
            h = modulus(&h, &self.constants.r);
        }
        modulus(&(h + k), &self.constants.r)
    }

    pub fn hash_bytes(&self, b: Vec<u8>) -> Result<BigInt, String> {
        let n = 31;
        let mut ints: Vec<BigInt> = Vec::new();
        for i in 0..b.len() / n {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[n * i..n * (i + 1)]);
            ints.push(v);
        }
        if b.len() % n != 0 {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[(b.len() / n) * n..]);
            ints.push(v);
        }
        self.hash(ints)
    }
}