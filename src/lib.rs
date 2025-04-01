#[allow(dead_code)]
// https://www.ietf.org/id/draft-sfluhrer-cfrg-ml-kem-security-considerations-02.html
//
// A KEM (such as ML-KEM) sounds like it may be a drop-in replacement for Diffie-Hellman (and in some
// scenarios, it can be). However this is not always the case. In Diffie-Hellman, the parties exchange
// two public keys, whereas in a KEM, the ciphertext is necessarily a function of Alice's public key,
// and thus can only be useful only with that specific public key. Additionally, a KEM differs from
// Diffie-Hellman which is asynchronous and non-interactive. In particular, for an 'ephemeral-ephemeral'
// key establishment, an encapsulator cannot pre-emptively initiate a key establishment, but requires
// an encapulation key. Nor can participants compute parts of the key establishment in parallel as is
// the case with Diffie-Hellman. As long as the application can handle larger public keys and ciphertexts,
// a KEM is a drop-in replacement for 'ephemeral-ephemeral' key exchange in protocols like TLS [RFC8446]
// and SSH [RFC4253] as well as 'static-ephemeral' key exchange in protocols like ECIES/HPKE [RFC9180],
// that is, in cases where Alice has a long term public key, and Bob can use that long term public key
// to establish communication. A KEM is not a drop-in replacement in applications such as the Diffie-Hellman
// ratchet in Signal [SIGNAL], implicit 'ephemeral-static' DH authentication in Noise [NOISE], Wireguard
// [WIRE], and EDHOC [RFC9528], and 'static-static' configurations in CMS [RFC6278] and Group OSCORE
// [I-D.ietf-core-oscore-groupcomm], where both sides have long-term public keys.
//
// https://csrc.nist.gov/events/2025/workshop-on-guidance-for-kems
// https://csrc.nist.gov/csrc/media/Presentations/2025/ml-kem-is-great/images-media/ml-kem-is-great.pdf
// --> NIST should mandate that ephemeral encapsulation keys are used in exactly one key-establishment transaction.

// Authentication and Key Agreement (AKA)
use aes::cipher::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit, KeySizeUser,
};
use anyhow::Result;
use oqs::{kem::Ciphertext, *};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    convert::TryInto,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct Certificate {
    u: oqs::sig::PublicKey,
    v: oqs::kem::PublicKey,
}

pub struct OwnedCertificate {
    cert: Certificate,
    u_sk: oqs::sig::SecretKey,
    v_sk: oqs::kem::SecretKey,
}

impl OwnedCertificate {
    pub fn new() -> Result<Self> {
        let fn_dsa = sig::Sig::new(sig::Algorithm::Falcon512)?;
        let ml_kem = kem::Kem::new(kem::Algorithm::Kyber512)?;
        let (u, u_sk) = fn_dsa.keypair()?;
        let (v, v_sk) = ml_kem.keypair()?;
        Ok(Self {
            cert: Certificate { u, v },
            u_sk,
            v_sk,
        })
    }
    pub fn sign<S: Serialize>(&self, msg: S) -> Result<oqs::sig::Signature> {
        let fn_dsa = sig::Sig::new(sig::Algorithm::Falcon512)?;
        let encoded = bincode::serialize(&msg)?;
        let s_1 = fn_dsa.sign(&encoded, &self.u_sk)?;
        Ok(s_1)
    }
    pub fn decrypt<D: DeserializeOwned>(&self, ct: &Ciphertext, msg: &[u8]) -> Result<D> {
        let ml_kem = kem::Kem::new(kem::Algorithm::Kyber512)?;
        let shared_key = ml_kem.decapsulate(&self.v_sk, ct)?;
        let cipher = Aes128Gcm::new_from_slice(&shared_key.into_vec()[0..Aes128Gcm::key_size()])?;

        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let ciphertext = cipher.decrypt(nonce, msg).unwrap();
        Ok(bincode::deserialize(&ciphertext)?)
    }
}

impl Certificate {
    pub fn verify<S: Serialize>(&self, msg: S, signature: &oqs::sig::Signature) -> Result<()> {
        let fn_dsa = sig::Sig::new(sig::Algorithm::Falcon512)?;
        let serialized = bincode::serialize(&msg)?;
        fn_dsa.verify(&serialized, signature, &self.u)?;
        Ok(())
    }
    pub fn encrypt<S: Serialize>(&self, msg: S) -> Result<(Ciphertext, Vec<u8>)> {
        let ml_kem = kem::Kem::new(kem::Algorithm::Kyber512)?;
        let encoded = bincode::serialize(&msg)?;

        let (recipient_ciphertext, shared_key) = ml_kem.encapsulate(&self.v)?;

        let cipher = Aes128Gcm::new_from_slice(&shared_key.into_vec()[0..Aes128Gcm::key_size()])?;

        let payload = Payload {
            msg: &encoded,
            aad: &[],
        };

        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();

        Ok((recipient_ciphertext, ciphertext))
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeRequestData {
    timestamp: u64,
    cert: Certificate,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeRequest {
    data: KeyExchangeRequestData,
    sig: oqs::sig::Signature,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeResponseData {
    timestamp: u64,
    hash: [u8; 32],
    cert: Certificate,
    ciphertext: (Ciphertext, Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeResponse {
    data: KeyExchangeResponseData,
    sig: oqs::sig::Signature,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeAckData {
    timestamp: u64,
    hash: [u8; 32],
    ciphertext: (Ciphertext, Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeAck {
    data: KeyExchangeAckData,
    sig: oqs::sig::Signature,
}

impl KeyExchangeAck {
    pub fn new(
        oc: &OwnedCertificate,
        resp: &KeyExchangeResponse,
        ciphertext: (Ciphertext, Vec<u8>),
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let data = KeyExchangeAckData {
            timestamp,
            hash: resp.hash(),
            ciphertext,
        };
        let sig = oc.sign(&data)?;

        Ok(KeyExchangeAck { data, sig })
    }
}

impl KeyExchangeRequest {
    pub fn new(oc: &OwnedCertificate) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let data = KeyExchangeRequestData {
            timestamp,
            cert: oc.cert.clone(),
        };
        let sig = oc.sign(&data)?;

        Ok(KeyExchangeRequest { data, sig })
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = Sha256::default();
        let encoded = bincode::serialize(&self.data).unwrap();
        hash.update(&encoded);
        let digest = hash.finalize().to_vec();
        let digest: [u8; 32] = digest.try_into().unwrap();
        digest
    }
}

impl KeyExchangeResponse {
    pub fn new(
        oc: &OwnedCertificate,
        req: &KeyExchangeRequest,
        ciphertext: (Ciphertext, Vec<u8>),
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let data = KeyExchangeResponseData {
            hash: req.hash(),
            ciphertext,
            timestamp,
            cert: oc.cert.clone(),
        };
        let sig = oc.sign(&data)?;

        Ok(KeyExchangeResponse { data, sig })
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = Sha256::default();
        let encoded = bincode::serialize(&self.data).unwrap();
        hash.update(&encoded);
        let digest = hash.finalize().to_vec();
        let digest: [u8; 32] = digest.try_into().unwrap();
        digest
    }
}

#[test]
// https://csrc.nist.gov/csrc/media/Events/test2025/workshop-on-guidance-for-kems/documents/papers/pqc-based-bidirectional.pdf
#[allow(non_snake_case)]
fn test_workshop() -> Result<()> {
    // common setup
    let alice = OwnedCertificate::new()?;
    let bob = OwnedCertificate::new()?;

    // 1. Alice -> R1
    // ---------------------------------
    // Generate the key-exchange request R1 with {timestamp t1 , Alice’s hybrid
    // certificate QA, signature s1}, ensuring that the signature s1
    // is created using the Alice’s PQC-based DSA private key uA.
    let R1 = KeyExchangeRequest::new(&alice)?;

    // 2. R1 -> Bob -> R2
    // ---------------------------------
    // Use the Alice’s PQC-based DSA public key UA to verify the signature s1
    R1.data.cert.verify(&R1.data, &R1.sig)?;
    // Generate a random number rB , and encrypt rB using the Alice's
    // PQC-based KEM public key VA to produce the ciphertext cB
    let bob_rb: u64 = 28328281;
    let cB = R1.data.cert.encrypt(bob_rb)?;
    // Calculate the hash value of the key-exchange request R1 as h1.
    // Generate the key-exchange response R2 with {timestamp t2 , hash value h1 ,
    // Bob’s hybrid certificate QB , ciphertext cB , signature s2},
    // ensuring that the signature s2 is created using the Bob’s PQC-based
    // DSA private key uB
    let R2 = KeyExchangeResponse::new(&bob, &R1, cB)?;

    // 3. R2-> Alice -> R3
    // ---------------------------------
    // Use the Bob’s PQC-based DSA public key UB to verify the signature s2.
    R2.data.cert.verify(&R2.data, &R2.sig)?;
    // Decrypt cB using the Alice's PQC-based KEM private key vA to produce the plaintext rB.
    let alice_rb: u64 = alice.decrypt(&R2.data.ciphertext.0, &R2.data.ciphertext.1)?;
    let alice_ra: u64 = 8827111;
    // Generate a random number rA, and encrypt rA using the Bob's
    // PQC-based KEM public key VB to produce the ciphertext cA.
    let cA = R2.data.cert.encrypt(alice_ra)?;
    // Calculate the hash value of the key-exchange response R2 as h2.
    // Generate the key-exchange ack R3 with {timestamp t3, request
    // hash h2, ciphertext cA, signature s3}, ensuring that the signature s3
    // is created using the Alice’s PQC-based DSA private key uA.
    let R3 = KeyExchangeAck::new(&alice, &R2, cA)?;
    let alice_shared_key = alice_ra + alice_rb;

    // 4. R3 -> bob
    R1.data.cert.verify(&R3.data, &R3.sig)?;
    let bob_ra: u64 = bob.decrypt(&R3.data.ciphertext.0, &R3.data.ciphertext.1)?;
    let bob_shared_key = bob_ra + bob_rb;

    assert_eq!(alice_shared_key, bob_shared_key);

    println!("KeyExchangeRequest.len={}", bincode::serialize(&R1)?.len());
    println!("KeyExchangeResponse.len={}", bincode::serialize(&R2)?.len());
    println!("KeyExchangeAck.len={}", bincode::serialize(&R3)?.len());

    Ok(())
}
