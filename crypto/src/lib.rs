// // Copyright(C) Facebook, Inc. and its affiliates.
use ed25519_dalek::ed25519;
use serde::{Deserialize, Serialize};

use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
// #[cfg(test)]
// #[path = "tests/crypto_tests.rs"]
// pub mod crypto_tests;
//pub mod picnic;

pub type CryptoError = ed25519::Error;
pub type PicnicError = picnic::Error;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest0(pub [u8; 32]);

impl Digest0 {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest0 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest0 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest0 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest0 {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest0(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest0;
}

// Comment from here for enabling PQCrypto
// use ed25519_dalek as dalek;
// use ed25519_dalek::Signer as _;
// use rand::rngs::OsRng;
// use rand::{CryptoRng, RngCore};
// use serde::{de, ser};

// use tokio::sync::mpsc::{channel, Sender};
// use tokio::sync::oneshot;


// // /// Represents a public key (in bytes).
// #[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
// pub struct PublicKey(pub [u8; 32]);

// impl PublicKey {
//     pub fn encode_base64(&self) -> String {
//         base64::encode(&self.0[..])
//     }

//     pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
//         let bytes = base64::decode(s)?;
//         let array = bytes[..32]
//             .try_into()
//             .map_err(|_| base64::DecodeError::InvalidLength)?;
//         Ok(Self(array))
//     }
// }

// impl fmt::Debug for PublicKey {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
//         write!(f, "{}", self.encode_base64())
//     }
// }

// impl fmt::Display for PublicKey {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
//         write!(f, "{}", self.encode_base64().get(0..16).unwrap())
//     }
// }

// impl Serialize for PublicKey {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: ser::Serializer,
//     {
//         serializer.serialize_str(&self.encode_base64())
//     }
// }

// impl<'de> Deserialize<'de> for PublicKey {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: de::Deserializer<'de>,
//     {
//         let s = String::deserialize(deserializer)?;
//         let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
//         Ok(value)
//     }
// }

// impl AsRef<[u8]> for PublicKey {
//     fn as_ref(&self) -> &[u8] {
//         &self.0
//     }
// }

// /// Represents a secret key (in bytes).
// pub struct SecretKey([u8; 64]);

// impl SecretKey {
//     pub fn encode_base64(&self) -> String {
//         base64::encode(&self.0[..])
//     }

//     pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
//         let bytes = base64::decode(s)?;
//         let array = bytes[..64]
//             .try_into()
//             .map_err(|_| base64::DecodeError::InvalidLength)?;
//         Ok(Self(array))
//     }
// }

// impl Serialize for SecretKey {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: ser::Serializer,
//     {
//         serializer.serialize_str(&self.encode_base64())
//     }
// }

// impl<'de> Deserialize<'de> for SecretKey {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: de::Deserializer<'de>,
//     {
//         let s = String::deserialize(deserializer)?;
//         let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
//         Ok(value)
//     }
// }

// impl Drop for SecretKey {
//     fn drop(&mut self) {
//         self.0.iter_mut().for_each(|x| *x = 0);
//     }
// }

// pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
//     generate_keypair(&mut OsRng)
// }

// pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, SecretKey)
// where
//     R: CryptoRng + RngCore,
// {
//     let keypair = dalek::Keypair::generate(csprng);
//     let public = PublicKey(keypair.public.to_bytes());
//     let secret = SecretKey(keypair.to_bytes());
//     (public, secret)
// }

// /// Represents an ed25519 signature.
// #[derive(Serialize, Deserialize, Clone, Default, Debug)]
// pub struct Signature {
//     part1: [u8; 32],
//     part2: [u8; 32],
// }

// impl Signature {
//     pub fn new(digest: &Digest0, secret: &SecretKey) -> Self {
//         let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
//         let sig = keypair.sign(&digest.0).to_bytes();
//         let part1 = sig[..32].try_into().expect("Unexpected signature length");
//         let part2 = sig[32..64].try_into().expect("Unexpected signature length");
//         Signature { part1, part2 }
//     }

//     fn flatten(&self) -> [u8; 64] {
//         [self.part1, self.part2]
//             .concat()
//             .try_into()
//             .expect("Unexpected signature length")
//     }

//     pub fn verify(&self, digest: &Digest0, public_key: &PublicKey) -> Result<(), CryptoError> {
//         let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
//         let key = dalek::PublicKey::from_bytes(&public_key.0)?;
//         key.verify_strict(&digest.0, &signature)
//     }

//     pub fn verify_batch<'a, I>(digest: &Digest0, votes: I) -> Result<(), CryptoError>
//     where
//         I: IntoIterator<Item = &'a (PublicKey, Signature)>,
//     {
//         let mut messages: Vec<&[u8]> = Vec::new();
//         let mut signatures: Vec<dalek::Signature> = Vec::new();
//         let mut keys: Vec<dalek::PublicKey> = Vec::new();
//         for (key, sig) in votes.into_iter() {
//             messages.push(&digest.0[..]);
//             signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
//             keys.push(dalek::PublicKey::from_bytes(&key.0)?);
//         }
//         dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
//     }
// }

// /// This service holds the node's private key. It takes digests as input and returns a signature
// /// over the digest (through a oneshot channel).
// #[derive(Clone)]
// pub struct SignatureService {
//     channel: Sender<(Digest0, oneshot::Sender<Signature>)>,
// }

// impl SignatureService {
//     pub fn new(secret: SecretKey) -> Self {
//         let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
//         tokio::spawn(async move {
//             while let Some((digest, sender)) = rx.recv().await {
//                 let signature = Signature::new(&digest, &secret);
//                 let _ = sender.send(signature);
//             }
//         });
//         Self { channel: tx }
//     }

//     pub async fn request_signature(&mut self, digest: Digest0) -> Signature {
//         let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
//         if let Err(e) = self.channel.send((digest, sender)).await {
//             panic!("Failed to send message Signature Service: {}", e);
//         }
//         receiver
//             .await
//             .expect("Failed to receive signature from Signature Service")
//     }
// }


// PICNIC Code, comment this if not needed


use picnic::DynamicSignature;
use picnic::SigningKey;
use picnic::VerificationKey;
use picnic::Verifier;
use picnic::signature::SignerMut;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{de, ser};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use picnic::Picnic3L3;
use sha2::{Sha256, Digest};
use std::cmp::Ordering;

/// Represents a public key (in bytes).
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey{
    //pub pubkey: Vec<u8>,
    pub pubkey: VerificationKey<Picnic3L3>,
}

impl PublicKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.pubkey.as_ref())
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = VerificationKey::<Picnic3L3>::try_from(bytes.as_slice()) 
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self{pubkey:array})
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(s.as_str()).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.pubkey.as_ref()
    }
}

impl std::hash::Hash for PublicKey{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode_base64().hash(state);
    }
}

impl Hash for PublicKey{
    fn digest(&self) -> Digest0 {
        let hash = Sha256::digest(self.encode_base64().as_bytes());
        Digest0{0:hash.into()}
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.digest()).cmp(&other.digest())
    }
}

impl PartialOrd for PublicKey{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::default::Default for PublicKey{
    fn default() -> Self {
        //let def_str = "AyqyiGUIcpnmqBcjY9s10sTjGlFp5FMF1xpraoxtL7hRofuDFwxCjHutXQDU0k1ENg==";
        let def_str = "CNE1sTCUPTlbOx1NnLpbilFWrs0jSYk0igB2A7B5C5WzQEG5TD8YaxIJCYwVd9ikrA==";
        let dec = base64::decode(def_str).unwrap();
        Self { pubkey: VerificationKey::<Picnic3L3>::try_from(dec.as_slice()).unwrap() }
    }
}

/// Represents a secret key (in bytes).

pub struct SecretKey{
    secret: SigningKey<Picnic3L3>,
}

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.secret.clone().as_ref())
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = SigningKey::<Picnic3L3>::try_from(bytes.as_slice()).expect("Unable to deserialize secret key");
        Ok(SecretKey { secret: array })
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(s.as_str()).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        //self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub struct KeyPair{
    pub pubkey: VerificationKey<Picnic3L3>,
    pub seckey: SigningKey<Picnic3L3>
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_keypair(&mut OsRng)
}

pub fn generate_keypair<R>(_csprng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    //let keypair = dalek::Keypair::generate(csprng);
    //let public = PublicKey(keypair.public.to_bytes());
    //let secret = SecretKey(keypair.to_bytes());
    let (secret, public) = SigningKey::<Picnic3L3>::random().expect("Unable to conduct keygen");
    (PublicKey{pubkey: public},SecretKey{secret:secret})
}

/// Represents an ed25519 signature.
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Signature {
    sig: Vec<u8>
}

impl Signature {
    pub fn new(digest: &Digest0, secret: &mut SecretKey) -> Self {
        //let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
        let sig = secret.secret.sign(&digest.0);
        //let sig_digest = *secret.secret.sign(&digest.0);
        let sig = Vec::from(sig.as_ref().clone());
        //let sig = keypair.sign(&digest.0).to_bytes();
        Signature { sig }
    }

    pub fn verify(&self, digest: &Digest0, public_key: &PublicKey) -> Result<(), PicnicError> {
        //let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
        //let key = dalek::PublicKey::from_bytes(&public_key.0)?;
        //key.verify_strict(&digest.0, &signature)
        let dyn_sig = DynamicSignature::from(self.sig.as_slice());
        public_key.pubkey.verify(&digest.0, &dyn_sig)
    }

    pub fn verify_batch<'a, I>(digest: &Digest0, votes: I) -> Result<(), PicnicError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        for (key, sig) in votes.into_iter() {
            let pk_sig = DynamicSignature::from(sig.sig.as_slice());
            match key.pubkey.verify(&digest.0, &pk_sig) {
                Err(e) =>{
                    println!("Error while verifying signatures {:?}",e);
                    return Err(e);
                },
                _=>{}
            }
        }
        Ok(())
        //dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest0, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(mut secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = Signature::new(&digest, &mut secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest0) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}