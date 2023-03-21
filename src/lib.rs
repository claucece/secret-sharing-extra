#![deny(missing_docs)]
//! A lib impl of Verifiable Secret Sharing Scheme

//! A rust implementation of (verifiable) Shamir Secret Sharing over a finite field.
//!
//!
pub use feldman_vss::VerifiableSecretSharingRistretto;
pub use feldman_vss_secp256k1::VerifiableSecretSharing;
pub use secp256k1_helper::{Secp256k1Point, Secp256k1Scalar};

mod feldman_vss;
mod feldman_vss_secp256k1;
mod secp256k1_helper;
