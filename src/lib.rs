#![deny(missing_docs)]
//! A lib impl of Verifiable Secret Sharing Scheme

//! A rust implementation of (verifiable) Shamir Secret Sharing over a finite field.
//!
//!
pub use feldman_vss::VerifiableSecretSharing;
pub use feldman_vss_ristretto::VerifiableSecretSharingRistretto;
pub use secp256k1_helper::{Secp256k1Point, Secp256k1Scalar};
pub use simple_sss::ShamirSecretSharing;

mod feldman_vss;
mod feldman_vss_ristretto;
mod secp256k1_helper;
mod simple_sss;
