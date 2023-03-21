use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use num_bigint_dig::BigInt;
use std::convert::TryInto;

use rand::{thread_rng, Rng};

/// The `VerifiableSecretSharing` structure.
pub struct VerifiableSecretSharingRistretto {
    /// the threshold of shares.
    pub threshold: usize,
    /// the total number of shares.
    pub share_amount: usize,
}

pub fn from_bigint(n: &BigInt) -> Scalar {
    if *n == BigInt::from(0) {
        Scalar::zero()
    } else {
        let (_sign, mut result_bytes) = n.to_bytes_be();
        if result_bytes.len() < 32 {
            // the size of the field is 32
            let mut padding = vec![0u8; 32 - result_bytes.len()];
            padding.extend(result_bytes.iter());
            result_bytes = padding
        }
        let tmp: [u8; 32] = result_bytes[..].try_into().unwrap();
        Scalar::from_bytes_mod_order(tmp)
    }
}

pub fn new_random() -> Scalar {
    let mut rand_bytes = [0u8; 32];
    thread_rng().fill(&mut rand_bytes[..]);

    let tmp: [u8; 32] = rand_bytes[..].try_into().unwrap();
    Scalar::from_bytes_mod_order(tmp)
}

impl VerifiableSecretSharingRistretto {
    /// Split the secret into shares and add commitments (of k size).
    ///
    pub fn split(&self, secret: &Scalar) -> (Vec<(usize, Scalar)>, Vec<RistrettoPoint>) {
        assert!(self.threshold <= self.share_amount);

        let polynomial = self.sample_polynomial(secret);
        let shares = self.evaluate_polynomial(&polynomial);
        let commitments = Self::generate_commitments(&polynomial);
        (shares, commitments)
    }

    /// Recover the secret with threshold+1 shares.
    pub fn recover(&self, shares: &[(usize, Scalar)]) -> Scalar {
        assert!(shares.len() == self.threshold);

        let (xs, ys): (Vec<usize>, Vec<Scalar>) = shares.iter().cloned().unzip();
        self.lagrange_interpolation(Scalar::zero(), &xs, &ys)
    }

    /// Verify that a specific share is valid (honest, or not corrupted).
    pub fn verify(share: (usize, Scalar), commitments: &[RistrettoPoint]) -> bool {
        let generator = RISTRETTO_BASEPOINT_POINT;
        let (share_index, share_value) = share;
        let share_value_commitment = generator * share_value;
        let share_index_scalar = from_bigint(&BigInt::from(share_index));
        let mut commitments_iter_rev = commitments.iter().rev();
        let commitments_head = commitments_iter_rev.next().unwrap();
        let share_index_commitment = commitments_iter_rev.fold(*commitments_head, |sum, item| {
            sum * share_index_scalar + *item
        });
        share_value_commitment == share_index_commitment
    }

    /// Verify that a set of shares are valid.
    pub fn verify_all(shares: &[(usize, Scalar)], commitments: &[RistrettoPoint]) -> bool {
        let generator = RISTRETTO_BASEPOINT_POINT;
        for &share in shares {
            let (share_index, share_value) = share;
            let share_value_commitment = generator * share_value;
            let share_index_scalar = from_bigint(&BigInt::from(share_index));
            let mut commitments_iter_rev = commitments.iter().rev();
            let commitments_head = commitments_iter_rev.next().unwrap();
            let share_index_commitment = commitments_iter_rev
                .fold(*commitments_head, |sum, item| {
                    sum * share_index_scalar + *item
                });
            if share_value_commitment != share_index_commitment {
                return false;
            }
        }

        return true;
    }

    fn generate_commitments(polynomial: &[Scalar]) -> Vec<RistrettoPoint> {
        let generator: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        (0..polynomial.len())
            .map(|i| generator * polynomial[i])
            .collect()
    }

    fn sample_polynomial(&self, secret: &Scalar) -> Vec<Scalar> {
        let mut coefficients = vec![*secret];
        let random_coefficients: Vec<Scalar> =
            (0..(self.threshold - 1)).map(|_| new_random()).collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: &[Scalar]) -> Vec<(usize, Scalar)> {
        (1..=self.share_amount)
            .map(|x| (x, self.mod_evaluate_at(polynomial, x)))
            .collect()
    }

    fn mod_evaluate_at(&self, polynomial: &[Scalar], x: usize) -> Scalar {
        let scalar_x: Scalar = from_bigint(&BigInt::from(x));
        polynomial
            .iter()
            .rev()
            .fold(Scalar::zero(), |sum, item| scalar_x * sum + *item)
    }

    fn lagrange_interpolation(&self, x: Scalar, xs: &[usize], ys: &[Scalar]) -> Scalar {
        let scalar_xs: Vec<Scalar> = xs.iter().map(|x| from_bigint(&BigInt::from(*x))).collect();
        (0..self.threshold).fold(Scalar::zero(), |sum, item| {
            let numerator: Scalar = (0..self.threshold).fold(Scalar::one(), |product, i| {
                if i == item {
                    product
                } else {
                    product * (x - scalar_xs[i])
                }
            });
            let denominator: Scalar = (0..self.threshold).fold(Scalar::one(), |product, i| {
                if i == item {
                    product
                } else {
                    product * (scalar_xs[item] - scalar_xs[i])
                }
            });
            sum + numerator * denominator.invert() * ys[item]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_integration() {
        let secret: Scalar = new_random();
        let vss = VerifiableSecretSharingRistretto {
            threshold: 50,
            share_amount: 256,
        };
        let (shares, commitments) = vss.split(&secret);
        let sub_shares = &shares[0..50];
        let recovered = vss.recover(&sub_shares);
        assert_eq!(secret, recovered);
        for share in shares {
            assert!(VerifiableSecretSharingRistretto::verify(
                share,
                &commitments
            ))
        }
    }
}
