# Verifiable-Secret-Sharing

This library provides a implementation of a verifiable secret sharing algorithm:
Shamir Secret Sharing with [Feldman's scheme](https://ieeexplore.ieee.org/document/4568297) for verification.

It is based on the code of [verifiable-secret-sharing](https://github.com/bitrocks/verifiable-secret-sharing),
but adapted to work with Curve25519/Ristretto.

Note that Feldman's scheme reveals information about the secret to dealer with
unlimited computing power.
