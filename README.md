# Verifiable-Secret-Sharing

This library provides a implementation of a verifiable secret sharing algorithm:
Shamir Secret Sharing with [Feldman's scheme](https://ieeexplore.ieee.org/document/4568297) for verification.

It is based on the code of [verifiable-secret-sharing](https://github.com/bitrocks/verifiable-secret-sharing),
but adapted to work with Curve25519/Ristretto.

Note that Feldman's scheme reveals information about the secret to dealer with
unlimited computing power.

*Warning*: This code is a research prototype. Do not use it in production.

## Requirements

In order to [natively](#native) build, run, test and benchmark the library, you will need the following:

```
  Rust >= 1.61.0
  Cargo
```

## Quickstart

### Local

#### Building

To install the latest version of Rust, use the following command (you can also check how to install on the [Rust documentation](https://www.rust-lang.org/tools/install)):

```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

To build the library, run:

```
  cargo build
```

#### Testing

To run the tests:

```
  cargo test
```

#### Benchmarking

To run a specific set of benchmarks, run (note the this process can slow.):

```
  cargo bench
```
