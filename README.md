# Nysm (Now You See Me)

![Build Status](https://github.com/endoze/nysm/actions/workflows/ci.yml/badge.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/endoze/nysm/badge.svg?branch=master)](https://coveralls.io/github/endoze/nysm?branch=master)
[![Crate](https://img.shields.io/crates/v/nysm.svg)](https://crates.io/crates/nysm)
[![Docs](https://docs.rs/nysm/badge.svg)](https://docs.rs/nysm)

#### Manage your Secrets Manager secrets via the command line

Nysm is a command line utility designed to make interacting with a Secrets
Provider like AWS Secrets Manager simple and easy. You can get a list of your
existing secrets, show the value of a specific secret, or update the value of a
specific secret.

# Installation

```sh
cargo install nysm
```

# Usage

List secrets:

```sh
nysm list
```

Show a specific secret:

```sh
nysm show some-secret-id
```

Edit an existing secret:

```sh
nysm edit some-secret-id
```
