//!
#![doc = include_str!("../README.md")]

/// Defines the command line interface of nysm.
pub mod cli;
/// Defines a set of structs and a trait that can be used to abstract
/// away individual secret provider details and allow for uniform access across
/// providers.
pub mod client;
/// Defines all of the errors that can occur during normal operations.
pub mod error;
/// Defines provider implementations.
pub mod provider;
