#![deny(missing_docs)]
use crate::error::NysmError;
use async_trait::async_trait;
use std::collections::VecDeque;

/// Represents a response from a secret provider that wraps around
/// the actual secret value held by a secret.
#[derive(Default)]
pub struct GetSecretValueResult {
  /// Secret string value associated with Secret.
  pub secret: String,
}

/// Represents an individual secret from a provider when querying
/// for an entire list of secrets.
pub struct Secret {
  /// Name of secret
  pub name: Option<String>,
  /// Uniform resource locator of secret
  pub uri: Option<String>,
  /// Description of secret
  pub description: Option<String>,
}

/// Represents a response from a secret provider after updating the
/// contents of a secret.
pub struct UpdateSecretValueResult {
  /// Name of secret
  pub name: Option<String>,
  /// Uniform resource locator of secret
  pub uri: Option<String>,
  /// Version of secret after update operation
  pub version_id: Option<String>,
}

/// Represents a response from a secret provider that wraps around
/// a list of secrets.
#[derive(Default)]
pub struct ListSecretsResult {
  /// Vector of secrets held by [ListSecretsResult]
  pub entries: Vec<Secret>,
}

impl ListSecretsResult {
  /// Creates an iterator from the referenced [ListSecretsResult]
  pub fn iter(&self) -> GetSecretsResultIter {
    self.into_iter()
  }

  /// Returns a tableized string output of [ListSecretsResult]
  pub fn table_display(&self) -> String {
    let mut builder = tabled::builder::Builder::default();
    builder.set_header(["Name", "Description", "URI"]);

    self.iter().for_each(|secret| {
      builder.push_record([
        format!("{:.20}", secret.name.clone().unwrap_or_default()),
        format!("{:.20}", secret.description.clone().unwrap_or_default()),
        secret.uri.clone().unwrap_or_default().to_string(),
      ]);
    });

    let mut table = builder.build();
    table.with(tabled::settings::Style::ascii());

    table.to_string()
  }
}

impl<'a> IntoIterator for &'a ListSecretsResult {
  type Item = &'a Secret;
  type IntoIter = GetSecretsResultIter<'a>;

  fn into_iter(self) -> Self::IntoIter {
    GetSecretsResultIter {
      items: self.entries.iter().collect(),
    }
  }
}

/// Iterator for GetSecretsResult
pub struct GetSecretsResultIter<'a> {
  items: VecDeque<&'a Secret>,
}

impl<'a> Iterator for GetSecretsResultIter<'a> {
  type Item = &'a Secret;

  fn next(&mut self) -> Option<Self::Item> {
    self.items.pop_back()
  }
}

/// This trait is designed to be implemented for each secret provider you'd
/// like to interface with.
///
/// It provides methods to retrieve a list of stored secrets, retrieve a
/// specific secret's value, and to update a specific secret's value.
#[async_trait]
#[cfg(not(tarpaulin_include))]
pub trait QuerySecrets {
  /// Requests a list of secrets from the secret provider.
  ///
  /// # Returns
  /// Returns a result containing either the [ListSecretsResult] struct or an [NysmError].
  async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError>;

  /// Requests a secret value for a specific secret from the secret provider.
  ///
  /// # Arguments
  /// * `secret_id` - String identifier for secret to retrieve value from
  ///
  /// # Returns
  /// Returns a result containing either the [GetSecretValueResult] struct or an [NysmError].
  async fn secret_value(&self, secret_id: String) -> Result<GetSecretValueResult, NysmError>;

  /// Requests an update to a secret value for a specific secret from the secret provider.
  ///
  /// # Arguments
  /// * `secret_id` - String identifier for secret to retrieve value from
  /// * `secret_value` - String contents to use as new secret value
  ///
  /// # Returns
  /// Returns a result containing either the [UpdateSecretValueResult] struct or an [NysmError].
  async fn update_secret_value(
    &self,
    secret_id: String,
    secret_value: String,
  ) -> Result<UpdateSecretValueResult, NysmError>;
}
