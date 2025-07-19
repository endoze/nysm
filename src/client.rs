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

/// Represents a response from a secret provider after creating a new secret.
pub struct CreateSecretResult {
  /// Name of secret
  pub name: Option<String>,
  /// Uniform resource locator of secret
  pub uri: Option<String>,
  /// Version of secret after create operation
  pub version_id: Option<String>,
}

/// Represents a response from a secret provider after deleting a secret.
pub struct DeleteSecretResult {
  /// Name of secret
  pub name: Option<String>,
  /// Uniform resource locator of secret
  pub uri: Option<String>,
  /// Date that the secret will be deleted
  pub deletion_date: Option<String>,
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
    builder.push_record(["Name", "Description", "URI"]);

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
  /// Indicates whether this provider supports reading secret values.
  ///
  /// Some providers (like GitHub Actions) only support write operations
  /// for security reasons. This method allows the CLI to adapt its
  /// behavior accordingly.
  ///
  /// # Returns
  /// Returns `true` if the provider supports reading secret values,
  /// `false` if it only supports write operations.
  fn supports_read(&self) -> bool {
    true
  }

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

  /// Creates a new secret with the specified value and optional description.
  ///
  /// # Arguments
  /// * `secret_id` - String identifier for the new secret
  /// * `secret_value` - String contents to use as the secret value
  /// * `description` - Optional description for the secret
  ///
  /// # Returns
  /// Returns a result containing either the [CreateSecretResult] struct or an [NysmError].
  async fn create_secret(
    &self,
    secret_id: String,
    secret_value: String,
    description: Option<String>,
  ) -> Result<CreateSecretResult, NysmError>;

  /// Deletes a secret from the secret provider.
  ///
  /// # Arguments
  /// * `secret_id` - String identifier for the secret to delete
  ///
  /// # Returns
  /// Returns a result containing either the [DeleteSecretResult] struct or an [NysmError].
  async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError>;
}

#[cfg(test)]
mod tests {
  use super::*;
  use async_trait::async_trait;

  struct MockReadableProvider;
  struct MockWriteOnlyProvider;

  #[async_trait]
  impl QuerySecrets for MockReadableProvider {
    async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
      Ok(ListSecretsResult::default())
    }

    async fn secret_value(&self, _secret_id: String) -> Result<GetSecretValueResult, NysmError> {
      Ok(GetSecretValueResult {
        secret: "test-value".to_string(),
      })
    }

    async fn update_secret_value(
      &self,
      _secret_id: String,
      _secret_value: String,
    ) -> Result<UpdateSecretValueResult, NysmError> {
      Ok(UpdateSecretValueResult {
        name: Some("test".to_string()),
        uri: None,
        version_id: None,
      })
    }

    async fn create_secret(
      &self,
      _secret_id: String,
      _secret_value: String,
      _description: Option<String>,
    ) -> Result<CreateSecretResult, NysmError> {
      Ok(CreateSecretResult {
        name: Some("test".to_string()),
        uri: None,
        version_id: None,
      })
    }

    async fn delete_secret(&self, _secret_id: String) -> Result<DeleteSecretResult, NysmError> {
      Ok(DeleteSecretResult {
        name: Some("test".to_string()),
        uri: None,
        deletion_date: None,
      })
    }
  }

  #[async_trait]
  impl QuerySecrets for MockWriteOnlyProvider {
    fn supports_read(&self) -> bool {
      false
    }

    async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
      Ok(ListSecretsResult::default())
    }

    async fn secret_value(&self, _secret_id: String) -> Result<GetSecretValueResult, NysmError> {
      Err(NysmError::SecretNotReadable)
    }

    async fn update_secret_value(
      &self,
      _secret_id: String,
      _secret_value: String,
    ) -> Result<UpdateSecretValueResult, NysmError> {
      Ok(UpdateSecretValueResult {
        name: Some("test".to_string()),
        uri: None,
        version_id: None,
      })
    }

    async fn create_secret(
      &self,
      _secret_id: String,
      _secret_value: String,
      _description: Option<String>,
    ) -> Result<CreateSecretResult, NysmError> {
      Ok(CreateSecretResult {
        name: Some("test".to_string()),
        uri: None,
        version_id: None,
      })
    }

    async fn delete_secret(&self, _secret_id: String) -> Result<DeleteSecretResult, NysmError> {
      Ok(DeleteSecretResult {
        name: Some("test".to_string()),
        uri: None,
        deletion_date: None,
      })
    }
  }

  #[test]
  fn test_default_supports_read_returns_true() {
    let provider = MockReadableProvider;
    assert!(provider.supports_read());
  }

  #[test]
  fn test_write_only_provider_supports_read_returns_false() {
    let provider = MockWriteOnlyProvider;
    assert!(!provider.supports_read());
  }

  #[tokio::test]
  async fn test_write_only_provider_returns_error_on_secret_value() {
    let provider = MockWriteOnlyProvider;
    let result = provider.secret_value("test-secret".to_string()).await;
    assert!(matches!(result, Err(NysmError::SecretNotReadable)));
  }

  #[test]
  fn test_list_secrets_result_table_display() {
    let result = ListSecretsResult {
      entries: vec![
        Secret {
          name: Some("secret1".to_string()),
          description: Some("Description 1".to_string()),
          uri: Some("arn:aws:secretsmanager:us-east-1:123456789012:secret:secret1".to_string()),
        },
        Secret {
          name: Some("very-long-secret-name-that-exceeds-twenty-chars".to_string()),
          description: Some(
            "Very long description that also exceeds twenty characters".to_string(),
          ),
          uri: Some("arn:aws:secretsmanager:us-east-1:123456789012:secret:long".to_string()),
        },
      ],
    };

    let table = result.table_display();
    assert!(table.contains("Name"));
    assert!(table.contains("Description"));
    assert!(table.contains("URI"));
    assert!(table.contains("secret1"));
    assert!(table.contains("Description 1"));
    assert!(table.contains("very-long-secret-nam"));
    assert!(table.contains("Very long descriptio"));
  }

  #[test]
  fn test_list_secrets_result_iter() {
    let result = ListSecretsResult {
      entries: vec![
        Secret {
          name: Some("secret1".to_string()),
          description: None,
          uri: None,
        },
        Secret {
          name: Some("secret2".to_string()),
          description: None,
          uri: None,
        },
      ],
    };

    let names: Vec<String> = result.iter().filter_map(|s| s.name.clone()).collect();

    assert_eq!(names.len(), 2);
    assert!(names.contains(&"secret1".to_string()));
    assert!(names.contains(&"secret2".to_string()));
  }
}
