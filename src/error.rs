#![deny(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[repr(u8)]
/// Enum to define all of the possible errors that can occur during normal
/// use of Nysm.
pub enum NysmError {
  /// Error occurs when attempting to parse data as Json fails.
  #[error("Unable to parse data as json")]
  SerdeJson(#[from] serde_json::Error),

  /// Error occurs when attempting to parse data as Text fails.
  #[error("Unable to parse data as yaml")]
  SerdeYaml(#[from] serde_yml::Error),

  /// Error occurs when pretty printing the contents of a secret fails.
  #[error("Unable to pretty print data")]
  BatPrint(#[from] bat::error::Error),

  /// Error occurs when reading/writing a temporary file for secret
  /// editing fails.
  #[error("Unable to read/write file caused by: {}", .0)]
  IO(#[from] std::io::Error),

  /// Error occurs when retrieving a list of secrets from a provider fails.
  #[error("Failed to list secrets: {0}")]
  ListSecretsFailed(String),

  /// Error occurs when a specific secret value cannot be retrieved.
  #[error("Failed to retrieve secret value: {0}")]
  GetSecretValueFailed(String),

  /// Error occurs when the secret does not support read operations.
  #[error("Secret does not support read operations")]
  SecretNotReadable,

  /// Error occurs when updating a secret's value fails.
  #[error("Failed to update secret: {0}")]
  UpdateSecretFailed(String),

  /// Error occurs when creating a secret fails.
  #[error("Failed to create secret: {0}")]
  CreateSecretFailed(String),

  /// Error occurs when deleting a secret fails.
  #[error("Failed to delete secret: {0}")]
  DeleteSecretFailed(String),

  /// Error occurs when authentication with a provider fails.
  #[error("Authentication failed: {0}")]
  AuthenticationFailed(String),

  /// Error occurs when provider configuration is invalid.
  #[error("Invalid configuration: {0}")]
  InvalidConfiguration(String),
}

impl PartialEq for NysmError {
  fn eq(&self, other: &Self) -> bool {
    std::mem::discriminant(self) == std::mem::discriminant(other)
  }
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
  use super::*;
  use serde::de::Error;

  #[test]
  fn test_serde_json_error() {
    let error = NysmError::SerdeJson(serde_json::Error::custom("custom error"));
    assert_eq!(error.to_string(), "Unable to parse data as json");
  }

  #[test]
  fn test_serde_yaml_error() {
    let error = NysmError::SerdeYaml(serde_yml::Error::custom("custom error"));
    assert_eq!(error.to_string(), "Unable to parse data as yaml");
  }

  #[test]
  fn test_bat_print_error() {
    let error = NysmError::BatPrint(Into::<bat::error::Error>::into("custom error"));
    assert_eq!(error.to_string(), "Unable to pretty print data");
  }

  #[test]
  fn test_io_error() {
    let error = NysmError::IO(std::io::Error::new(
      std::io::ErrorKind::Other,
      "custom error",
    ));
    assert_eq!(
      error.to_string(),
      "Unable to read/write file caused by: custom error"
    );
  }

  #[test]
  fn test_list_secrets_failed_error() {
    let error = NysmError::ListSecretsFailed("connection timeout".to_string());
    assert_eq!(
      error.to_string(),
      "Failed to list secrets: connection timeout"
    );
  }

  #[test]
  fn test_get_secret_value_failed_error() {
    let error = NysmError::GetSecretValueFailed("secret not found".to_string());
    assert_eq!(
      error.to_string(),
      "Failed to retrieve secret value: secret not found"
    );
  }

  #[test]
  fn test_secret_not_readable_error() {
    let error = NysmError::SecretNotReadable;
    assert_eq!(error.to_string(), "Secret does not support read operations");
  }

  #[test]
  fn test_update_secret_failed_error() {
    let error = NysmError::UpdateSecretFailed("permission denied".to_string());
    assert_eq!(
      error.to_string(),
      "Failed to update secret: permission denied"
    );
  }

  #[test]
  fn test_create_secret_failed_error() {
    let error = NysmError::CreateSecretFailed("secret already exists".to_string());
    assert_eq!(
      error.to_string(),
      "Failed to create secret: secret already exists"
    );
  }

  #[test]
  fn test_delete_secret_failed_error() {
    let error = NysmError::DeleteSecretFailed("secret in use".to_string());
    assert_eq!(error.to_string(), "Failed to delete secret: secret in use");
  }

  #[test]
  fn test_authentication_failed_error() {
    let error = NysmError::AuthenticationFailed("invalid token".to_string());
    assert_eq!(error.to_string(), "Authentication failed: invalid token");
  }

  #[test]
  fn test_invalid_configuration_error() {
    let error = NysmError::InvalidConfiguration("missing repository name".to_string());
    assert_eq!(
      error.to_string(),
      "Invalid configuration: missing repository name"
    );
  }

  #[test]
  fn test_partial_eq() {
    let error1 = NysmError::SerdeJson(serde_json::Error::custom("custom error"));
    let error2 = NysmError::SerdeJson(serde_json::Error::custom("custom error"));
    let error3 = NysmError::SerdeYaml(serde_yml::Error::custom("different error"));

    assert_eq!(error1, error2);
    assert_ne!(error1, error3);
  }
}
