#![deny(missing_docs)]
#[derive(thiserror::Error, Debug)]
/// Enum to define all of the possible errors that can occur during normal
/// use of Nysm.
pub enum NysmError {
  /// Error occurs when attempting to parse data as Json fails.
  #[error("Unable to parse data as json")]
  SerdeJson(#[from] serde_json::Error),

  /// Error occurs when attempting to parse data as Text fails.
  #[error("Unable to parse data as yaml")]
  SerdeYaml(#[from] serde_yaml::Error),

  /// Error occurs when pretty printing the contents of a secret fails.
  #[error("Unable to pretty print data")]
  BatPrint(#[from] bat::error::Error),

  /// Error occurs when reading/writing a temporary file for secret
  /// editing fails.
  #[error("Unable to read/write file caused by: {}", .0)]
  IO(#[from] std::io::Error),

  /// Error occurs when retrieving a list of secrets from a provider fails.
  #[error("Unable to retrieve list of secrets from aws response")]
  AwsListSecretsNoList,

  /// Error occurs when a specific secret has no string value.
  #[error("Unable to retrieve string value from aws response")]
  AwsSecretValueNoValueString,

  /// Error occurs when updating a secret's string value fails
  #[error("Unable to update secret value")]
  AwsSecretValueUpdate,
}

impl PartialEq for NysmError {
  fn eq(&self, other: &Self) -> bool {
    std::mem::discriminant(self) == std::mem::discriminant(other)
  }
}
