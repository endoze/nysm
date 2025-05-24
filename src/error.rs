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
  #[error("Unable to retrieve list of secrets from aws response")]
  AwsListSecretsNoList,

  /// Error occurs when a specific secret has no string value.
  #[error("Unable to retrieve string value from aws response")]
  AwsSecretValueNoValueString,

  /// Error occurs when updating a secret's string value fails
  #[error("Unable to update secret value")]
  AwsSecretValueUpdate,

  /// Error occurs when creating a secret fails
  #[error("Unable to create secret")]
  AwsSecretValueCreate,
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
  fn test_aws_list_secrets_no_list_error() {
    let error = NysmError::AwsListSecretsNoList;
    assert_eq!(
      error.to_string(),
      "Unable to retrieve list of secrets from aws response"
    );
  }

  #[test]
  fn test_aws_secret_value_no_value_string_error() {
    let error = NysmError::AwsSecretValueNoValueString;
    assert_eq!(
      error.to_string(),
      "Unable to retrieve string value from aws response"
    );
  }

  #[test]
  fn test_aws_secret_value_update_error() {
    let error = NysmError::AwsSecretValueUpdate;
    assert_eq!(error.to_string(), "Unable to update secret value");
  }

  #[test]
  fn test_aws_secret_value_create_error() {
    let error = NysmError::AwsSecretValueCreate;
    assert_eq!(error.to_string(), "Unable to create secret");
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
