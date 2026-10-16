#![deny(missing_docs)]
#![cfg(not(tarpaulin_include))]
use crate::client::{
  CreateSecretResult, DeleteSecretResult, GetSecretValueResult, ListSecretsResult, QuerySecrets,
  Secret, UpdateSecretValueResult,
};
use crate::error::NysmError;

use async_trait::async_trait;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model;

const DESCRIPTION_ANNOTATION: &str = "description";
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

impl From<model::Secret> for Secret {
  fn from(value: model::Secret) -> Self {
    Self {
      name: value.name.rsplit('/').next().map(String::from),
      description: value.annotations.get(DESCRIPTION_ANNOTATION).cloned(),
      uri: Some(value.name),
    }
  }
}

impl From<model::SecretVersion> for UpdateSecretValueResult {
  fn from(value: model::SecretVersion) -> Self {
    let (secret, version) = split_version_name(&value.name);

    Self {
      name: secret.rsplit('/').next().map(String::from),
      uri: Some(secret.to_string()),
      version_id: version.map(String::from),
    }
  }
}

impl From<model::SecretVersion> for CreateSecretResult {
  fn from(value: model::SecretVersion) -> Self {
    let result = UpdateSecretValueResult::from(value);

    Self {
      name: result.name,
      uri: result.uri,
      version_id: result.version_id,
    }
  }
}

impl TryFrom<model::AccessSecretVersionResponse> for GetSecretValueResult {
  type Error = NysmError;

  fn try_from(value: model::AccessSecretVersionResponse) -> Result<Self, Self::Error> {
    let data = value
      .payload
      .map(|payload| payload.data)
      .unwrap_or_default();

    let secret = String::from_utf8(data.to_vec()).map_err(|_| {
      NysmError::GetSecretValueFailed(format!("Secret '{}' is not valid UTF-8", value.name))
    })?;

    Ok(Self { secret })
  }
}

/// Splits `projects/p/secrets/s/versions/v` into `("projects/p/secrets/s", Some("v"))`.
fn split_version_name(name: &str) -> (&str, Option<&str>) {
  match name.rsplit_once("/versions/") {
    Some((secret, version)) => (secret, Some(version)),
    None => (name, None),
  }
}

/// Rejects values over Secret Manager's 64 KiB payload limit before any
/// secret is created.
fn validate_payload(secret_value: &str) -> Result<(), NysmError> {
  if secret_value.len() > MAX_PAYLOAD_BYTES {
    return Err(NysmError::CreateSecretFailed(format!(
      "Google Secret Manager: value is {} bytes, the limit is {} bytes",
      secret_value.len(),
      MAX_PAYLOAD_BYTES
    )));
  }

  Ok(())
}

/// Wrapper struct to hold a Google Cloud Secret Manager client that
/// implements the [QuerySecrets] trait.
///
/// Authenticates with Application Default Credentials (`gcloud auth
/// application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or the
/// metadata server). Descriptions are stored in the secret's `description`
/// annotation.
///
/// # Example
/// ```rust,no_run
/// use nysm::provider::gcp::GcpClient;
///
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async {
/// let client = GcpClient::new("my-project".to_string()).await.unwrap();
/// # })
/// ```
pub struct GcpClient {
  client: SecretManagerService,
  project: String,
}

impl GcpClient {
  /// Create a new client for the given Google Cloud project ID.
  ///
  /// # Errors
  /// Returns [NysmError::InvalidConfiguration] if the project is empty or
  /// the client cannot be built, for example when no credentials are found.
  pub async fn new(project: String) -> Result<Self, NysmError> {
    if project.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "Google Cloud project cannot be empty".to_string(),
      ));
    }

    let client = SecretManagerService::builder().build().await.map_err(|e| {
      NysmError::InvalidConfiguration(format!("Failed to create Google Cloud client: {}", e))
    })?;

    Ok(Self { client, project })
  }

  fn project_name(&self) -> String {
    format!("projects/{}", self.project)
  }

  fn secret_name(&self, secret_id: &str) -> String {
    format!("projects/{}/secrets/{}", self.project, secret_id)
  }

  async fn add_version(
    &self,
    secret_id: &str,
    secret_value: String,
  ) -> google_cloud_secretmanager_v1::Result<model::SecretVersion> {
    self
      .client
      .add_secret_version()
      .set_parent(self.secret_name(secret_id))
      .set_payload(model::SecretPayload::new().set_data(secret_value))
      .send()
      .await
  }
}

#[async_trait]
impl QuerySecrets for GcpClient {
  async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
    let mut entries = vec![];
    let mut page_token = String::new();

    loop {
      let response = self
        .client
        .list_secrets()
        .set_parent(self.project_name())
        .set_page_token(page_token)
        .send()
        .await
        .map_err(|e| NysmError::ListSecretsFailed(format!("Google Secret Manager: {}", e)))?;

      entries.extend(response.secrets.into_iter().map(Secret::from));

      if response.next_page_token.is_empty() {
        break;
      }

      page_token = response.next_page_token;
    }

    Ok(ListSecretsResult { entries })
  }

  async fn secret_value(&self, secret_id: String) -> Result<GetSecretValueResult, NysmError> {
    self
      .client
      .access_secret_version()
      .set_name(format!("{}/versions/latest", self.secret_name(&secret_id)))
      .send()
      .await
      .map_err(|e| NysmError::GetSecretValueFailed(format!("Google Secret Manager: {}", e)))?
      .try_into()
  }

  async fn update_secret_value(
    &self,
    secret_id: String,
    secret_value: String,
  ) -> Result<UpdateSecretValueResult, NysmError> {
    self
      .add_version(&secret_id, secret_value)
      .await
      .map(Into::into)
      .map_err(|e| NysmError::UpdateSecretFailed(format!("Google Secret Manager: {}", e)))
  }

  async fn create_secret(
    &self,
    secret_id: String,
    secret_value: String,
    description: Option<String>,
  ) -> Result<CreateSecretResult, NysmError> {
    validate_payload(&secret_value)?;

    let secret = model::Secret::new()
      .set_replication(
        model::Replication::new().set_automatic(model::replication::Automatic::new()),
      )
      .set_annotations(description.map(|d| (DESCRIPTION_ANNOTATION, d)));

    self
      .client
      .create_secret()
      .set_parent(self.project_name())
      .set_secret_id(&secret_id)
      .set_secret(secret)
      .send()
      .await
      .map_err(|e| NysmError::CreateSecretFailed(format!("Google Secret Manager: {}", e)))?;

    let version_error = match self.add_version(&secret_id, secret_value).await {
      Ok(version) => return Ok(version.into()),
      Err(e) => e,
    };

    let name = self.secret_name(&secret_id);
    // A secret with no versions blocks a retry (ALREADY_EXISTS) and cannot be
    // read by `edit`, so roll it back instead of leaving it behind.
    let rollback = self.client.delete_secret().set_name(&name).send().await;

    Err(NysmError::CreateSecretFailed(match rollback {
      Ok(()) => format!(
        "Google Secret Manager: failed to add a value to '{}', so it was removed: {}",
        name, version_error
      ),
      Err(delete_error) => format!(
        "Google Secret Manager: '{}' was created without a value ({}) and could not be \
         removed ({}). Run `nysm delete {}` before retrying",
        name, version_error, delete_error, secret_id
      ),
    }))
  }

  async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError> {
    let name = self.secret_name(&secret_id);

    self
      .client
      .delete_secret()
      .set_name(&name)
      .send()
      .await
      .map_err(|e| NysmError::DeleteSecretFailed(format!("Google Secret Manager: {}", e)))?;

    Ok(DeleteSecretResult {
      name: Some(secret_id),
      uri: Some(name),
      deletion_date: None,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn secret_uses_last_segment_as_name_and_description_annotation() {
    let secret: Secret = model::Secret::new()
      .set_name("projects/p/secrets/db-password")
      .set_annotations([(DESCRIPTION_ANNOTATION, "Database password")])
      .into();

    assert_eq!(secret.name.as_deref(), Some("db-password"));
    assert_eq!(
      secret.uri.as_deref(),
      Some("projects/p/secrets/db-password")
    );
    assert_eq!(secret.description.as_deref(), Some("Database password"));
  }

  #[test]
  fn secret_without_description_annotation() {
    let secret: Secret = model::Secret::new()
      .set_name("projects/p/secrets/db-password")
      .into();

    assert_eq!(secret.description, None);
  }

  #[test]
  fn secret_version_splits_secret_and_version() {
    let result: UpdateSecretValueResult = model::SecretVersion::new()
      .set_name("projects/p/secrets/db-password/versions/3")
      .into();

    assert_eq!(result.name.as_deref(), Some("db-password"));
    assert_eq!(
      result.uri.as_deref(),
      Some("projects/p/secrets/db-password")
    );
    assert_eq!(result.version_id.as_deref(), Some("3"));
  }

  #[test]
  fn access_response_decodes_utf8_payload() -> Result<(), NysmError> {
    let result: GetSecretValueResult = model::AccessSecretVersionResponse::new()
      .set_payload(model::SecretPayload::new().set_data(r#"{"key":"value"}"#))
      .try_into()?;

    assert_eq!(result.secret, r#"{"key":"value"}"#);

    Ok(())
  }

  #[test]
  fn access_response_without_payload_is_empty() -> Result<(), NysmError> {
    let result: GetSecretValueResult = model::AccessSecretVersionResponse::new().try_into()?;

    assert_eq!(result.secret, "");

    Ok(())
  }

  #[test]
  fn access_response_rejects_non_utf8_payload() {
    let result: Result<GetSecretValueResult, _> = model::AccessSecretVersionResponse::new()
      .set_name("projects/p/secrets/binary/versions/1")
      .set_payload(model::SecretPayload::new().set_data(vec![0xff, 0xfe]))
      .try_into();

    assert!(matches!(result, Err(NysmError::GetSecretValueFailed(_))));
  }

  #[test]
  fn payload_at_limit_is_accepted() {
    assert!(validate_payload(&"a".repeat(MAX_PAYLOAD_BYTES)).is_ok());
  }

  #[test]
  fn payload_over_limit_is_rejected() {
    let result = validate_payload(&"a".repeat(MAX_PAYLOAD_BYTES + 1));

    assert!(matches!(result, Err(NysmError::CreateSecretFailed(_))));
  }
}
