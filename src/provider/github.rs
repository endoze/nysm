#![deny(missing_docs)]
#![cfg(not(tarpaulin_include))]
use crate::client::{
  CreateSecretResult, DeleteSecretResult, GetSecretValueResult, ListSecretsResult, QuerySecrets,
  UpdateSecretValueResult,
};
use crate::error::NysmError;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use octocrab::Octocrab;
use octocrab::models::PublicKey;
use octocrab::models::repos::secrets::{CreateRepositorySecret, RepositorySecret};

/// Wrapper struct to hold a GitHub API client that implements
/// the [QuerySecrets] trait for GitHub Actions secrets.
///
/// GitHub Actions secrets are write-only - you cannot retrieve
/// their values through the API. This provider supports listing,
/// creating, updating, and deleting secrets, but not reading values.
///
/// # Example
/// ```rust,no_run
/// use nysm::provider::github::GitHubClient;
///
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async {
/// let client = GitHubClient::new(
///     "ghp_xxxxxxxxxxxx".to_string(),
///     "owner".to_string(),
///     "repo".to_string()
/// ).unwrap();
/// # })
/// ```
pub struct GitHubClient {
  client: Octocrab,
  owner: String,
  repo: String,
}

impl GitHubClient {
  /// Create a new GitHub client with authentication token and repository information.
  ///
  /// # Arguments
  /// * `token` - GitHub personal access token or GITHUB_TOKEN
  /// * `owner` - Repository owner (user or organization)
  /// * `repo` - Repository name
  ///
  /// # Returns
  /// Returns a Result containing the GitHubClient or an error if configuration is invalid.
  pub fn new(token: String, owner: String, repo: String) -> Result<Self, NysmError> {
    if token.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "GitHub token cannot be empty".to_string(),
      ));
    }

    if owner.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "GitHub owner cannot be empty".to_string(),
      ));
    }

    if repo.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "GitHub repository name cannot be empty".to_string(),
      ));
    }

    let client = Octocrab::builder()
      .personal_token(token)
      .build()
      .map_err(|e| {
        NysmError::InvalidConfiguration(format!("Failed to create GitHub client: {}", e))
      })?;

    Ok(Self {
      client,
      owner,
      repo,
    })
  }

  /// Get the repository's public key for encrypting secrets.
  async fn get_repo_public_key(&self) -> Result<PublicKey, NysmError> {
    self
      .client
      .repos(&self.owner, &self.repo)
      .secrets()
      .get_public_key()
      .await
      .map_err(|e| {
        NysmError::AuthenticationFailed(format!("Failed to get repository public key: {}", e))
      })
  }

  /// Encrypt a secret value using the repository's public key.
  fn encrypt_secret(
    &self,
    public_key: &PublicKey,
    secret_value: &str,
  ) -> Result<String, NysmError> {
    sodiumoxide::init().map_err(|_| {
      NysmError::InvalidConfiguration("Failed to initialize sodium crypto library".to_string())
    })?;

    let key_bytes = STANDARD
      .decode(&public_key.key)
      .map_err(|e| NysmError::InvalidConfiguration(format!("Invalid public key format: {}", e)))?;

    let public_key = sodiumoxide::crypto::box_::PublicKey::from_slice(&key_bytes)
      .ok_or_else(|| NysmError::InvalidConfiguration("Invalid public key".to_string()))?;

    let encrypted = sodiumoxide::crypto::sealedbox::seal(secret_value.as_bytes(), &public_key);

    Ok(STANDARD.encode(encrypted))
  }
}

#[async_trait]
impl QuerySecrets for GitHubClient {
  fn supports_read(&self) -> bool {
    false
  }

  async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
    let secrets = self
      .client
      .repos(&self.owner, &self.repo)
      .secrets()
      .get_secrets()
      .await
      .map_err(|e| match e {
        octocrab::Error::GitHub { source, .. } => {
          NysmError::ListSecretsFailed(format!("GitHub API error: {}", source.message))
        }
        _ => NysmError::ListSecretsFailed(format!("GitHub API error: {}", e)),
      })?;

    let entries = secrets
      .secrets
      .into_iter()
      .map(|secret: RepositorySecret| crate::client::Secret {
        name: Some(secret.name.clone()),
        uri: Some(format!(
          "/repos/{}/{}/actions/secrets/{}",
          self.owner, self.repo, secret.name
        )),
        description: None,
      })
      .collect();

    Ok(ListSecretsResult { entries })
  }

  async fn secret_value(&self, _secret_id: String) -> Result<GetSecretValueResult, NysmError> {
    Err(NysmError::SecretNotReadable)
  }

  async fn update_secret_value(
    &self,
    secret_id: String,
    secret_value: String,
  ) -> Result<UpdateSecretValueResult, NysmError> {
    let public_key = self.get_repo_public_key().await?;
    let encrypted_value = self.encrypt_secret(&public_key, &secret_value)?;

    self
      .client
      .repos(&self.owner, &self.repo)
      .secrets()
      .create_or_update_secret(
        &secret_id,
        &CreateRepositorySecret {
          encrypted_value: &encrypted_value,
          key_id: &public_key.key_id,
        },
      )
      .await
      .map_err(|e| NysmError::UpdateSecretFailed(format!("GitHub API error: {}", e)))?;

    Ok(UpdateSecretValueResult {
      name: Some(secret_id.clone()),
      uri: Some(format!(
        "/repos/{}/{}/actions/secrets/{}",
        self.owner, self.repo, secret_id
      )),
      version_id: None,
    })
  }

  async fn create_secret(
    &self,
    secret_id: String,
    secret_value: String,
    _description: Option<String>,
  ) -> Result<CreateSecretResult, NysmError> {
    let public_key = self.get_repo_public_key().await?;
    let encrypted_value = self.encrypt_secret(&public_key, &secret_value)?;

    self
      .client
      .repos(&self.owner, &self.repo)
      .secrets()
      .create_or_update_secret(
        &secret_id,
        &CreateRepositorySecret {
          encrypted_value: &encrypted_value,
          key_id: &public_key.key_id,
        },
      )
      .await
      .map_err(|e| NysmError::CreateSecretFailed(format!("GitHub API error: {}", e)))?;

    Ok(CreateSecretResult {
      name: Some(secret_id.clone()),
      uri: Some(format!(
        "/repos/{}/{}/actions/secrets/{}",
        self.owner, self.repo, secret_id
      )),
      version_id: None,
    })
  }

  async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError> {
    self
      .client
      .repos(&self.owner, &self.repo)
      .secrets()
      .delete_secret(&secret_id)
      .await
      .map_err(|e| NysmError::DeleteSecretFailed(format!("GitHub API error: {}", e)))?;

    Ok(DeleteSecretResult {
      name: Some(secret_id),
      uri: None,
      deletion_date: None,
    })
  }
}
