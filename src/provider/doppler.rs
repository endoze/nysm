#![deny(missing_docs)]
#![cfg(not(tarpaulin_include))]
use crate::client::{
  CreateSecretResult, DeleteSecretResult, GetSecretValueResult, ListSecretsResult, QuerySecrets,
  Secret, UpdateSecretValueResult,
};
use crate::error::NysmError;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
struct DopplerListSecretsResponse {
  secrets: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DopplerSecretResponse {
  value: DopplerSecretValue,
}

#[derive(Debug, Deserialize)]
struct DopplerSecretValue {
  raw: String,
}

#[derive(Debug, Serialize)]
struct DopplerUpdateSecretRequest {
  secrets: std::collections::HashMap<String, String>,
}

/// Wrapper struct to hold a Doppler API client that implements
/// the [QuerySecrets] trait for Doppler secrets management.
///
/// Doppler is a centralized secrets management platform that provides
/// secure storage and retrieval of secrets across environments.
///
/// # Example
/// ```rust,no_run
/// use nysm::provider::doppler::DopplerClient;
///
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async {
/// let client = DopplerClient::new(
///     "dp.st.xxxxxxxxxxxx".to_string(),
///     "dev".to_string(),
///     "backend".to_string()
/// ).unwrap();
/// # })
/// ```
pub struct DopplerClient {
  client: Client,
  token: String,
  project: String,
  config: String,
}

impl DopplerClient {
  /// Create a new Doppler client with authentication token and project information.
  ///
  /// # Arguments
  /// * `token` - Doppler service token (format: dp.st.xxxx)
  /// * `project` - Doppler project name
  /// * `config` - Doppler config/environment name (e.g., "dev", "staging", "prod")
  ///
  /// # Returns
  /// Returns a Result containing the DopplerClient or an error if configuration is invalid.
  pub fn new(token: String, project: String, config: String) -> Result<Self, NysmError> {
    if token.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "Doppler token cannot be empty".to_string(),
      ));
    }

    if !token.starts_with("dp.") {
      return Err(NysmError::InvalidConfiguration(
        "Invalid Doppler token format. Expected format: dp.xx.xxxx".to_string(),
      ));
    }

    if project.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "Doppler project cannot be empty".to_string(),
      ));
    }

    if config.is_empty() {
      return Err(NysmError::InvalidConfiguration(
        "Doppler config cannot be empty".to_string(),
      ));
    }

    let client = Client::builder()
      .use_rustls_tls()
      .build()
      .map_err(|e| NysmError::InvalidConfiguration(format!("Failed to create HTTP client: {}", e)))?;

    Ok(Self {
      client,
      token,
      project,
      config,
    })
  }

  fn get_base_url(&self) -> String {
    format!("https://api.doppler.com/v3/configs/config")
  }

  fn get_auth_header(&self) -> (&str, String) {
    ("Authorization", format!("Bearer {}", self.token))
  }

  fn get_project_params(&self) -> Vec<(&str, &str)> {
    vec![("project", &self.project), ("config", &self.config)]
  }
}

#[async_trait]
impl QuerySecrets for DopplerClient {
  async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
    let url = format!("{}/secrets", self.get_base_url());
    
    let response = self
      .client
      .get(&url)
      .header(self.get_auth_header().0, self.get_auth_header().1)
      .query(&self.get_project_params())
      .send()
      .await
      .map_err(|e| NysmError::ListSecretsFailed(format!("Doppler API request failed: {}", e)))?;

    match response.status() {
      StatusCode::OK => {
        let data: DopplerListSecretsResponse = response
          .json()
          .await
          .map_err(|e| NysmError::ListSecretsFailed(format!("Failed to parse response: {}", e)))?;

        let entries = data
          .secrets
          .into_iter()
          .map(|(name, _)| Secret {
            name: Some(name.clone()),
            uri: Some(format!("{}/{}?project={}&config={}", 
              self.get_base_url(), 
              name,
              self.project,
              self.config
            )),
            description: None,
          })
          .collect();

        Ok(ListSecretsResult { entries })
      }
      StatusCode::UNAUTHORIZED => Err(NysmError::AuthenticationFailed(
        "Invalid Doppler token".to_string(),
      )),
      status => {
        let error_text = response.text().await.unwrap_or_default();
        Err(NysmError::ListSecretsFailed(format!(
          "Doppler API error ({}): {}",
          status, error_text
        )))
      }
    }
  }

  async fn secret_value(&self, secret_id: String) -> Result<GetSecretValueResult, NysmError> {
    let url = format!("{}/secret", self.get_base_url());
    
    let mut params = self.get_project_params();
    params.push(("name", &secret_id));

    let response = self
      .client
      .get(&url)
      .header(self.get_auth_header().0, self.get_auth_header().1)
      .query(&params)
      .send()
      .await
      .map_err(|e| NysmError::GetSecretValueFailed(format!("Doppler API request failed: {}", e)))?;

    match response.status() {
      StatusCode::OK => {
        let data: DopplerSecretResponse = response
          .json()
          .await
          .map_err(|e| NysmError::GetSecretValueFailed(format!("Failed to parse response: {}", e)))?;

        Ok(GetSecretValueResult {
          secret: data.value.raw,
        })
      }
      StatusCode::UNAUTHORIZED => Err(NysmError::AuthenticationFailed(
        "Invalid Doppler token".to_string(),
      )),
      StatusCode::NOT_FOUND => Err(NysmError::GetSecretValueFailed(format!(
        "Secret '{}' not found in project '{}' config '{}'",
        secret_id, self.project, self.config
      ))),
      status => {
        let error_text = response.text().await.unwrap_or_default();
        Err(NysmError::GetSecretValueFailed(format!(
          "Doppler API error ({}): {}",
          status, error_text
        )))
      }
    }
  }

  async fn update_secret_value(
    &self,
    secret_id: String,
    secret_value: String,
  ) -> Result<UpdateSecretValueResult, NysmError> {
    let url = format!("{}/secrets", self.get_base_url());
    
    let mut secrets = std::collections::HashMap::new();
    secrets.insert(secret_id.clone(), secret_value);

    let request_body = DopplerUpdateSecretRequest { secrets };

    let response = self
      .client
      .post(&url)
      .header(self.get_auth_header().0, self.get_auth_header().1)
      .header("Content-Type", "application/json")
      .query(&self.get_project_params())
      .json(&request_body)
      .send()
      .await
      .map_err(|e| NysmError::UpdateSecretFailed(format!("Doppler API request failed: {}", e)))?;

    match response.status() {
      StatusCode::OK => {
        Ok(UpdateSecretValueResult {
          name: Some(secret_id.clone()),
          uri: Some(format!("{}/{}?project={}&config={}", 
            self.get_base_url(), 
            secret_id,
            self.project,
            self.config
          )),
          version_id: None,
        })
      }
      StatusCode::UNAUTHORIZED => Err(NysmError::AuthenticationFailed(
        "Invalid Doppler token".to_string(),
      )),
      status => {
        let error_text = response.text().await.unwrap_or_default();
        Err(NysmError::UpdateSecretFailed(format!(
          "Doppler API error ({}): {}",
          status, error_text
        )))
      }
    }
  }

  async fn create_secret(
    &self,
    secret_id: String,
    secret_value: String,
    _description: Option<String>,
  ) -> Result<CreateSecretResult, NysmError> {
    let result = self.update_secret_value(secret_id.clone(), secret_value).await?;

    Ok(CreateSecretResult {
      name: result.name,
      uri: result.uri,
      version_id: result.version_id,
    })
  }

  async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError> {
    let url = format!("{}/secret", self.get_base_url());
    
    let response = self
      .client
      .delete(&url)
      .header(self.get_auth_header().0, self.get_auth_header().1)
      .query(&self.get_project_params())
      .json(&json!({ "name": secret_id }))
      .send()
      .await
      .map_err(|e| NysmError::DeleteSecretFailed(format!("Doppler API request failed: {}", e)))?;

    match response.status() {
      StatusCode::OK | StatusCode::NO_CONTENT => {
        Ok(DeleteSecretResult {
          name: Some(secret_id),
          uri: None,
          deletion_date: None,
        })
      }
      StatusCode::UNAUTHORIZED => Err(NysmError::AuthenticationFailed(
        "Invalid Doppler token".to_string(),
      )),
      StatusCode::NOT_FOUND => Err(NysmError::DeleteSecretFailed(format!(
        "Secret '{}' not found in project '{}' config '{}'",
        secret_id, self.project, self.config
      ))),
      status => {
        let error_text = response.text().await.unwrap_or_default();
        Err(NysmError::DeleteSecretFailed(format!(
          "Doppler API error ({}): {}",
          status, error_text
        )))
      }
    }
  }
}