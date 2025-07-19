#![deny(missing_docs)]
#![cfg(not(tarpaulin_include))]
use crate::client::{
  CreateSecretResult, DeleteSecretResult, GetSecretValueResult, ListSecretsResult, QuerySecrets,
  Secret, UpdateSecretValueResult,
};
use crate::error::NysmError;

use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_secretsmanager::operation::{
  create_secret::CreateSecretOutput, delete_secret::DeleteSecretOutput,
  get_secret_value::GetSecretValueOutput, list_secrets::ListSecretsOutput,
  update_secret::UpdateSecretOutput,
};
use aws_types::region::Region;

impl From<ListSecretsOutput> for ListSecretsResult {
  fn from(value: ListSecretsOutput) -> Self {
    let list = value.secret_list();

    let entries = list
      .iter()
      .map(|entry| Secret {
        name: entry.name.clone(),
        uri: entry.arn.clone(),
        description: entry.description.clone(),
      })
      .collect();

    ListSecretsResult { entries }
  }
}

impl From<GetSecretValueOutput> for GetSecretValueResult {
  fn from(value: GetSecretValueOutput) -> Self {
    let Some(secret) = value.secret_string() else {
      return GetSecretValueResult::default();
    };

    GetSecretValueResult {
      secret: secret.to_owned(),
    }
  }
}

impl From<UpdateSecretOutput> for UpdateSecretValueResult {
  fn from(value: UpdateSecretOutput) -> Self {
    Self {
      name: value.name().map(String::from),
      uri: value.arn().map(String::from),
      version_id: value.version_id().map(String::from),
    }
  }
}

impl From<CreateSecretOutput> for CreateSecretResult {
  fn from(value: CreateSecretOutput) -> Self {
    Self {
      name: value.name().map(String::from),
      uri: value.arn().map(String::from),
      version_id: value.version_id().map(String::from),
    }
  }
}

impl From<DeleteSecretOutput> for DeleteSecretResult {
  fn from(value: DeleteSecretOutput) -> Self {
    Self {
      name: value.name().map(String::from),
      uri: value.arn().map(String::from),
      deletion_date: value.deletion_date().map(|d| d.to_string()),
    }
  }
}

/// Wrapper struct to hold onto an actual aws client that we can
/// interact with. Implements [QuerySecrets] trait for AWS.
///
/// You can create an [AwsClient] using the following code:
///
/// ```rust,no_run
/// use nysm::provider::aws::AwsClient;
///
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// let region = String::from("us-west-2");
/// # rt.block_on(async {
/// let client = AwsClient::new(Some(region)).await;
/// # })
/// ```
///
pub struct AwsClient {
  client: aws_sdk_secretsmanager::client::Client,
}

impl AwsClient {
  /// Create a new client with an optional region specified
  /// otherwise will default to the region provided via the awscli configuration
  pub async fn new(region: Option<String>) -> Self {
    let region = region.map(Region::new);
    let region_provider = RegionProviderChain::first_try(region).or_default_provider();

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
      .region(region_provider)
      .load()
      .await;
    let client = aws_sdk_secretsmanager::client::Client::new(&config);

    Self { client }
  }
}

#[async_trait]
impl QuerySecrets for AwsClient {
  async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
    match self.client.list_secrets().send().await {
      Ok(secrets_list) => {
        let mut results: Vec<ListSecretsOutput> = vec![secrets_list.clone()];
        let mut current_token = secrets_list.next_token().map(String::from);

        while let Some(token) = current_token.as_ref() {
          if let Ok(val) = self.client.list_secrets().next_token(token).send().await {
            current_token = val.next_token().map(String::from);
            results.push(val);
          }
        }

        let entries = results.into_iter().fold(vec![], |mut acc, elem| {
          acc.append(&mut Into::<ListSecretsResult>::into(elem).entries);

          acc
        });

        Ok(ListSecretsResult { entries })
      }
      Err(e) => Err(NysmError::ListSecretsFailed(format!(
        "AWS Secrets Manager: {}",
        e
      ))),
    }
  }

  async fn secret_value(&self, secret_id: String) -> Result<GetSecretValueResult, NysmError> {
    // TODO: return 2 different errors
    // depending on secret itself not existing
    // or secret string not existing
    match self
      .client
      .get_secret_value()
      .secret_id(secret_id)
      .send()
      .await
    {
      Ok(secret) => Ok(secret.into()),
      Err(e) => Err(NysmError::GetSecretValueFailed(format!(
        "AWS Secrets Manager: {}",
        e
      ))),
    }
  }

  async fn update_secret_value(
    &self,
    secret_id: String,
    secret_value: String,
  ) -> Result<UpdateSecretValueResult, NysmError> {
    match self
      .client
      .update_secret()
      .secret_id(secret_id)
      .secret_string(secret_value)
      .send()
      .await
    {
      Ok(secret) => Ok(secret.into()),
      Err(e) => Err(NysmError::UpdateSecretFailed(format!(
        "AWS Secrets Manager: {}",
        e
      ))),
    }
  }

  async fn create_secret(
    &self,
    secret_id: String,
    secret_value: String,
    description: Option<String>,
  ) -> Result<CreateSecretResult, NysmError> {
    let mut request = self
      .client
      .create_secret()
      .name(secret_id)
      .secret_string(secret_value);

    if let Some(desc) = description {
      request = request.description(desc);
    }

    match request.send().await {
      Ok(secret) => Ok(secret.into()),
      Err(e) => Err(NysmError::CreateSecretFailed(format!(
        "AWS Secrets Manager: {}",
        e
      ))),
    }
  }

  async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError> {
    match self
      .client
      .delete_secret()
      .secret_id(secret_id)
      .send()
      .await
    {
      Ok(secret) => Ok(secret.into()),
      Err(e) => Err(NysmError::DeleteSecretFailed(format!(
        "AWS Secrets Manager: {}",
        e
      ))),
    }
  }
}
