#![cfg(not(tarpaulin_include))]
use clap::Parser;
use nysm::{
  cli::{ArgumentParser, Provider},
  client::QuerySecrets,
  provider::{aws::AwsClient, github::GitHubClient},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  rustls::crypto::ring::default_provider()
    .install_default()
    .expect("Failed to install rustls crypto provider");

  let cli = ArgumentParser::parse();

  let client: Box<dyn QuerySecrets> = match cli.provider {
    Provider::Aws => Box::new(AwsClient::new(cli.region.clone()).await),
    Provider::Github => {
      let token = cli.github_token.clone().unwrap();
      let owner = cli.github_owner.clone().unwrap();
      let repo = cli.github_repo.clone().unwrap();

      Box::new(GitHubClient::new(token, owner, repo)?)
    }
  };

  cli.run_subcommand(client).await;

  Ok(())
}
