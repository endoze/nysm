#![cfg(not(tarpaulin_include))]
use clap::Parser;
use nysm::{
  cli::{ArgumentParser, Providers},
  client::QuerySecrets,
  provider::{aws::AwsClient, github::GitHubClient, doppler::DopplerClient},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  rustls::crypto::ring::default_provider()
    .install_default()
    .expect("Failed to install rustls crypto provider");

  let cli = ArgumentParser::parse();

  let (client, command): (Box<dyn QuerySecrets>, _) = match &cli.provider {
    Providers::Aws(aws) => {
      let client = Box::new(AwsClient::new(aws.region.clone()).await);
      (client, &aws.command)
    }
    Providers::Github(github) => {
      let token = github.token.clone()
        .ok_or("GitHub token is required. Set via --token or GITHUB_TOKEN env var")?;
      let client = Box::new(GitHubClient::new(token, github.owner.clone(), github.repo.clone())?);
      (client, &github.command)
    }
    Providers::Doppler(doppler) => {
      let token = doppler.token.clone()
        .ok_or("Doppler token is required. Set via --token or DOPPLER_TOKEN env var")?;
      let client = Box::new(DopplerClient::new(token, doppler.project.clone(), doppler.config.clone())?);
      (client, &doppler.command)
    }
  };

  ArgumentParser::run_subcommand(client, command).await;

  Ok(())
}
