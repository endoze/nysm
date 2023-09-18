#![cfg(not(tarpaulin_include))]
use clap::Parser;
use nysm::{cli::ArgumentParser, provider::aws::AwsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let cli = ArgumentParser::parse();
  let client = AwsClient::new(cli.region.clone()).await;

  cli.run_subcommand(client).await;

  Ok(())
}
