#![deny(missing_docs)]
use crate::client::QuerySecrets;
use crate::error::NysmError;
use bat::PrettyPrinter;
use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use tempfile::TempDir;

/// Enum to define available secret providers
#[derive(Clone, Debug, ValueEnum)]
pub enum Provider {
  /// AWS Secrets Manager
  Aws,
  /// GitHub Actions Secrets
  Github,
}

/// This struct defines the main command line interface for Nysm.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct ArgumentParser {
  /// Which subcommand to use
  #[command(subcommand)]
  pub command: Commands,
  /// Secret provider to use
  #[arg(long, value_enum, default_value = "aws", global = true)]
  pub provider: Provider,
  /// AWS region to retrieve secrets from
  #[arg(
    short,
    long,
    global = true,
    help_heading = "AWS Provider Options",
    conflicts_with_all = ["github_token", "github_owner", "github_repo"]
  )]
  pub region: Option<String>,
  /// GitHub personal access token (can also be set via GITHUB_TOKEN env var)
  #[arg(
    long,
    env = "GITHUB_TOKEN",
    global = true,
    help_heading = "GitHub Provider Options",
    required_if_eq("provider", "github"),
    conflicts_with = "region"
  )]
  pub github_token: Option<String>,
  /// GitHub repository owner (user or organization)
  #[arg(
    long,
    global = true,
    help_heading = "GitHub Provider Options",
    required_if_eq("provider", "github"),
    conflicts_with = "region"
  )]
  pub github_owner: Option<String>,
  /// GitHub repository name
  #[arg(
    long,
    global = true,
    help_heading = "GitHub Provider Options",
    required_if_eq("provider", "github"),
    conflicts_with = "region"
  )]
  pub github_repo: Option<String>,
}

/// This enum defines the main command line subcommands for Nysm.
#[derive(Subcommand, PartialEq, Debug)]
pub enum Commands {
  /// Retrieve a list of secrets
  List(List),
  /// Edit the value of a specific secret
  Edit(Edit),
  /// Show the value of a specific secret
  Show(Show),
  /// Create a new secret
  Create(Create),
  /// Delete a secret
  Delete(Delete),
}

/// Retrieve a list of secrets
#[derive(Args, PartialEq, Debug)]
pub struct List {}

/// Edit the value of a specific secret
#[derive(Args, PartialEq, Debug)]
pub struct Edit {
  /// ID of the secret to edit
  pub secret_id: String,
  #[clap(
    value_enum,
    short = 'f',
    long = "secret-format",
    default_value = "json"
  )]
  /// Format of the secret as stored by the provider
  pub secret_format: DataFormat,
  /// Format to edit the secret in
  #[clap(value_enum, short = 'e', long = "edit-format", default_value = "yaml")]
  pub edit_format: DataFormat,
}

/// Show the value of a specific secret
#[derive(Args, PartialEq, Debug)]
pub struct Show {
  /// ID of the secret to edit
  pub secret_id: String,
  /// Format to print the secret in
  #[clap(value_enum, short = 'p', long = "print-format", default_value = "yaml")]
  pub print_format: DataFormat,
  #[clap(
    value_enum,
    short = 'f',
    long = "secret-format",
    default_value = "json"
  )]
  /// Format of the secret as stored by the provider
  pub secret_format: DataFormat,
}

/// Create a new secret
#[derive(Args, PartialEq, Debug)]
pub struct Create {
  /// ID of the secret to create
  pub secret_id: String,
  /// Description of the secret
  #[clap(short = 'd', long = "description")]
  pub description: Option<String>,
  /// Format of the secret as stored by the provider
  #[clap(
    value_enum,
    short = 'f',
    long = "secret-format",
    default_value = "json"
  )]
  pub secret_format: DataFormat,
  /// Format to edit the secret in
  #[clap(value_enum, short = 'e', long = "edit-format", default_value = "yaml")]
  pub edit_format: DataFormat,
}

/// Delete a secret
#[derive(Args, PartialEq, Debug)]
pub struct Delete {
  /// ID of the secret to delete
  pub secret_id: String,
}

/// Enum to describe the different data formats that can be used with Secrets
#[derive(Clone, Debug, Deserialize, Serialize, ValueEnum, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
  /// Json format
  Json,
  /// Yaml format
  Yaml,
  /// Plaintext format
  Text,
}

impl std::fmt::Display for DataFormat {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::fmt::Debug::fmt(self, f)
  }
}

impl ArgumentParser {
  /// Runs the given subcommand and uses the provided client
  ///
  /// # Arguments
  /// * `client` - Trait object that implements [QuerySecrets]
  ///
  #[cfg(not(tarpaulin_include))]
  pub async fn run_subcommand(&self, client: Box<dyn QuerySecrets>) {
    let result = match &self.command {
      Commands::List(args) => {
        let result = list(&*client, args).await;

        match result {
          Ok(list) => println!("{}", list),
          Err(error) => println!("{}", error),
        }

        Ok(())
      }
      Commands::Edit(args) => edit(&*client, args).await,
      Commands::Show(args) => show(&*client, args).await,
      Commands::Create(args) => create(&*client, args).await,
      Commands::Delete(args) => delete(&*client, args).await,
    };

    if let Err(error) = result {
      println!("{}", error);
    }
  }
}

async fn list(client: &dyn QuerySecrets, _args: &List) -> Result<String, NysmError> {
  let secrets_list = client.secrets_list().await?;

  Ok(secrets_list.table_display())
}

async fn show(client: &dyn QuerySecrets, args: &Show) -> Result<(), NysmError> {
  if !client.supports_read() {
    return Err(NysmError::SecretNotReadable);
  }

  let secret_value = client.secret_value(args.secret_id.clone()).await?;

  let formatted_secret = reformat_data(
    &secret_value.secret,
    &args.secret_format,
    &args.print_format,
  )?;

  let _ = pretty_print(formatted_secret, &args.print_format);

  Ok(())
}

async fn edit(client: &dyn QuerySecrets, args: &Edit) -> Result<(), NysmError> {
  if client.supports_read() {
    let secret_value = client.secret_value(args.secret_id.clone()).await?;

    if let Ok(dir) = temporary_directory() {
      let update_contents = launch_editor(
        secret_value.secret,
        dir,
        &args.secret_format,
        &args.edit_format,
      )?;

      if let Some(contents) = update_contents {
        let _ = client
          .update_secret_value(args.secret_id.clone(), contents)
          .await?;
      }
    }
  } else {
    let template = match args.edit_format {
      DataFormat::Json => "{}".to_string(),
      DataFormat::Yaml => "# Enter new secret value below\n".to_string(),
      DataFormat::Text => "".to_string(),
    };

    if let Ok(dir) = temporary_directory() {
      let update_contents =
        launch_editor(template.clone(), dir, &args.edit_format, &args.edit_format)?;

      if let Some(contents) = update_contents {
        if contents == template {
          println!("No changes made, skipping update.");
        } else {
          println!("Warning: This will completely replace the existing secret.");
          let formatted_contents =
            reformat_data(&contents, &args.edit_format, &args.secret_format)?;
          let _ = client
            .update_secret_value(args.secret_id.clone(), formatted_contents)
            .await?;
        }
      }
    }
  }

  Ok(())
}

async fn create(client: &dyn QuerySecrets, args: &Create) -> Result<(), NysmError> {
  if let Ok(dir) = temporary_directory() {
    let initial_content = match args.edit_format {
      DataFormat::Json => "{}".to_string(),
      DataFormat::Yaml => "".to_string(),
      DataFormat::Text => "".to_string(),
    };

    let secret_contents =
      launch_editor(initial_content, dir, &args.edit_format, &args.edit_format)?;

    if let Some(contents) = secret_contents {
      let formatted_contents = reformat_data(&contents, &args.edit_format, &args.secret_format)?;
      let _ = client
        .create_secret(
          args.secret_id.clone(),
          formatted_contents,
          args.description.clone(),
        )
        .await?;
    }
  }

  Ok(())
}

async fn delete(client: &dyn QuerySecrets, args: &Delete) -> Result<(), NysmError> {
  let _ = client.delete_secret(args.secret_id.clone()).await?;

  Ok(())
}

fn strip_trailing_whitespace_from_block_scalars(content: &str) -> String {
  if content.contains(": |") {
    content
      .lines()
      .map(|line| line.trim_end())
      .collect::<Vec<_>>()
      .join("\n")
  } else {
    content.to_string()
  }
}

fn reformat_data(
  content: &str,
  source_format: &DataFormat,
  destination_format: &DataFormat,
) -> Result<String, NysmError> {
  Ok(match source_format {
    DataFormat::Json => {
      let json_value: serde_json::Value = serde_json::from_str(content)?;

      match destination_format {
        DataFormat::Json => serde_json::to_string_pretty(&json_value)?,
        DataFormat::Yaml => serde_yml::to_string(&json_value)?,
        DataFormat::Text => String::from(content),
      }
    }
    DataFormat::Yaml => match destination_format {
      DataFormat::Yaml => {
        serde_yml::from_str::<serde_yml::Value>(content)?;
        String::from(content)
      }
      DataFormat::Json => {
        let cleaned_content = strip_trailing_whitespace_from_block_scalars(content);
        let yaml_value: serde_yml::Value = serde_yml::from_str(&cleaned_content)?;
        serde_json::to_string_pretty(&yaml_value)?
      }
      DataFormat::Text => String::from(content),
    },
    DataFormat::Text => String::from(content),
  })
}

/// Pretty prints a string with bat.
///
/// # Arguments
/// * `content` - String to be pretty printed
/// * `print_format` - Format to print the string as
///
/// # Returns
/// Returns a result with either an empty tuple or a NysmError. This can error if
/// bat has trouble printing in the specified format.
#[cfg(not(tarpaulin_include))]
fn pretty_print(content: String, print_format: &DataFormat) -> Result<(), NysmError> {
  if std::io::stdout().is_terminal() {
    let language_string = print_format.to_string();
    let mut printer = PrettyPrinter::new();
    let _printer = match print_format {
      DataFormat::Yaml | DataFormat::Json => printer.language(&language_string),
      _ => &mut printer,
    };

    #[allow(unused)]
    #[cfg(not(test))]
    let _ = _printer
      .grid(true)
      .line_numbers(true)
      .paging_mode(bat::PagingMode::QuitIfOneScreen)
      .pager("less")
      .theme("OneHalfDark")
      .input_from_bytes(content.as_bytes())
      .print()?;
  } else {
    println!("{}", content);
  }

  Ok(())
}

/// This method is designed to open up an editor with contents from a secret.
///
/// # Arguments
/// * `contents` - String contents to open up in an editor
/// * `path` - Temporary directory to save the contents of the file to when editing a secret
/// * `secret_format` - Format of the secret as given by the secret provider
/// * `edit_format` - Format of the secret to use while editing the secret in an editor
///
/// # Returns
/// Returns a result containing the changes to the contents originally passed into the method.
/// Can error if any IO operation fails (read/write of the temporary file).
///
fn launch_editor<P>(
  contents: String,
  path: P,
  secret_format: &DataFormat,
  edit_format: &DataFormat,
) -> Result<Option<String>, NysmError>
where
  P: AsRef<std::path::Path>,
{
  let language_string = edit_format.to_string().to_lowercase();
  let file_path = path.as_ref().join("data").with_extension(language_string);

  let file_contents = reformat_data(&contents, secret_format, edit_format)?;
  std::fs::write(&file_path, file_contents)?;

  let mut editor = match std::env::var("EDITOR") {
    Ok(editor) => editor,
    Err(_) => String::from("vim"),
  };

  editor.push(' ');
  editor.push_str(&file_path.to_string_lossy());

  #[cfg(test)]
  editor.insert_str(0, "vim(){ :; }; ");

  std::process::Command::new("/usr/bin/env")
    .arg("sh")
    .arg("-c")
    .arg(editor)
    .spawn()
    .expect("Error: Failed to run editor")
    .wait()
    .expect("Error: Editor returned a non-zero status");

  let file_contents: String = std::fs::read_to_string(file_path)?;
  let json_data = reformat_data(&file_contents, edit_format, secret_format)?;

  if json_data.eq(&contents) {
    println!("It seems the file hasn't changed, not persisting changes.");

    Ok(None)
  } else {
    Ok(Some(json_data))
  }
}

fn temporary_directory() -> std::io::Result<TempDir> {
  TempDir::new()
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures::FutureExt;
  use lazy_static::lazy_static;
  use serde_json::json;
  use std::env::VarError;
  use std::future::Future;
  use std::panic::AssertUnwindSafe;
  use std::panic::{RefUnwindSafe, UnwindSafe};
  use std::{env, panic};

  lazy_static! {
    static ref SERIAL_TEST: tokio::sync::Mutex<()> = Default::default();
  }

  /// Sets environment variables to the given value for the duration of the closure.
  /// Restores the previous values when the closure completes or panics, before unwinding the panic.
  pub async fn async_with_env_vars<F>(kvs: Vec<(&str, Option<&str>)>, closure: F)
  where
    F: Future<Output = ()> + UnwindSafe + RefUnwindSafe,
  {
    let guard = SERIAL_TEST.lock().await;
    let mut old_kvs: Vec<(&str, Result<String, VarError>)> = Vec::new();

    for (k, v) in kvs {
      let old_v = env::var(k);
      old_kvs.push((k, old_v));
      match v {
        None => unsafe { env::remove_var(k) },
        Some(v) => unsafe { env::set_var(k, v) },
      }
    }

    match closure.catch_unwind().await {
      Ok(_) => {
        for (k, v) in old_kvs {
          reset_env(k, v);
        }
      }
      Err(err) => {
        for (k, v) in old_kvs {
          reset_env(k, v);
        }
        drop(guard);
        panic::resume_unwind(err);
      }
    }
  }

  fn reset_env(k: &str, old: Result<String, VarError>) {
    if let Ok(v) = old {
      unsafe { env::set_var(k, v) };
    } else {
      unsafe { env::remove_var(k) };
    }
  }

  type TestResult = Result<(), Box<dyn std::error::Error>>;

  mod reformat_data {
    use super::*;

    #[test]
    fn from_json_to_yaml() -> TestResult {
      let data = r#"{"banana": true, "apple": false}"#;
      let expected = "apple: false\nbanana: true\n";

      let result = reformat_data(data, &DataFormat::Json, &DataFormat::Yaml)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_json_to_json() -> TestResult {
      let data = r#"{"banana": true, "apple": false}"#;
      let json_value = json!({
        "apple": false,
        "banana": true,
      });
      let expected = serde_json::to_string_pretty(&json_value)?;

      let result = reformat_data(data, &DataFormat::Json, &DataFormat::Json)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_json_to_text() -> TestResult {
      let data = r#"{"apple":false,"banana":true}"#;
      let expected = json!({
        "apple": false,
        "banana": true,
      })
      .to_string();

      let result = reformat_data(data, &DataFormat::Json, &DataFormat::Text)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_yaml_to_json() -> TestResult {
      let yaml_string = r#"apple: false
banana: true
"#;
      let json_value = json!({
        "apple": false,
        "banana": true,
      });
      let expected = serde_json::to_string_pretty(&json_value)?;

      let result = reformat_data(yaml_string, &DataFormat::Yaml, &DataFormat::Json)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_yaml_to_yaml() -> TestResult {
      let yaml_string = r#"apple: false
banana: true
"#;
      let expected = "apple: false\nbanana: true\n";

      let result = reformat_data(yaml_string, &DataFormat::Yaml, &DataFormat::Yaml)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_yaml_to_text() -> TestResult {
      let yaml_string = r#"apple: false
banana: true
"#;
      let expected = "apple: false\nbanana: true\n";

      let result = reformat_data(yaml_string, &DataFormat::Yaml, &DataFormat::Text)?;

      assert_eq!(expected, result);

      Ok(())
    }

    #[test]
    fn from_yaml_with_trailing_whitespace_to_json() -> TestResult {
      let yaml_string = "application.yml: |-\n  banana: false \n  apple: true\n  flasdjfljasdlfjalsd: alsdkjflasjdflajdslf\n";

      let result = reformat_data(yaml_string, &DataFormat::Yaml, &DataFormat::Json)?;

      assert!(!result.contains("false \\n"));
      assert!(result.contains("false\\n"));

      Ok(())
    }

    #[test]
    fn from_text() -> TestResult {
      let text = "This is a plain string with no data structure.";
      let expected = "This is a plain string with no data structure.";

      let result = reformat_data(text, &DataFormat::Text, &DataFormat::Text)?;

      assert_eq!(expected, result);

      Ok(())
    }
  }

  #[test]
  fn data_format_display() -> TestResult {
    assert_eq!(format!("{}", DataFormat::Json), "Json");
    assert_eq!(format!("{}", DataFormat::Yaml), "Yaml");
    assert_eq!(format!("{}", DataFormat::Text), "Text");

    Ok(())
  }

  #[test]
  fn test_yaml_with_mixed_whitespace_fixture() -> TestResult {
    let fixture_path = "tests/fixtures/mixed_whitespace.yml";
    let problematic_yaml =
      std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");

    let result = reformat_data(&problematic_yaml, &DataFormat::Yaml, &DataFormat::Json)?;

    assert!(result.contains("application.yml"));
    assert!(result.contains("banana: false"));
    assert!(!result.contains("false \\n"));

    Ok(())
  }

  mod argument_parsing {
    use super::*;

    #[test]
    fn accepts_region() -> TestResult {
      let args = "nysm -r us-west-2 list".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(arg_parser.region.unwrap(), "us-west-2".to_string());

      Ok(())
    }

    #[test]
    fn sets_list_subcommand() -> TestResult {
      let args = "nysm -r us-west-2 list".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(arg_parser.command, Commands::List(List {}));

      Ok(())
    }

    #[test]
    fn sets_show_subcommand() -> TestResult {
      let args = "nysm -r us-west-2 show testing-secrets".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(
        arg_parser.command,
        Commands::Show(Show {
          secret_id: "testing-secrets".into(),
          print_format: DataFormat::Yaml,
          secret_format: DataFormat::Json,
        })
      );

      Ok(())
    }

    #[test]
    fn sets_edit_subcommand() -> TestResult {
      let args = "nysm -r us-west-2 edit testing-secrets".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(
        arg_parser.command,
        Commands::Edit(Edit {
          secret_id: "testing-secrets".into(),
          edit_format: DataFormat::Yaml,
          secret_format: DataFormat::Json,
        })
      );

      Ok(())
    }

    #[test]
    fn sets_create_subcommand() -> TestResult {
      let args = "nysm -r us-west-2 create new-secret".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(
        arg_parser.command,
        Commands::Create(Create {
          secret_id: "new-secret".into(),
          description: None,
          edit_format: DataFormat::Yaml,
          secret_format: DataFormat::Json,
        })
      );

      Ok(())
    }

    #[test]
    fn sets_create_subcommand_with_description() -> TestResult {
      let args = vec![
        "nysm",
        "-r",
        "us-west-2",
        "create",
        "new-secret",
        "-d",
        "Test secret",
      ];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(
        arg_parser.command,
        Commands::Create(Create {
          secret_id: "new-secret".into(),
          description: Some("Test secret".into()),
          edit_format: DataFormat::Yaml,
          secret_format: DataFormat::Json,
        })
      );

      Ok(())
    }

    #[test]
    fn sets_delete_subcommand() -> TestResult {
      let args = "nysm -r us-west-2 delete test-secret".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(
        arg_parser.command,
        Commands::Delete(Delete {
          secret_id: "test-secret".into(),
        })
      );

      Ok(())
    }

    #[test]
    fn defaults_to_aws_provider() -> TestResult {
      let args = "nysm list".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert!(matches!(arg_parser.provider, Provider::Aws));

      Ok(())
    }

    #[test]
    fn accepts_aws_provider() -> TestResult {
      let args = "nysm --provider aws list".split_whitespace();
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert!(matches!(arg_parser.provider, Provider::Aws));

      Ok(())
    }

    #[test]
    fn accepts_github_provider() -> TestResult {
      let args = vec![
        "nysm",
        "--provider",
        "github",
        "--github-token",
        "test-token",
        "--github-owner",
        "test-owner",
        "--github-repo",
        "test-repo",
        "list",
      ];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert!(matches!(arg_parser.provider, Provider::Github));

      Ok(())
    }

    #[test]
    fn accepts_github_token() -> TestResult {
      let args = vec!["nysm", "--github-token", "ghp_123456", "list"];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(arg_parser.github_token, Some("ghp_123456".to_string()));

      Ok(())
    }

    #[test]
    fn accepts_github_owner() -> TestResult {
      let args = vec!["nysm", "--github-owner", "myorg", "list"];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(arg_parser.github_owner, Some("myorg".to_string()));

      Ok(())
    }

    #[test]
    fn accepts_github_repo() -> TestResult {
      let args = vec!["nysm", "--github-repo", "myrepo", "list"];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert_eq!(arg_parser.github_repo, Some("myrepo".to_string()));

      Ok(())
    }

    #[test]
    fn accepts_all_github_options() -> TestResult {
      let args = vec![
        "nysm",
        "--provider",
        "github",
        "--github-token",
        "ghp_123456",
        "--github-owner",
        "myorg",
        "--github-repo",
        "myrepo",
        "list",
      ];
      let arg_parser = ArgumentParser::try_parse_from(args)?;

      assert!(matches!(arg_parser.provider, Provider::Github));
      assert_eq!(arg_parser.github_token, Some("ghp_123456".to_string()));
      assert_eq!(arg_parser.github_owner, Some("myorg".to_string()));
      assert_eq!(arg_parser.github_repo, Some("myrepo".to_string()));

      Ok(())
    }
  }

  #[allow(clippy::field_reassign_with_default)]
  mod client {
    use super::*;
    use crate::client::{
      CreateSecretResult, DeleteSecretResult, GetSecretValueResult, ListSecretsResult, Secret,
      UpdateSecretValueResult,
    };
    use async_trait::async_trait;

    pub struct TestClient {
      fails_on_list_secrets: bool,
      fails_on_get_secret_value: bool,
      fails_on_update_secret_value: bool,
      fails_on_create_secret: bool,
      fails_on_delete_secret: bool,
      is_write_only: bool,
      on_create_secret: Option<Box<dyn Fn(&str) + Send + Sync>>,
      on_update_secret: Option<Box<dyn Fn(&str) + Send + Sync>>,
      on_delete_secret: Option<Box<dyn Fn(&str) + Send + Sync>>,
    }

    impl Default for TestClient {
      fn default() -> Self {
        Self {
          fails_on_list_secrets: false,
          fails_on_get_secret_value: false,
          fails_on_update_secret_value: false,
          fails_on_create_secret: false,
          fails_on_delete_secret: false,
          is_write_only: false,
          on_create_secret: None,
          on_update_secret: None,
          on_delete_secret: None,
        }
      }
    }

    #[async_trait]
    impl QuerySecrets for TestClient {
      fn supports_read(&self) -> bool {
        !self.is_write_only
      }

      async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
        if self.fails_on_list_secrets {
          return Err(NysmError::ListSecretsFailed("Test error".to_string()));
        }

        Ok(ListSecretsResult {
          entries: vec![Secret {
            name: Some("secret-one".into()),
            uri: Some("some-unique-id-one".into()),
            description: Some("blah blah blah".into()),
          }],
        })
      }

      async fn secret_value(&self, _secret_id: String) -> Result<GetSecretValueResult, NysmError> {
        if self.is_write_only {
          return Err(NysmError::SecretNotReadable);
        }

        if self.fails_on_get_secret_value {
          return Err(NysmError::GetSecretValueFailed("Test error".to_string()));
        }

        let secret_value = json!({
          "apple": true,
          "banana": false,
        });

        let secret_value = serde_json::to_string_pretty(&secret_value)?;

        Ok(GetSecretValueResult {
          secret: secret_value,
        })
      }

      async fn update_secret_value(
        &self,
        _secret_id: String,
        secret_value: String,
      ) -> Result<UpdateSecretValueResult, NysmError> {
        if self.fails_on_update_secret_value {
          return Err(NysmError::UpdateSecretFailed("Test error".to_string()));
        }

        if let Some(callback) = &self.on_update_secret {
          callback(&secret_value);
        }

        Ok(UpdateSecretValueResult {
          name: Some("testy-test-secret".into()),
          uri: Some("some-unique-id".into()),
          version_id: Some("definitely-a-new-version-id".into()),
        })
      }

      async fn create_secret(
        &self,
        _secret_id: String,
        secret_value: String,
        _description: Option<String>,
      ) -> Result<CreateSecretResult, NysmError> {
        if self.fails_on_create_secret {
          return Err(NysmError::CreateSecretFailed("Test error".to_string()));
        }

        if let Some(callback) = &self.on_create_secret {
          callback(&secret_value);
        }

        Ok(CreateSecretResult {
          name: Some("new-test-secret".into()),
          uri: Some("some-new-unique-id".into()),
          version_id: Some("new-secret-version-id".into()),
        })
      }

      async fn delete_secret(&self, secret_id: String) -> Result<DeleteSecretResult, NysmError> {
        if self.fails_on_delete_secret {
          return Err(NysmError::DeleteSecretFailed("Test error".to_string()));
        }

        if let Some(callback) = &self.on_delete_secret {
          callback(&secret_id);
        }

        Ok(DeleteSecretResult {
          name: Some("deleted-secret".into()),
          uri: Some("some-deleted-unique-id".into()),
          deletion_date: Some("2024-01-01".into()),
        })
      }
    }

    mod list_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_list_call_fails() -> TestResult {
        let mut client = TestClient::default();
        client.fails_on_list_secrets = true;

        let result = list(&client, &List {}).await;

        assert_eq!(
          result,
          Err(NysmError::ListSecretsFailed("Test error".to_string()))
        );

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_list_api_call_succeeds() -> TestResult {
        let client = TestClient::default();

        let result = list(&client, &List {}).await;

        assert!(result.is_ok());

        Ok(())
      }
    }

    mod show_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_show_call_fails() -> TestResult {
        let mut client = TestClient::default();
        client.fails_on_get_secret_value = true;

        let result = show(
          &client,
          &Show {
            secret_id: "fake".into(),
            print_format: DataFormat::Json,
            secret_format: DataFormat::Json,
          },
        )
        .await;

        assert_eq!(
          result,
          Err(NysmError::GetSecretValueFailed("Test error".to_string()))
        );

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_show_call_succeeds() -> TestResult {
        let client = TestClient::default();

        let result = show(
          &client,
          &Show {
            secret_id: "fake".into(),
            print_format: DataFormat::Json,
            secret_format: DataFormat::Json,
          },
        )
        .await;

        assert!(result.is_ok());

        Ok(())
      }

      #[tokio::test]
      async fn error_when_provider_does_not_support_read() -> TestResult {
        let mut client = TestClient::default();
        client.is_write_only = true;

        let result = show(
          &client,
          &Show {
            secret_id: "write-only-secret".into(),
            print_format: DataFormat::Yaml,
            secret_format: DataFormat::Json,
          },
        )
        .await;

        assert_eq!(result, Err(NysmError::SecretNotReadable));

        Ok(())
      }
    }

    mod edit_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_update_call_fails() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'another: true\n' >> "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.fails_on_update_secret_value = true;

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(
              result,
              Err(NysmError::UpdateSecretFailed("Test error".to_string()))
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn json_error_when_api_update_call_fails_due_to_syntax() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'another: true\n' >> "))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(
              result,
              Err(NysmError::SerdeJson(
                serde_json::from_str::<String>(";;;").unwrap_err()
              ))
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn yaml_error_when_api_update_call_fails_due_to_syntax() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo '@invalid_yaml' >> "))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Yaml,
              },
            )
            .await;

            assert_eq!(
              result,
              Err(NysmError::SerdeYaml(
                serde_yml::from_str::<String>("::::").unwrap_err()
              ))
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn error_when_api_get_call_fails() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo >/dev/null 2>&1 <<<"))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.fails_on_get_secret_value = true;

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(
              result,
              Err(NysmError::GetSecretValueFailed("Test error".to_string()))
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_get_calls_succeed() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo >/dev/null 2>&1 <<<"))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_no_editor_environment_variable() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", None)],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = edit(
              &client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_get_calls_succeed_and_no_change() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo >/dev/null 2>&1 <<<"))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = edit(
              &client,
              &Edit {
                secret_id: "secret-one".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn uses_correct_formats_for_editing() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'updated_key: yaml_value\n' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();

            client.on_update_secret = Some(Box::new(|secret_string| {
              let parsed: serde_json::Value =
                serde_json::from_str(secret_string).expect("Should be valid JSON");
              assert_eq!(parsed["updated_key"], "yaml_value");
            }));

            let result = edit(
              &client,
              &Edit {
                secret_id: "secret-one".into(),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn write_only_provider_uses_json_template() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo '{\"new_key\": \"new_value\"}' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.is_write_only = true;
            client.on_update_secret = Some(Box::new(|secret_string| {
              let parsed: serde_json::Value =
                serde_json::from_str(secret_string).expect("Should be valid JSON");
              assert_eq!(parsed["new_key"], "new_value");
            }));

            let result = edit(
              &client,
              &Edit {
                secret_id: "write-only-secret".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn write_only_provider_uses_yaml_template() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'key: value\nanother: true' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.is_write_only = true;
            client.on_update_secret = Some(Box::new(|secret_string| {
              let parsed: serde_json::Value =
                serde_json::from_str(secret_string).expect("Should be valid JSON");
              assert_eq!(parsed["key"], "value");
              assert_eq!(parsed["another"], true);
            }));

            let result = edit(
              &client,
              &Edit {
                secret_id: "write-only-secret".into(),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn write_only_provider_uses_text_template() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'plain text secret' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.is_write_only = true;
            client.on_update_secret = Some(Box::new(|secret_string| {
              assert_eq!(secret_string.trim(), "plain text secret");
            }));

            let result = edit(
              &client,
              &Edit {
                secret_id: "write-only-secret".into(),
                edit_format: DataFormat::Text,
                secret_format: DataFormat::Text,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn write_only_provider_skips_update_when_no_changes() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo '{}' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.is_write_only = true;
            let update_called = std::sync::Arc::new(std::sync::Mutex::new(false));
            let update_called_clone = update_called.clone();
            client.on_update_secret = Some(Box::new(move |_| {
              *update_called_clone.lock().unwrap() = true;
            }));

            let result = edit(
              &client,
              &Edit {
                secret_id: "write-only-secret".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
            assert!(
              !*update_called.lock().unwrap(),
              "Update should not be called when content is unchanged"
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn write_only_provider_cannot_read_secret() -> TestResult {
        let mut client = TestClient::default();
        client.is_write_only = true;

        let result = client.secret_value("test-secret".to_string()).await;
        assert!(matches!(result, Err(NysmError::SecretNotReadable)));

        Ok(())
      }
    }

    mod create_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_create_call_fails() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'test: value\n' >> "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();
            client.fails_on_create_secret = true;

            let result = create(
              &client,
              &Create {
                secret_id: "fake".into(),
                description: None,
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(
              result,
              Err(NysmError::CreateSecretFailed("Test error".to_string()))
            );
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_create_call_succeeds() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'test: value\n' >> "))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = create(
              &client,
              &Create {
                secret_id: "new-secret".into(),
                description: Some("Test description".into()),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_no_changes_made_in_editor() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo >/dev/null 2>&1 <<<"))],
          AssertUnwindSafe(async {
            let client = TestClient::default();

            let result = create(
              &client,
              &Create {
                secret_id: "new-secret".into(),
                description: None,
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }

      #[tokio::test]
      async fn uses_correct_formats_for_editing() -> TestResult {
        async_with_env_vars(
          vec![("EDITOR", Some("echo 'key: yaml_value\n' > "))],
          AssertUnwindSafe(async {
            let mut client = TestClient::default();

            client.on_create_secret = Some(Box::new(|secret_string| {
              let parsed: serde_json::Value =
                serde_json::from_str(secret_string).expect("Should be valid JSON");
              assert_eq!(parsed["key"], "yaml_value");
            }));

            let result = create(
              &client,
              &Create {
                secret_id: "new-secret".into(),
                description: None,
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert!(result.is_ok());
          }),
        )
        .await;

        Ok(())
      }
    }

    mod delete_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_delete_call_fails() -> TestResult {
        let mut client = TestClient::default();
        client.fails_on_delete_secret = true;

        let result = delete(
          &client,
          &Delete {
            secret_id: "fake".into(),
          },
        )
        .await;

        assert_eq!(
          result,
          Err(NysmError::DeleteSecretFailed("Test error".to_string()))
        );

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_delete_call_succeeds() -> TestResult {
        let client = TestClient::default();

        let result = delete(
          &client,
          &Delete {
            secret_id: "test-secret".into(),
          },
        )
        .await;

        assert!(result.is_ok());

        Ok(())
      }

      #[tokio::test]
      async fn calls_callback_with_secret_id() -> TestResult {
        let mut client = TestClient::default();

        client.on_delete_secret = Some(Box::new(|secret_id| {
          assert_eq!(secret_id, "test-secret");
        }));

        let result = delete(
          &client,
          &Delete {
            secret_id: "test-secret".into(),
          },
        )
        .await;

        assert!(result.is_ok());

        Ok(())
      }
    }
  }
}
