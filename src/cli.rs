#![deny(missing_docs)]
use crate::client::QuerySecrets;
use crate::error::NysmError;
use bat::PrettyPrinter;
use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use tempfile::TempDir;

/// This struct defines the main command line interface for Nysm.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct ArgumentParser {
  /// Which subcommand to use
  #[command(subcommand)]
  pub command: Commands,
  /// Region to retreive secrets from
  #[arg(short, long, global = true)]
  pub region: Option<String>,
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
  pub async fn run_subcommand(&self, client: impl QuerySecrets) {
    let result = match &self.command {
      Commands::List(args) => {
        let result = list(client, args).await;

        match result {
          Ok(list) => println!("{}", list),
          Err(error) => println!("{}", error),
        }

        Ok(())
      }
      Commands::Edit(args) => edit(client, args).await,
      Commands::Show(args) => show(client, args).await,
    };

    if let Err(error) = result {
      println!("{}", error);
    }
  }
}

async fn list(client: impl QuerySecrets, _args: &List) -> Result<String, NysmError> {
  let secrets_list = client.secrets_list().await?;

  Ok(secrets_list.table_display())
}

async fn show(client: impl QuerySecrets, args: &Show) -> Result<(), NysmError> {
  let secret_value = client.secret_value(args.secret_id.clone()).await?;

  let formatted_secret = reformat_data(
    &secret_value.secret,
    &args.secret_format,
    &args.print_format,
  )?;

  let _ = pretty_print(formatted_secret, &args.print_format);

  Ok(())
}

async fn edit(client: impl QuerySecrets, args: &Edit) -> Result<(), NysmError> {
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

  Ok(())
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
        DataFormat::Yaml => serde_yaml::to_string(&json_value)?,
        DataFormat::Text => String::from(content),
      }
    }
    DataFormat::Yaml => {
      let yaml_value: serde_yaml::Value = serde_yaml::from_str(content)?;

      match destination_format {
        DataFormat::Json => serde_json::to_string_pretty(&yaml_value)?,
        DataFormat::Yaml => serde_yaml::to_string(&yaml_value)?,
        DataFormat::Text => String::from(content),
      }
    }
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
    println!("It seems the file hasn't changed, not persisting back to AWS Secrets Manager.");

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
        None => env::remove_var(k),
        Some(v) => env::set_var(k, v),
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
      env::set_var(k, v);
    } else {
      env::remove_var(k);
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
  }

  #[allow(clippy::field_reassign_with_default)]
  mod client {
    use super::*;
    use crate::client::{GetSecretValueResult, ListSecretsResult, Secret, UpdateSecretValueResult};
    use async_trait::async_trait;

    #[derive(Default)]
    pub struct TestClient {
      fails_on_list_secrets: bool,
      fails_on_get_secret_value: bool,
      fails_on_update_secret_value: bool,
    }

    #[async_trait]
    impl QuerySecrets for TestClient {
      async fn secrets_list(&self) -> Result<ListSecretsResult, NysmError> {
        if self.fails_on_list_secrets {
          return Err(NysmError::AwsListSecretsNoList);
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
        if self.fails_on_get_secret_value {
          return Err(NysmError::AwsSecretValueNoValueString);
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
        _secret_value: String,
      ) -> Result<UpdateSecretValueResult, NysmError> {
        if self.fails_on_update_secret_value {
          return Err(NysmError::AwsSecretValueUpdate);
        }

        Ok(UpdateSecretValueResult {
          name: Some("testy-test-secret".into()),
          uri: Some("some-unique-id".into()),
          version_id: Some("definitely-a-new-version-id".into()),
        })
      }
    }

    mod list_output {
      use super::*;

      #[tokio::test]
      async fn error_when_api_list_call_fails() -> TestResult {
        let mut client = TestClient::default();
        client.fails_on_list_secrets = true;

        let result = list(client, &List {}).await;

        assert_eq!(result, Err(NysmError::AwsListSecretsNoList));

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_list_api_call_succeeds() -> TestResult {
        let client = TestClient::default();

        let result = list(client, &List {}).await;

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
          client,
          &Show {
            secret_id: "fake".into(),
            print_format: DataFormat::Json,
            secret_format: DataFormat::Json,
          },
        )
        .await;

        assert_eq!(result, Err(NysmError::AwsSecretValueNoValueString));

        Ok(())
      }

      #[tokio::test]
      async fn ok_when_api_show_call_succeeds() -> TestResult {
        let client = TestClient::default();

        let result = show(
          client,
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
              client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Yaml,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(result, Err(NysmError::AwsSecretValueUpdate));
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
              client,
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
              client,
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
                serde_yaml::from_str::<String>("::::").unwrap_err()
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
              client,
              &Edit {
                secret_id: "fake".into(),
                edit_format: DataFormat::Json,
                secret_format: DataFormat::Json,
              },
            )
            .await;

            assert_eq!(result, Err(NysmError::AwsSecretValueNoValueString));
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
              client,
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
              client,
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
              client,
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
    }
  }
}
