use std::{error::Error, fmt::Display, fs, io, path::PathBuf, process::exit};

use clap::{Parser, Subcommand};
use error_stack::{IntoReport, Report, Result, ResultExt};

use w3name::{
  error::{APIError, ClientError},
  ipns::{deserialize_ipns_entry, revision_from_ipns_entry, validate_ipns_entry},
  Name, Revision, W3NameClient, WritableName,
};

#[derive(Parser)]
#[clap(name = "w3name", version, about, long_about = None)]
/// A tool for creating verifiable names in a web3 world.
struct Cli {
  /// Enable verbose debug logging
  #[clap(long, global = true)]
  verbose: bool,

  #[clap(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Lookup the current value for a name record.
  Resolve {
    /// The name identifier, e.g. "k51qzi5uqu5dka3tmn6ipgsrq1u2bkuowdwlqcw0vibledypt1y9y5i8v8xwvu"
    #[clap(value_parser)]
    name: String,
  },

  /// Publish a new value for a name, signed with the name's private key.
  Publish {
    /// Path to a key file (see the `create` command to make one).
    #[clap(short, long, value_parser, value_name = "KEY_FILE")]
    key: PathBuf,

    /// The value to publish.
    #[clap(short, long, value_parser)]
    value: String,
  },

  /// Create a new public/private keypair and save it to disk.
  Create {
    /// Filename to write the key to.
    ///
    /// If not given, will write to a file named `<name>.key`,
    /// where `<name>` is the string form of the public key.
    #[clap(short, long, value_parser)]
    output: Option<PathBuf>,
  },

  /// Parse a record
  Parse {
    /// base64-encoded record
    #[clap(value_parser)]
    record: Option<String>,
  },
}

#[tokio::main]
async fn main() {
  let cli = Cli::parse();

  // Initialize logging based on verbose flag
  if cli.verbose {
    env_logger::Builder::from_default_env()
      .filter_level(log::LevelFilter::Debug)
      .init();
  } else {
    env_logger::Builder::from_default_env()
      .filter_level(log::LevelFilter::Warn)
      .init();
  }

  use Commands::*;
  let res = match &cli.command {
    Resolve { name } => {
      resolve(name).await
    }

    Publish { key, value } => {
      publish(key, value).await
    }

    Create { output } => {
      create(output)
    }

    Parse { record } => parse_record(record),
  };

  if let Err(err_report) = res {
    eprintln!("{err_report:?}");
    exit(1);
  }
}

async fn resolve(name_str: &str) -> Result<(), CliError> {
  let client = W3NameClient::default();

  log::debug!("Resolving name: {}", name_str);

  let name = Name::parse(name_str)
    .change_context(CliError::Resolve)
    .attach_printable(format!("name: {}", name_str))?;

  match client.resolve(&name).await {
    Ok(revision) => {
      log::debug!("Successfully resolved to: {}", revision.value());
      println!("{}", revision.value());
      Ok(())
    }

    Err(err_report) => {
      if is_404(&err_report) {
        eprintln!("no record found for key {}", name_str);
        Ok(())
      } else {
        Err(err_report
          .change_context(CliError::Resolve)
          .attach_printable(format!("name: {}", name_str)))
      }
    },
  }
}

fn create(output: &Option<PathBuf>) -> Result<(), CliError> {
  let name = WritableName::new();
  let output = output
    .clone()
    .unwrap_or_else(|| PathBuf::from(format!("{}.key", name.to_string())));

  let bytes = name
    .keypair()
    .to_protobuf_encoding()
    .report()
    .change_context(CliError::Create)?;
  fs::write(&output, bytes)
    .report()
    .change_context(CliError::Create)?;
  println!("wrote new keypair to {}", output.display());
  Ok(())
}

async fn resolve_via_trustless_gateway(name_str: &str) -> Result<Revision, CliError> {
  log::debug!("Fetching IPNS record from trustless gateway for: {}", name_str);

  let url = format!("https://trustless-gateway.link/ipns/{}", name_str);
  let client = reqwest::Client::new();

  let response = client
    .get(&url)
    .header("Accept", "application/vnd.ipfs.ipns-record")
    .send()
    .await
    .report()
    .change_context(CliError::Resolve)
    .attach_printable("fetching from trustless gateway")?;

  if !response.status().is_success() {
    return Err(Report::new(CliError::Resolve)
      .attach_printable(format!("trustless gateway returned: {}", response.status())));
  }

  let record_bytes = response
    .bytes()
    .await
    .report()
    .change_context(CliError::Resolve)
    .attach_printable("reading response from trustless gateway")?;

  let entry = deserialize_ipns_entry(&record_bytes).change_context(CliError::Resolve)?;
  let name = Name::parse(name_str).change_context(CliError::Resolve)?;

  validate_ipns_entry(&entry, name.public_key()).change_context(CliError::Resolve)?;

  let revision = revision_from_ipns_entry(&entry, &name).change_context(CliError::Resolve)?;

  log::debug!("Successfully parsed IPNS record from trustless gateway: sequence={}", revision.sequence());

  Ok(revision)
}

async fn publish(key_file: &PathBuf, value: &str) -> Result<(), CliError> {
  let client = W3NameClient::default();
  let key_bytes = fs::read(key_file).report().change_context(CliError::Other)?;
  let writable = WritableName::decode(&key_bytes).change_context(CliError::Other)?;

  let name_str = writable.to_string();

  log::debug!("Publishing to name: {}", name_str);
  log::debug!("New value: {}", value);
  log::debug!("Key file: {}", key_file.display());

  // to avoid having to keep old revisions around, we first try to resolve and increment any existing records
  let new_revision = match client.resolve(&writable.to_name()).await {
    Ok(revision) => {
      log::debug!("Found existing revision via w3name, incrementing from sequence {}", revision.sequence());
      revision.increment(value)
    },

    // If w3name resolve fails, try trustless gateway fallback
    Err(err_report) => {
      if is_404(&err_report) {
        log::debug!("No existing record found (404), creating initial revision (v0)");
        Revision::v0(&writable.to_name(), value)
      } else {
        // Try trustless gateway fallback for other errors (500, network issues, etc)
        let error_msg = if let Some(api_err) = err_report.downcast_ref::<APIError>() {
          format!("{} - {}", api_err.status_code, api_err.message)
        } else {
          format!("{:?}", err_report)
        };
        log::warn!("w3name resolve failed ({}) - trying trustless gateway fallback", error_msg);

        match resolve_via_trustless_gateway(&name_str).await {
          Ok(revision) => {
            log::debug!("Found existing revision via trustless gateway, incrementing from sequence {}", revision.sequence());
            revision.increment(value)
          },
          Err(_gateway_err) => {
            log::debug!("Trustless gateway also failed, creating initial revision (v0)");
            Revision::v0(&writable.to_name(), value)
          }
        }
      }
    },
  };

  client
    .publish(&writable, &new_revision)
    .await
    .change_context(CliError::Publish)
    .attach_printable(format!("name: {}", name_str))
    .attach_printable(format!("value: {}", value))?;

  println!(
    "published new value for key {}: {}",
    name_str,
    value
  );
  Ok(())
}

fn parse_record(input: &Option<String>) -> Result<(), CliError> {
  let record_encoded = match input {
    Some(record) => record.clone(),
    None => io::read_to_string(io::stdin()).map_err(|_| Report::new(CliError::Parse))?,
  };
  let entry_bytes = base64::decode(record_encoded)
    .report()
    .change_context(CliError::Parse)?;
  let entry = deserialize_ipns_entry(&entry_bytes).change_context(CliError::Parse)?;
  // println!("record: {:?}", &entry);
  let name = Name::from_bytes(&entry.pub_key).change_context(CliError::Parse)?;
  validate_ipns_entry(&entry, name.public_key()).change_context(CliError::Parse)?;

  let revision = revision_from_ipns_entry(&entry, &name).change_context(CliError::Parse)?;
  // Ok(revision)
  println!("{}", revision);
  Ok(())
}

/// Returns true if the error report contains an [APIError] with a 404 status
fn is_404(report: &Report<ClientError>) -> bool {
  let maybe_api_err: Option<&APIError> = report.downcast_ref();
  if let Some(err) = maybe_api_err {
    err.status_code == 404
  } else {
    false
  }
}

/// Returns true if the error report contains an [APIError] with a 500 status
fn is_500(report: &Report<ClientError>) -> bool {
  let maybe_api_err: Option<&APIError> = report.downcast_ref();
  if let Some(err) = maybe_api_err {
    err.status_code == 500
  } else {
    false
  }
}


#[derive(Debug, Clone)]
enum CliError {
  Resolve,
  Publish,
  Create,
  Parse,
  Other,
}

impl Display for CliError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      CliError::Resolve => write!(f, "failed to resolve name"),
      CliError::Publish => write!(f, "failed to publish value"),
      CliError::Create => write!(f, "failed to create new keypair"),
      CliError::Parse => write!(f, "failed to parse record"),
      CliError::Other => write!(f, "operation failed"),
    }
  }
}

impl Error for CliError {}
