use std::{path::PathBuf, process::ExitCode, sync::OnceLock};

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;

use crate::client::KanidmClient;

mod client;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(short, long)]
    verbose: bool,

    #[arg(name = "USERNAME", required = true)]
    username: String,

    #[arg(name = "PASSWORD")]
    password: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut client = match get_client(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let password = args.password.unwrap_or_else(get_password);

    if let Err(e) = client.auth_anonymous() {
        eprintln!("Failed to authenticate: {e:?}");
        return ExitCode::FAILURE;
    }

    let token = match client.idm_account_unix_cred_verify(&args.username, &password) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to get token: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    if token.is_some_and(|t| t.valid) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn config_paths() -> &'static [&'static str] {
    const DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/kanidm/config"];

    static CONFIG_PATHS: OnceLock<&[&str]> = OnceLock::new();

    CONFIG_PATHS.get_or_init(|| {
        let mut paths = DEFAULT_CONFIG_PATHS.to_vec();
        if let Ok(mut home) = std::env::var("HOME") {
            home.push_str("/.config/kanidm");
            paths.push(String::leak(home))
        }
        Vec::leak(paths)
    })
}

fn get_client(args: &Args) -> Result<KanidmClient> {
    let mut contents = None;
    if let Some(cfg_path) = &args.config {
        match std::fs::read_to_string(cfg_path) {
            Ok(s) => {
                if args.verbose {
                    eprintln!(
                        "Using config file {cfg_path:?} (from {cfg_path:?} only)",
                        cfg_path = cfg_path
                    );
                }
                contents = Some(s)
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("Failed to read config file {cfg_path:?}: {e:?}")
                }
            }
        }
    } else {
        for path in config_paths() {
            match std::fs::read_to_string(path) {
                Ok(s) => {
                    if args.verbose {
                        eprintln!(
                            "Using config file {path:?} (from {paths:?})",
                            path = path,
                            paths = config_paths()
                        );
                    }
                    contents = Some(s)
                }
                Err(e) => {
                    if args.verbose {
                        eprintln!("Failed to read config file {path:?}: {e:?}")
                    }
                }
            }
        }
    }

    if let Some(contents) = contents {
        let config: ClientConfig = toml::from_str(&contents)?;
        Ok(KanidmClient::new(config.uri))
    } else {
        eprintln!("Failed to find config file");
        Err(anyhow::anyhow!("Failed to find config file"))
    }
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    pub uri: String,
}

fn get_password() -> String {
    // Check KANIDM_PASSWORD first
    if let Ok(password) = std::env::var("KANIDM_PASSWORD") {
        return password;
    };

    rpassword::read_password().unwrap()
}
