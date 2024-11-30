use std::{path::PathBuf, process::ExitCode, sync::OnceLock};

use clap::Parser;
use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(name = "USERNAME", required = true)]
    username: String,

    #[arg(name = "PASSWORD")]
    password: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let client = match get_client(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let password = args.password.unwrap_or_else(get_password);

    if let Err(e) = client.auth_anonymous().await {
        eprintln!("Failed to authenticate: {e:?}");
        return ExitCode::FAILURE;
    }

    let token = match client
        .idm_account_unix_cred_verify(&args.username, &password)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to get token: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    if token.is_some() {
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

fn get_client(args: &Args) -> Result<KanidmClient, ClientError> {
    let mut builder = KanidmClientBuilder::new();

    if let Some(cfg_path) = &args.config {
        builder = builder.read_options_from_optional_config(cfg_path)?;
    } else {
        for path in config_paths() {
            builder = builder.read_options_from_optional_config(path)?;
        }
    }

    builder.build()
}

fn get_password() -> String {
    // Check KANIDM_PASSWORD first
    if let Ok(password) = std::env::var("KANIDM_PASSWORD") {
        return password;
    };

    rpassword::read_password().unwrap()
}
