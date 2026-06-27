mod models;
mod oauth;
mod credential;
mod storage;
mod ide_db;
mod protobuf;

use clap::{Parser, Subcommand};
use models::{Account, TokenData};
use colored::*;
use std::process::Command;
use tabled::{Table, Tabled};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "agy-auth")]
#[command(author, version, about = "AGY CLI Multi-Account Management Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all Antigravity/AGY accounts
    #[command(alias = "ls")]
    List,

    /// Add a new account (using interactive browser login or refresh token)
    #[command(alias = "login")]
    Add {
        /// Optional: Google OAuth refresh token. If not provided, starts interactive browser login.
        refresh_token: Option<String>,
    },

    /// Switch active account
    #[command(alias = "use")]
    Switch {
        /// The account ID or Email to switch to
        account: Option<String>,
    },

    /// Show the currently active account details
    #[command(alias = "whoami")]
    Current,

    /// Delete an account from the local registry
    #[command(alias = "remove")]
    Delete {
        /// The account ID or Email to delete
        account: String,
    },
}

#[derive(Tabled)]
struct AccountDisplay {
    #[tabled(rename = "Active")]
    active: String,
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Email")]
    email: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Tags")]
    tags: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            if let Err(e) = list_accounts().await {
                eprintln!("{} {}", "Error:".red(), e);
            }
        }
        Commands::Add { refresh_token } => {
            if let Err(e) = add_account(refresh_token).await {
                eprintln!("{} {}", "Error:".red(), e);
            }
        }
        Commands::Switch { account } => {
            if let Err(e) = switch_account(account.as_deref()).await {
                eprintln!("{} {}", "Error:".red(), e);
            }
        }
        Commands::Current => {
            if let Err(e) = show_current_account().await {
                eprintln!("{} {}", "Error:".red(), e);
            }
        }
        Commands::Delete { account } => {
            if let Err(e) = delete_account(&account).await {
                eprintln!("{} {}", "Error:".red(), e);
            }
        }
    }

    Ok(())
}

async fn list_accounts() -> anyhow::Result<()> {
    let accounts = storage::list_accounts().map_err(|e| anyhow::anyhow!(e))?;
    let current_id = storage::get_current_account_id();

    let display_list: Vec<AccountDisplay> = accounts
        .into_iter()
        .map(|acc| {
            let active = if Some(acc.id.clone()) == current_id {
                "  *  ".green().bold().to_string()
            } else {
                "".to_string()
            };
            AccountDisplay {
                active,
                id: acc.id,
                email: acc.email,
                name: acc.name.unwrap_or_default(),
                tags: acc.tags.join(", "),
            }
        })
        .collect();

    if display_list.is_empty() {
        println!("No AGY accounts registered. Use `agy-auth add` to log in.");
    } else {
        println!("{}", Table::new(display_list).to_string());
    }

    Ok(())
}

async fn add_account(refresh_token: Option<String>) -> anyhow::Result<()> {
    let token = match refresh_token {
        Some(rt) => rt,
        None => {
            // Interactive login via browser callback
            run_interactive_login().await?
        }
    };

    println!("Authenticating with Google OAuth...");
    let token_res = oauth::refresh_access_token(&token)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to exchange token: {}", e))?;
    let user_info = oauth::get_user_info(&token_res.access_token)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to retrieve user info: {}", e))?;

    let token_data = TokenData::new(
        token_res.access_token,
        token.clone(),
        token_res.expires_in,
        Some(user_info.email.clone()),
    )
    .with_oauth_metadata(token_res.oauth_client_key, token_res.id_token);

    let email = user_info.email.clone();
    let display_name = user_info.get_display_name();

    storage::upsert_account(email.clone(), display_name, token_data)
        .map_err(|e| anyhow::anyhow!("Failed to register account: {}", e))?;

    println!("Successfully registered account: {}", email.bright_green());
    println!("Use `agy-auth switch {}` to switch to this account.", email.cyan());

    Ok(())
}

async fn run_interactive_login() -> anyhow::Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to local port: {}", e))?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{}/oauth-callback", port);
    let expected_state = uuid::Uuid::new_v4().to_string();

    let auth_url = oauth::get_auth_url(&redirect_uri, Some(&expected_state));

    println!("{}\n", "Please open the following link in your browser to authorize AGY CLI:".bright_blue().bold());
    println!("  {}", auth_url.underline().cyan());
    println!("\nWaiting for browser callback on port {}...", port);

    open_browser(&auth_url);

    let timeout_dur = tokio::time::Duration::from_secs(300);

    tokio::select! {
        res = accept_and_extract_code(listener, &expected_state, port) => {
            let auth_code = res?;
            println!("Authorization code received! Exchanging code...");
            let token_res = oauth::exchange_code(&auth_code, &redirect_uri)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to exchange authorization code: {}", e))?;
            let refresh_token = token_res.refresh_token.ok_or_else(|| {
                anyhow::anyhow!("Google did not return a refresh token. If you've logged in before, please revoke access first or pass the refresh token manually.")
            })?;
            Ok(refresh_token)
        }
        _ = tokio::time::sleep(timeout_dur) => {
            Err(anyhow::anyhow!("Interactive login timed out after 5 minutes"))
        }
    }
}

async fn accept_and_extract_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
    port: u16,
) -> anyhow::Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buffer = [0u8; 4096];
        let bytes_read = stream.read(&mut buffer).await?;
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);

        let first_line = match request.lines().next() {
            Some(line) => line,
            None => continue,
        };
        let mut parts = first_line.split_whitespace();
        let method = parts.next();
        let target = parts.next();

        if let (Some("GET"), Some(path)) = (method, target) {
            let full_url = format!("http://localhost:{}{}", port, path);
            if let Ok(url) = url::Url::parse(&full_url) {
                if url.path() == "/oauth-callback" {
                    let mut code = None;
                    let mut state = None;
                    for (key, val) in url.query_pairs() {
                        if key == "code" {
                            code = Some(val.into_owned());
                        } else if key == "state" {
                            state = Some(val.into_owned());
                        }
                    }

                    if let (Some(c), Some(s)) = (code, state) {
                        if s != expected_state {
                            let response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nState mismatch error.";
                            let _ = stream.write_all(response.as_bytes()).await;
                            return Err(anyhow::anyhow!("OAuth state mismatch"));
                        }

                        let html = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n\
                        <html>\
                        <body style='font-family: sans-serif; text-align: center; padding: 50px; background: #0d1117; color: #fff;'>\
                            <h1 style='color: #4ade80;'>\u{2705} 授权成功!</h1>\
                            <p>您已成功登录，可以关闭此窗口返回终端。</p>\
                            <script>setTimeout(function() { window.close(); }, 2000);</script>\
                        </body>\
                        </html>";
                        let _ = stream.write_all(html.as_bytes()).await;
                        let _ = stream.flush().await;
                        return Ok(c);
                    }
                }
            }
        }

        let response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot Found";
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = Command::new("cmd").args(["/c", "start", url]).spawn();
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(url).spawn();
}

async fn switch_account(account_ref: Option<&str>) -> anyhow::Result<()> {
    let accounts = storage::list_accounts().map_err(|e| anyhow::anyhow!(e))?;
    if accounts.is_empty() {
        return Err(anyhow::anyhow!(
            "No registered accounts found. Please add an account using `agy-auth add` first."
        ));
    }

    let target = match account_ref {
        Some(r) => accounts
            .into_iter()
            .find(|acc| acc.id == r || acc.email.eq_ignore_ascii_case(r))
            .ok_or_else(|| anyhow::anyhow!("Account not found matching: '{}'", r))?,
        None => {
            use dialoguer::{theme::ColorfulTheme, Select};

            let current_id = storage::get_current_account_id();
            let mut items = Vec::new();
            let mut default_idx = 0;

            for (idx, acc) in accounts.iter().enumerate() {
                let mut label = acc.email.clone();
                if let Some(ref name) = acc.name {
                    if !name.is_empty() {
                        label = format!("{} ({})", label, name);
                    }
                }
                if Some(acc.id.clone()) == current_id {
                    label = format!("{} [Active]", label);
                    default_idx = idx;
                }
                items.push(label);
            }

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select the account to switch to")
                .default(default_idx)
                .items(&items)
                .interact_opt()
                .map_err(|e| anyhow::anyhow!("Failed to read selection: {}", e))?;

            match selection {
                Some(idx) => accounts.into_iter().nth(idx).unwrap(),
                None => {
                    println!("Switch cancelled.");
                    return Ok(());
                }
            }
        }
    };

    switch_to_account_object(&target).await
}

async fn switch_to_account_object(target: &Account) -> anyhow::Result<()> {
    let mut account = target.clone();
    
    // Ensure token is fresh
    let fresh_token = oauth::ensure_fresh_token(&account.token)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to refresh access token: {}", e))?;
    if fresh_token.access_token != account.token.access_token {
        account.token = fresh_token;
    }

    // Set current active account in cockpit registry
    storage::set_current_account_id(&account.id).map_err(|e| anyhow::anyhow!(e))?;
    account.update_last_used();
    storage::save_account(&account).map_err(|e| anyhow::anyhow!(e))?;

    // Inject system credentials (Keychain / Credential Manager / Secret Service)
    credential::write_antigravity_system_credential(&account)
        .map_err(|e| anyhow::anyhow!("Failed to write system credentials: {}", e))?;

    // Optionally inject into the Antigravity IDE SQLite profile if it exists
    if let Some(db_path) = ide_db::get_default_ide_db_path() {
        let _ = ide_db::inject_account_to_ide_db(&db_path, &account);
    }

    println!(
        "{} Switched to AGY account: {}",
        "Success:".green().bold(),
        account.email.bright_green()
    );

    Ok(())
}

async fn show_current_account() -> anyhow::Result<()> {
    let current_id = storage::get_current_account_id();
    if let Some(id) = current_id {
        let account = storage::load_account(&id).map_err(|e| anyhow::anyhow!(e))?;
        println!("Currently active AGY account:");
        println!("  {:<10} {}", "Email:".bright_blue(), account.email);
        println!("  {:<10} {}", "ID:".bright_blue(), account.id);
        println!("  {:<10} {}", "Name:".bright_blue(), account.name.unwrap_or_default());
        println!("  {:<10} {}", "Tags:".bright_blue(), account.tags.join(", "));
        println!("  {:<10} {}", "Created:".bright_blue(), chrono::DateTime::from_timestamp(account.created_at, 0).unwrap_or_default().to_rfc3339());
        println!("  {:<10} {}", "Last Used:".bright_blue(), chrono::DateTime::from_timestamp(account.last_used, 0).unwrap_or_default().to_rfc3339());
    } else {
        println!("No active AGY account selected. Use `agy-auth switch <account_id_or_email>` or `agy-auth add`.");
    }
    Ok(())
}

async fn delete_account(account_ref: &str) -> anyhow::Result<()> {
    let accounts = storage::list_accounts().map_err(|e| anyhow::anyhow!(e))?;
    let target = accounts.into_iter().find(|acc| {
        acc.id == account_ref || acc.email.eq_ignore_ascii_case(account_ref)
    }).ok_or_else(|| {
        anyhow::anyhow!("Account not found matching: '{}'", account_ref)
    })?;

    storage::delete_account(&target.id).map_err(|e| anyhow::anyhow!(e))?;
    println!("{} Deleted account: {}", "Success:".green().bold(), target.email.bright_green());

    // If we deleted the active account, clear the current active selection
    let current_id = storage::get_current_account_id();
    if current_id == Some(target.id) {
        let mut index = storage::load_account_index().map_err(|e| anyhow::anyhow!(e))?;
        index.current_account_id = None;
        storage::save_account_index(&index).map_err(|e| anyhow::anyhow!(e))?;
        println!("The active account was deleted. No active account is currently selected.");
    }

    Ok(())
}
