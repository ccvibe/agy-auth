use super::models::Account;
use super::protobuf;
use base64::{engine::general_purpose, Engine as _};
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};

pub fn get_default_ide_db_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()?;
        let path = home.join("Library/Application Support/Antigravity IDE/User/globalStorage/state.vscdb");
        if path.exists() {
            return Some(path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        let appdata = PathBuf::from(appdata);
        let candidates = vec![
            appdata.join("Antigravity IDE").join("User").join("globalStorage").join("state.vscdb"),
            appdata.join("Antigravity").join("User").join("globalStorage").join("state.vscdb"),
        ];
        for path in candidates {
            if path.exists() {
                return Some(path);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir()?;
        let path = home.join(".config/Antigravity IDE/User/globalStorage/state.vscdb");
        if path.exists() {
            return Some(path);
        }
    }

    None
}

pub fn inject_account_to_ide_db(db_path: &Path, account: &Account) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|e| format!("Failed to open state database: {}", e))?;

    // 1. Inject Unified OAuth Token
    let current_topic: Vec<u8> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?",
            ["antigravityUnifiedStateSync.oauthToken"],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("Failed to query Unified OAuth token: {}", e))?
        .map(|value| {
            general_purpose::STANDARD
                .decode(value)
                .map_err(|e| format!("Failed to decode Unified OAuth Base64: {}", e))
        })
        .transpose()?
        .unwrap_or_default();

    let mut topic = protobuf::remove_unified_topic_entry(&current_topic, "oauthTokenInfoSentinelKey")?;

    let oauth_info = protobuf::create_oauth_info_with_metadata(
        &account.token.access_token,
        &account.token.refresh_token,
        account.token.expiry_timestamp,
        account.token.is_gcp_tos,
        account.token.id_token.as_deref(),
        Some(&account.email),
    );

    topic.extend(protobuf::create_unified_topic_entry(
        "oauthTokenInfoSentinelKey",
        &oauth_info,
    ));
    let topic_b64 = general_purpose::STANDARD.encode(&topic);

    conn.execute(
        "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
        ["antigravityUnifiedStateSync.oauthToken", &topic_b64],
    )
    .map_err(|e| format!("Failed to write Unified OAuth token to db: {}", e))?;

    // 2. Inject User Status
    let user_status_payload = protobuf::create_minimal_user_status_payload(&account.email);
    let user_status_topic = protobuf::create_unified_topic_entry("userStatusSentinelKey", &user_status_payload);
    let user_status_b64 = general_purpose::STANDARD.encode(user_status_topic);

    conn.execute(
        "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
        ["antigravityUnifiedStateSync.userStatus", &user_status_b64],
    )
    .map_err(|e| format!("Failed to write User Status to db: {}", e))?;

    // 3. Inject Onboarding flag
    conn.execute(
        "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
        ["antigravityOnboarding", "true"],
    )
    .map_err(|e| format!("Failed to write onboarding flag to db: {}", e))?;

    Ok(())
}
