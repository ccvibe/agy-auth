use super::credential;
use super::ide_db;
use super::models::{Account, TokenData};
use super::oauth;
use super::protobuf;
use super::storage;
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
struct ImportEntry {
    email: Option<String>,
    name: Option<String>,
    refresh_token: String,
    tags: Vec<String>,
    notes: Option<String>,
    /// When importing a full Account payload, reuse token fields if refresh fails later? No — always refresh.
    token_override: Option<TokenData>,
}

#[derive(Debug)]
pub struct ImportSummary {
    pub imported: Vec<Account>,
    pub failed: Vec<(String, String)>,
}

/// Import the current Antigravity account from local OS / IDE / CLI credentials.
pub async fn import_from_local() -> Result<Account, String> {
    let (refresh_token, source) = discover_local_refresh_token()?;
    println!("Found local Antigravity credentials from: {}", source);
    import_from_refresh_token(
        refresh_token,
        None,
        None,
        Vec::new(),
        None,
        &format!("local ({})", source),
    )
    .await
}

/// Import one or more accounts from a JSON file (or raw JSON string content path).
pub async fn import_from_json_file(path: &Path) -> Result<ImportSummary, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read JSON file '{}': {}", path.display(), e))?;
    import_from_json_content(&content, path.file_stem().and_then(|s| s.to_str()))
        .await
}

pub async fn import_from_json_content(
    json_content: &str,
    filename_hint: Option<&str>,
) -> Result<ImportSummary, String> {
    let trimmed = json_content.trim();
    if trimmed.is_empty() {
        return Err("JSON content is empty".to_string());
    }

    let fallback_email = filename_hint
        .map(|s| s.replace("_at_", "@").replace("_AT_", "@"))
        .filter(|s| s.contains('@'));

    let mut entries = collect_import_entries(trimmed, &fallback_email)?;
    if entries.is_empty() {
        return Err("No valid refresh_token found in JSON".to_string());
    }

    // De-dupe by refresh_token (keep first)
    let mut seen = std::collections::HashSet::new();
    entries.retain(|e| seen.insert(e.refresh_token.clone()));

    let mut imported = Vec::new();
    let mut failed = Vec::new();
    let total = entries.len();

    for (index, entry) in entries.into_iter().enumerate() {
        let label = entry
            .email
            .clone()
            .unwrap_or_else(|| format!("entry #{}", index + 1));
        println!(
            "[{}/{}] Importing {}...",
            index + 1,
            total,
            label
        );

        // Prefer live refresh so tokens stay fresh. Fall back to embedded TokenData
        // only when the payload already has a full Account token and refresh fails.
        match import_from_refresh_token(
            entry.refresh_token.clone(),
            entry.email.clone(),
            entry.name.clone(),
            entry.tags.clone(),
            entry.notes.clone(),
            "json",
        )
        .await
        {
            Ok(account) => {
                println!("  -> {}", account.email);
                imported.push(account);
            }
            Err(refresh_err) => {
                if let Some(token) = entry.token_override {
                    let Some(email) = entry
                        .email
                        .clone()
                        .or_else(|| token.email.clone())
                        .filter(|s| !s.trim().is_empty())
                    else {
                        failed.push((
                            label,
                            format!(
                                "Refresh failed ({}) and JSON entry has no email",
                                refresh_err
                            ),
                        ));
                        continue;
                    };

                    // Use embedded token without network refresh as last resort.
                    match storage::upsert_account(email, entry.name.clone(), token) {
                        Ok(mut account) => {
                            if let Err(e) =
                                apply_metadata(&mut account, entry.tags, entry.notes)
                            {
                                failed.push((account.email.clone(), e));
                                continue;
                            }
                            println!("  -> {} (offline token)", account.email);
                            imported.push(account);
                        }
                        Err(e) => {
                            failed.push((
                                label,
                                format!(
                                    "save failed after refresh error ({}): {}",
                                    refresh_err, e
                                ),
                            ));
                        }
                    }
                } else {
                    failed.push((label, refresh_err));
                }
            }
        }
    }

    Ok(ImportSummary { imported, failed })
}

async fn import_from_refresh_token(
    refresh_token: String,
    email_hint: Option<String>,
    name_hint: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
    source_label: &str,
) -> Result<Account, String> {
    let refresh_token = refresh_token.trim().to_string();
    if refresh_token.is_empty() {
        return Err(format!("{} refresh_token is empty", source_label));
    }

    let token_response = oauth::refresh_access_token(&refresh_token).await?;
    let user_info = oauth::get_user_info(&token_response.access_token).await?;

    let email = email_hint
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| user_info.email.clone());

    let name = name_hint
        .filter(|s| !s.trim().is_empty())
        .or_else(|| user_info.get_display_name());

    let final_refresh = token_response
        .refresh_token
        .unwrap_or(refresh_token);

    let token = TokenData::new(
        token_response.access_token,
        final_refresh,
        token_response.expires_in,
        Some(email.clone()),
    )
    .with_oauth_metadata(token_response.oauth_client_key, token_response.id_token);

    let mut account = storage::upsert_account(email, name, token)?;
    apply_metadata(&mut account, tags, notes)?;
    Ok(account)
}

fn apply_metadata(
    account: &mut Account,
    tags: Vec<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let mut changed = false;
    if !tags.is_empty() {
        account.tags = tags;
        changed = true;
    }
    if let Some(notes) = notes {
        account.notes = Some(notes);
        changed = true;
    }
    if changed {
        storage::save_account(account)?;
    }
    Ok(())
}

fn discover_local_refresh_token() -> Result<(String, &'static str), String> {
    let mut errors = Vec::new();

    // 1) OS secret storage (Keychain / Credential Manager / secret-tool)
    match credential::read_antigravity_system_credential() {
        Ok(Some(cred)) => {
            if !cred.refresh_token.trim().is_empty() {
                return Ok((cred.refresh_token, "system credential store"));
            }
            errors.push("system credential store: empty refresh_token".to_string());
        }
        Ok(None) => errors.push("system credential store: not found".to_string()),
        Err(e) => errors.push(format!("system credential store: {}", e)),
    }

    // 2) AGY / Antigravity CLI oauth token file
    match read_cli_oauth_refresh_token() {
        Ok(Some(token)) => return Ok((token, "CLI oauth token file")),
        Ok(None) => errors.push("CLI oauth token file: not found".to_string()),
        Err(e) => errors.push(format!("CLI oauth token file: {}", e)),
    }

    // 3) Antigravity IDE state.vscdb
    match read_ide_db_refresh_token() {
        Ok(Some(token)) => return Ok((token, "IDE state.vscdb")),
        Ok(None) => errors.push("IDE state.vscdb: not found or empty".to_string()),
        Err(e) => errors.push(format!("IDE state.vscdb: {}", e)),
    }

    Err(format!(
        "Could not find a local Antigravity account. Tried:\n  - {}",
        errors.join("\n  - ")
    ))
}

fn read_cli_oauth_refresh_token() -> Result<Option<String>, String> {
    let home = dirs::home_dir().ok_or("Unable to get home directory")?;
    let candidates = [
        home.join(".gemini/antigravity-cli/antigravity-oauth-token"),
        home.join(".gemini/antigravity/antigravity-oauth-token"),
    ];

    for path in candidates {
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

        if let Some(token) = value
            .pointer("/token/refresh_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(token.to_string()));
        }
        if let Some(token) = value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(token.to_string()));
        }
    }

    Ok(None)
}

fn read_ide_db_refresh_token() -> Result<Option<String>, String> {
    let Some(db_path) = ide_db::get_default_ide_db_path() else {
        return Ok(None);
    };

    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| format!("Failed to open IDE database: {}", e))?;

    let state_data: String = match conn.query_row(
        "SELECT value FROM ItemTable WHERE key = ?",
        ["antigravityUnifiedStateSync.oauthToken"],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(format!("Failed to query IDE oauth token: {}", e)),
    };

    let blob = general_purpose::STANDARD
        .decode(state_data.trim())
        .map_err(|e| format!("Failed to base64-decode IDE oauth token: {}", e))?;

    Ok(protobuf::extract_refresh_token_from_unified_oauth_token(&blob))
}

fn collect_import_entries(
    json_content: &str,
    fallback_email: &Option<String>,
) -> Result<Vec<ImportEntry>, String> {
    // 1) Simplified format: [{email, refresh_token}] or single object
    #[derive(Debug, serde::Deserialize)]
    struct SimpleAccount {
        email: String,
        refresh_token: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        notes: Option<String>,
    }

    if let Ok(accounts) = serde_json::from_str::<Vec<SimpleAccount>>(json_content)
        .or_else(|_| serde_json::from_str::<SimpleAccount>(json_content).map(|a| vec![a]))
    {
        return Ok(accounts
            .into_iter()
            .filter(|a| !a.refresh_token.trim().is_empty())
            .map(|a| ImportEntry {
                email: Some(a.email),
                name: a.name,
                refresh_token: a.refresh_token.trim().to_string(),
                tags: a.tags,
                notes: a.notes,
                token_override: None,
            })
            .collect());
    }

    // 2) Full Account format (single or array) — cockpit / ~/.agy_auth export compatible
    if let Ok(accounts) = serde_json::from_str::<Vec<Account>>(json_content)
        .or_else(|_| serde_json::from_str::<Account>(json_content).map(|a| vec![a]))
    {
        return Ok(accounts
            .into_iter()
            .filter(|a| !a.token.refresh_token.trim().is_empty())
            .map(|a| ImportEntry {
                email: Some(a.email.clone()),
                name: a.name.clone(),
                refresh_token: a.token.refresh_token.clone(),
                tags: a.tags.clone(),
                notes: a.notes.clone(),
                token_override: Some(a.token),
            })
            .collect());
    }

    // 3) Generic JSON object / array extraction (token.refresh_token etc.)
    let parsed: serde_json::Value = serde_json::from_str(json_content)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let mut entries = Vec::new();
    match parsed {
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(entry) = extract_import_entry(&item, fallback_email) {
                    entries.push(entry);
                }
            }
        }
        serde_json::Value::Object(_) => {
            if let Some(entry) = extract_import_entry(&parsed, fallback_email) {
                entries.push(entry);
            }
        }
        _ => return Err("Unsupported JSON format (expected object or array)".to_string()),
    }

    Ok(entries)
}

fn extract_import_entry(
    value: &serde_json::Value,
    fallback_email: &Option<String>,
) -> Option<ImportEntry> {
    let obj = value.as_object()?;

    let refresh_token = obj
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("refreshToken").and_then(|v| v.as_str()))
        .or_else(|| {
            obj.get("token")
                .and_then(|t| t.get("refresh_token"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            obj.get("token")
                .and_then(|t| t.get("refreshToken"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;

    let email = obj
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| fallback_email.clone());

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let tags = obj
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|val| val.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let notes = obj
        .get("notes")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Capture nested token if present for offline fallback
    let token_override = if let Some(token_val) = obj.get("token") {
        serde_json::from_value::<TokenData>(token_val.clone()).ok()
    } else {
        None
    };

    Some(ImportEntry {
        email,
        name,
        refresh_token,
        tags,
        notes,
        token_override,
    })
}
