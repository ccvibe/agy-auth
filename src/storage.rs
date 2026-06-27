use super::models::{Account, AccountIndex, AccountSummary};
use std::fs;
use std::path::PathBuf;

const DATA_DIR: &str = ".agy_auth";
const ACCOUNTS_INDEX: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";

pub fn get_data_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Unable to get home directory")?;
    let path = home.join(DATA_DIR);
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create data directory: {}", e))?;
    }
    Ok(path)
}

pub fn get_accounts_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let path = data_dir.join(ACCOUNTS_DIR);
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create accounts directory: {}", e))?;
    }
    Ok(path)
}

pub fn load_account_index() -> Result<AccountIndex, String> {
    let data_dir = get_data_dir()?;
    let path = data_dir.join(ACCOUNTS_INDEX);
    if !path.exists() {
        return Ok(AccountIndex::new());
    }

    let content = fs::read_to_string(&path).map_err(|e| format!("Failed to read index: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse index: {}", e))
}

pub fn save_account_index(index: &AccountIndex) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let path = data_dir.join(ACCOUNTS_INDEX);
    let content = serde_json::to_string_pretty(index)
        .map_err(|e| format!("Failed to serialize index: {}", e))?;
    fs::write(&path, content).map_err(|e| format!("Failed to write index: {}", e))
}

pub fn load_account(account_id: &str) -> Result<Account, String> {
    let accounts_dir = get_accounts_dir()?;
    let path = accounts_dir.join(format!("{}.json", account_id));
    if !path.exists() {
        return Err(format!("Account not found: {}", account_id));
    }

    let content = fs::read_to_string(&path).map_err(|e| format!("Failed to read account file: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse account: {}", e))
}

pub fn save_account(account: &Account) -> Result<(), String> {
    let accounts_dir = get_accounts_dir()?;
    let path = accounts_dir.join(format!("{}.json", account.id));
    let content = serde_json::to_string_pretty(account)
        .map_err(|e| format!("Failed to serialize account: {}", e))?;
    fs::write(&path, content).map_err(|e| format!("Failed to write account file: {}", e))
}

pub fn delete_account(account_id: &str) -> Result<(), String> {
    let accounts_dir = get_accounts_dir()?;
    let path = accounts_dir.join(format!("{}.json", account_id));
    if path.exists() {
        let _ = fs::remove_file(path);
    }

    let mut index = load_account_index()?;
    index.accounts.retain(|acc| acc.id != account_id);
    if index.current_account_id.as_deref() == Some(account_id) {
        index.current_account_id = None;
    }
    save_account_index(&index)?;

    Ok(())
}

pub fn list_accounts() -> Result<Vec<Account>, String> {
    let index = load_account_index()?;
    let mut list = Vec::new();
    for summary in index.accounts {
        if let Ok(acc) = load_account(&summary.id) {
            list.push(acc);
        }
    }
    Ok(list)
}

pub fn get_current_account_id() -> Option<String> {
    load_account_index().ok().and_then(|idx| idx.current_account_id)
}

pub fn set_current_account_id(account_id: &str) -> Result<(), String> {
    let mut index = load_account_index()?;
    index.current_account_id = Some(account_id.to_string());
    save_account_index(&index)
}

pub fn upsert_account(
    email: String,
    name: Option<String>,
    token: super::models::TokenData,
) -> Result<Account, String> {
    let mut index = load_account_index()?;
    
    // Find matching ID by email
    let matching_id = index.accounts.iter().find(|acc| acc.email.eq_ignore_ascii_case(&email)).map(|acc| acc.id.clone());
    
    let account_id = matching_id.unwrap_or_else(|| {
        uuid::Uuid::new_v4().to_string()
    });

    let account = if let Ok(mut existing) = load_account(&account_id) {
        existing.token = token;
        existing.name = name.clone();
        existing.update_last_used();
        existing
    } else {
        let mut new_acc = Account::new(account_id.clone(), email.clone(), token);
        new_acc.name = name.clone();
        new_acc
    };

    save_account(&account)?;

    // Update index
    index.accounts.retain(|acc| acc.id != account_id);
    index.accounts.push(AccountSummary {
        id: account_id,
        email,
        name,
        created_at: account.created_at,
        last_used: account.last_used,
    });
    save_account_index(&index)?;

    Ok(account)
}
