use serde::{Deserialize, Serialize};

fn decrypt(bytes: &[u8]) -> String {
    let decrypted: Vec<u8> = bytes.iter().map(|&b| b ^ 0x55).collect();
    String::from_utf8(decrypted).unwrap()
}

fn get_client_id() -> String {
    std::env::var("GOOGLE_CLIENT_ID").unwrap_or_else(|_| {
        let bytes = [100, 101, 98, 100, 101, 101, 99, 101, 99, 101, 96, 108, 100, 120, 33, 56, 61, 38, 38, 60, 59, 103, 61, 103, 100, 57, 54, 39, 48, 103, 102, 96, 35, 33, 58, 57, 58, 63, 61, 97, 50, 97, 101, 102, 48, 37, 123, 52, 37, 37, 38, 123, 50, 58, 58, 50, 57, 48, 32, 38, 48, 39, 54, 58, 59, 33, 48, 59, 33, 123, 54, 58, 56];
        decrypt(&bytes)
    })
}

fn get_client_secret() -> String {
    std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_else(|_| {
        let bytes = [18, 26, 22, 6, 5, 13, 120, 30, 96, 109, 19, 2, 7, 97, 109, 99, 25, 49, 25, 31, 100, 56, 25, 23, 109, 38, 13, 22, 97, 47, 99, 36, 17, 20, 51];
        decrypt(&bytes)
    })
}

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_OAUTH_CLIENT_KEY: &str = "antigravity_enterprise";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(skip)]
    pub oauth_client_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(default)]
    pub id: Option<String>,
    pub email: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

impl UserInfo {
    pub fn get_display_name(&self) -> Option<String> {
        if let Some(name) = &self.name {
            if !name.trim().is_empty() {
                return Some(name.clone());
            }
        }
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            (None, None) => None,
        }
    }
}

pub fn get_auth_url(redirect_uri: &str, state: Option<&str>) -> String {
    let scopes = vec![
        "openid",
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/cclog",
        "https://www.googleapis.com/auth/experimentsandconfigs",
    ]
    .join(" ");

    let client_id = get_client_id();
    let mut params = vec![
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", &scopes),
        ("access_type", "offline"),
        ("prompt", "consent"),
    ];

    if let Some(state) = state.filter(|value| !value.trim().is_empty()) {
        params.push(("state", state));
    }

    let url = url::Url::parse_with_params(AUTH_URL, &params).expect("Invalid Auth URL");
    url.to_string()
}

pub async fn exchange_code(code: &str, redirect_uri: &str) -> Result<TokenResponse, String> {
    let client = reqwest::Client::new();
    let client_id = get_client_id();
    let client_secret = get_client_secret();
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];

    let response = client
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {}", e))?;

    let status = response.status();
    if status.is_success() {
        let mut token_res = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;
        token_res.oauth_client_key = Some(DEFAULT_OAUTH_CLIENT_KEY.to_string());
        Ok(token_res)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Token exchange failed ({}): {}", status, error_text))
    }
}

pub async fn refresh_access_token(refresh_token: &str) -> Result<TokenResponse, String> {
    let client = reqwest::Client::new();
    let client_id = get_client_id();
    let client_secret = get_client_secret();
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];

    let response = client
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Refresh token request failed: {}", e))?;

    if response.status().is_success() {
        let mut token_data = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| format!("Failed to parse refresh response: {}", e))?;
        token_data.oauth_client_key = Some(DEFAULT_OAUTH_CLIENT_KEY.to_string());
        Ok(token_data)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Refresh token failed: {}", error_text))
    }
}

pub async fn get_user_info(access_token: &str) -> Result<UserInfo, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("UserInfo request failed: {}", e))?;

    if response.status().is_success() {
        response
            .json::<UserInfo>()
            .await
            .map_err(|e| format!("Failed to parse user info: {}", e))
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to retrieve user info: {}", error_text))
    }
}

pub async fn ensure_fresh_token(
    current_token: &super::models::TokenData,
) -> Result<super::models::TokenData, String> {
    let now = chrono::Utc::now().timestamp();
    if current_token.expiry_timestamp > now + 300 {
        return Ok(current_token.clone());
    }

    let response = refresh_access_token(&current_token.refresh_token).await?;
    let mut token = super::models::TokenData::new(
        response.access_token,
        current_token.refresh_token.clone(),
        response.expires_in,
        current_token.email.clone(),
    ).with_oauth_metadata(
        response.oauth_client_key,
        response.id_token.or_else(|| current_token.id_token.clone()),
    );
    token.is_gcp_tos = current_token.is_gcp_tos;
    token.project_id = current_token.project_id.clone();
    Ok(token)
}
