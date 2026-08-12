use base64::{engine::general_purpose, Engine as _};

/// Protobuf Varint encoding
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while value >= 0x80 {
        buf.push((value & 0x7F | 0x80) as u8);
        value >>= 7;
    }
    buf.push(value as u8);
    buf
}

/// Encode length-delimited field (wire_type = 2)
pub fn encode_len_delim_field(field_num: u32, data: &[u8]) -> Vec<u8> {
    let tag = (field_num << 3) | 2;
    let mut f = encode_varint(tag as u64);
    f.extend(encode_varint(data.len() as u64));
    f.extend_from_slice(data);
    f
}

/// Encode string field (wire_type = 2)
pub fn encode_string_field(field_num: u32, value: &str) -> Vec<u8> {
    encode_len_delim_field(field_num, value.as_bytes())
}

/// Encode Varint field (wire_type = 0)
pub fn encode_varint_field(field_num: u32, value: u64) -> Vec<u8> {
    let tag = (field_num << 3) | 0;
    let mut field = encode_varint(tag as u64);
    field.extend(encode_varint(value));
    field
}

/// Read Protobuf Varint
pub fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            return Err("Incomplete protobuf varint".to_string());
        }
        let byte = data[pos];
        result |= ((byte & 0x7F) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    Ok((result, pos))
}

/// Skip Protobuf field
pub fn skip_field(data: &[u8], offset: usize, wire_type: u8) -> Result<usize, String> {
    match wire_type {
        0 => {
            // Varint
            let (_, new_offset) = read_varint(data, offset)?;
            Ok(new_offset)
        }
        1 => {
            // 64-bit
            Ok(offset + 8)
        }
        2 => {
            // Length-delimited
            let (length, content_offset) = read_varint(data, offset)?;
            Ok(content_offset + length as usize)
        }
        5 => {
            // 32-bit
            Ok(offset + 4)
        }
        _ => Err(format!("Unknown wire_type: {}", wire_type)),
    }
}

/// Create OAuthTokenInfo message with official metadata
pub fn create_oauth_info_with_metadata(
    access_token: &str,
    refresh_token: &str,
    expiry: i64,
    is_gcp_tos: Option<bool>,
    id_token: Option<&str>,
    email: Option<&str>,
) -> Vec<u8> {
    let mut is_gcp_tos = is_gcp_tos.unwrap_or(false);
    if let Some(email) = email.map(str::trim).filter(|value| !value.is_empty()) {
        let lower = email.to_ascii_lowercase();
        if lower.ends_with("@gmail.com") || lower.ends_with("@googlemail.com") {
            is_gcp_tos = false;
        }
    }

    // Field 1: access_token (string, wire_type = 2)
    let field1 = encode_string_field(1, access_token);

    // Field 2: token_type (string, fixed value "Bearer", wire_type = 2)
    let field2 = encode_string_field(2, "Bearer");

    // Field 3: refresh_token (string, wire_type = 2)
    let field3 = encode_string_field(3, refresh_token);

    // Field 4: expiry (nested Timestamp message, wire_type = 2)
    let timestamp_tag = (1 << 3) | 0;
    let mut timestamp_msg = encode_varint(timestamp_tag);
    timestamp_msg.extend(encode_varint(expiry as u64));
    timestamp_msg.extend(encode_varint_field(2, 0));

    let field4 = encode_len_delim_field(4, &timestamp_msg);

    let mut oauth_info = Vec::new();
    oauth_info.extend(field1);
    oauth_info.extend(field2);
    oauth_info.extend(field3);
    oauth_info.extend(field4);
    if let Some(id_token) = id_token.map(str::trim).filter(|value| !value.is_empty()) {
        oauth_info.extend(encode_string_field(5, id_token));
    }
    if is_gcp_tos {
        oauth_info.extend(encode_varint_field(6, 1));
    }
    oauth_info
}

/// Create unified-state Topic.data entry
pub fn create_unified_topic_entry(sentinel_key: &str, payload: &[u8]) -> Vec<u8> {
    let row = encode_string_field(1, &general_purpose::STANDARD.encode(payload));
    let entry = [
        encode_string_field(1, sentinel_key),
        encode_len_delim_field(2, &row),
    ]
    .concat();
    encode_len_delim_field(1, &entry)
}

/// Create minimal UserStatus payload
pub fn create_minimal_user_status_payload(email: &str) -> Vec<u8> {
    [encode_string_field(3, email), encode_string_field(7, email)].concat()
}

/// Remove specified map entry from Topic.data, keeping other sentinel rows intact
pub fn remove_unified_topic_entry(data: &[u8], target_key: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let start_offset = offset;
        let (tag, new_offset) = read_varint(data, offset)?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        let next_offset = skip_field(data, new_offset, wire_type)?;

        let should_remove = if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return Err("Incomplete Topic.data entry".to_string());
            }
            let entry = &data[content_offset..content_offset + length];
            unified_topic_entry_key(entry) == Some(target_key)
        } else {
            false
        };

        if !should_remove {
            result.extend_from_slice(&data[start_offset..next_offset]);
        }
        offset = next_offset;
    }

    Ok(result)
}

fn unified_topic_entry_key(data: &[u8]) -> Option<&str> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            return std::str::from_utf8(&data[content_offset..content_offset + length]).ok();
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

/// Extract refresh_token from `antigravityUnifiedStateSync.oauthToken` blob.
/// Primary path: Topic.data[oauthTokenInfoSentinelKey].Row.value = base64(OAuthTokenInfo), field 3.
/// Fallback: walk length-delimited fields looking for a Google refresh token (`1//...`).
pub fn extract_refresh_token_from_unified_oauth_token(data: &[u8]) -> Option<String> {
    if let Some(token) = extract_refresh_token_via_sentinel(data) {
        return Some(token);
    }
    scan_refresh_token_strings(data)
}

fn extract_refresh_token_via_sentinel(data: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let entry = &data[content_offset..content_offset + length];
            if let Some(refresh_token) = extract_refresh_token_from_unified_entry(entry) {
                return Some(refresh_token);
            }
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

fn extract_refresh_token_from_unified_entry(data: &[u8]) -> Option<String> {
    let mut offset = 0;
    let mut sentinel_matched = false;
    let mut row_data: Option<Vec<u8>> = None;

    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let value = &data[content_offset..content_offset + length];
            if field_num == 1 {
                if let Ok(key) = std::str::from_utf8(value) {
                    // Official sentinel written by agy-auth / cockpit inject path.
                    // Also accept native IDE variants that embed OAuthTokenInfo the same way.
                    sentinel_matched = key == "oauthTokenInfoSentinelKey"
                        || key.contains("oauthToken")
                        || key.contains("authState");
                }
            } else if field_num == 2 {
                row_data = Some(value.to_vec());
            }
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    if !sentinel_matched {
        return None;
    }

    let row_data = row_data?;
    let oauth_info_b64 = extract_string_field(&row_data, 1)?;
    let oauth_info = general_purpose::STANDARD.decode(oauth_info_b64).ok()?;
    extract_string_field(&oauth_info, 3).filter(|s| looks_like_refresh_token(s))
}

fn extract_string_field(data: &[u8], target_field: u32) -> Option<String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == target_field && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let value = &data[content_offset..content_offset + length];
            return String::from_utf8(value.to_vec()).ok();
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

fn looks_like_refresh_token(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("1//") && trimmed.len() >= 20
}

fn scan_refresh_token_strings(data: &[u8]) -> Option<String> {
    fn walk(data: &[u8], depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let mut offset = 0;
        while offset < data.len() {
            let (tag, new_offset) = match read_varint(data, offset) {
                Ok(v) => v,
                Err(_) => break,
            };
            let wire_type = (tag & 7) as u8;
            let field_num = (tag >> 3) as u32;

            if wire_type == 2 {
                let (length, content_offset) = match read_varint(data, new_offset) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let length = length as usize;
                if content_offset + length > data.len() {
                    break;
                }
                let value = &data[content_offset..content_offset + length];

                if let Ok(s) = std::str::from_utf8(value) {
                    if looks_like_refresh_token(s) {
                        return Some(s.trim().to_string());
                    }
                    // Nested base64(OAuthTokenInfo) commonly appears as field 1 of Row.
                    if field_num == 1 && s.len() > 40 {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(s.trim()) {
                            if let Some(token) = walk(&decoded, depth + 1) {
                                return Some(token);
                            }
                            if let Some(token) = extract_string_field(&decoded, 3)
                                .filter(|t| looks_like_refresh_token(&t))
                            {
                                return Some(token);
                            }
                        }
                    }
                }

                if let Some(token) = walk(value, depth + 1) {
                    return Some(token);
                }

                offset = content_offset + length;
            } else {
                offset = match skip_field(data, new_offset, wire_type) {
                    Ok(v) => v,
                    Err(_) => break,
                };
            }
        }
        None
    }

    walk(data, 0)
}
