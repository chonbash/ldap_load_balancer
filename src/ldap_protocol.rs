// LDAP protocol handling with BER encoding/decoding
// Implements basic BER parsing for LDAP v3 protocol

use anyhow::{Context, Result, bail};
use std::io::{Cursor, Read};

// LDAP Control (request or response)
#[derive(Debug, Clone)]
pub struct Control {
    pub ctype: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

/// RFC 4533 Sync Request Control OID
pub const SYNC_REQUEST_OID: &str = "1.3.6.1.4.1.4203.1.9.1.1";

/// Parsed Sync Request control value (RFC 4533)
#[derive(Debug, Clone)]
pub struct SyncRequestControl {
    /// 1 = refreshOnly, 3 = refreshAndPersist
    pub mode: u8,
    pub cookie: Option<Vec<u8>>,
    pub reload_hint: bool,
}

impl SyncRequestControl {
    pub fn is_refresh_and_persist(&self) -> bool {
        self.mode == 3
    }
}

// LDAP Message structure
#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: i32,
    pub protocol_op: ProtocolOp,
    pub controls: Option<Vec<Control>>,
}

#[derive(Debug, Clone)]
pub enum ProtocolOp {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(SearchResultDone),
    ModifyRequest(ModifyRequest),
    ModifyResponse(ModifyResponse),
    AddRequest(AddRequest),
    AddResponse(AddResponse),
    DelRequest(DelRequest),
    DelResponse(DelResponse),
    ModifyDNRequest(ModifyDNRequest),
    ModifyDNResponse(ModifyDNResponse),
    CompareRequest(CompareRequest),
    CompareResponse(CompareResponse),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
    IntermediateResponse(IntermediateResponse),
    UnbindRequest,
    UnbindResponse,
    /// AbandonRequest: [APPLICATION 16] MessageID - no server response per RFC 4511
    AbandonRequest(i32),
}

#[derive(Debug, Clone)]
pub struct IntermediateResponse {
    pub response_name: Option<String>,
    pub response_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub version: i32,
    pub name: String,
    pub authentication: BindAuthentication,
}

#[derive(Debug, Clone)]
pub enum BindAuthentication {
    Simple(String),
    Sasl { mechanism: String, credentials: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct BindResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

/// LDAP Search filter (RFC 4511). Can be converted to string for ldap3.
#[derive(Debug, Clone)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch { attribute: String, value: Vec<u8> },
    Substrings {
        attribute: String,
        substrings: Vec<SubstringFilterItem>,
    },
    GreaterOrEqual { attribute: String, value: Vec<u8> },
    LessOrEqual { attribute: String, value: Vec<u8> },
    Present(String),
    ApproxMatch { attribute: String, value: Vec<u8> },
    ExtensibleMatch {
        matching_rule: Option<String>,
        typ: Option<String>,
        match_value: Vec<u8>,
        dn_attributes: bool,
    },
    /// Unparsed or unknown filter (e.g. context-specific); stored as (tag, raw value).
    Raw(u8, Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum SubstringFilterItem {
    Initial(Vec<u8>),
    Any(Vec<u8>),
    Final(Vec<u8>),
}

impl Filter {
    /// String form suitable for ldap3 search (e.g. "(cn=foo)", "(&(a=b)(c=d))").
    pub fn to_ldap_string(&self) -> String {
        match self {
            Filter::And(fs) => format!("(&{})", fs.iter().map(Filter::to_ldap_string).collect::<String>()),
            Filter::Or(fs) => format!("(|{})", fs.iter().map(Filter::to_ldap_string).collect::<String>()),
            Filter::Not(f) => format!("(!{})", f.to_ldap_string()),
            Filter::EqualityMatch { attribute, value } => {
                let v = String::from_utf8_lossy(value);
                let escaped = v.replace('\\', "\\\\").replace('*', "\\2a").replace('(', "\\28").replace(')', "\\29").replace('\x00', "\\00");
                format!("({}={})", attribute, escaped)
            }
            Filter::Present(attr) => format!("({}=*)", attr),
            Filter::Substrings { attribute, substrings } => {
                let mut s = attribute.clone();
                s.push('=');
                for item in substrings {
                    match item {
                        SubstringFilterItem::Initial(b) => s.push_str(&String::from_utf8_lossy(b).replace('*', "\\2a")),
                        SubstringFilterItem::Any(b) => {
                            s.push('*');
                            s.push_str(&String::from_utf8_lossy(b).replace('*', "\\2a"));
                        }
                        SubstringFilterItem::Final(b) => {
                            s.push('*');
                            s.push_str(&String::from_utf8_lossy(b).replace('*', "\\2a"));
                        }
                    }
                }
                format!("({})", s)
            }
            Filter::GreaterOrEqual { attribute, value } => format!("({}>={})", attribute, String::from_utf8_lossy(value)),
            Filter::LessOrEqual { attribute, value } => format!("({}<={})", attribute, String::from_utf8_lossy(value)),
            Filter::ApproxMatch { attribute, value } => format!("({}~={})", attribute, String::from_utf8_lossy(value)),
            Filter::ExtensibleMatch { matching_rule, typ, match_value, .. } => {
                let v = String::from_utf8_lossy(match_value);
                let mut s = String::from(":=");
                if let Some(mr) = matching_rule.as_ref() {
                    s = format!(":{}:=", mr) + &v;
                } else if let Some(t) = typ.as_ref() {
                    s = format!(":dn:{}:=", t) + &v;
                } else {
                    s.push_str(&v);
                }
                format!("(:{})", s)
            }
            Filter::Raw(_, _) => "(objectClass=*)".to_string(), // fallback for raw
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base_object: String,
    pub scope: SearchScope,
    pub deref_aliases: i32,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

impl TryFrom<u8> for SearchScope {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(SearchScope::BaseObject),
            1 => Ok(SearchScope::SingleLevel),
            2 => Ok(SearchScope::WholeSubtree),
            _ => bail!("Invalid search scope: {}", value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub object_name: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone)]
pub struct SearchResultDone {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct ModifyRequest {
    pub object: String,
    pub changes: Vec<ModifyChange>,
}

#[derive(Debug, Clone)]
pub struct ModifyChange {
    pub operation: ModifyOperation,
    pub modification: Attribute,
}

#[derive(Debug, Clone, Copy)]
pub enum ModifyOperation {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

#[derive(Debug, Clone)]
pub struct ModifyResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct AddRequest {
    pub entry: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone)]
pub struct AddResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct DelRequest {
    pub entry: String,
}

#[derive(Debug, Clone)]
pub struct DelResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct ModifyDNRequest {
    pub entry: String,
    pub newrdn: String,
    pub delete_old_rdn: bool,
    pub new_superior: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModifyDNResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct CompareRequest {
    pub entry: String,
    pub attr: String,
    pub assertion_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CompareResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct ExtendedRequest {
    pub request_name: String,
    pub request_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ExtendedResponse {
    pub result_code: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
    pub response_name: Option<String>,
    pub response_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: String,
    pub attr_values: Vec<Vec<u8>>,
}

// BER parsing utilities
pub(crate) struct BerReader<'a> {
    pub(crate) cursor: Cursor<&'a [u8]>,
}

impl<'a> BerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    /// Read single-byte tag. For multi-byte tags (tag number >= 31), use read_tag_multibyte().
    fn read_tag(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read tag that may be multi-byte (X.690: high tag number). Returns full tag bytes (1 or more).
    #[allow(dead_code)]
    pub(crate) fn read_tag_multibyte(&mut self) -> Result<Vec<u8>> {
        let first = self.read_tag()?;
        let mut tag_bytes = vec![first];
        if (first & 0x1F) == 0x1F {
            loop {
                let b = self.read_tag()?;
                tag_bytes.push(b);
                if (b & 0x80) == 0 {
                    break;
                }
            }
        }
        Ok(tag_bytes)
    }

    fn read_length(&mut self) -> Result<usize> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        let first_byte = buf[0];

        if (first_byte & 0x80) == 0 {
            // Short form
            Ok(first_byte as usize)
        } else {
            // Long form
            let length_bytes = (first_byte & 0x7F) as usize;
            if length_bytes == 0 {
                bail!("Indefinite length not supported");
            }
            if length_bytes > 4 {
                bail!("Length too large: {} bytes", length_bytes);
            }
            if self.remaining() < length_bytes {
                bail!("BER truncated: length encoding needs {} bytes, {} remaining", length_bytes, self.remaining());
            }
            let mut length = 0u32;
            for _ in 0..length_bytes {
                self.cursor.read_exact(&mut buf)?;
                length = (length << 8) | buf[0] as u32;
            }
            Ok(length as usize)
        }
    }

    fn read_integer(&mut self) -> Result<i32> {
        let tag = self.read_tag()?;
        if (tag & 0x1F) != 0x02 {
            bail!("Expected INTEGER tag (0x02), got: 0x{:02X}", tag);
        }
        let length = self.read_length()?;
        if length > 4 {
            bail!("Integer too large: {} bytes", length);
        }
        if self.remaining() < length {
            bail!("BER truncated: integer needs {} bytes, {} remaining", length, self.remaining());
        }
        let mut buf = vec![0u8; length];
        self.cursor.read_exact(&mut buf)?;

        let mut value = 0i32;
        for &byte in &buf {
            value = (value << 8) | (byte as i32);
        }

        // Sign extension for negative numbers
        if length < 4 && (buf[0] & 0x80) != 0 {
            value |= !0 << (length * 8);
        }

        Ok(value)
    }

    /// Read OCTET STRING TLV. Accepts: 0x04 (universal), 0x08 (context, e.g. SASL mechanism), 0x30 (SEQUENCE), or context-specific 0x80..=0xBF.
    fn read_octet_string(&mut self) -> Result<Vec<u8>> {
        let tag = self.read_tag()?;
        let ok = (tag & 0x1F) == 0x04  // universal OCTET STRING
            || (tag & 0x1F) == 0x08    // context (e.g. SASL mechanism in BindRequest)
            || tag == 0x30             // SEQUENCE (some clients use for DN etc.)
            || (tag >= 0x80 && tag <= 0xBF); // context-specific [0]..[31]
        if !ok {
            bail!("Expected OCTET STRING tag (0x04), got: 0x{:02X}", tag);
        }
        self.read_octet_string_value()
    }

    /// Read only length + value of OCTET STRING (tag already consumed). Use after read_tag() for [0] IMPLICIT etc.
    fn read_octet_string_value(&mut self) -> Result<Vec<u8>> {
        let length = self.read_length()?;
        if self.remaining() < length {
            bail!("BER truncated: octet string needs {} bytes, {} remaining", length, self.remaining());
        }
        let mut buf = vec![0u8; length];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_octet_string()?;
        String::from_utf8(bytes).context("Invalid UTF-8 string")
    }

    fn read_sequence(&mut self) -> Result<usize> {
        let tag = self.read_tag()?;
        if (tag & 0x1F) != 0x10 {
            bail!("Expected SEQUENCE tag, got: 0x{:02X}", tag);
        }
        self.read_length()
    }

    fn read_enumerated(&mut self) -> Result<u8> {
        let tag = self.read_tag()?;
        if (tag & 0x1F) != 0x0A {
            bail!("Expected ENUMERATED tag, got: 0x{:02X}", tag);
        }
        let length = self.read_length()?;
        if length != 1 {
            bail!("Enumerated value must be 1 byte, got: {}", length);
        }
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_boolean(&mut self) -> Result<bool> {
        let tag = self.read_tag()?;
        if (tag & 0x1F) != 0x01 {
            bail!("Expected BOOLEAN tag, got: 0x{:02X}", tag);
        }
        let length = self.read_length()?;
        if length != 1 {
            bail!("Boolean value must be 1 byte, got: {}", length);
        }
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }

    #[allow(dead_code)]
    fn position(&self) -> u64 {
        self.cursor.position()
    }

    fn remaining(&self) -> usize {
        let pos = self.cursor.position() as usize;
        let len = self.cursor.get_ref().len();
        len.saturating_sub(pos)
    }

    fn read_raw_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.remaining() < n {
            bail!("BER truncated: need {} bytes, {} remaining", n, self.remaining());
        }
        let mut buf = vec![0u8; n];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read OID (Universal tag 6). Returns OID components as string "1.2.3.4".
    #[allow(dead_code)]
    pub(crate) fn read_oid(&mut self) -> Result<String> {
        let tag = self.read_tag()?;
        if (tag & 0x1F) != 0x06 {
            bail!("Expected OID tag (0x06), got: 0x{:02X}", tag);
        }
        let length = self.read_length()?;
        if self.remaining() < length {
            bail!("BER truncated: OID needs {} bytes, {} remaining", length, self.remaining());
        }
        let bytes = self.read_raw_bytes(length)?;
        oid_bytes_to_string(&bytes)
    }

    /// Read length, supporting indefinite form (0x80). Returns None for indefinite length.
    #[allow(dead_code)]
    pub(crate) fn read_length_or_indefinite(&mut self) -> Result<Option<usize>> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        let first_byte = buf[0];
        if (first_byte & 0x80) == 0 {
            return Ok(Some(first_byte as usize));
        }
        if first_byte == 0x80 {
            return Ok(None); // indefinite
        }
        let length_bytes = (first_byte & 0x7F) as usize;
        if length_bytes > 4 {
            bail!("Length too large: {} bytes", length_bytes);
        }
        if self.remaining() < length_bytes {
            bail!("BER truncated: length encoding needs {} bytes, {} remaining", length_bytes, self.remaining());
        }
        let mut length = 0usize;
        for _ in 0..length_bytes {
            self.cursor.read_exact(&mut buf)?;
            length = (length << 8) | buf[0] as usize;
        }
        Ok(Some(length))
    }
}

/// Decode BER OID bytes to dotted string (e.g. "1.2.840.113549").
#[allow(dead_code)]
pub(crate) fn oid_bytes_to_string(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let mut components = Vec::new();
    let mut val: u64 = 0;
    for &b in bytes {
        val = val
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7F) as u64))
            .ok_or_else(|| anyhow::anyhow!("OID value overflow"))?;
        if (b & 0x80) == 0 {
            components.push(val);
            val = 0;
        }
    }
    if (bytes.last().copied().unwrap_or(0) & 0x80) != 0 {
        bail!("OID encoding truncated");
    }
    // First two components encoded as 40 * first + second
    let mut parts = Vec::with_capacity(components.len() + 1);
    if let Some(&first) = components.first() {
        parts.push((first / 40).to_string());
        parts.push((first % 40).to_string());
        for &c in &components[1..] {
            parts.push(c.to_string());
        }
    }
    Ok(parts.join("."))
}

/// Encode OID string to BER bytes (e.g. "1.2.840" -> bytes).
fn oid_string_to_bytes(oid: &str) -> Result<Vec<u8>> {
    let components: Vec<u64> = oid
        .split('.')
        .map(|s| s.trim().parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("Invalid OID component"))?;
    if components.is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let first = components[0].min(6);
    let second = components.get(1).copied().unwrap_or(0);
    let mut val = first * 40 + second;
    let mut buf = Vec::new();
    loop {
        buf.push((val % 128) as u8);
        val /= 128;
        if val == 0 {
            break;
        }
    }
    buf.reverse();
    for (i, b) in buf.iter().enumerate() {
        out.push(if i < buf.len() - 1 { *b | 0x80 } else { *b });
    }
    for &c in components.iter().skip(2) {
        let mut val = c;
        buf.clear();
        loop {
            buf.push((val % 128) as u8);
            val /= 128;
            if val == 0 {
                break;
            }
        }
        buf.reverse();
        for (i, b) in buf.iter().enumerate() {
            out.push(if i < buf.len() - 1 { *b | 0x80 } else { *b });
        }
    }
    Ok(out)
}

// BER encoding utilities
pub struct BerWriter {
    buffer: Vec<u8>,
}

impl BerWriter {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    pub fn write_tag(&mut self, tag: u8) {
        self.buffer.push(tag);
    }

    /// Write multi-byte tag (X.690 high tag number). `tag_bytes` must be 1 or more bytes.
    pub fn write_tag_multi(&mut self, tag_bytes: &[u8]) {
        self.buffer.extend_from_slice(tag_bytes);
    }

    /// Write OID (Universal 6) from dotted string (e.g. "1.2.840.113549").
    pub fn write_oid(&mut self, oid: &str) -> Result<()> {
        self.write_tag(0x06);
        let bytes = oid_string_to_bytes(oid)?;
        self.write_length(bytes.len());
        self.buffer.extend_from_slice(&bytes);
        Ok(())
    }

    fn write_length(&mut self, length: usize) {
        if length < 128 {
            // Short form
            self.buffer.push(length as u8);
        } else {
            // Long form
            let mut bytes = Vec::new();
            let mut len = length;
            while len > 0 {
                bytes.push((len & 0xFF) as u8);
                len >>= 8;
            }
            bytes.reverse();
            self.buffer.push(0x80 | bytes.len() as u8);
            self.buffer.extend_from_slice(&bytes);
        }
    }

    pub fn write_integer(&mut self, value: i32) {
        self.write_tag(0x02); // INTEGER tag
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0 || (value < 0 && b != 0xFF))
            .unwrap_or(3);
        let actual_bytes = &bytes[start..];
        if actual_bytes.is_empty() || (value >= 0 && actual_bytes[0] & 0x80 != 0) {
            // Need sign extension
            self.write_length(actual_bytes.len() + 1);
            if value >= 0 {
                self.buffer.push(0);
            } else {
                self.buffer.push(0xFF);
            }
            self.buffer.extend_from_slice(actual_bytes);
        } else {
            self.write_length(actual_bytes.len());
            self.buffer.extend_from_slice(actual_bytes);
        }
    }

    fn write_octet_string(&mut self, data: &[u8]) {
        self.write_tag(0x04); // OCTET STRING tag
        self.write_length(data.len());
        self.buffer.extend_from_slice(data);
    }

    pub fn write_string(&mut self, s: &str) {
        self.write_octet_string(s.as_bytes());
    }

    #[allow(dead_code)]
    fn write_boolean(&mut self, value: bool) {
        self.write_tag(0x01); // BOOLEAN tag
        self.write_length(1);
        self.buffer.push(if value { 0xFF } else { 0x00 });
    }

    pub fn write_enumerated(&mut self, value: u8) {
        self.write_tag(0x0A); // ENUMERATED tag
        self.write_length(1);
        self.buffer.push(value);
    }

    /// Reserve a length byte (no tag). Used for [APPLICATION n] IMPLICIT SEQUENCE.
    /// Call patch_implicit_sequence_length(pos) after writing the content.
    pub fn write_length_placeholder(&mut self) -> usize {
        let pos = self.buffer.len();
        self.buffer.push(0);
        pos
    }

    /// Back-patch length at pos for content written after the placeholder.
    /// Supports short and long form.
    pub fn patch_implicit_sequence_length(&mut self, pos: usize) {
        let content_len = self.buffer.len() - (pos + 1);
        if content_len < 128 {
            self.buffer[pos] = content_len as u8;
        } else {
            let mut bytes = Vec::new();
            let mut len = content_len;
            while len > 0 {
                bytes.push((len & 0xFF) as u8);
                len >>= 8;
            }
            bytes.reverse();
            self.buffer[pos] = 0x80 | bytes.len() as u8;
            for (i, b) in bytes.iter().enumerate() {
                self.buffer.insert(pos + 1 + i, *b);
            }
        }
    }

    pub fn start_sequence(&mut self) -> usize {
        self.write_tag(0x30); // SEQUENCE tag
        let length_pos = self.buffer.len();
        self.buffer.push(0); // Placeholder for length
        length_pos
    }

    pub fn end_sequence(&mut self, start_pos: usize) {
        let sequence_start = start_pos + 1;
        let sequence_length = self.buffer.len() - sequence_start;
        let length_bytes = if sequence_length < 128 {
            1
        } else if sequence_length < 256 {
            2
        } else if sequence_length < 65536 {
            3
        } else {
            4
        };

        if length_bytes > 1 {
            // Overwrite placeholder with first length byte, then insert remaining bytes (no remove)
            self.buffer[sequence_start - 1] = 0x80 | (length_bytes - 1) as u8;
            for i in 0..(length_bytes - 1) {
                let byte = (sequence_length >> (8 * (length_bytes - 2 - i))) & 0xFF;
                self.buffer.insert(sequence_start + i, byte as u8);
            }
        } else {
            self.buffer[sequence_start - 1] = sequence_length as u8;
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buffer
    }
}

// LDAP protocol tag constants
pub const LDAP_TAG_BIND_REQUEST: u8 = 0x60;
pub const LDAP_TAG_BIND_RESPONSE: u8 = 0x61;
pub const LDAP_TAG_UNBIND_REQUEST: u8 = 0x42;
pub const LDAP_TAG_SEARCH_REQUEST: u8 = 0x63;
pub const LDAP_TAG_SEARCH_RESULT_ENTRY: u8 = 0x64;
pub const LDAP_TAG_SEARCH_RESULT_DONE: u8 = 0x65;
pub const LDAP_TAG_MODIFY_REQUEST: u8 = 0x66;
pub const LDAP_TAG_MODIFY_RESPONSE: u8 = 0x67;
pub const LDAP_TAG_ADD_REQUEST: u8 = 0x68;
pub const LDAP_TAG_ADD_RESPONSE: u8 = 0x69;
pub const LDAP_TAG_DEL_REQUEST: u8 = 0x4A;
pub const LDAP_TAG_DEL_RESPONSE: u8 = 0x6B;
pub const LDAP_TAG_MODIFY_DN_REQUEST: u8 = 0x6C;
pub const LDAP_TAG_MODIFY_DN_RESPONSE: u8 = 0x6D;
pub const LDAP_TAG_COMPARE_REQUEST: u8 = 0x6E;
pub const LDAP_TAG_COMPARE_RESPONSE: u8 = 0x6F;
pub const LDAP_TAG_EXTENDED_REQUEST: u8 = 0x77;
pub const LDAP_TAG_EXTENDED_RESPONSE: u8 = 0x78;
/// AbandonRequest [APPLICATION 16] - no response
pub const LDAP_TAG_ABANDON_REQUEST: u8 = 0x50;
/// [25] IMPLICIT - intermediate response
pub const LDAP_TAG_INTERMEDIATE_RESPONSE: u8 = 0xB9;

/// Context [0] IMPLICIT SEQUENCE OF control
const LDAP_CONTEXT_CONTROLS: u8 = 0xA0;

/// Parse only the LDAP message header (SEQUENCE, messageID, protocolOp tag).
/// Returns (message_id, request_tag) for building error responses when full parse fails.
pub fn parse_ldap_message_header(data: &[u8]) -> Result<(i32, u8)> {
    let mut reader = BerReader::new(data);
    let _seq_len = reader.read_sequence()?;
    let message_id = reader.read_integer()?;
    let tag = reader.read_tag()?;
    Ok((message_id, tag))
}

pub fn parse_ldap_message(data: &[u8]) -> Result<LdapMessage> {
    let mut reader = BerReader::new(data);

    // LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls [0] OPTIONAL }
    let _seq_len = reader.read_sequence()?;

    let message_id = reader.read_integer()?;

    let tag = reader.read_tag()?;
    let protocol_op = match tag {
        LDAP_TAG_BIND_REQUEST => ProtocolOp::BindRequest(parse_bind_request(&mut reader)?),
        LDAP_TAG_UNBIND_REQUEST => ProtocolOp::UnbindRequest,
        LDAP_TAG_SEARCH_REQUEST => ProtocolOp::SearchRequest(parse_search_request(&mut reader)?),
        LDAP_TAG_MODIFY_REQUEST => ProtocolOp::ModifyRequest(parse_modify_request(&mut reader)?),
        LDAP_TAG_ADD_REQUEST => ProtocolOp::AddRequest(parse_add_request(&mut reader)?),
        LDAP_TAG_DEL_REQUEST => ProtocolOp::DelRequest(parse_del_request(&mut reader)?),
        LDAP_TAG_MODIFY_DN_REQUEST => ProtocolOp::ModifyDNRequest(parse_modify_dn_request(&mut reader)?),
        LDAP_TAG_COMPARE_REQUEST => ProtocolOp::CompareRequest(parse_compare_request(&mut reader)?),
        LDAP_TAG_EXTENDED_REQUEST => ProtocolOp::ExtendedRequest(parse_extended_request(&mut reader)?),
        LDAP_TAG_ABANDON_REQUEST => ProtocolOp::AbandonRequest(reader.read_integer()?),
        _ => bail!("Unsupported LDAP operation tag: 0x{:02X}", tag),
    };

    let controls = if reader.remaining() > 0 {
        let next_tag = reader.read_tag()?;
        if next_tag == LDAP_CONTEXT_CONTROLS {
            Some(parse_controls(&mut reader)?)
        } else {
            // Put tag back by re-creating reader from current position - we can't, so we don't support extra trailing data
            None
        }
    } else {
        None
    };

    Ok(LdapMessage {
        message_id,
        protocol_op,
        controls,
    })
}

/// Parse controls: SEQUENCE OF Control, each Control ::= SEQUENCE { type, critical DEFAULT FALSE, value OPTIONAL }
fn parse_controls(reader: &mut BerReader) -> Result<Vec<Control>> {
    let _seq_len = reader.read_length()?;
    let mut controls = Vec::new();
    while reader.remaining() > 0 {
        let _ctrl_seq = reader.read_sequence()?;
        let ctype = reader.read_string()?;
        let (critical, value) = if reader.remaining() > 0 {
            let tag1 = reader.read_tag()?;
            if (tag1 & 0x1F) == 0x01 {
                let len = reader.read_length()?;
                let b = reader.read_raw_bytes(len)?;
                let c = !b.is_empty() && b[0] != 0;
                let val = if reader.remaining() > 0 {
                    let _tag2 = reader.read_tag()?;
                    Some(reader.read_octet_string_value()?)
                } else {
                    None
                };
                (c, val)
            } else if (tag1 & 0x1F) == 0x04 {
                (false, Some(reader.read_octet_string_value()?))
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };
        controls.push(Control {
            ctype,
            critical,
            value,
        });
    }
    Ok(controls)
}

/// Find Sync Request control and parse its value. Returns None if not present or parse error.
pub fn get_sync_request_control(controls: Option<&[Control]>) -> Option<SyncRequestControl> {
    let controls = controls?;
    let ctrl = controls.iter().find(|c| c.ctype == SYNC_REQUEST_OID)?;
    let value = ctrl.value.as_ref()?;
    parse_sync_request_value(value).ok()
}

/// Parse Sync Request control value: SEQUENCE { mode ENUMERATED, cookie OCTET STRING OPT, reloadHint BOOLEAN OPT }
fn parse_sync_request_value(data: &[u8]) -> Result<SyncRequestControl> {
    let mut reader = BerReader::new(data);
    let _seq = reader.read_sequence()?;
    let mode = reader.read_enumerated()?;
    let mut cookie = None;
    let mut reload_hint = false;
    while reader.remaining() > 0 {
        let tag = reader.read_tag()?;
        if (tag & 0x1F) == 0x04 {
            cookie = Some(reader.read_octet_string_value()?);
        } else if (tag & 0x1F) == 0x01 {
            let len = reader.read_length()?;
            let b = reader.read_raw_bytes(len)?;
            reload_hint = !b.is_empty() && b[0] != 0;
        }
    }
    Ok(SyncRequestControl {
        mode,
        cookie,
        reload_hint,
    })
}

fn parse_bind_request(reader: &mut BerReader) -> Result<BindRequest> {
    let _len = reader.read_length()?;
    let version = reader.read_integer()?;
    let name = reader.read_string()?;
    
    // Authentication: RFC 4511 simple is [0] IMPLICIT OCTET STRING (0x80), but clients send various tags (0x41, 0x61, 0xD0, etc.).
    // Treat anything that is not SASL (0xA3) as simple bind (tag + OCTET STRING password).
    let auth_tag = reader.read_tag()?;
    let authentication = if auth_tag == 0xA3 {
        // SASL bind
        let _sasl_len = reader.read_length()?;
        let mechanism = reader.read_string()?;
        let credentials = if reader.remaining() > 0 {
            reader.read_octet_string().ok()
        } else {
            None
        };
        BindAuthentication::Sasl {
            mechanism,
            credentials: credentials.unwrap_or_default(),
        }
    } else {
        // Simple bind: tag already read (0x80, 0x41, etc.); read length + value only
        let password = reader.read_octet_string_value()?;
        BindAuthentication::Simple(String::from_utf8(password)?)
    };

    Ok(BindRequest {
        version,
        name,
        authentication,
    })
}

fn parse_search_request(reader: &mut BerReader) -> Result<SearchRequest> {
    let _len = reader.read_length()?;
    let base_object = reader.read_string()?;
    let scope = SearchScope::try_from(reader.read_enumerated()?)?;
    let deref_aliases = reader.read_enumerated()? as i32;
    let size_limit = reader.read_integer()?;
    let time_limit = reader.read_integer()?;
    let types_only = reader.read_boolean()?;
    
    let filter = parse_filter(reader)?;
    
    // Attributes
    let _attrs_tag = reader.read_tag()?;
    let _attrs_len = reader.read_length()?;
    let mut attributes = Vec::new();
    while reader.remaining() > 0 {
        let attr = reader.read_string()?;
        attributes.push(attr);
    }

    Ok(SearchRequest {
        base_object,
        scope,
        deref_aliases,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes,
    })
}

/// RFC 4511 Filter CHOICE: [0]=and, [1]=or, [2]=not, [3]=equalityMatch, [4]=substrings, [5]=greaterOrEqual, [6]=lessOrEqual, [7]=present, [8]=approxMatch, [9]=extensibleMatch.
fn parse_filter(reader: &mut BerReader) -> Result<Filter> {
    let tag = reader.read_tag()?;
    let len = reader.read_length()?;
    let content = reader.read_raw_bytes(len)?;
    parse_filter_content(&content, tag)
}

fn parse_filter_content(content: &[u8], tag: u8) -> Result<Filter> {
    let mut sub = BerReader::new(content);
    match tag {
        0x80 => {
            // and [0] SET OF filter
            let mut filters = Vec::new();
            while sub.remaining() > 0 {
                filters.push(parse_filter(&mut sub)?);
            }
            Ok(Filter::And(filters))
        }
        0x81 => {
            // or [1] SET OF filter
            let mut filters = Vec::new();
            while sub.remaining() > 0 {
                filters.push(parse_filter(&mut sub)?);
            }
            Ok(Filter::Or(filters))
        }
        0x82 => {
            // not [2] filter
            let f = parse_filter(&mut sub)?;
            Ok(Filter::Not(Box::new(f)))
        }
        0xA3 => {
            // equalityMatch [3] AttributeValueAssertion SEQUENCE { attributeDesc, assertionValue }
            let _seq = sub.read_sequence()?;
            let attribute = sub.read_string()?;
            let value = sub.read_octet_string()?;
            Ok(Filter::EqualityMatch { attribute, value })
        }
        0xA4 => {
            // substrings [4] SubstringFilter
            let _seq = sub.read_sequence()?;
            let attribute = sub.read_string()?;
            let _seq2_tag = sub.read_tag()?;
            let _seq2_len = sub.read_length()?;
            let mut substrings = Vec::new();
            while sub.remaining() > 0 {
                let t = sub.read_tag()?;
                let val = sub.read_octet_string_value()?;
                let item = match t {
                    0x80 => SubstringFilterItem::Initial(val),
                    0x81 => SubstringFilterItem::Any(val),
                    0x82 => SubstringFilterItem::Final(val),
                    _ => continue,
                };
                substrings.push(item);
            }
            Ok(Filter::Substrings { attribute, substrings })
        }
        0xA5 => {
            let _seq = sub.read_sequence()?;
            let attribute = sub.read_string()?;
            let value = sub.read_octet_string()?;
            Ok(Filter::GreaterOrEqual { attribute, value })
        }
        0xA6 => {
            let _seq = sub.read_sequence()?;
            let attribute = sub.read_string()?;
            let value = sub.read_octet_string()?;
            Ok(Filter::LessOrEqual { attribute, value })
        }
        0x87 => {
            // present [7] IMPLICIT AttributeDescription (OCTET STRING): content is raw bytes or inner 0x04 TLV
            let attribute = if !content.is_empty() && content[0] == 0x04 {
                sub.read_string()?
            } else {
                String::from_utf8_lossy(content).to_string()
            };
            Ok(Filter::Present(attribute))
        }
        0xA8 => {
            let _seq = sub.read_sequence()?;
            let attribute = sub.read_string()?;
            let value = sub.read_octet_string()?;
            Ok(Filter::ApproxMatch { attribute, value })
        }
        0xA9 => {
            // extensibleMatch [9] MatchingRuleAssertion
            let _seq = sub.read_sequence()?;
            let mut matching_rule = None;
            let mut typ = None;
            let mut match_value = Vec::new();
            let mut dn_attributes = false;
            while sub.remaining() > 0 {
                let t = sub.read_tag()?;
                if (t & 0x1F) == 0x04 {
                    let v = sub.read_octet_string_value()?;
                    let s = String::from_utf8_lossy(&v).to_string();
                    if matching_rule.is_none() {
                        matching_rule = Some(s);
                    } else if typ.is_none() {
                        typ = Some(s);
                    } else {
                        match_value = v;
                    }
                } else if (t & 0x1F) == 0x01 {
                    let _len = sub.read_length()?;
                    let b = sub.read_raw_bytes(1)?;
                    dn_attributes = !b.is_empty() && b[0] != 0;
                }
            }
            if match_value.is_empty() && typ.is_some() {
                match_value = typ.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
                typ = None;
            }
            Ok(Filter::ExtensibleMatch {
                matching_rule,
                typ,
                match_value,
                dn_attributes,
            })
        }
        _ => Ok(Filter::Raw(tag, content.to_vec())),
    }
}

fn parse_modify_request(reader: &mut BerReader) -> Result<ModifyRequest> {
    let _len = reader.read_length()?;
    let object = reader.read_string()?;
    
    let _changes_tag = reader.read_tag()?;
    let _changes_len = reader.read_length()?;
    let mut changes = Vec::new();
    
    while reader.remaining() > 0 {
        let _change_seq_tag = reader.read_tag()?;
        let _change_seq_len = reader.read_length()?;
        let operation = reader.read_enumerated()?;
        let modification = parse_attribute(reader)?;
        
        changes.push(ModifyChange {
            operation: match operation {
                0 => ModifyOperation::Add,
                1 => ModifyOperation::Delete,
                2 => ModifyOperation::Replace,
                _ => bail!("Invalid modify operation: {}", operation),
            },
            modification,
        });
    }

    Ok(ModifyRequest {
        object,
        changes,
    })
}

fn parse_add_request(reader: &mut BerReader) -> Result<AddRequest> {
    let _len = reader.read_length()?;
    let entry = reader.read_string()?;
    
    let _attrs_tag = reader.read_tag()?;
    let _attrs_len = reader.read_length()?;
    let mut attributes = Vec::new();
    
    while reader.remaining() > 0 {
        let attr = parse_attribute(reader)?;
        attributes.push(attr);
    }

    Ok(AddRequest {
        entry,
        attributes,
    })
}

fn parse_del_request(reader: &mut BerReader) -> Result<DelRequest> {
    let _len = reader.read_length()?;
    let entry = reader.read_string()?;
    Ok(DelRequest { entry })
}

/// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { entry, newrdn, deleteoldrdn, newSuperior [0] OPTIONAL }
fn parse_modify_dn_request(reader: &mut BerReader) -> Result<ModifyDNRequest> {
    let _len = reader.read_length()?;
    let entry = reader.read_string()?;
    let newrdn = reader.read_string()?;
    let delete_old_rdn = reader.read_boolean()?;
    let new_superior = if reader.remaining() > 0 {
        let tag = reader.read_tag()?;
        if tag == 0x80 {
            // [0] IMPLICIT LDAPDN (OCTET STRING) - tag already read
            let bytes = reader.read_octet_string_value()?;
            Some(String::from_utf8_lossy(&bytes).to_string())
        } else {
            bail!("ModifyDNRequest: expected newSuperior [0], got tag 0x{:02X}", tag);
        }
    } else {
        None
    };
    Ok(ModifyDNRequest {
        entry,
        newrdn,
        delete_old_rdn,
        new_superior,
    })
}

/// CompareRequest ::= [APPLICATION 14] SEQUENCE { entry, ava AttributeValueAssertion }
/// AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue OCTET STRING }
fn parse_compare_request(reader: &mut BerReader) -> Result<CompareRequest> {
    let _len = reader.read_length()?;
    let entry = reader.read_string()?;
    let _ava_tag = reader.read_tag()?;
    let _ava_len = reader.read_length()?;
    let attr = reader.read_string()?;
    let assertion_value = reader.read_octet_string()?;
    Ok(CompareRequest {
        entry,
        attr,
        assertion_value,
    })
}

fn parse_extended_request(reader: &mut BerReader) -> Result<ExtendedRequest> {
    let _len = reader.read_length()?;
    let request_name = reader.read_string()?;
    let request_value = if reader.remaining() > 0 {
        Some(reader.read_octet_string()?)
    } else {
        None
    };
    Ok(ExtendedRequest {
        request_name,
        request_value,
    })
}

fn parse_attribute(reader: &mut BerReader) -> Result<Attribute> {
    let _seq_tag = reader.read_tag()?;
    let _seq_len = reader.read_length()?;
    let attr_type = reader.read_string()?;
    
    let _vals_tag = reader.read_tag()?;
    let _vals_len = reader.read_length()?;
    let mut attr_values = Vec::new();
    
    while reader.remaining() > 0 {
        let value = reader.read_octet_string()?;
        attr_values.push(value);
    }

    Ok(Attribute {
        attr_type,
        attr_values,
    })
}

pub fn encode_ldap_message(message: &LdapMessage) -> Result<Vec<u8>> {
    let mut writer = BerWriter::new();
    let seq_start = writer.start_sequence();
    
    writer.write_integer(message.message_id);
    
    match &message.protocol_op {
        ProtocolOp::BindResponse(resp) => {
            encode_bind_response(&mut writer, resp)?;
        }
        ProtocolOp::SearchResultEntry(entry) => {
            encode_search_result_entry(&mut writer, entry)?;
        }
        ProtocolOp::SearchResultDone(done) => {
            encode_search_result_done(&mut writer, done)?;
        }
        ProtocolOp::ModifyResponse(resp) => {
            encode_modify_response(&mut writer, resp)?;
        }
        ProtocolOp::AddResponse(resp) => {
            encode_add_response(&mut writer, resp)?;
        }
        ProtocolOp::DelResponse(resp) => {
            encode_del_response(&mut writer, resp)?;
        }
        ProtocolOp::ModifyDNResponse(resp) => {
            encode_modify_dn_response(&mut writer, resp)?;
        }
        ProtocolOp::CompareResponse(resp) => {
            encode_compare_response(&mut writer, resp)?;
        }
        ProtocolOp::ExtendedResponse(resp) => {
            encode_extended_response(&mut writer, resp)?;
        }
        ProtocolOp::IntermediateResponse(resp) => {
            encode_intermediate_response(&mut writer, resp)?;
        }
        _ => bail!("Cannot encode operation type"),
    }
    
    if let Some(ref controls) = message.controls {
        if !controls.is_empty() {
            writer.write_tag(LDAP_CONTEXT_CONTROLS);
            let ctrl_seq_start = writer.start_sequence();
            for ctrl in controls {
                encode_control(&mut writer, ctrl)?;
            }
            writer.end_sequence(ctrl_seq_start);
        }
    }
    
    writer.end_sequence(seq_start);
    Ok(writer.into_vec())
}

/// Encode one Control: SEQUENCE { type, critical DEFAULT FALSE, value OPTIONAL }
fn encode_control(writer: &mut BerWriter, ctrl: &Control) -> Result<()> {
    let seq_start = writer.start_sequence();
    writer.write_string(&ctrl.ctype);
    if ctrl.critical {
        writer.write_boolean(true);
    }
    if let Some(ref value) = ctrl.value {
        writer.write_octet_string(value);
    }
    writer.end_sequence(seq_start);
    Ok(())
}

fn encode_bind_response(writer: &mut BerWriter, resp: &BindResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_BIND_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_search_result_entry(writer: &mut BerWriter, entry: &SearchResultEntry) -> Result<()> {
    writer.write_tag(LDAP_TAG_SEARCH_RESULT_ENTRY);
    let len_pos = writer.write_length_placeholder();
    writer.write_string(&entry.object_name);
    let attrs_start = writer.start_sequence();
    for attr in &entry.attributes {
        encode_attribute(writer, attr)?;
    }
    writer.end_sequence(attrs_start);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_search_result_done(writer: &mut BerWriter, done: &SearchResultDone) -> Result<()> {
    writer.write_tag(LDAP_TAG_SEARCH_RESULT_DONE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(done.result_code as u8);
    writer.write_string(&done.matched_dn);
    writer.write_string(&done.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_modify_response(writer: &mut BerWriter, resp: &ModifyResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_MODIFY_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_add_response(writer: &mut BerWriter, resp: &AddResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_ADD_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_del_response(writer: &mut BerWriter, resp: &DelResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_DEL_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_modify_dn_response(writer: &mut BerWriter, resp: &ModifyDNResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_MODIFY_DN_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_compare_response(writer: &mut BerWriter, resp: &CompareResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_COMPARE_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_extended_response(writer: &mut BerWriter, resp: &ExtendedResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_EXTENDED_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(resp.result_code as u8);
    writer.write_string(&resp.matched_dn);
    writer.write_string(&resp.diagnostic_message);
    if let Some(ref name) = resp.response_name {
        writer.write_string(name);
    }
    if let Some(ref value) = resp.response_value {
        writer.write_octet_string(value);
    }
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_intermediate_response(writer: &mut BerWriter, resp: &IntermediateResponse) -> Result<()> {
    writer.write_tag(LDAP_TAG_INTERMEDIATE_RESPONSE);
    let len_pos = writer.write_length_placeholder();
    if let Some(ref name) = resp.response_name {
        writer.write_string(name);
    }
    if let Some(ref value) = resp.response_value {
        writer.write_octet_string(value);
    }
    writer.patch_implicit_sequence_length(len_pos);
    Ok(())
}

fn encode_attribute(writer: &mut BerWriter, attr: &Attribute) -> Result<()> {
    let seq_start = writer.start_sequence();
    writer.write_string(&attr.attr_type);
    
    let vals_start = writer.start_sequence();
    for value in &attr.attr_values {
        writer.write_octet_string(value);
    }
    writer.end_sequence(vals_start);
    
    writer.end_sequence(seq_start);
    Ok(())
}

// Helper function to convert ldap3::Scope to our SearchScope
pub fn scope_from_ldap3(scope: ldap3::Scope) -> SearchScope {
    match scope {
        ldap3::Scope::Base => SearchScope::BaseObject,
        ldap3::Scope::OneLevel => SearchScope::SingleLevel,
        ldap3::Scope::Subtree => SearchScope::WholeSubtree,
    }
}

pub fn scope_to_ldap3(scope: SearchScope) -> ldap3::Scope {
    match scope {
        SearchScope::BaseObject => ldap3::Scope::Base,
        SearchScope::SingleLevel => ldap3::Scope::OneLevel,
        SearchScope::WholeSubtree => ldap3::Scope::Subtree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_scope_try_from() {
        assert_eq!(SearchScope::try_from(0).unwrap(), SearchScope::BaseObject);
        assert_eq!(SearchScope::try_from(1).unwrap(), SearchScope::SingleLevel);
        assert_eq!(SearchScope::try_from(2).unwrap(), SearchScope::WholeSubtree);
        assert!(SearchScope::try_from(3).is_err());
        assert!(SearchScope::try_from(255).is_err());
    }

    #[test]
    fn test_scope_conversion() {
        assert_eq!(scope_to_ldap3(SearchScope::BaseObject), ldap3::Scope::Base);
        assert_eq!(scope_to_ldap3(SearchScope::SingleLevel), ldap3::Scope::OneLevel);
        assert_eq!(scope_to_ldap3(SearchScope::WholeSubtree), ldap3::Scope::Subtree);

        assert_eq!(scope_from_ldap3(ldap3::Scope::Base), SearchScope::BaseObject);
        assert_eq!(scope_from_ldap3(ldap3::Scope::OneLevel), SearchScope::SingleLevel);
        assert_eq!(scope_from_ldap3(ldap3::Scope::Subtree), SearchScope::WholeSubtree);
    }

    #[test]
    fn test_ber_writer_integer() {
        let mut writer = BerWriter::new();
        writer.write_integer(0);
        writer.write_integer(127);
        writer.write_integer(-128);
        writer.write_integer(256);
        writer.write_integer(-1);
        let result = writer.into_vec();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_ber_writer_string() {
        let mut writer = BerWriter::new();
        writer.write_string("test");
        writer.write_string("");
        writer.write_string("привет");
        let result = writer.into_vec();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_ber_writer_boolean() {
        let mut writer = BerWriter::new();
        writer.write_boolean(true);
        writer.write_boolean(false);
        let result = writer.into_vec();
        assert_eq!(result.len(), 6); // 2 bytes per boolean (tag + length + value)
    }

    #[test]
    fn test_ber_writer_sequence() {
        let mut writer = BerWriter::new();
        let seq_start = writer.start_sequence();
        writer.write_integer(42);
        writer.write_string("test");
        writer.end_sequence(seq_start);
        let result = writer.into_vec();
        assert!(!result.is_empty());
        assert_eq!(result[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_ber_writer_long_length() {
        let mut writer = BerWriter::new();
        let seq_start = writer.start_sequence();
        // Write enough data to require long form length encoding
        for _ in 0..200 {
            writer.write_string("test");
        }
        writer.end_sequence(seq_start);
        let result = writer.into_vec();
        assert!(!result.is_empty());
        // Check that length is encoded in long form (starts with 0x8X)
        assert!(result[1] & 0x80 != 0);
    }

    #[test]
    fn test_encode_bind_response() {
        let response = BindResponse {
            result_code: 0,
            matched_dn: "".to_string(),
            diagnostic_message: "".to_string(),
        };
        let message = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindResponse(response),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_search_result_done() {
        let done = SearchResultDone {
            result_code: 0,
            matched_dn: "".to_string(),
            diagnostic_message: "Success".to_string(),
        };
        let message = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchResultDone(done),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_search_result_entry() {
        let entry = SearchResultEntry {
            object_name: "cn=test,dc=example,dc=com".to_string(),
            attributes: vec![
                Attribute {
                    attr_type: "cn".to_string(),
                    attr_values: vec!["test".as_bytes().to_vec()],
                },
                Attribute {
                    attr_type: "mail".to_string(),
                    attr_values: vec!["test@example.com".as_bytes().to_vec()],
                },
            ],
        };
        let message = LdapMessage {
            message_id: 3,
            protocol_op: ProtocolOp::SearchResultEntry(entry),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_modify_response() {
        let response = ModifyResponse {
            result_code: 0,
            matched_dn: "cn=test,dc=example,dc=com".to_string(),
            diagnostic_message: "".to_string(),
        };
        let message = LdapMessage {
            message_id: 4,
            protocol_op: ProtocolOp::ModifyResponse(response),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_add_response() {
        let response = AddResponse {
            result_code: 0,
            matched_dn: "".to_string(),
            diagnostic_message: "".to_string(),
        };
        let message = LdapMessage {
            message_id: 5,
            protocol_op: ProtocolOp::AddResponse(response),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_del_response() {
        let response = DelResponse {
            result_code: 0,
            matched_dn: "".to_string(),
            diagnostic_message: "".to_string(),
        };
        let message = LdapMessage {
            message_id: 6,
            protocol_op: ProtocolOp::DelResponse(response),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_extended_response() {
        let response = ExtendedResponse {
            result_code: 0,
            matched_dn: "".to_string(),
            diagnostic_message: "".to_string(),
            response_name: Some("1.3.6.1.4.1.4203.1.11.3".to_string()),
            response_value: Some("dn:cn=test".as_bytes().to_vec()),
        };
        let message = LdapMessage {
            message_id: 7,
            protocol_op: ProtocolOp::ExtendedResponse(response),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_ber_reader_short_length() {
        let data = vec![0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]; // OCTET STRING "hello"
        let mut reader = BerReader::new(&data);
        let result = reader.read_octet_string().unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_ber_reader_integer() {
        let data = vec![0x02, 0x01, 0x2A]; // INTEGER 42
        let mut reader = BerReader::new(&data);
        let result = reader.read_integer().unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_ber_reader_negative_integer() {
        let data = vec![0x02, 0x01, 0xFF]; // INTEGER -1
        let mut reader = BerReader::new(&data);
        let result = reader.read_integer().unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn test_ber_reader_boolean() {
        let data = vec![0x01, 0x01, 0xFF]; // BOOLEAN true
        let mut reader = BerReader::new(&data);
        assert_eq!(reader.read_boolean().unwrap(), true);

        let data = vec![0x01, 0x01, 0x00]; // BOOLEAN false
        let mut reader = BerReader::new(&data);
        assert_eq!(reader.read_boolean().unwrap(), false);
    }

    #[test]
    fn test_ber_reader_enumerated() {
        let data = vec![0x0A, 0x01, 0x02]; // ENUMERATED 2
        let mut reader = BerReader::new(&data);
        let result = reader.read_enumerated().unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn test_ber_reader_sequence() {
        // SEQUENCE containing INTEGER 42
        let data = vec![0x30, 0x03, 0x02, 0x01, 0x2A];
        let mut reader = BerReader::new(&data);
        let len = reader.read_sequence().unwrap();
        assert_eq!(len, 3);
        let value = reader.read_integer().unwrap();
        assert_eq!(value, 42);
    }

    // --- BER full implementation tests: round-trip, boundaries, multi-byte tag, OID, invalid ---

    #[test]
    fn test_ber_roundtrip_octet_string_lengths() {
        for len in [0_usize, 1, 127, 128, 256] {
            let s = "x".repeat(len);
            let mut writer = BerWriter::new();
            writer.write_string(&s);
            let encoded = writer.into_vec();
            let mut reader = BerReader::new(&encoded);
            let decoded = reader.read_octet_string().unwrap();
            assert_eq!(decoded.len(), len, "length {}", len);
            assert_eq!(decoded, s.as_bytes());
        }
    }

    #[test]
    fn test_ber_length_boundary_127() {
        let mut data = vec![0x04, 0x7F];
        data.extend_from_slice(&[0u8; 127]);
        let mut reader = BerReader::new(&data);
        let result = reader.read_octet_string().unwrap();
        assert_eq!(result.len(), 127);
    }

    #[test]
    fn test_ber_length_boundary_128() {
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend_from_slice(&[0u8; 128]);
        let mut reader = BerReader::new(&data);
        let result = reader.read_octet_string().unwrap();
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_ber_oid_roundtrip() {
        let oids = ["1.2.3", "1.2.840.113549", "1.3.6.1.4.1.4203.1.9.1.1"];
        for oid in oids {
            let mut writer = BerWriter::new();
            writer.write_oid(oid).unwrap();
            let encoded = writer.into_vec();
            let mut reader = BerReader::new(&encoded);
            let decoded = reader.read_oid().unwrap();
            assert_eq!(decoded, oid, "OID roundtrip");
        }
    }

    #[test]
    fn test_ber_oid_bytes_to_string() {
        // 1.2.840 = 0x2A 0x86 0x48 (BER encoding)
        let bytes = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]; // 1.2.840.113549
        let s = oid_bytes_to_string(&bytes).unwrap();
        assert_eq!(s, "1.2.840.113549");
    }

    #[test]
    fn test_ber_tag_multibyte_read() {
        // Single-byte tag: 0x04 (OCTET STRING)
        let data = vec![0x04, 0x01, 0x00];
        let mut reader = BerReader::new(&data);
        let tag_bytes = reader.read_tag_multibyte().unwrap();
        assert_eq!(tag_bytes, vec![0x04]);
        // Multi-byte tag: 0x1F 0x81 0x00 (tag number 128 in high-tag form)
        let data2 = vec![0x1F, 0x81, 0x00, 0x01, 0x01, 0xFF];
        let mut reader2 = BerReader::new(&data2);
        let tag_bytes2 = reader2.read_tag_multibyte().unwrap();
        assert_eq!(tag_bytes2, vec![0x1F, 0x81, 0x00]);
    }

    #[test]
    fn test_ber_write_tag_multi() {
        let mut writer = BerWriter::new();
        writer.write_tag_multi(&[0x1F, 0x81, 0x00]);
        writer.write_string("x");
        let out = writer.into_vec();
        assert_eq!(out[0], 0x1F);
        assert_eq!(out[1], 0x81);
        assert_eq!(out[2], 0x00);
    }

    #[test]
    fn test_ber_read_length_or_indefinite() {
        let data = vec![0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BerReader::new(&data);
        reader.read_tag().unwrap();
        let len = reader.read_length_or_indefinite().unwrap();
        assert_eq!(len, Some(5));
        let data_indef = vec![0x04, 0x80]; // indefinite
        let mut reader2 = BerReader::new(&data_indef);
        reader2.read_tag().unwrap();
        let len2 = reader2.read_length_or_indefinite().unwrap();
        assert_eq!(len2, None);
    }

    #[test]
    fn test_ber_truncated_integer_fails() {
        let data = vec![0x02, 0x02, 0xFF]; // INTEGER length 2 but only 1 byte
        let mut reader = BerReader::new(&data);
        assert!(reader.read_integer().is_err());
    }

    #[test]
    fn test_ber_invalid_tag_fails() {
        let data = vec![0x05, 0x00]; // NULL tag when expecting INTEGER
        let mut reader = BerReader::new(&data);
        assert!(reader.read_integer().is_err());
    }

    /// LDAPMessage with BindRequest (simple bind, auth tag 0x80): SEQUENCE { id=1, bindRequest [0] { version=3, name, simple [0] "secret" } }
    #[test]
    fn test_parse_bind_request_simple_tag_0x80() {
        // name = "cn=admin,dc=example,dc=com" (26 bytes), password = "secret" (6 bytes). Bind content: 3+2+26+2+6 = 39 (0x27). Outer: 3+2+39 = 44 (0x2c).
        let msg = vec![
            0x30, 0x2c, // SEQUENCE length 44
            0x02, 0x01, 0x01, // messageID 1
            0x60, 0x27, // [0] BindRequest length 39
            0x02, 0x01, 0x03, // version 3
            0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, // name (26 bytes)
            0x80, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // [0] simple OCTET STRING "secret"
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        assert_eq!(parsed.message_id, 1);
        match &parsed.protocol_op {
            ProtocolOp::BindRequest(b) => {
                assert_eq!(b.version, 3);
                assert_eq!(b.name, "cn=admin,dc=example,dc=com");
                match &b.authentication {
                    BindAuthentication::Simple(pw) => assert_eq!(pw, "secret"),
                    _ => panic!("expected Simple bind"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    /// Same as above but auth tag 0x61 (some clients send [APPLICATION 1] instead of [0]).
    #[test]
    fn test_parse_bind_request_simple_tag_0x61() {
        let msg = vec![
            0x30, 0x2c, 0x02, 0x01, 0x01, 0x60, 0x27,
            0x02, 0x01, 0x03,
            0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
            0x61, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // 0x61 instead of 0x80
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        match &parsed.protocol_op {
            ProtocolOp::BindRequest(b) => {
                match &b.authentication {
                    BindAuthentication::Simple(pw) => assert_eq!(pw, "secret"),
                    _ => panic!("expected Simple bind"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    /// Same but auth tag 0x41 (some clients send this for simple bind).
    #[test]
    fn test_parse_bind_request_simple_tag_0x41() {
        let msg = vec![
            0x30, 0x2c, 0x02, 0x01, 0x01, 0x60, 0x27,
            0x02, 0x01, 0x03,
            0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
            0x41, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // 0x41 instead of 0x80
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        match &parsed.protocol_op {
            ProtocolOp::BindRequest(b) => {
                match &b.authentication {
                    BindAuthentication::Simple(pw) => assert_eq!(pw, "secret"),
                    _ => panic!("expected Simple bind"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    /// Same but auth tag 0xD0 (some clients send this for simple bind).
    #[test]
    fn test_parse_bind_request_simple_tag_0xd0() {
        let msg = vec![
            0x30, 0x2c, 0x02, 0x01, 0x01, 0x60, 0x27,
            0x02, 0x01, 0x03,
            0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
            0xD0, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // 0xD0 instead of 0x80
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        match &parsed.protocol_op {
            ProtocolOp::BindRequest(b) => {
                match &b.authentication {
                    BindAuthentication::Simple(pw) => assert_eq!(pw, "secret"),
                    _ => panic!("expected Simple bind"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    /// BindRequest with SASL auth (tag 0xA3): mechanism "EXTERNAL", no credentials.
    /// Parser reads: after 0xA3 the length, then read_string() = length+bytes (no inner tag).
    #[test]
    fn test_parse_bind_request_sasl_tag_0xa3() {
        // SaslCredentials: A3 <len=10> mechanism 0x08 length 8 "EXTERNAL". BindRequest: version(3) + name(26) + sasl(2+10)=43 (0x2b). Outer: 3+2+43=48 (0x30).
        let msg = vec![
            0x30, 0x30, // SEQUENCE length 48
            0x02, 0x01, 0x01, // messageID 1
            0x60, 0x2b, // [0] BindRequest length 43
            0x02, 0x01, 0x03, // version 3
            0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, // name (26 bytes)
            0xA3, 0x0a, // [3] SaslCredentials length 10
            0x08, 0x08, 0x45, 0x58, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, // mechanism: tag 0x08, length 8, "EXTERNAL"
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        assert_eq!(parsed.message_id, 1);
        match &parsed.protocol_op {
            ProtocolOp::BindRequest(b) => {
                assert_eq!(b.version, 3);
                assert_eq!(b.name, "cn=admin,dc=example,dc=com");
                match &b.authentication {
                    BindAuthentication::Sasl { mechanism, credentials } => {
                        assert_eq!(mechanism, "EXTERNAL");
                        assert!(credentials.is_empty());
                    }
                    _ => panic!("expected Sasl bind"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    #[test]
    fn test_get_sync_request_control_none() {
        assert!(get_sync_request_control(None).is_none());
        assert!(get_sync_request_control(Some(&[])).is_none());
    }

    #[test]
    fn test_get_sync_request_control_wrong_oid() {
        let controls = vec![Control {
            ctype: "1.2.3.4".to_string(),
            critical: false,
            value: None,
        }];
        assert!(get_sync_request_control(Some(&controls)).is_none());
    }

    #[test]
    fn test_sync_request_control_refresh_and_persist() {
        // BER for Sync Request value: SEQUENCE { ENUMERATED 3 } (mode = refreshAndPersist)
        let value = vec![0x30, 0x03, 0x0A, 0x01, 0x03];
        let controls = vec![Control {
            ctype: SYNC_REQUEST_OID.to_string(),
            critical: false,
            value: Some(value),
        }];
        let ctrl = get_sync_request_control(Some(&controls)).unwrap();
        assert_eq!(ctrl.mode, 3);
        assert!(ctrl.is_refresh_and_persist());
        assert!(ctrl.cookie.is_none());
        assert!(!ctrl.reload_hint);
    }

    #[test]
    fn test_sync_request_control_refresh_only() {
        let value = vec![0x30, 0x03, 0x0A, 0x01, 0x01];
        let controls = vec![Control {
            ctype: SYNC_REQUEST_OID.to_string(),
            critical: false,
            value: Some(value),
        }];
        let ctrl = get_sync_request_control(Some(&controls)).unwrap();
        assert_eq!(ctrl.mode, 1);
        assert!(!ctrl.is_refresh_and_persist());
    }

    #[test]
    fn test_encode_intermediate_response() {
        let resp = IntermediateResponse {
            response_name: Some("1.3.6.1.4.1.4203.1.9.1.4".to_string()),
            response_value: Some(vec![0x00, 0x01, 0x02]),
        };
        let message = LdapMessage {
            message_id: 10,
            protocol_op: ProtocolOp::IntermediateResponse(resp),
            controls: None,
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x30);
    }

    #[test]
    fn test_encode_ldap_message_with_controls() {
        let done = SearchResultDone {
            result_code: 0,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        };
        let message = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchResultDone(done),
            controls: Some(vec![
                Control {
                    ctype: "1.2.840.113556.1.4.319".to_string(), // Paged Results OID
                    critical: false,
                    value: Some(vec![0x30, 0x00]), // empty cookie
                },
            ]),
        };
        let encoded = encode_ldap_message(&message).unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.contains(&0xA0), "encoded message should contain controls [0] 0xA0");
        // OID is BER-encoded (not ASCII); control SEQUENCE contains type as OID bytes
        assert!(encoded.len() > 30, "encoded message with control should have reasonable length");
    }

    #[test]
    fn test_filter_present_to_ldap_string() {
        let f = Filter::Present("objectClass".to_string());
        assert_eq!(f.to_ldap_string(), "(objectClass=*)");
    }

    #[test]
    fn test_filter_equality_to_ldap_string() {
        let f = Filter::EqualityMatch {
            attribute: "cn".to_string(),
            value: b"admin".to_vec(),
        };
        assert_eq!(f.to_ldap_string(), "(cn=admin)");
    }

    #[test]
    fn test_parse_search_request_with_filter_present() {
        // LDAPMessage: SEQUENCE { messageID 1, SearchRequest { base "", scope 2, deref 0, sizeLimit 0, timeLimit 0, typesOnly false, filter present objectClass, attributes {} } }
        // "objectClass" = 11 chars → 0x04 0x0B + 11 bytes = 13; filter 0x87 0x0D (13). SearchRequest: 17 + 2 + 13 + 2 = 34 (0x22). Outer: 3 + 2 + 34 = 39 (0x27).
        let msg = vec![
            0x30, 0x27, // SEQUENCE 39
            0x02, 0x01, 0x01, // messageID 1
            0x63, 0x22, // SearchRequest length 34
            0x04, 0x00, // baseObject ""
            0x0A, 0x01, 0x02, // scope wholeSubtree
            0x0A, 0x01, 0x00, // derefAliases never
            0x02, 0x01, 0x00, // sizeLimit 0
            0x02, 0x01, 0x00, // timeLimit 0
            0x01, 0x01, 0x00, // typesOnly false
            0x87, 0x0D, 0x04, 0x0B, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, // present "objectClass" (11 chars)
            0x30, 0x00, // attributes empty SEQUENCE
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        match &parsed.protocol_op {
            ProtocolOp::SearchRequest(sr) => {
                assert_eq!(sr.base_object, "");
                assert_eq!(sr.scope, SearchScope::WholeSubtree);
                match &sr.filter {
                    Filter::Present(attr) => assert_eq!(attr, "objectClass"),
                    _ => panic!("expected Present filter"),
                }
                assert_eq!(sr.filter.to_ldap_string(), "(objectClass=*)");
            }
            _ => panic!("expected SearchRequest"),
        }
    }

    #[test]
    fn test_parse_search_request_filter_equality() {
        // Filter equalityMatch (cn=admin): [3] SEQUENCE { attributeDesc "cn", assertionValue "admin" }
        // 0xA3 len 0x0D 0x30 0x0B 0x04 0x02 cn 0x04 0x05 admin
        let msg = vec![
            0x30, 0x1D, // SEQUENCE 29
            0x02, 0x01, 0x01,
            0x63, 0x19, // SearchRequest 25
            0x04, 0x00, 0x0A, 0x01, 0x02, 0x0A, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
            0xA3, 0x0D, 0x30, 0x0B, 0x04, 0x02, 0x63, 0x6E, 0x04, 0x05, 0x61, 0x64, 0x6D, 0x69, 0x6E, // equalityMatch cn=admin
            0x30, 0x00,
        ];
        let parsed = parse_ldap_message(&msg).unwrap();
        match &parsed.protocol_op {
            ProtocolOp::SearchRequest(sr) => {
                match &sr.filter {
                    Filter::EqualityMatch { attribute, value } => {
                        assert_eq!(attribute, "cn");
                        assert_eq!(value.as_slice(), b"admin");
                    }
                    _ => panic!("expected EqualityMatch"),
                }
                assert_eq!(sr.filter.to_ldap_string(), "(cn=admin)");
            }
            _ => panic!("expected SearchRequest"),
        }
    }
}
