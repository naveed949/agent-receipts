use std::collections::{BTreeSet, HashSet};

use crate::{canonical_json_value, Error, Json, Wtf16};

const HTTPS_PROTOCOL: &str = "https";
const HTTPS_RESOLUTION: &str = "public-only";
const HTTPS_REDIRECTS: &str = "none";
const MAX_SAFE_INT: f64 = 9_007_199_254_740_991.0;
const TOP_FIELDS: &[&str] = &[
    "version",
    "filesystem",
    "network",
    "git",
    "environment",
    "output",
    "container",
];
const FILESYSTEM_FIELDS: &[&str] = &["read", "sensitiveRead", "write"];
const GIT_FIELDS: &[&str] = &["write", "hooks"];
const ENVIRONMENT_FIELDS: &[&str] = &["secrets", "ambientSecrets"];
const OUTPUT_FIELDS: &[&str] = &["unrestricted"];
const CONTAINER_FIELDS: &[&str] = &["socket"];
const HTTPS_FIELDS: &[&str] = &[
    "protocol",
    "host",
    "port",
    "methods",
    "resolution",
    "redirects",
    "maxResponseBytes",
    "timeoutMs",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityPath {
    FilesystemRead,
    FilesystemSensitiveRead,
    FilesystemWrite,
    NetworkOutbound,
    NetworkHttps,
    GitWrite,
    GitHooks,
    EnvironmentSecrets,
    EnvironmentAmbientSecrets,
    OutputUnrestricted,
    ContainerSocket,
}

impl AuthorityPath {
    pub const ALL: [Self; 11] = [
        Self::FilesystemRead,
        Self::FilesystemSensitiveRead,
        Self::FilesystemWrite,
        Self::NetworkOutbound,
        Self::NetworkHttps,
        Self::GitWrite,
        Self::GitHooks,
        Self::EnvironmentSecrets,
        Self::EnvironmentAmbientSecrets,
        Self::OutputUnrestricted,
        Self::ContainerSocket,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemSensitiveRead => "filesystem.sensitiveRead",
            Self::FilesystemWrite => "filesystem.write",
            Self::NetworkOutbound => "network.outbound",
            Self::NetworkHttps => "network.https",
            Self::GitWrite => "git.write",
            Self::GitHooks => "git.hooks",
            Self::EnvironmentSecrets => "environment.secrets",
            Self::EnvironmentAmbientSecrets => "environment.ambientSecrets",
            Self::OutputUnrestricted => "output.unrestricted",
            Self::ContainerSocket => "container.socket",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relationship {
    Widening,
    Narrowing,
    Mixed,
    Unchanged,
}

impl Relationship {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Widening => "widening",
            Self::Narrowing => "narrowing",
            Self::Mixed => "mixed",
            Self::Unchanged => "unchanged",
        }
    }

    fn from_lists(widened: &[AuthorityPath], narrowed: &[AuthorityPath]) -> Self {
        match (!widened.is_empty(), !narrowed.is_empty()) {
            (true, true) => Self::Mixed,
            (true, false) => Self::Widening,
            (false, true) => Self::Narrowing,
            (false, false) => Self::Unchanged,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareResult {
    pub relationship: Relationship,
    pub widened: Vec<AuthorityPath>,
    pub narrowed: Vec<AuthorityPath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidInput,
    NotAnObject,
    CrossVersion,
    UnsupportedVersion,
    UnknownField,
    HttpsInV1,
    OutboundInV2,
    InvalidScope,
    InvalidFlag,
    InvalidHttpsHost,
    InvalidHttpsPort,
    InvalidHttpsMethod,
    InvalidHttpsBounds,
    InvalidHttpsShape,
}

impl AuthorityError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NotAnObject => "not_an_object",
            Self::CrossVersion => "cross_version",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownField => "unknown_field",
            Self::HttpsInV1 => "https_in_v1",
            Self::OutboundInV2 => "outbound_in_v2",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidFlag => "invalid_flag",
            Self::InvalidHttpsHost => "invalid_https_host",
            Self::InvalidHttpsPort => "invalid_https_port",
            Self::InvalidHttpsMethod => "invalid_https_method",
            Self::InvalidHttpsBounds => "invalid_https_bounds",
            Self::InvalidHttpsShape => "invalid_https_shape",
        }
    }
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AuthorityError {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Scope {
    Any,
    Identifiers(Vec<String>),
}

impl Scope {
    fn empty() -> Self {
        Self::Identifiers(Vec::new())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HttpMethod {
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
}

impl HttpMethod {
    fn parse(name: &str) -> Result<Self, AuthorityError> {
        match name {
            "DELETE" => Ok(Self::Delete),
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "OPTIONS" => Ok(Self::Options),
            "PATCH" => Ok(Self::Patch),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            _ => Err(AuthorityError::InvalidHttpsMethod),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpsRule {
    protocol: String,
    host: String,
    port: u16,
    methods: Vec<HttpMethod>,
    resolution: String,
    redirects: String,
    max_response_bytes: u64,
    timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Network {
    V1 { outbound: Scope },
    V2 { https: Vec<HttpsRule> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityPolicy {
    version: PolicyVersion,
    filesystem_read: Scope,
    filesystem_sensitive_read: Scope,
    filesystem_write: Scope,
    network: Network,
    git_write: Scope,
    git_hooks: Scope,
    environment_secrets: Scope,
    environment_ambient_secrets: bool,
    output_unrestricted: bool,
    container_socket: bool,
}

pub fn compare_authority_contracts(
    previous: &Json,
    next: &Json,
) -> Result<CompareResult, AuthorityError> {
    let previous = parse_policy(previous)?;
    let next = parse_policy(next)?;
    if previous.version != next.version {
        return Err(AuthorityError::CrossVersion);
    }
    let mut widened = Vec::new();
    let mut narrowed = Vec::new();
    for path in AuthorityPath::ALL {
        let (wide, narrow) = compare_path(&previous, &next, path);
        if wide {
            widened.push(path);
        }
        if narrow {
            narrowed.push(path);
        }
    }
    Ok(CompareResult {
        relationship: Relationship::from_lists(&widened, &narrowed),
        widened,
        narrowed,
    })
}

pub fn compare_authority_contracts_bytes(
    previous: &[u8],
    next: &[u8],
) -> Result<CompareResult, AuthorityError> {
    let previous = parse_json(previous)?;
    let next = parse_json(next)?;
    compare_authority_contracts(&previous, &next)
}

pub fn normalize_authority_policy(value: &Json) -> Result<Json, AuthorityError> {
    emit_policy(&parse_policy(value)?)
}

pub fn normalize_authority_policy_bytes(value: &[u8]) -> Result<Json, AuthorityError> {
    normalize_authority_policy(&parse_json(value)?)
}

pub fn normalize_https_authority_rules(value: &Json) -> Result<Json, AuthorityError> {
    emit_https_rules(&parse_https_rules(value)?)
}

pub fn normalize_https_authority_rules_bytes(value: &[u8]) -> Result<Json, AuthorityError> {
    normalize_https_authority_rules(&parse_json(value)?)
}

pub fn is_https_authority_subset(inner: &Json, outer: &Json) -> Result<bool, AuthorityError> {
    let inner = parse_https_rules(inner)?;
    let outer = parse_https_rules(outer)?;
    Ok(https_subset(&inner, &outer))
}

pub fn is_https_authority_subset_bytes(inner: &[u8], outer: &[u8]) -> Result<bool, AuthorityError> {
    let inner = parse_json(inner)?;
    let outer = parse_json(outer)?;
    is_https_authority_subset(&inner, &outer)
}

fn parse_json(bytes: &[u8]) -> Result<Json, AuthorityError> {
    crate::parse::parse(bytes).map_err(|err| match err {
        Error::InvalidJson | Error::NotUtf8 | Error::TooDeep | Error::Cycle | Error::TypeError => {
            AuthorityError::InvalidInput
        }
    })
}

fn parse_policy(value: &Json) -> Result<AuthorityPolicy, AuthorityError> {
    let entries = value.as_object().ok_or(AuthorityError::NotAnObject)?;
    reject_unknown(entries, TOP_FIELDS)?;
    let version = match field(value, "version") {
        None => PolicyVersion::V1,
        Some(item) => parse_version(item)?,
    };
    let filesystem = field(value, "filesystem");
    if let Some(domain) = filesystem {
        reject_domain(domain, FILESYSTEM_FIELDS)?;
    }
    let git = field(value, "git");
    if let Some(domain) = git {
        reject_domain(domain, GIT_FIELDS)?;
    }
    let environment = field(value, "environment");
    if let Some(domain) = environment {
        reject_domain(domain, ENVIRONMENT_FIELDS)?;
    }
    let output = field(value, "output");
    if let Some(domain) = output {
        reject_domain(domain, OUTPUT_FIELDS)?;
    }
    let container = field(value, "container");
    if let Some(domain) = container {
        reject_domain(domain, CONTAINER_FIELDS)?;
    }
    let network = parse_network(field(value, "network"), version)?;
    Ok(AuthorityPolicy {
        version,
        filesystem_read: parse_scope(filesystem.and_then(|domain| field(domain, "read")))?,
        filesystem_sensitive_read: parse_scope(
            filesystem.and_then(|domain| field(domain, "sensitiveRead")),
        )?,
        filesystem_write: parse_scope(filesystem.and_then(|domain| field(domain, "write")))?,
        network,
        git_write: parse_scope(git.and_then(|domain| field(domain, "write")))?,
        git_hooks: parse_scope(git.and_then(|domain| field(domain, "hooks")))?,
        environment_secrets: parse_scope(environment.and_then(|domain| field(domain, "secrets")))?,
        environment_ambient_secrets: parse_flag(
            environment.and_then(|domain| field(domain, "ambientSecrets")),
        )?,
        output_unrestricted: parse_flag(output.and_then(|domain| field(domain, "unrestricted")))?,
        container_socket: parse_flag(container.and_then(|domain| field(domain, "socket")))?,
    })
}

fn parse_version(value: &Json) -> Result<PolicyVersion, AuthorityError> {
    match json_string(value).as_deref() {
        Ok("1") => Ok(PolicyVersion::V1),
        Ok("2") => Ok(PolicyVersion::V2),
        _ => Err(AuthorityError::UnsupportedVersion),
    }
}

fn parse_network(value: Option<&Json>, version: PolicyVersion) -> Result<Network, AuthorityError> {
    let Some(value) = value else {
        return Ok(match version {
            PolicyVersion::V1 => Network::V1 {
                outbound: Scope::empty(),
            },
            PolicyVersion::V2 => Network::V2 { https: Vec::new() },
        });
    };
    let entries = value.as_object().ok_or(AuthorityError::NotAnObject)?;
    match version {
        PolicyVersion::V1 => {
            if field(value, "https").is_some() {
                return Err(AuthorityError::HttpsInV1);
            }
            reject_unknown(entries, &["outbound"])?;
            Ok(Network::V1 {
                outbound: parse_scope(field(value, "outbound"))?,
            })
        }
        PolicyVersion::V2 => {
            if field(value, "outbound").is_some() {
                return Err(AuthorityError::OutboundInV2);
            }
            reject_unknown(entries, &["https"])?;
            let https = match field(value, "https") {
                None => Vec::new(),
                Some(rules) => parse_https_rules(rules)?,
            };
            Ok(Network::V2 { https })
        }
    }
}

fn parse_scope(value: Option<&Json>) -> Result<Scope, AuthorityError> {
    let Some(value) = value else {
        return Ok(Scope::empty());
    };
    if let Ok(text) = json_string(value) {
        if text == "any" {
            return Ok(Scope::Any);
        }
        return Err(AuthorityError::InvalidScope);
    }
    let Some(items) = value.as_array() else {
        return Err(AuthorityError::InvalidScope);
    };
    let mut idents = Vec::with_capacity(items.len());
    for item in items {
        let text = json_string(item).map_err(|_| AuthorityError::InvalidScope)?;
        if text.is_empty() || text.trim() != text {
            return Err(AuthorityError::InvalidScope);
        }
        idents.push(text);
    }
    idents.sort_by(|left, right| {
        Wtf16::from_str(left)
            .units()
            .cmp(Wtf16::from_str(right).units())
    });
    idents.dedup();
    Ok(Scope::Identifiers(idents))
}

fn parse_flag(value: Option<&Json>) -> Result<bool, AuthorityError> {
    match value {
        None => Ok(false),
        Some(item) => item.as_bool().ok_or(AuthorityError::InvalidFlag),
    }
}

fn parse_https_rules(value: &Json) -> Result<Vec<HttpsRule>, AuthorityError> {
    let items = value.as_array().ok_or(AuthorityError::InvalidHttpsShape)?;
    let mut rules = Vec::with_capacity(items.len());
    for item in items {
        rules.push(parse_https_rule(item)?);
    }
    normalize_https_rules(rules)
}

fn parse_https_rule(value: &Json) -> Result<HttpsRule, AuthorityError> {
    let entries = value.as_object().ok_or(AuthorityError::InvalidHttpsShape)?;
    if entries.len() != HTTPS_FIELDS.len() {
        return Err(AuthorityError::InvalidHttpsShape);
    }
    reject_unknown(entries, HTTPS_FIELDS)?;
    let protocol = required_string(value, "protocol")?;
    if protocol != HTTPS_PROTOCOL {
        return Err(AuthorityError::InvalidHttpsShape);
    }
    let host = parse_host(&required_string(value, "host")?)?;
    let port = parse_port(field(value, "port").ok_or(AuthorityError::InvalidHttpsShape)?)?;
    let methods = parse_methods(field(value, "methods").ok_or(AuthorityError::InvalidHttpsShape)?)?;
    let resolution = required_string(value, "resolution")?;
    if resolution != HTTPS_RESOLUTION {
        return Err(AuthorityError::InvalidHttpsShape);
    }
    let redirects = required_string(value, "redirects")?;
    if redirects != HTTPS_REDIRECTS {
        return Err(AuthorityError::InvalidHttpsShape);
    }
    let max_response_bytes = parse_positive_safe_int(
        field(value, "maxResponseBytes").ok_or(AuthorityError::InvalidHttpsShape)?,
    )?;
    let timeout_ms = parse_positive_safe_int(
        field(value, "timeoutMs").ok_or(AuthorityError::InvalidHttpsShape)?,
    )?;
    Ok(HttpsRule {
        protocol,
        host,
        port,
        methods,
        resolution,
        redirects,
        max_response_bytes,
        timeout_ms,
    })
}

fn parse_host(raw: &str) -> Result<String, AuthorityError> {
    if raw.is_empty() || !raw.is_ascii() || raw.ends_with('.') || raw.starts_with('.') {
        return Err(AuthorityError::InvalidHttpsHost);
    }
    if raw.contains(':') || raw.contains('/') || raw.contains('@') {
        return Err(AuthorityError::InvalidHttpsHost);
    }
    let lower = raw.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return Err(AuthorityError::InvalidHttpsHost);
    }
    let last = labels.len() - 1;
    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(AuthorityError::InvalidHttpsHost);
        }
        if label.starts_with("xn--") {
            return Err(AuthorityError::InvalidHttpsHost);
        }
        if index == last {
            if !label.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return Err(AuthorityError::InvalidHttpsHost);
            }
        } else if !is_ldh(label) {
            return Err(AuthorityError::InvalidHttpsHost);
        }
    }
    Ok(lower)
}

fn is_ldh(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn parse_port(value: &Json) -> Result<u16, AuthorityError> {
    let number = exact_int(value).ok_or(AuthorityError::InvalidHttpsPort)?;
    if (1..=65535).contains(&number) {
        u16::try_from(number).map_err(|_| AuthorityError::InvalidHttpsPort)
    } else {
        Err(AuthorityError::InvalidHttpsPort)
    }
}

fn parse_positive_safe_int(value: &Json) -> Result<u64, AuthorityError> {
    let number = exact_int(value).ok_or(AuthorityError::InvalidHttpsBounds)?;
    if number < 1 || (number as f64) > MAX_SAFE_INT {
        return Err(AuthorityError::InvalidHttpsBounds);
    }
    Ok(number)
}

fn exact_int(value: &Json) -> Option<u64> {
    let number = value.as_number()?;
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 {
        return None;
    }
    Some(number as u64)
}

fn parse_methods(value: &Json) -> Result<Vec<HttpMethod>, AuthorityError> {
    let items = value.as_array().ok_or(AuthorityError::InvalidHttpsMethod)?;
    if items.is_empty() {
        return Err(AuthorityError::InvalidHttpsMethod);
    }
    let mut methods = BTreeSet::new();
    for item in items {
        let name = json_string(item).map_err(|_| AuthorityError::InvalidHttpsMethod)?;
        methods.insert(HttpMethod::parse(&name)?);
    }
    Ok(methods.into_iter().collect())
}

fn normalize_https_rules(mut rules: Vec<HttpsRule>) -> Result<Vec<HttpsRule>, AuthorityError> {
    sort_https_rules(&mut rules)?;
    rules.dedup();
    let mut kept = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let covered = rules
            .iter()
            .enumerate()
            .any(|(other, cover)| other != index && rule_covers(cover, rule));
        if !covered {
            kept.push(rule.clone());
        }
    }
    sort_https_rules(&mut kept)?;
    Ok(kept)
}

fn sort_https_rules(rules: &mut [HttpsRule]) -> Result<(), AuthorityError> {
    let mut keyed = Vec::with_capacity(rules.len());
    for rule in rules.iter() {
        let json = emit_https_rule(rule)?;
        let bytes = canonical_json_value(&json).map_err(|_| AuthorityError::InvalidHttpsShape)?;
        keyed.push((bytes, rule.clone()));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (slot, (_, rule)) in rules.iter_mut().zip(keyed) {
        *slot = rule;
    }
    Ok(())
}

fn rule_covers(cover: &HttpsRule, inner: &HttpsRule) -> bool {
    inner
        .methods
        .iter()
        .all(|method| method_covered(cover, inner, *method))
}

fn method_covered(cover: &HttpsRule, inner: &HttpsRule, method: HttpMethod) -> bool {
    cover.protocol == inner.protocol
        && cover.host == inner.host
        && cover.port == inner.port
        && cover.resolution == inner.resolution
        && cover.redirects == inner.redirects
        && cover.methods.contains(&method)
        && cover.max_response_bytes >= inner.max_response_bytes
        && cover.timeout_ms >= inner.timeout_ms
}

fn https_subset(inner: &[HttpsRule], outer: &[HttpsRule]) -> bool {
    inner.iter().all(|rule| {
        rule.methods.iter().all(|method| {
            outer
                .iter()
                .any(|cover| method_covered(cover, rule, *method))
        })
    })
}

fn compare_path(
    previous: &AuthorityPolicy,
    next: &AuthorityPolicy,
    path: AuthorityPath,
) -> (bool, bool) {
    match path {
        AuthorityPath::FilesystemRead => {
            compare_scope(&previous.filesystem_read, &next.filesystem_read)
        }
        AuthorityPath::FilesystemSensitiveRead => compare_scope(
            &previous.filesystem_sensitive_read,
            &next.filesystem_sensitive_read,
        ),
        AuthorityPath::FilesystemWrite => {
            compare_scope(&previous.filesystem_write, &next.filesystem_write)
        }
        AuthorityPath::NetworkOutbound => {
            compare_scope(&network_outbound(previous), &network_outbound(next))
        }
        AuthorityPath::NetworkHttps => compare_https(previous, next),
        AuthorityPath::GitWrite => compare_scope(&previous.git_write, &next.git_write),
        AuthorityPath::GitHooks => compare_scope(&previous.git_hooks, &next.git_hooks),
        AuthorityPath::EnvironmentSecrets => {
            compare_scope(&previous.environment_secrets, &next.environment_secrets)
        }
        AuthorityPath::EnvironmentAmbientSecrets => compare_flag(
            previous.environment_ambient_secrets,
            next.environment_ambient_secrets,
        ),
        AuthorityPath::OutputUnrestricted => {
            compare_flag(previous.output_unrestricted, next.output_unrestricted)
        }
        AuthorityPath::ContainerSocket => {
            compare_flag(previous.container_socket, next.container_socket)
        }
    }
}

fn network_outbound(policy: &AuthorityPolicy) -> Scope {
    match &policy.network {
        Network::V1 { outbound } => outbound.clone(),
        Network::V2 { .. } => Scope::empty(),
    }
}

fn network_https(policy: &AuthorityPolicy) -> &[HttpsRule] {
    match &policy.network {
        Network::V1 { .. } => &[],
        Network::V2 { https } => https,
    }
}

fn compare_https(previous: &AuthorityPolicy, next: &AuthorityPolicy) -> (bool, bool) {
    let previous = network_https(previous);
    let next = network_https(next);
    let next_subset = https_subset(next, previous);
    let previous_subset = https_subset(previous, next);
    (!next_subset, !previous_subset)
}

fn compare_scope(before: &Scope, after: &Scope) -> (bool, bool) {
    match (before, after) {
        (Scope::Any, Scope::Any) => (false, false),
        (_, Scope::Any) => (true, false),
        (Scope::Any, _) => (false, true),
        (Scope::Identifiers(before), Scope::Identifiers(after)) => {
            let before_set: HashSet<&str> = before.iter().map(String::as_str).collect();
            let after_set: HashSet<&str> = after.iter().map(String::as_str).collect();
            let widened = after.iter().any(|item| !before_set.contains(item.as_str()));
            let narrowed = before.iter().any(|item| !after_set.contains(item.as_str()));
            (widened, narrowed)
        }
    }
}

fn compare_flag(before: bool, after: bool) -> (bool, bool) {
    (after && !before, before && !after)
}

fn emit_policy(policy: &AuthorityPolicy) -> Result<Json, AuthorityError> {
    let mut entries = Vec::new();
    let version = match policy.version {
        PolicyVersion::V1 => "1",
        PolicyVersion::V2 => "2",
    };
    entries.push(pair("version", json_str(version)));
    push_scope(&mut entries, "filesystem", "read", &policy.filesystem_read)?;
    push_scope(
        &mut entries,
        "filesystem",
        "sensitiveRead",
        &policy.filesystem_sensitive_read,
    )?;
    push_scope(
        &mut entries,
        "filesystem",
        "write",
        &policy.filesystem_write,
    )?;
    match &policy.network {
        Network::V1 { outbound } => {
            push_scope(&mut entries, "network", "outbound", outbound)?;
        }
        Network::V2 { https } => {
            if !https.is_empty() {
                let rules = emit_https_rules(https)?;
                insert_domain(&mut entries, "network", "https", rules)?;
            }
        }
    }
    push_scope(&mut entries, "git", "write", &policy.git_write)?;
    push_scope(&mut entries, "git", "hooks", &policy.git_hooks)?;
    push_scope(
        &mut entries,
        "environment",
        "secrets",
        &policy.environment_secrets,
    )?;
    push_flag(
        &mut entries,
        "environment",
        "ambientSecrets",
        policy.environment_ambient_secrets,
    )?;
    push_flag(
        &mut entries,
        "output",
        "unrestricted",
        policy.output_unrestricted,
    )?;
    push_flag(&mut entries, "container", "socket", policy.container_socket)?;
    Json::object(collapse_domains(entries)?).map_err(|_| AuthorityError::InvalidInput)
}

fn push_scope(
    entries: &mut Vec<(Wtf16, Json)>,
    domain: &str,
    name: &str,
    scope: &Scope,
) -> Result<(), AuthorityError> {
    match scope {
        Scope::Any => insert_domain(entries, domain, name, json_str("any")),
        Scope::Identifiers(items) if items.is_empty() => Ok(()),
        Scope::Identifiers(items) => {
            let values = items.iter().map(|item| json_str(item)).collect();
            insert_domain(entries, domain, name, Json::array(values))
        }
    }
}

fn push_flag(
    entries: &mut Vec<(Wtf16, Json)>,
    domain: &str,
    name: &str,
    flag: bool,
) -> Result<(), AuthorityError> {
    if flag {
        insert_domain(entries, domain, name, Json::bool(true))
    } else {
        Ok(())
    }
}

fn insert_domain(
    entries: &mut Vec<(Wtf16, Json)>,
    domain: &str,
    name: &str,
    value: Json,
) -> Result<(), AuthorityError> {
    entries.push((
        Wtf16::from_str(domain),
        Json::object(vec![pair(name, value)]).map_err(|_| AuthorityError::InvalidInput)?,
    ));
    Ok(())
}

fn collapse_domains(entries: Vec<(Wtf16, Json)>) -> Result<Vec<(Wtf16, Json)>, AuthorityError> {
    let mut merged: Vec<(Wtf16, Vec<(Wtf16, Json)>)> = Vec::new();
    let mut version = None;
    for (key, value) in entries {
        if key == Wtf16::from_str("version") {
            version = Some(value);
            continue;
        }
        let child = value
            .as_object()
            .ok_or(AuthorityError::InvalidInput)?
            .to_vec();
        if let Some((_, existing)) = merged.iter_mut().find(|(name, _)| name == &key) {
            existing.extend(child);
        } else {
            merged.push((key, child));
        }
    }
    let mut out = Vec::new();
    if let Some(version) = version {
        out.push((Wtf16::from_str("version"), version));
    }
    for (key, children) in merged {
        out.push((
            key,
            Json::object(children).map_err(|_| AuthorityError::InvalidInput)?,
        ));
    }
    Ok(out)
}

fn emit_https_rules(rules: &[HttpsRule]) -> Result<Json, AuthorityError> {
    let mut items = Vec::with_capacity(rules.len());
    for rule in rules {
        items.push(emit_https_rule(rule)?);
    }
    Ok(Json::array(items))
}

fn emit_https_rule(rule: &HttpsRule) -> Result<Json, AuthorityError> {
    let methods = rule
        .methods
        .iter()
        .map(|method| json_str(method.as_str()))
        .collect();
    Json::object(vec![
        pair("protocol", json_str(&rule.protocol)),
        pair("host", json_str(&rule.host)),
        pair(
            "port",
            Json::number(f64::from(rule.port)).map_err(|_| AuthorityError::InvalidHttpsPort)?,
        ),
        pair("methods", Json::array(methods)),
        pair("resolution", json_str(&rule.resolution)),
        pair("redirects", json_str(&rule.redirects)),
        pair(
            "maxResponseBytes",
            Json::number(rule.max_response_bytes as f64)
                .map_err(|_| AuthorityError::InvalidHttpsBounds)?,
        ),
        pair(
            "timeoutMs",
            Json::number(rule.timeout_ms as f64).map_err(|_| AuthorityError::InvalidHttpsBounds)?,
        ),
    ])
    .map_err(|_| AuthorityError::InvalidHttpsShape)
}

fn reject_domain(value: &Json, allowed: &[&str]) -> Result<(), AuthorityError> {
    let entries = value.as_object().ok_or(AuthorityError::NotAnObject)?;
    reject_unknown(entries, allowed)
}

fn reject_unknown(entries: &[(Wtf16, Json)], allowed: &[&str]) -> Result<(), AuthorityError> {
    for (key, _) in entries {
        let name = String::from_utf16(key.units()).map_err(|_| AuthorityError::UnknownField)?;
        if !allowed.contains(&name.as_str()) {
            return Err(AuthorityError::UnknownField);
        }
    }
    Ok(())
}

fn field<'a>(value: &'a Json, name: &str) -> Option<&'a Json> {
    let want = Wtf16::from_str(name);
    value
        .as_object()?
        .iter()
        .find(|(key, _)| key == &want)
        .map(|(_, child)| child)
}

fn required_string(value: &Json, name: &str) -> Result<String, AuthorityError> {
    json_string(field(value, name).ok_or(AuthorityError::InvalidHttpsShape)?)
        .map_err(|_| AuthorityError::InvalidHttpsShape)
}

fn json_string(value: &Json) -> Result<String, AuthorityError> {
    let units = value.as_string().ok_or(AuthorityError::InvalidInput)?;
    String::from_utf16(units.units()).map_err(|_| AuthorityError::InvalidInput)
}

fn json_str(text: &str) -> Json {
    Json::string(Wtf16::from_str(text))
}

fn pair(name: &str, value: Json) -> (Wtf16, Json) {
    (Wtf16::from_str(name), value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> Json {
        crate::parse::parse(text.as_bytes()).unwrap()
    }

    fn cmp(previous: &str, next: &str) -> CompareResult {
        compare_authority_contracts(&policy(previous), &policy(next)).unwrap()
    }

    fn err(previous: &str, next: &str) -> AuthorityError {
        compare_authority_contracts(&policy(previous), &policy(next)).unwrap_err()
    }

    fn rule(
        host: &str,
        port: u16,
        methods: &[&str],
        max_response_bytes: u64,
        timeout_ms: u64,
    ) -> HttpsRule {
        let mut parsed = methods
            .iter()
            .map(|name| HttpMethod::parse(name).unwrap())
            .collect::<Vec<_>>();
        parsed.sort();
        parsed.dedup();
        HttpsRule {
            protocol: HTTPS_PROTOCOL.to_string(),
            host: host.to_string(),
            port,
            methods: parsed,
            resolution: HTTPS_RESOLUTION.to_string(),
            redirects: HTTPS_REDIRECTS.to_string(),
            max_response_bytes,
            timeout_ms,
        }
    }

    #[test]
    fn v1_widening_adds_a_read_path() {
        let result = cmp(
            r#"{"filesystem":{"read":["docs/a"],"write":["docs/a"]}}"#,
            r#"{"filesystem":{"read":["docs/a","docs/b"],"write":["docs/a"]}}"#,
        );
        assert_eq!(result.relationship, Relationship::Widening);
        assert_eq!(result.widened, vec![AuthorityPath::FilesystemRead]);
        assert!(result.narrowed.is_empty());
    }

    #[test]
    fn mixed_follows_fixed_path_order() {
        let result = cmp(
            r#"{"filesystem":{"write":["x"]},"git":{"hooks":["h"]},"output":{"unrestricted":false}}"#,
            r#"{"container":{"socket":true},"filesystem":{"read":"any"},"git":{"hooks":[]}}"#,
        );
        assert_eq!(result.relationship, Relationship::Mixed);
        assert_eq!(
            result.widened,
            vec![
                AuthorityPath::FilesystemRead,
                AuthorityPath::ContainerSocket
            ]
        );
        assert_eq!(
            result.narrowed,
            vec![AuthorityPath::FilesystemWrite, AuthorityPath::GitHooks]
        );
    }

    #[test]
    fn identifier_membership_matches_set_equality() {
        let shared: String = (0..400)
            .map(|index| format!(r#""id{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        let previous = format!(r#"{{"filesystem":{{"read":[{shared},"dup","dup"]}}}}"#);
        let same = format!(r#"{{"filesystem":{{"read":["dup",{shared}]}}}}"#);
        let wider = format!(r#"{{"filesystem":{{"read":[{shared},"dup","extra"]}}}}"#);
        let same_result = cmp(&previous, &same);
        assert_eq!(same_result.relationship, Relationship::Unchanged);
        assert!(same_result.widened.is_empty());
        assert!(same_result.narrowed.is_empty());
        let wide_result = cmp(&previous, &wider);
        assert_eq!(wide_result.relationship, Relationship::Widening);
        assert_eq!(wide_result.widened, vec![AuthorityPath::FilesystemRead]);
        assert!(wide_result.narrowed.is_empty());
    }

    #[test]
    fn empty_false_and_absent_are_unchanged() {
        let result = cmp(
            r#"{"filesystem":{"read":["b","a","a"],"write":[]},"output":{"unrestricted":false}}"#,
            r#"{"filesystem":{"read":["a","b"]}}"#,
        );
        assert_eq!(result.relationship, Relationship::Unchanged);
        assert!(result.widened.is_empty());
        assert!(result.narrowed.is_empty());
    }

    #[test]
    fn any_to_list_is_narrowing() {
        let result = cmp(
            r#"{"environment":{"secrets":"any"}}"#,
            r#"{"environment":{"secrets":["API_KEY"]}}"#,
        );
        assert_eq!(result.relationship, Relationship::Narrowing);
        assert_eq!(result.narrowed, vec![AuthorityPath::EnvironmentSecrets]);
    }

    #[test]
    fn https_split_and_merged_are_unchanged() {
        let previous = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000},{"protocol":"https","host":"api.example.com","port":443,"methods":["HEAD"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let next = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"API.example.com","port":443,"methods":["HEAD","GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let result = cmp(previous, next);
        assert_eq!(result.relationship, Relationship::Unchanged);
    }

    #[test]
    fn https_bounds_mixed_puts_the_path_in_both_lists() {
        let previous = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let next = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":2048,"timeoutMs":500}]}}"#;
        let result = cmp(previous, next);
        assert_eq!(result.relationship, Relationship::Mixed);
        assert_eq!(result.widened, vec![AuthorityPath::NetworkHttps]);
        assert_eq!(result.narrowed, vec![AuthorityPath::NetworkHttps]);
    }

    #[test]
    fn rejections_match_vector_classes() {
        assert_eq!(
            err("{}", r#"{"version":"2"}"#),
            AuthorityError::CrossVersion
        );
        assert_eq!(
            err(
                r#"{"filesystem":{"read":[]}}"#,
                r#"{"filesystem":{"read":[],"exec":["x"]}}"#
            ),
            AuthorityError::UnknownField
        );
        assert_eq!(
            err("{}", r#"{"network":{"https":[]}}"#),
            AuthorityError::HttpsInV1
        );
        assert_eq!(
            err(
                r#"{"version":"2"}"#,
                r#"{"version":"2","network":{"outbound":"any"}}"#
            ),
            AuthorityError::OutboundInV2
        );
        assert_eq!(
            err(r#"{"version":"3"}"#, r#"{"version":"3"}"#),
            AuthorityError::UnsupportedVersion
        );
        assert_eq!(
            err(r#"{"git":{"write":[" padded"]}}"#, "{}"),
            AuthorityError::InvalidScope
        );
        assert_eq!(
            err(r#"{"output":{"unrestricted":"yes"}}"#, "{}"),
            AuthorityError::InvalidFlag
        );
        assert_eq!(
            err(
                r#"{"version":"2","network":{"https":[{"protocol":"https","host":"127.0.0.1","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#,
                r#"{"version":"2"}"#
            ),
            AuthorityError::InvalidHttpsHost
        );
    }

    #[test]
    fn host_validation_edges() {
        assert!(parse_host("api.example.com").is_ok());
        assert!(parse_host("API.Example.COM").is_ok());
        assert_eq!(parse_host("API.Example.COM").unwrap(), "api.example.com");
        assert!(parse_host("127.0.0.1").is_err());
        assert!(parse_host("example.com.").is_err());
        assert!(parse_host("*.example.com").is_err());
        assert!(parse_host("xn--n3h.example").is_err());
        assert!(parse_host("bücher.example").is_err());
        assert!(parse_host("localhost").is_err());
        assert!(parse_host("a..b.com").is_err());
        assert!(parse_host("example..com").is_err());
        assert!(parse_host("user@api.example.com").is_err());
        assert!(parse_host("api.example.com:443").is_err());
        assert!(parse_host("[::1]").is_err());
    }

    #[test]
    fn path_prefix_is_not_a_subset() {
        let result = cmp(
            r#"{"filesystem":{"read":["docs"]}}"#,
            r#"{"filesystem":{"read":["docs/a"]}}"#,
        );
        assert_eq!(result.relationship, Relationship::Mixed);
    }

    #[test]
    fn empty_https_is_subset_of_any() {
        assert!(https_subset(
            &[],
            &[rule("api.example.com", 443, &["GET"], 1024, 1000)]
        ));
        assert!(!https_subset(
            &[rule("api.example.com", 443, &["GET"], 1024, 1000)],
            &[]
        ));
        assert!(https_subset(&[], &[]));
    }

    #[test]
    fn subset_mutation_protocol() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let mut outer = inner.clone();
        outer.protocol = "http".to_string();
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_host() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let outer = rule("api.example.org", 443, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_port() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let outer = rule("api.example.com", 444, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_resolution() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let mut outer = inner.clone();
        outer.resolution = "any".to_string();
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_redirects() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let mut outer = inner.clone();
        outer.redirects = "follow".to_string();
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_methods() {
        let inner = rule("api.example.com", 443, &["POST"], 1024, 1000);
        let outer = rule("api.example.com", 443, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_max_response_bytes() {
        let inner = rule("api.example.com", 443, &["GET"], 2048, 1000);
        let outer = rule("api.example.com", 443, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn subset_mutation_timeout_ms() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 2000);
        let outer = rule("api.example.com", 443, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }

    #[test]
    fn port_zero_and_too_large_are_invalid() {
        let zero = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":0,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let huge = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":65536,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        assert_eq!(
            compare_authority_contracts(&policy(zero), &policy(r#"{"version":"2"}"#)).unwrap_err(),
            AuthorityError::InvalidHttpsPort
        );
        assert_eq!(
            compare_authority_contracts(&policy(huge), &policy(r#"{"version":"2"}"#)).unwrap_err(),
            AuthorityError::InvalidHttpsPort
        );
    }

    fn https_rule(host: &str, port: &str, methods: &str, extra: &str) -> String {
        format!(
            r#"{{"version":"2","network":{{"https":[{{"protocol":"https","host":"{host}","port":{port},"methods":{methods},"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000{extra}}}]}}}}"#
        )
    }

    fn https_err(text: &str) -> AuthorityError {
        compare_authority_contracts(&policy(text), &policy(r#"{"version":"2"}"#)).unwrap_err()
    }

    #[test]
    fn lowercase_and_unknown_methods_are_invalid() {
        assert_eq!(
            https_err(&https_rule("api.example.com", "443", r#"["get"]"#, "")),
            AuthorityError::InvalidHttpsMethod
        );
        assert_eq!(
            https_err(&https_rule("api.example.com", "443", r#"["TRACE"]"#, "")),
            AuthorityError::InvalidHttpsMethod
        );
        assert_eq!(
            https_err(&https_rule("api.example.com", "443", "[]", "")),
            AuthorityError::InvalidHttpsMethod
        );
    }

    #[test]
    fn protocol_resolution_and_redirects_must_be_the_fixed_strings() {
        let http = r#"{"version":"2","network":{"https":[{"protocol":"http","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let any = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"any","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        let follow = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"follow","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        assert_eq!(https_err(http), AuthorityError::InvalidHttpsShape);
        assert_eq!(https_err(any), AuthorityError::InvalidHttpsShape);
        assert_eq!(https_err(follow), AuthorityError::InvalidHttpsShape);
    }

    #[test]
    fn omitted_port_is_invalid() {
        let omitted = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1024,"timeoutMs":1000}]}}"#;
        assert_eq!(https_err(omitted), AuthorityError::InvalidHttpsShape);
    }

    #[test]
    fn duplicate_keys_in_bytes_are_invalid() {
        let previous = br#"{"filesystem":{"read":["first"],"read":["second"]}}"#;
        let next = br#"{}"#;
        assert_eq!(
            compare_authority_contracts_bytes(previous, next).unwrap_err(),
            AuthorityError::InvalidInput
        );
    }

    #[test]
    fn extra_https_field_and_false_https_are_invalid() {
        assert_eq!(
            https_err(&https_rule(
                "api.example.com",
                "443",
                r#"["GET"]"#,
                r#","path":"/""#
            )),
            AuthorityError::InvalidHttpsShape
        );
        assert_eq!(
            https_err(r#"{"version":"2","network":{"https":false}}"#),
            AuthorityError::InvalidHttpsShape
        );
        assert_eq!(
            https_err(r#"{"version":"2","network":{"https":{"host":"api.example.com"}}}"#),
            AuthorityError::InvalidHttpsShape
        );
    }

    #[test]
    fn bounds_must_be_positive_safe_integers() {
        let zero_bytes = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":0,"timeoutMs":1000}]}}"#;
        let frac = r#"{"version":"2","network":{"https":[{"protocol":"https","host":"api.example.com","port":443,"methods":["GET"],"resolution":"public-only","redirects":"none","maxResponseBytes":1.5,"timeoutMs":1000}]}}"#;
        assert_eq!(https_err(zero_bytes), AuthorityError::InvalidHttpsBounds);
        assert_eq!(https_err(frac), AuthorityError::InvalidHttpsBounds);
    }

    #[test]
    fn ports_do_not_default_to_443() {
        let inner = rule("api.example.com", 443, &["GET"], 1024, 1000);
        let outer = rule("api.example.com", 8443, &["GET"], 1024, 1000);
        assert!(!https_subset(&[inner], &[outer]));
    }
}
