use std::{collections::HashSet, ops::Not, str::FromStr, sync::LazyLock};

use mirrord_analytics::CollectAnalytics;
use mirrord_config_derive::MirrordConfig;
use mirrord_protocol::tcp::{
    HTTP_BODY_JSON_FILTER_VERSION, HTTP_COMPOSITE_FILTER_VERSION, HTTP_METHOD_FILTER_VERSION,
};
use schemars::JsonSchema;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::{
    config::{ConfigContext, ConfigError, from_env::FromEnv, source::MirrordConfigSource},
    util::MirrordToggleableConfig,
};

/// Filter configuration for the HTTP traffic stealer feature.
///
/// Allows the user to set a filter (regex) for the HTTP headers, so that the stealer traffic
/// feature only captures HTTP requests that match the specified filter, forwarding unmatched
/// requests to their original destinations.
///
/// Only does something when [`feature.network.incoming.mode`](#feature-network-incoming-mode) is
/// set as `"steal"`, ignored otherwise.
///
/// For example, to filter based on header:
/// ```json
/// {
///   "header_filter": "host: api\\..+"
/// }
/// ```
/// Setting that filter will make mirrord only steal requests with the `host` header set to hosts
/// that start with "api", followed by a dot, and then at least one more character.
///
/// For example, to filter based on path:
/// ```json
/// {
///   "path_filter": "^/api/"
/// }
/// ```
/// Setting this filter will make mirrord only steal requests to URIs starting with "/api/".
///
///
/// This can be useful for filtering out Kubernetes liveness, readiness and startup probes.
/// For example, for avoiding stealing any probe sent by kubernetes, you can set this filter:
/// ```json
/// {
///   "header_filter": "^User-Agent: (?!kube-probe)"
/// }
/// ```
/// Setting this filter will make mirrord only steal requests that **do** have a user agent that
/// **does not** begin with "kube-probe".
///
/// Similarly, you can exclude certain paths using a negative look-ahead:
/// ```json
/// {
///   "path_filter": "^(?!/health/)"
/// }
/// ```
/// Setting this filter will make mirrord only steal requests to URIs that do not start with
/// "/health/".
///
/// With `all_of` and `any_of`, you can use multiple HTTP filters at the same time.
///
/// If you want to steal HTTP requests that match **every** pattern specified, use `all_of`.
/// For example, this filter steals only HTTP requests to endpoint `/api/my-endpoint` that contain
/// header `x-debug-session` with value `121212`.
/// ```json
/// {
///   "all_of": [
///     { "header": "^x-debug-session: 121212$" },
///     { "path": "^/api/my-endpoint$" }
///   ]
/// }
/// ```
///
/// If you want to steal HTTP requests that match **any** of the patterns specified, use `any_of`.
/// For example, this filter steals HTTP requests to endpoint `/api/my-endpoint`
/// **and** HTTP requests that contain header `x-debug-session` with value `121212`.
/// ```json
/// {
///  "any_of": [
///    { "path": "^/api/my-endpoint$"},
///    { "header": "^x-debug-session: 121212$" }
///  ]
/// }
/// ```
#[derive(MirrordConfig, Default, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
#[config(map_to = "HttpFilterFileConfig", derive = "JsonSchema")]
#[cfg_attr(test, config(derive = "PartialEq, Eq"))]
pub struct HttpFilterConfig {
    /// ##### feature.network.incoming.http_filter.header_filter {#feature-network-incoming-http-header-filter}
    ///
    ///
    /// Supports regexes validated by the
    /// [`fancy-regex`](https://docs.rs/fancy-regex/latest/fancy_regex/) crate.
    ///
    /// The HTTP traffic feature converts the HTTP headers to `HeaderKey: HeaderValue`,
    /// case-insensitive.
    #[config(env = "MIRRORD_HTTP_HEADER_FILTER")]
    pub header_filter: Option<String>,

    /// ##### feature.network.incoming.http_filter.path_filter {#feature-network-incoming-http-path-filter}
    ///
    ///
    /// Supports regexes validated by the
    /// [`fancy-regex`](https://docs.rs/fancy-regex/latest/fancy_regex/) crate.
    ///
    /// Case-insensitive. Tries to find match in the path (without query) and path+query.
    /// If any of the two matches, the request is stolen.
    #[config(env = "MIRRORD_HTTP_PATH_FILTER")]
    pub path_filter: Option<String>,

    /// ##### feature.network.incoming.http_filter.method_filter {#feature-network-incoming-http-method-filter}
    ///
    ///
    /// Supports standard [HTTP methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods), and non-standard HTTP methods.
    ///
    /// Case-insensitive. If the request method matches the filter, the request is stolen.
    #[config(env = "MIRRORD_HTTP_METHOD_FILTER")]
    pub method_filter: Option<String>,

    /// ##### feature.network.incoming.http_filter.body_filter {#feature-network-incoming-http-body-filter}
    ///
    /// Matches the request based on the contents of its body. Currently only JSON body filtering
    /// is supported.
    pub body_filter: Option<BodyFilter>,

    /// ##### feature.network.incoming.http_filter.all_of {#feature-network-incoming-http_filter-all_of}
    ///
    /// An array of HTTP filters.
    ///
    /// Each inner filter specifies either header or path regex.
    /// Requests must match all of the filters to be stolen.
    ///
    /// Cannot be an empty list.
    ///
    /// Example:
    /// ```json
    /// {
    ///   "all_of": [
    ///     { "header": "x-user: my-user$" },
    ///     { "path": "^/api/v1/my-endpoint" }
    ///     { "method": "post" }
    ///   ]
    /// }
    /// ```
    pub all_of: Option<Vec<InnerFilter>>,

    /// ##### feature.network.incoming.http_filter.any_of {#feature-network-incoming-http_filter-any_of}
    ///
    /// An array of HTTP filters.
    ///
    /// Each inner filter specifies either header or path regex.
    /// Requests must match at least one of the filters to be stolen.
    ///
    /// Cannot be an empty list.
    ///
    /// Example:
    /// ```json
    /// {
    ///   "any_of": [
    ///     { "header": "^x-user: my-user$" },
    ///     { "path": "^/api/v1/my-endpoint" }
    ///     { "method": "post" }
    ///   ]
    /// }
    /// ```
    pub any_of: Option<Vec<InnerFilter>>,

    /// ##### feature.network.incoming.http_filter.ports {#feature-network-incoming-http_filter-ports}
    ///
    /// Activate the HTTP traffic filter only for these ports.
    ///
    /// Accepts:
    /// - A list of port numbers: `[80, 8080, 3000]`
    /// - Wildcard for all ports: `["*"]`
    ///
    /// When set to `["*"]`, the HTTP filter applies to ALL ports the application
    /// listens on, which is useful for services on non-standard ports.
    ///
    /// Other ports will *not* be stolen, unless listed in
    /// [`feature.network.incoming.ports`](#feature-network-incoming-ports).
    ///
    /// We check the pod's health probe ports and automatically add them here, as they're
    /// usually the same ports your app might be listening on. If your app ports and the
    /// health probe ports don't match, then setting this option will override this behavior.
    ///
    /// Defaults to `[80, 8080]` when not specified.
    #[config(env = "MIRRORD_HTTP_FILTER_PORTS")]
    pub ports: Option<PortList>,
}

impl HttpFilterConfig {
    pub fn is_filter_set(&self) -> bool {
        self.header_filter.is_some()
            || self.path_filter.is_some()
            || self.method_filter.is_some()
            || self.all_of.is_some()
            || self.any_of.is_some()
            || self.body_filter.is_some()
    }

    /// Returns `true` if ports is set to wildcard `["*"]`.
    pub fn ports_is_wildcard(&self) -> bool {
        self.ports.as_ref().is_some_and(|p| p.is_all())
    }

    pub fn ensure_usable_with(
        &self,
        agent_protocol_version: Option<Version>,
    ) -> Result<(), ConfigError> {
        #![allow(clippy::type_complexity)]
        static REQUIREMENTS: [(fn(&HttpFilterConfig) -> bool, &LazyLock<VersionReq>, &str); 3] = [
            (
                HttpFilterConfig::is_composite,
                &HTTP_COMPOSITE_FILTER_VERSION,
                "'any_of' or 'all_of' HTTP filter types",
            ),
            (
                HttpFilterConfig::has_method_filter,
                &HTTP_METHOD_FILTER_VERSION,
                "'method' http filter type",
            ),
            (
                HttpFilterConfig::has_json_body_filter,
                &HTTP_BODY_JSON_FILTER_VERSION,
                "JSON body filters",
            ),
        ];

        for (validator, version, what) in REQUIREMENTS {
            if validator(self)
                && agent_protocol_version
                    .as_ref()
                    .map(|v| version.matches(v))
                    .unwrap_or(false)
                    .not()
            {
                Err(ConfigError::Conflict(format!(
                    "Cannot use {what}, protocol version used by mirrord-agent must match {}. \
                    Consider using a newer version of mirrord-agent",
                    **version
                )))?
            }
        }

        Ok(())
    }

    fn is_composite(&self) -> bool {
        self.all_of.is_some() || self.any_of.is_some()
    }

    fn has_method_filter(&self) -> bool {
        self.method_filter.is_some()
            || self.all_of.as_ref().is_some_and(|composite| {
                composite
                    .iter()
                    .any(|f| matches!(f, InnerFilter::Method { .. }))
            })
            || self.any_of.as_ref().is_some_and(|composite| {
                composite
                    .iter()
                    .any(|f| matches!(f, InnerFilter::Method { .. }))
            })
    }

    fn has_json_body_filter(&self) -> bool {
        matches!(self.body_filter, Some(BodyFilter::Json { .. }))
            || self.all_of.as_ref().is_some_and(|composite| {
                composite
                    .iter()
                    .any(|f| matches!(f, InnerFilter::Body(BodyFilter::Json { .. })))
            })
            || self.any_of.as_ref().is_some_and(|composite| {
                composite
                    .iter()
                    .any(|f| matches!(f, InnerFilter::Body(BodyFilter::Json { .. })))
            })
    }

}

#[derive(PartialEq, Eq, Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InnerFilter {
    /// ##### feature.network.incoming.inner_filter.header_filter {#feature-network-incoming-inner-header-filter}
    ///
    ///
    /// Supports regexes validated by the
    /// [`fancy-regex`](https://docs.rs/fancy-regex/latest/fancy_regex/) crate.
    ///
    /// The HTTP traffic feature converts the HTTP headers to `HeaderKey: HeaderValue`,
    /// case-insensitive.
    Header {
        header: String,
    },

    /// ##### feature.network.incoming.inner_filter.path_filter {#feature-network-incoming-inner-path-filter}
    ///
    ///
    /// Supports regexes validated by the
    /// [`fancy-regex`](https://docs.rs/fancy-regex/latest/fancy_regex/) crate.
    ///
    /// Case-insensitive. Tries to find match in the path (without query) and path+query.
    /// If any of the two matches, the request is stolen.
    Path {
        path: String,
    },

    Method {
        method: String,
    },

    /// ##### feature.network.incoming.inner_filter.body_filter {#feature-network-incoming-inner-body-filter}
    ///
    /// Matches the request based on the contents of its body. Currently only JSON body filtering is
    /// supported.
    Body(BodyFilter),
}

#[derive(PartialEq, Eq, Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "body", rename_all = "lowercase")]
pub enum BodyFilter {
    /// ##### feature.network.incoming.inner_filter.body_filter.json {#feature-network-incoming-inner-body-filter-json}
    ///
    /// Tries to parse the body as a JSON object and find (a) matching subobjects(s).
    ///
    /// `query` should be a valid JSONPath (RFC 9535) query string.
    //
    /// `matches` should be a regex. Supports regexes validated by the
    /// [`fancy-regex`](https://docs.rs/fancy-regex/latest/fancy_regex/) crate
    ///
    /// Example:
    /// ```json
    /// "http_filter": {
    ///   "body_filter": {
    ///     "body": "json",
    ///     "query": "$.library.books[*]",
    ///     "matches": "^\\d{3,5}$"
    ///   }
    /// }
    /// ```
    /// will match
    /// ```json
    /// {
    ///   "library": {
    ///     "books": [
    ///       34555,
    ///       1233,
    ///       234
    ///       23432
    ///     ]
    ///   }
    /// }
    /// ```
    ///
    /// The filter will match if there is at least one query result.
    ///
    /// Non-string matches are stringified before being compared to
    /// the regex. To filter query results by type, the `typeof`
    /// [function extension](https://www.rfc-editor.org/rfc/rfc9535.html#name-function-extensions)
    /// is provided. It takes in a single `NodesType` parameter and
    /// returns `"null" | "bool" | "number" | "string" | "array" | "object"`,
    /// depending on the type of the argument. If not all nodes in the
    /// argument have the same type, it returns `nothing`.
    ///
    /// Example:
    ///
    /// ```json
    /// "body_filter": {
    ///   "body": "json",
    ///   "query": "$.books[?(typeof(@) == 'number')]",
    ///   "matches": "4$"
    /// }
    /// ```
    /// will match
    ///
    /// ```json
    /// {
    ///   "books": [
    ///     1111,
    ///     2222,
    ///     4444
    ///   ]
    /// }
    /// ```
    ///
    /// but not
    ///
    /// ```json
    /// {
    ///   "books": [
    ///     "1111",
    ///     "2222",
    ///     "4444"
    ///   ]
    /// }
    /// ```
    ///
    ///
    ///
    /// To use with with `all_of` or `any_of`, use the following syntax:
    /// ```json
    /// "http_filter": {
    ///   "all_of": [
    ///     {
    ///       "path": "/buildings"
    ///     },
    ///     {
    ///       "body": "json",
    ///       "query": "$.library.books[*]",
    ///       "matches": "^\\d{3,5}$"
    ///     }
    ///   ]
    /// }
    /// ```
    Json { query: String, matches: String },
}

/// Represents a single item in a port list: either a port number or the wildcard "*".
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PortItem {
    /// Wildcard "*" - matches all ports
    Wildcard(WildcardMarker),
    /// Specific port number
    Port(u16),
}

/// Marker type that serializes/deserializes as the string "*".
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct WildcardMarker;

impl Serialize for WildcardMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("*")
    }
}

impl<'de> Deserialize<'de> for WildcardMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "*" {
            Ok(WildcardMarker)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"*\", got \"{}\"",
                s
            )))
        }
    }
}

impl JsonSchema for WildcardMarker {
    fn schema_name() -> String {
        "Wildcard".to_owned()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::SingleOrVec::Single(Box::new(
                schemars::schema::InstanceType::String,
            ))),
            const_value: Some(serde_json::Value::String("*".to_owned())),
            ..Default::default()
        }
        .into()
    }
}

/// <!--${internal}-->
/// Helper struct for setting up ports configuration (part of the HTTP traffic stealer feature).
///
/// Defaults to a list of ports `[80, 8080]`.
/// Supports wildcard `["*"]` to apply filter to all ports.
/// When `"*"` is present alongside port numbers, the wildcard takes precedence.
///
/// We use this to allow implementing a custom [`Default`] initialization, as the [`MirrordConfig`]
/// macro (currently) doesn't support more intricate expressions.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct PortList(Vec<PortItem>);

impl PartialEq for PortList {
    fn eq(&self, other: &Self) -> bool {
        // Compare as sets - order doesn't matter
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.iter().all(|item| other.0.contains(item))
    }
}

impl Eq for PortList {}

impl MirrordToggleableConfig for HttpFilterFileConfig {
    fn disabled_config(context: &mut ConfigContext) -> Result<Self::Generated, ConfigError> {
        let header_filter = FromEnv::new("MIRRORD_HTTP_HEADER_FILTER")
            .source_value(context)
            .transpose()?;

        let path_filter = FromEnv::new("MIRRORD_HTTP_PATH_FILTER")
            .source_value(context)
            .transpose()?;

        let method_filter = FromEnv::new("MIRRORD_HTTP_METHOD_FILTER")
            .source_value(context)
            .transpose()?;

        let all_of = None;
        let any_of = None;

        let body_filter = None;

        let ports = FromEnv::new("MIRRORD_HTTP_FILTER_PORTS")
            .source_value(context)
            .transpose()?;

        Ok(Self::Generated {
            header_filter,
            path_filter,
            method_filter,
            body_filter,
            all_of,
            any_of,
            ports,
        })
    }
}

impl Default for PortList {
    fn default() -> Self {
        Self(vec![PortItem::Port(80), PortItem::Port(8080)])
    }
}

impl PortList {
    /// Creates a `PortList` from any iterable of port numbers.
    pub fn from_ports(iter: impl IntoIterator<Item = u16>) -> Self {
        PortList(iter.into_iter().map(PortItem::Port).collect())
    }

    /// Returns true if this contains the "all ports" wildcard
    pub fn is_all(&self) -> bool {
        self.0.iter().any(|item| matches!(item, PortItem::Wildcard(_)))
    }

    /// Checks if the port list contains a specific port.
    /// Returns true if wildcard is present or if the specific port is in the set.
    pub fn contains(&self, port: &u16) -> bool {
        self.is_all()
            || self
                .0
                .iter()
                .any(|item| matches!(item, PortItem::Port(p) if p == port))
    }

    /// Returns an iterator over the specific port numbers (excludes wildcard).
    pub fn ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().filter_map(|item| match item {
            PortItem::Port(p) => Some(*p),
            PortItem::Wildcard(_) => None,
        })
    }

    /// Returns the count of specific ports (excludes wildcard).
    pub fn count(&self) -> usize {
        self.0
            .iter()
            .filter(|item| matches!(item, PortItem::Port(_)))
            .count()
    }
}

impl FromStr for PortList {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // FromStr only handles numeric ports (semicolon separated)
        // Wildcard ["*"] is only supported via JSON deserialization
        let items = s
            .split(';')
            .map(|part| part.parse().map(PortItem::Port))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PortList(items))
    }
}

impl core::fmt::Display for PortList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_all() {
            write!(f, "[*]")
        } else {
            write!(f, "[")?;
            let mut first = true;
            for p in self.ports() {
                if first {
                    write!(f, "{p}")?;
                    first = false;
                } else {
                    write!(f, ", {p}")?;
                }
            }
            write!(f, "]")
        }
    }
}

impl CollectAnalytics for &HttpFilterConfig {
    fn collect_analytics(&self, analytics: &mut mirrord_analytics::Analytics) {
        analytics.add("header_filter", self.header_filter.is_some());
        analytics.add("path_filter", self.path_filter.is_some());
        analytics.add(
            "ports_count",
            self.ports.as_ref().map(|p| p.count()).unwrap_or_default(),
        );
        analytics.add(
            "ports_wildcard",
            self.ports.as_ref().is_some_and(|p| p.is_all()),
        );
    }
}

/// Formats a message describing which ports will have traffic stolen.
///
/// Returns "ignoring incoming traffic" if no ports are configured.
///
/// # Arguments
/// * `http_filter_ports` - Ports with HTTP filtering enabled
/// * `incoming_ports` - All ports configured for incoming traffic
///
/// # Examples
/// ```
/// use std::collections::HashSet;
/// use mirrord_config::feature::network::incoming::http_filter::{PortList, format_stolen_ports_message};
///
/// // Wildcard
/// let ports: PortList = serde_json::from_str(r#"["*"]"#).unwrap();
/// assert_eq!(format_stolen_ports_message(Some(&ports), None), "all ports (filtered)");
///
/// // Specific ports
/// let ports: PortList = serde_json::from_str(r#"[80]"#).unwrap();
/// assert_eq!(format_stolen_ports_message(Some(&ports), None), "port 80 (filtered)");
/// ```
pub fn format_stolen_ports_message(
    http_filter_ports: Option<&PortList>,
    incoming_ports: Option<&HashSet<u16>>,
) -> String {
    // Check if wildcard ["*"] is used - all ports are filtered
    if http_filter_ports.is_some_and(|p| p.is_all()) {
        return "all ports (filtered)".to_string();
    }

    let filtered: Vec<u16> = http_filter_ports
        .map(|p| p.ports().collect())
        .unwrap_or_default();

    let filtered_set: HashSet<u16> = filtered.iter().copied().collect();

    let unfiltered: Vec<u16> = incoming_ports
        .map(|p| p.difference(&filtered_set).copied().collect())
        .unwrap_or_default();

    fn format_ports(ports: &[u16], suffix: &str) -> Option<String> {
        match ports {
            [] => None,
            [port] => Some(format!("port {port} ({suffix})")),
            ports => Some(format!("ports {ports:?} ({suffix})")),
        }
    }

    let parts: Vec<String> = [
        format_ports(&filtered, "filtered"),
        format_ports(&unfiltered, "unfiltered"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if parts.is_empty() {
        "ignoring incoming traffic".to_string()
    } else {
        parts.join(" and ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_list_wildcard_array() {
        let json = r#"["*"]"#;
        let port_list: PortList = serde_json::from_str(json).unwrap();
        assert!(port_list.is_all());
        assert!(port_list.contains(&80));
        assert!(port_list.contains(&3000));
        assert!(port_list.contains(&9999));
    }

    #[test]
    fn test_port_list_mixed() {
        // [123, "*"] - wildcard with specific port, wildcard takes precedence
        let json = r#"[123, "*"]"#;
        let port_list: PortList = serde_json::from_str(json).unwrap();
        assert!(port_list.is_all());
        assert!(port_list.contains(&123));
    }

    #[test]
    fn test_port_list_specific_ports() {
        let json = r#"[80, 8080]"#;
        let port_list: PortList = serde_json::from_str(json).unwrap();
        assert!(!port_list.is_all());
        assert!(port_list.contains(&80));
        assert!(port_list.contains(&8080));
        assert!(!port_list.contains(&3000));
    }

    #[test]
    fn test_port_list_default() {
        let port_list = PortList::default();
        assert!(!port_list.is_all());
        assert!(port_list.contains(&80));
        assert!(port_list.contains(&8080));
        assert!(!port_list.contains(&3000));
    }

    #[test]
    fn test_port_list_display() {
        let port_list: PortList = serde_json::from_str(r#"["*"]"#).unwrap();
        assert_eq!(format!("{}", port_list), "[*]");
    }

    #[test]
    fn test_port_list_from_str() {
        let port_list: PortList = "80;8080".parse().unwrap();
        assert!(!port_list.is_all());
        assert!(port_list.contains(&80));
        assert!(port_list.contains(&8080));
    }

    #[test]
    fn test_port_list_single_port_rejected() {
        let result: Result<PortList, _> = serde_json::from_str(r#"8080"#);
        assert!(result.is_err());

        let result: Result<PortList, _> = serde_json::from_str(r#""8080""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_port_list_serialize_roundtrip() {
        // Wildcard
        let port_list: PortList = serde_json::from_str(r#"["*"]"#).unwrap();
        let json = serde_json::to_string(&port_list).unwrap();
        assert_eq!(json, r#"["*"]"#);
        let deserialized: PortList = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_all());

        // Specific port
        let port_list: PortList = serde_json::from_str(r#"[80]"#).unwrap();
        let json = serde_json::to_string(&port_list).unwrap();
        assert_eq!(json, r#"[80]"#);
        let deserialized: PortList = serde_json::from_str(&json).unwrap();
        assert!(deserialized.contains(&80));
    }

    #[test]
    fn test_port_list_invalid_port_range() {
        // Port number > 65535 should fail
        let result: Result<PortList, _> = serde_json::from_str(r#"[99999]"#);
        assert!(result.is_err());

        // Valid max port should work
        let result: Result<PortList, _> = serde_json::from_str(r#"[65535]"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_port_list_empty_array() {
        // Empty array is valid - means no ports are filtered
        let result: Result<PortList, _> = serde_json::from_str(r#"[]"#);
        assert!(result.is_ok());
        let port_list = result.unwrap();
        assert!(!port_list.is_all());
        assert!(!port_list.contains(&80));
    }

    mod stolen_ports_message {
        use super::*;

        #[test]
        fn wildcard_returns_all_ports() {
            let ports: PortList = serde_json::from_str(r#"["*"]"#).unwrap();
            let result = format_stolen_ports_message(Some(&ports), None);
            assert_eq!(result, "all ports (filtered)");
        }

        #[test]
        fn wildcard_ignores_incoming_ports() {
            let ports: PortList = serde_json::from_str(r#"["*"]"#).unwrap();
            let incoming: HashSet<u16> = [80, 8080].into();
            let result = format_stolen_ports_message(Some(&ports), Some(&incoming));
            assert_eq!(result, "all ports (filtered)");
        }

        #[test]
        fn single_filtered_port() {
            let ports: PortList = serde_json::from_str(r#"[80]"#).unwrap();
            let result = format_stolen_ports_message(Some(&ports), None);
            assert_eq!(result, "port 80 (filtered)");
        }

        #[test]
        fn multiple_filtered_ports() {
            let ports: PortList = serde_json::from_str(r#"[80, 8080]"#).unwrap();
            let result = format_stolen_ports_message(Some(&ports), None);
            // Note: order may vary, so we check contains
            assert!(result.contains("(filtered)"));
            assert!(result.contains("80"));
            assert!(result.contains("8080"));
        }

        #[test]
        fn single_unfiltered_port() {
            let incoming: HashSet<u16> = [3000].into();
            let result = format_stolen_ports_message(None, Some(&incoming));
            assert_eq!(result, "port 3000 (unfiltered)");
        }

        #[test]
        fn multiple_unfiltered_ports() {
            let incoming: HashSet<u16> = [3000, 4000].into();
            let result = format_stolen_ports_message(None, Some(&incoming));
            assert!(result.contains("(unfiltered)"));
            assert!(result.contains("3000"));
            assert!(result.contains("4000"));
        }

        #[test]
        fn filtered_and_unfiltered_ports() {
            let filtered: PortList = serde_json::from_str(r#"[80]"#).unwrap();
            let incoming: HashSet<u16> = [80, 3000].into();
            let result = format_stolen_ports_message(Some(&filtered), Some(&incoming));
            assert!(result.contains("port 80 (filtered)"));
            assert!(result.contains("port 3000 (unfiltered)"));
            assert!(result.contains(" and "));
        }

        #[test]
        fn overlapping_ports_excluded_from_unfiltered() {
            // incoming.ports = [80, 8080, 3000], http_filter.ports = [80, 8080]
            // unfiltered should only show 3000
            let filtered: PortList = serde_json::from_str(r#"[80, 8080]"#).unwrap();
            let incoming: HashSet<u16> = [80, 8080, 3000].into();
            let result = format_stolen_ports_message(Some(&filtered), Some(&incoming));
            assert!(result.contains("port 3000 (unfiltered)"));
            // 80 and 8080 should only appear in filtered, not unfiltered
            assert!(!result.contains("port 80 (unfiltered)"));
            assert!(!result.contains("port 8080 (unfiltered)"));
        }

        #[test]
        fn no_ports_returns_ignoring_message() {
            let result = format_stolen_ports_message(None, None);
            assert_eq!(result, "ignoring incoming traffic");
        }

        #[test]
        fn empty_incoming_ports_returns_ignoring_message() {
            let incoming: HashSet<u16> = HashSet::new();
            let result = format_stolen_ports_message(None, Some(&incoming));
            assert_eq!(result, "ignoring incoming traffic");
        }

        #[test]
        fn empty_filtered_ports_returns_ignoring_message() {
            let filtered: PortList = serde_json::from_str(r#"[]"#).unwrap();
            let result = format_stolen_ports_message(Some(&filtered), None);
            assert_eq!(result, "ignoring incoming traffic");
        }
    }
}
