//! Indicator-of-compromise (IoC) extractor.
//!
//! Scans every string discovered in data sections for the kinds of
//! artifacts malware analysts care about — URLs, IPv4 / IPv6
//! addresses, e-mail addresses, file paths, registry keys, BTC /
//! ETH wallet hashes, named-pipe and mutex names. Each match is
//! tagged on its containing string address with an `IoC` Custom
//! kind, so the existing `tags --filter ioc` report renders the full
//! list at-a-glance.
//!
//! Detection is regex-free (no `regex` crate dependency added) —
//! each kind has a small hand-rolled validator that checks for the
//! shape malware actually emits:
//!
//! * `http://` / `https://` / `ftp://` prefix → URL
//! * `\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}` with octet bounds → IPv4
//! * `:` count ≥ 2 + 0-9a-f chars only → IPv6 (loose)
//! * `HKLM\\` / `HKCU\\` / `HKEY_` prefix → Win registry key
//! * `\\\\.\\pipe\\` prefix → named pipe
//! * `Global\\` / `Local\\` prefix → Windows mutex
//! * `C:\\` / `D:\\` … → Win file path
//! * `/etc/` / `/tmp/` / `/var/` / `/usr/` → POSIX path
//! * 8-bit ASCII e-mail shape (`X@Y.Z`)
//! * `0x[0-9a-f]{40}` → ETH address
//! * 25-34 char base58 → BTC address (heuristic)
//!
//! Surfaces `metadata.ioc_count` (total matches) and `metadata.iocs`
//! (newline-joined list) for downstream consumers.

use gr_program::tags::TagKind;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::strings::{find_strings, is_data_section};

pub struct IocExtractor;

impl Analyzer for IocExtractor {
    fn name(&self) -> &str {
        "IoC Extractor"
    }
    fn description(&self) -> &str {
        "Find URLs / IPs / registry keys / mutex names / wallets in discovered strings"
    }
    fn priority(&self) -> u32 {
        // After StringSearchAnalyzer (200), before TagAnalyzer (950).
        // Re-scans data sections itself instead of relying on the
        // symbol-table entries written by StringSearch — those
        // already had the string-label mangling applied, which
        // breaks our URL/IPv6 regex match.
        940
    }
    fn provides(&self) -> &'static [&'static str] {
        &["iocs"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let data_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| is_data_section(&s.name) && s.size > 0)
            .map(|s| (s.address, s.size))
            .collect();

        let mut matches: Vec<(u64, IocKind, String)> = Vec::new();
        for (addr, size) in data_sections {
            // Cap section sample at 8 MiB to keep this cheap on
            // resource-heavy binaries.
            let read = (size).min(8 * 1024 * 1024) as usize;
            let mut buf = vec![0u8; read];
            if program.info.memory.read_bytes(addr, &mut buf).is_err() {
                continue;
            }
            for (sym_addr, s) in find_strings(&buf, addr) {
                if let Some(kind) = classify(&s) {
                    matches.push((sym_addr, kind, s));
                }
            }
        }

        let total = matches.len();
        for (addr, kind, s) in &matches {
            program.tags.add_address(
                *addr,
                TagKind::Custom("ioc".to_string()),
                format!("{}: {}", kind.label(), s),
                true,
            );
        }

        program
            .metadata
            .set_property("ioc_count", total.to_string());
        if !matches.is_empty() {
            let joined: Vec<String> = matches
                .iter()
                .map(|(addr, kind, s)| format!("0x{:x} {} {}", addr, kind.label(), s))
                .collect();
            program.metadata.set_property("iocs", joined.join("\n"));
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: total,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Url,
    Ipv4,
    Ipv6,
    Email,
    WinRegistryKey,
    WinNamedPipe,
    WinMutex,
    WinPath,
    PosixPath,
    EthAddress,
    BtcAddress,
    UserAgent,
    Domain,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Email => "email",
            Self::WinRegistryKey => "registry-key",
            Self::WinNamedPipe => "named-pipe",
            Self::WinMutex => "mutex",
            Self::WinPath => "win-path",
            Self::PosixPath => "posix-path",
            Self::EthAddress => "eth-addr",
            Self::BtcAddress => "btc-addr",
            Self::UserAgent => "user-agent",
            Self::Domain => "domain",
        }
    }
}

/// Best-effort one-shot classification. We pick the most specific
/// category for a string; the ordering below is significant — a
/// `Url` match short-circuits any further checks since "http://foo"
/// also contains a domain.
pub fn classify(s: &str) -> Option<IocKind> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    if looks_like_url(trimmed) {
        return Some(IocKind::Url);
    }
    if looks_like_user_agent(trimmed) {
        return Some(IocKind::UserAgent);
    }
    if looks_like_registry_key(trimmed) {
        return Some(IocKind::WinRegistryKey);
    }
    if looks_like_named_pipe(trimmed) {
        return Some(IocKind::WinNamedPipe);
    }
    if looks_like_mutex(trimmed) {
        return Some(IocKind::WinMutex);
    }
    if looks_like_win_path(trimmed) {
        return Some(IocKind::WinPath);
    }
    if looks_like_posix_path(trimmed) {
        return Some(IocKind::PosixPath);
    }
    if looks_like_ipv4(trimmed) {
        return Some(IocKind::Ipv4);
    }
    if looks_like_ipv6(trimmed) {
        return Some(IocKind::Ipv6);
    }
    if looks_like_email(trimmed) {
        return Some(IocKind::Email);
    }
    if looks_like_eth_address(trimmed) {
        return Some(IocKind::EthAddress);
    }
    if looks_like_btc_address(trimmed) {
        return Some(IocKind::BtcAddress);
    }
    if looks_like_domain(trimmed) {
        return Some(IocKind::Domain);
    }
    None
}

fn looks_like_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://"))
        && s.len() > 8
        && s.len() < 4096
        && !s.contains(' ')
        && s[7..].contains(['.', '/'])
}

fn looks_like_user_agent(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    s.len() > 12
        && s.len() < 1024
        && (lower.starts_with("mozilla/") || lower.starts_with("user-agent: "))
}

fn looks_like_registry_key(s: &str) -> bool {
    s.starts_with("HKLM\\")
        || s.starts_with("HKCU\\")
        || s.starts_with("HKEY_")
        || s.starts_with("Software\\")
        || s.starts_with("SOFTWARE\\")
        || s.starts_with("SYSTEM\\")
        || s.starts_with("System\\")
}

fn looks_like_named_pipe(s: &str) -> bool {
    s.starts_with("\\\\.\\pipe\\") || s.starts_with("\\\\.\\\\pipe\\\\")
}

fn looks_like_mutex(s: &str) -> bool {
    (s.starts_with("Global\\") || s.starts_with("Local\\"))
        && s.len() > 8
        && s.len() < 256
        && !s.contains(' ')
}

fn looks_like_win_path(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
        && s.len() < 4096
        && !s.chars().any(|c| c == '\n' || c == '\r')
}

fn looks_like_posix_path(s: &str) -> bool {
    (s.starts_with("/etc/")
        || s.starts_with("/tmp/")
        || s.starts_with("/var/")
        || s.starts_with("/usr/")
        || s.starts_with("/home/")
        || s.starts_with("/opt/")
        || s.starts_with("/proc/")
        || s.starts_with("/dev/")
        || s.starts_with("/root/"))
        && s.len() > 5
        && s.len() < 4096
        && !s.contains(' ')
}

fn looks_like_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    octets.iter().all(|o| {
        !o.is_empty()
            && o.len() <= 3
            && o.bytes().all(|b| b.is_ascii_digit())
            && o.parse::<u32>().is_ok_and(|n| n <= 255)
    })
}

fn looks_like_ipv6(s: &str) -> bool {
    // Conservative IPv6: at least two `:` and every char in
    // [0-9a-fA-F:], 2-39 chars. Excludes IPv4-mapped forms with
    // dots so we don't double-classify.
    if s.contains('.') || s.contains(' ') {
        return false;
    }
    let colons = s.bytes().filter(|&b| b == b':').count();
    if colons < 2 {
        return false;
    }
    if s.len() < 3 || s.len() > 39 {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
}

fn looks_like_email(s: &str) -> bool {
    let at = s.find('@');
    let Some(at) = at else { return false };
    if at == 0 || at == s.len() - 1 {
        return false;
    }
    let (local, domain) = s.split_at(at);
    let domain = &domain[1..];
    !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b'+')
        && domain.contains('.')
        && domain.len() >= 3
        && domain.len() <= 253
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn looks_like_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_btc_address(s: &str) -> bool {
    // Heuristic base58: 26-35 chars, starts with 1 / 3 / bc1, alnum
    // minus 0OIl. Used by malware ransom notes / config blobs.
    if s.len() < 26 || s.len() > 64 {
        return false;
    }
    if s.starts_with("bc1") {
        return s.len() <= 64
            && s.bytes().skip(3).all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit()
            });
    }
    if !(s.starts_with('1') || s.starts_with('3')) {
        return false;
    }
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric() && b != b'0' && b != b'O' && b != b'I' && b != b'l'
    })
}

fn looks_like_domain(s: &str) -> bool {
    // Last-resort: 5-253 chars, ≥1 dot, ASCII alphanumerics and dots
    // / hyphens. Tightened beyond the naïve check so we don't flag
    // version strings (`1.2.3`), shared libraries (`lib.so`), file
    // extensions (`.history`), or struct member access (`obj.field`).
    if s.len() < 5 || s.len() > 253 {
        return false;
    }
    if s.contains(' ') || s.contains('/') || s.contains(':') {
        return false;
    }
    // Must not start with a separator — `.history`, `-foo.com`,
    // `_x.org` aren't valid domains.
    let first = s.as_bytes()[0];
    if first == b'.' || first == b'-' || first == b'_' {
        return false;
    }
    let Some(dot) = s.rfind('.') else { return false };
    let sld = &s[..dot]; // everything before the last dot
    let tld = &s[dot + 1..];
    // SLD must be ≥ 2 chars and contain ≥ 1 alphabetic — kills
    // version strings (`1.2.3`) and pure-numeric SLDs (`12.org`).
    if sld.len() < 2 {
        return false;
    }
    if !sld.bytes().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    if tld.len() < 2 || tld.len() > 24 {
        return false;
    }
    // TLD must be all-lowercase alphabetic. Real domains use
    // lowercase in strings; mixed-case is almost always a code
    // identifier (`obj.SomeMethod`, `Type.Field`). This single check
    // filters out a huge swath of false positives.
    if !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    // TLD allowlist — small enough to fit inline, big enough to
    // cover the common cases. Two-letter ccTLDs are accepted by
    // the 2-char short-circuit.
    if tld.len() > 2 && !is_known_tld(tld) {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Allowlist of common TLDs (gTLDs + the malware-popular new TLDs).
/// 2-character ccTLDs are accepted without consulting this list.
fn is_known_tld(tld: &str) -> bool {
    matches!(
        tld,
        "com" | "org" | "net" | "info" | "biz" | "name" | "pro"
        | "edu" | "gov" | "mil" | "int" | "arpa"
        | "io" | "ai" | "app" | "dev" | "xyz" | "online" | "site"
        | "top" | "click" | "link" | "live" | "shop" | "club"
        | "tech" | "cloud" | "store" | "blog" | "host" | "space"
        | "agency" | "today" | "world" | "global" | "digital"
        | "icu" | "fun" | "rest" | "wtf" | "tools" | "support"
        | "monster" | "country" | "buzz" | "uno" | "cyou"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_classified() {
        assert_eq!(classify("http://malware.example.com/c2"), Some(IocKind::Url));
        assert_eq!(classify("https://c2.example.com"), Some(IocKind::Url));
        assert_ne!(classify("http://"), Some(IocKind::Url)); // too short
    }

    #[test]
    fn ipv4_classified() {
        assert_eq!(classify("192.168.1.1"), Some(IocKind::Ipv4));
        assert_eq!(classify("8.8.8.8"), Some(IocKind::Ipv4));
        assert_eq!(classify("255.255.255.255"), Some(IocKind::Ipv4));
        assert_ne!(classify("256.0.0.1"), Some(IocKind::Ipv4));
        assert_ne!(classify("1.2.3"), Some(IocKind::Ipv4));
    }

    #[test]
    fn ipv6_classified() {
        assert_eq!(classify("fe80::1"), Some(IocKind::Ipv6));
        assert_eq!(classify("2001:db8::1"), Some(IocKind::Ipv6));
        assert_ne!(classify("::"), Some(IocKind::Ipv6)); // too short, only 2 chars
    }

    #[test]
    fn registry_key() {
        assert_eq!(
            classify("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some(IocKind::WinRegistryKey)
        );
        assert_eq!(
            classify("Software\\Microsoft\\Windows"),
            Some(IocKind::WinRegistryKey)
        );
    }

    #[test]
    fn email() {
        assert_eq!(classify("attacker@evil.example"), Some(IocKind::Email));
        assert_ne!(classify("@example.com"), Some(IocKind::Email));
        assert_ne!(classify("user@"), Some(IocKind::Email));
    }

    #[test]
    fn eth_address() {
        assert_eq!(
            classify("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"),
            Some(IocKind::EthAddress)
        );
        // wrong length
        assert_ne!(
            classify("0x742d35Cc6634C0532925a3b844Bc454e4438f4"),
            Some(IocKind::EthAddress)
        );
    }

    #[test]
    fn btc_address_legacy() {
        assert_eq!(
            classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some(IocKind::BtcAddress)
        );
    }

    #[test]
    fn win_path() {
        assert_eq!(classify("C:\\Windows\\System32\\cmd.exe"), Some(IocKind::WinPath));
        assert_eq!(classify("D:/data/file.txt"), Some(IocKind::WinPath));
    }

    #[test]
    fn posix_path() {
        assert_eq!(classify("/etc/passwd"), Some(IocKind::PosixPath));
        assert_eq!(classify("/tmp/.X11-unix"), Some(IocKind::PosixPath));
        assert_ne!(classify("/"), Some(IocKind::PosixPath));
    }

    #[test]
    fn mutex_and_pipe() {
        assert_eq!(classify("Global\\MyEvilMutex_v3"), Some(IocKind::WinMutex));
        assert_eq!(
            classify("\\\\.\\pipe\\MyEvilPipe"),
            Some(IocKind::WinNamedPipe)
        );
    }

    #[test]
    fn domain_only() {
        assert_eq!(classify("malware.example.com"), Some(IocKind::Domain));
        assert_ne!(classify("1.2.3"), Some(IocKind::Domain)); // TLD all-digit
    }

    #[test]
    fn domain_false_positives_filtered() {
        // Leading dot — looks like a file extension, not a domain.
        assert_ne!(classify(".history"), Some(IocKind::Domain));
        assert_ne!(classify(".bashrc"), Some(IocKind::Domain));
        // Mixed-case TLD: code identifier, not a domain.
        assert_ne!(classify("obj.SomeMethod"), Some(IocKind::Domain));
        assert_ne!(classify("Type.Field"), Some(IocKind::Domain));
        // Unknown TLD > 2 chars: not a real TLD.
        assert_ne!(classify("foo.invalidtld"), Some(IocKind::Domain));
        // Leading hyphen / underscore.
        assert_ne!(classify("-foo.com"), Some(IocKind::Domain));
        assert_ne!(classify("_x.org"), Some(IocKind::Domain));
        // Pure-numeric SLD.
        assert_ne!(classify("12.org"), Some(IocKind::Domain));
        // Note: `lib.so` is technically ambiguous (Somalia ccTLD vs
        // shared library suffix). We accept the false positive on
        // 2-char ccTLDs to preserve recall on real C2 domains;
        // callers can post-filter `.so` / `.dll` / `.exe` if needed.
    }

    #[test]
    fn domain_real_cases_still_classified() {
        assert_eq!(classify("attacker.com"), Some(IocKind::Domain));
        assert_eq!(classify("evil.example.io"), Some(IocKind::Domain));
        assert_eq!(classify("sub.domain.net"), Some(IocKind::Domain));
        // 2-letter ccTLD short-circuit.
        assert_eq!(classify("malware.ru"), Some(IocKind::Domain));
        assert_eq!(classify("c2.cn"), Some(IocKind::Domain));
    }

    #[test]
    fn random_strings_not_classified() {
        assert_eq!(classify("hello world"), None);
        assert_eq!(classify("error: file not found"), None);
        assert_eq!(classify(""), None);
        assert_eq!(classify("   "), None);
    }

    #[test]
    fn user_agent() {
        assert_eq!(
            classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            Some(IocKind::UserAgent)
        );
    }
}
