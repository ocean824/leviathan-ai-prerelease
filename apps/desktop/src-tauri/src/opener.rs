use std::process::Command;

use serde_json::{json, Value};
use url::Url;

const ALLOWED_HOSTS: &[&str] = &[
    "app.alpaca.markets",
    "my.tastytrade.com",
    "cert-my.staging-tasty.works",
    "id.ctrader.com",
    "login.coinbase.com",
    "app.snaptrade.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenExternalUrlError {
    InvalidUrl,
    BrowserUnavailable,
}

impl OpenExternalUrlError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "URL_NOT_ALLOWED",
            Self::BrowserUnavailable => "BROWSER_UNAVAILABLE",
        }
    }
}

fn has_userinfo(input: &str, parsed: &Url) -> bool {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return true;
    }

    let Some((_, remainder)) = input.split_once("://") else {
        return true;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

fn validate_external_url(input: &str) -> Result<Url, OpenExternalUrlError> {
    let parsed = Url::parse(input).map_err(|_| OpenExternalUrlError::InvalidUrl)?;
    if parsed.scheme() != "https"
        || has_userinfo(input, &parsed)
        || parsed.port().is_some_and(|port| port != 443)
        || parsed.host_str().map_or(true, |host| {
            !ALLOWED_HOSTS
                .iter()
                .any(|allowed| host.eq_ignore_ascii_case(allowed))
        })
    {
        return Err(OpenExternalUrlError::InvalidUrl);
    }
    Ok(parsed)
}

fn browser_command(url: &Url) -> Command {
    #[cfg(windows)]
    let mut command = Command::new("explorer.exe");
    #[cfg(target_os = "macos")]
    let mut command = Command::new("/usr/bin/open");
    command.arg(url.as_str());
    command
}

fn open_in_system_browser(url: &Url) -> Result<(), OpenExternalUrlError> {
    #[cfg(windows)]
    {
        browser_command(url)
            .spawn()
            .map(|_| ())
            .map_err(|_| OpenExternalUrlError::BrowserUnavailable)
    }
    #[cfg(target_os = "macos")]
    {
        browser_command(url)
            .spawn()
            .map(|_| ())
            .map_err(|_| OpenExternalUrlError::BrowserUnavailable)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = url;
        Err(OpenExternalUrlError::BrowserUnavailable)
    }
}

#[tauri::command]
pub fn open_external_url(url: String) -> Result<(), Value> {
    let parsed = validate_external_url(&url).map_err(|error| json!({ "code": error.code() }))?;
    open_in_system_browser(&parsed).map_err(|error| json!({ "code": error.code() }))
}

#[cfg(test)]
mod tests {
    use super::{browser_command, validate_external_url, OpenExternalUrlError};

    mod acceptance {
        include!("opener/acceptance.rs");
    }

    #[test]
    fn accepts_only_the_connection_and_snaptrade_hosts_over_https() {
        for host in [
            "app.alpaca.markets",
            "my.tastytrade.com",
            "cert-my.staging-tasty.works",
            "id.ctrader.com",
            "login.coinbase.com",
            "app.snaptrade.com",
        ] {
            let url = validate_external_url(&format!("https://{host}/authorize?state=synthetic"));
            assert!(url.is_ok(), "expected allowed host {host}");
        }
    }

    #[test]
    fn host_matching_is_case_insensitive_but_exact() {
        assert!(validate_external_url("https://APP.ALPACA.MARKETS/oauth").is_ok());
        for input in [
            "https://app.alpaca.markets.evil.example/oauth",
            "https://evil-app.alpaca.markets/oauth",
            "https://app.alpaca.markets./oauth",
            "https://attacker.example/oauth",
        ] {
            assert_eq!(
                validate_external_url(input),
                Err(OpenExternalUrlError::InvalidUrl)
            );
        }
    }

    #[test]
    fn rejects_non_https_schemes_and_unsafe_authorities() {
        for input in [
            "http://app.alpaca.markets/oauth",
            "javascript:alert(1)",
            "file:///C:/Windows/win.ini",
            "custom://app.alpaca.markets/oauth",
            "https://user@app.alpaca.markets/oauth",
            "https://user:password@app.alpaca.markets/oauth",
            "https://@app.alpaca.markets/oauth",
            "https://app.alpaca.markets@attacker.example/oauth",
        ] {
            assert_eq!(
                validate_external_url(input),
                Err(OpenExternalUrlError::InvalidUrl)
            );
        }
    }

    #[test]
    fn permits_only_default_or_explicit_https_port_443() {
        assert!(validate_external_url("https://app.alpaca.markets/oauth").is_ok());
        assert!(validate_external_url("https://app.alpaca.markets:443/oauth").is_ok());
        for input in [
            "https://app.alpaca.markets:80/oauth",
            "https://app.alpaca.markets:444/oauth",
        ] {
            assert_eq!(
                validate_external_url(input),
                Err(OpenExternalUrlError::InvalidUrl)
            );
        }
    }

    #[test]
    fn browser_command_passes_the_validated_url_as_one_argument_without_a_shell() {
        let input = "https://app.snaptrade.com/redeem?token=synthetic&next=%26%20explorer.exe";
        let parsed = validate_external_url(input).expect("host-pinned URL");
        let command = browser_command(&parsed);
        #[cfg(windows)]
        assert_eq!(command.get_program(), "explorer.exe");
        #[cfg(target_os = "macos")]
        assert_eq!(command.get_program(), "/usr/bin/open");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0], parsed.as_str());
    }
}
