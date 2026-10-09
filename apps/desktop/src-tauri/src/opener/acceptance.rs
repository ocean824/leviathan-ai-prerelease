use serde_json::json;

use crate::opener::open_external_url;

#[test]
fn public_command_returns_the_fixed_denial_for_unsafe_urls() {
    for input in [
        "http://app.alpaca.markets/oauth",
        "javascript:alert(1)",
        "file:///C:/Windows/win.ini",
        "https://attacker.example/oauth",
        "https://app.alpaca.markets:444/oauth",
        "https://user@app.alpaca.markets/oauth",
        "https://user:password@app.alpaca.markets/oauth",
        "https://@app.alpaca.markets/oauth",
        "https://app.alpaca.markets@attacker.example/oauth",
    ] {
        assert_eq!(
            open_external_url(input.to_owned()),
            Err(json!({ "code": "URL_NOT_ALLOWED" })),
            "unexpected public result for unsafe URL"
        );
    }
}
