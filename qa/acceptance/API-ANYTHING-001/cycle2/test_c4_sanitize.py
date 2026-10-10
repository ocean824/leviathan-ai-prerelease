"""Cycle 4: fixture sanitising.  The recorded raw body is stored (and later replayed through the template), so sanitising must
(1) never change the values the recipe picks (extract(sanitized) == extract(raw)), (2) remove personal data that is not needed,
(3) for HTML remove scripts / inputs / hidden fields, and (4) refuse credentials."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

HERE = Path(__file__).resolve().parent
OPS = list(A.SITES)


def probe(collector: Path, body: str, content_type: str = "application/json", recipe=None) -> dict:
    env = {**os.environ, "AA_DIST": str(collector / "dist")}
    env.pop("AA_CONTROL", None)
    done = subprocess.run([A.NODE, str(HERE / "sanitize_probe.mjs")], input=json.dumps({"body": body, "contentType": content_type, "recipe": recipe}),
                          capture_output=True, text=True, env=env, cwd=collector, timeout=60)
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout)


# native values with TWO OR MORE capitalised words, which are public content and must survive byte for byte
MULTIWORD = {
    "cnn.fear_greed": [("rating", "Extreme Greed"), ("rating", "Extreme Fear"), ("rating", "Not Available")],
    "calendar.fed": [("name", "Federal Open Market Committee"), ("agency", "Federal Reserve"), ("agency", "Federal Reserve Board"), ("type", "Press Conference")],
    "earnings.forward": [("quarter", "Fiscal Q4"), ("status", "Date Confirmed"), ("type", "After Close")],
    "senate.efd.ptr": [("url", "https://efdsearch.senate.gov/search/report/Annual Report")],
    "cboe.daily.stats": [("unit", "Index Points"), ("expiry", "Front Month"), ("name", "put_call_ratio")],
}
ITEM_KEY = {"cnn.fear_greed": ("fear_and_greed_historical", "data"), "calendar.fed": ("events",), "earnings.forward": ("calendar",),
            "senate.efd.ptr": ("reports",), "cboe.daily.stats": ("dailyStatistics",)}


def with_value(op: str, key: str, value: str) -> dict:
    case = C.native_case(op)
    node = case["body"]
    for part in ITEM_KEY[op]:
        node = node[part]
    node[0][key] = value
    return case["body"]


@pytest.mark.parametrize(("op", "key", "value"), [(op, k, v) for op, vals in MULTIWORD.items() for k, v in vals])
def test_extract_of_the_sanitised_body_equals_extract_of_the_raw_body_for_multiword_public_values(collector, op, key, value) -> None:
    recipe = C.mapping_for(collector / "dist")[op]["recipe"]
    body = with_value(op, key, value)
    out = probe(collector, json.dumps(body), recipe=recipe.get("recipe", recipe))
    assert "error" not in out, out
    assert out["raw_rows"] == out["sanitized_rows"], f"{op}: sanitising changed picked values for {key}={value!r}: {out['sanitized_rows']}"


@pytest.mark.parametrize("op", OPS)
def test_a_realistic_native_body_is_unchanged_by_sanitising_where_it_is_public(collector, op) -> None:
    recipe = C.mapping_for(collector / "dist")[op]["recipe"]
    case = C.native_case(op)
    out = probe(collector, case["text"], recipe=recipe)
    assert out["raw_rows"] == out["sanitized_rows"], op
    assert "[REDACTED]" not in out["sanitized"], op


PERSONAL = {
    "first_name": "jane", "last_name": "doe", "full_name": "Jane Q Doe", "name": "jdoe", "senator_name": "Doe, Jane",
    "email": "jane.doe@example.com", "phone": "5551234567", "address": "Apt 4B Maple Court", "street": "Maple Court 14",
}


@pytest.mark.parametrize("field", list(PERSONAL))
def test_personal_fields_that_the_recipe_does_not_pick_do_not_survive_in_the_stored_body(collector, field) -> None:
    case = C.native_case("senate.efd.ptr")
    case["body"]["reports"][0][field] = PERSONAL[field]
    recipe = C.mapping_for(collector / "dist")["senate.efd.ptr"]["recipe"]
    out = probe(collector, json.dumps(case["body"]), recipe=recipe)
    assert PERSONAL[field] not in out["sanitized"], f"{field}={PERSONAL[field]!r} survived sanitising"
    assert out["raw_rows"] == out["sanitized_rows"]


# ---------------------------------------------------------------- HTML (Fed calendar, Senate eFD style pages)

HTML = """<!doctype html><html><head><title>FOMC Calendar</title><style>.x{color:red}</style>
<meta name="csrf-token" content="abcDEF123456SECRET">
<script>window.sessionToken = "abc123secret"; fetch('/api?access_token=zzz')</script></head>
<body onload="boot()">
<h1>Federal Open Market Committee</h1>
<table><tr><td>Oct 28-29</td><td>FOMC Meeting</td><td>Press Conference</td></tr></table>
<form action="/search" method="post">
  <input type="text" name="first_name" value="Jane Doe">
  <input type="hidden" name="csrfmiddlewaretoken" value="s3cr3tT0ken">
  <input type="password" name="pw" value="hunter22">
  <input type="email" name="email" value="jane.doe@example.com">
  <textarea name="note">call me at 555-123-4567</textarea>
  <select name="state"><option value="TX" selected>Texas</option></select>
  <div hidden>secret hidden text</div>
  <button type="submit">Search</button>
</form>
<p>Filed by Senator Jane Doe, 14 Maple Street, jane.doe@example.com, 555-123-4567, SSN 123-45-6789.</p>
<a href="/report/1" title="Report for jane.doe@example.com">Annual Report</a>
</body></html>"""


def test_html_sanitising_removes_scripts_styles_inputs_hidden_fields_and_personal_values(collector) -> None:
    out = probe(collector, HTML, "text/html; charset=utf-8")
    if "error" in out:
        pytest.fail(f"unexpected refusal: {out['error']}")
    text = out["sanitized"]
    for tag in ("<script", "<style", "<input", "<textarea", "<select", "<option"):
        assert tag not in text.lower(), tag
    for leaked in ("secret hidden text", "s3cr3tT0ken", "hunter22", "jane.doe@example.com", "555-123-4567", "123-45-6789", "14 Maple Street", "call me at"):
        assert leaked not in text, leaked
    assert "Oct 28-29" in text and "FOMC Meeting" in text, "public table content must remain"


@pytest.mark.xfail(reason="OBSERVATION (low): the HTML path still redacts any two-capitalised-word text; harmless today because all five recipes are JSON, but an HTML recipe would not replay", strict=False)
def test_html_sanitising_keeps_public_multiword_content(collector) -> None:
    out = probe(collector, HTML, "text/html")
    text = out["sanitized"]
    for kept in ("Federal Open Market Committee", "Press Conference", "Annual Report"):
        assert kept in text, f"public content {kept!r} was redacted from the stored HTML"


@pytest.mark.xfail(reason="OBSERVATION (low): <meta name=csrf-token content=...> survives the HTML sanitiser (only value/placeholder/title/alt attributes are screened)", strict=False)
def test_html_sanitising_does_not_leave_session_tokens_in_meta_or_inline_handlers(collector) -> None:
    text = probe(collector, HTML, "text/html")["sanitized"]
    assert "abcDEF123456SECRET" not in text and "abc123secret" not in text


@pytest.mark.parametrize(("label", "body"), [
    ("bearer token in html text", "<html><body><p>Authorization: Bearer abcdefghijklmnop</p></body></html>"),
    ("access_token in a link", '<html><body><a href="/x?access_token=abc123">x</a></body></html>'),
    ("set-cookie text", "<html><body>Set-Cookie: sid=abc</body></html>"),
])
def test_html_with_credentials_is_refused(collector, label, body) -> None:
    out = probe(collector, body, "text/html")
    assert out.get("error") == "CANDIDATE_CONTAINS_CREDENTIALS", (label, out)


@pytest.mark.parametrize(("label", "body"), [
    ("cookie key", {"cookie": "a=b", "data": []}),
    ("authorization key", {"headers": {"Authorization": "x"}}),
    ("x-token key", {"x-api-token": "abc"}),
    ("bearer value", {"note": "use Bearer abcdefghijklmnop here"}),
    ("session query", {"link": "https://x.example/?session=abc"}),
])
def test_json_with_credentials_is_refused(collector, label, body) -> None:
    assert probe(collector, json.dumps(body))["error"] == "CANDIDATE_CONTAINS_CREDENTIALS", label


def test_non_json_with_a_json_content_type_is_refused(collector) -> None:
    assert probe(collector, "<html>nope</html>", "application/json")["error"] == "CANDIDATE_FIXTURE_NOT_JSON"
