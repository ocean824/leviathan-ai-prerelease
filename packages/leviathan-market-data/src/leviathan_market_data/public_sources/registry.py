"""Static, non-secret discovery metadata for public evidence sources."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class PublicSourceV1:
    source_id: str
    endpoint: str
    format: str
    auth: str
    tos_classification: str
    tos_url: str
    tier: int
    cadence: str
    point_in_time_rule: str
    factor_tags: tuple[str, ...]
    schema_version: Literal[1] = 1
    redistribution: Literal[False] = False
    capabilities: tuple[str, ...] = ()
    us_eligibility: Literal["eligible", "ineligible", "unverified"] | None = None
    us_eligibility_note: str | None = None


def register_many(*contributions: Iterable[PublicSourceV1]) -> tuple[PublicSourceV1, ...]:
    """Compose independently owned source registries and reject unsafe metadata."""
    sources = tuple(source for group in contributions for source in group)
    ids = tuple(source.source_id for source in sources)
    if len(ids) != len(set(ids)):
        raise ValueError("DUPLICATE_PUBLIC_SOURCE_ID")
    if any(
        type(source) is not PublicSourceV1
        or source.redistribution is not False
        or type(source.capabilities) is not tuple
        or any(
            not isinstance(capability, str) or not capability for capability in source.capabilities
        )
        or source.tier not in (1, 2, 3)
        or source.schema_version != 1
        or source.tos_classification not in {"ALLOWED", "REVIEW", "EXCLUDED"}
        or not source.source_id
        or not source.endpoint
        or not source.tos_url.startswith("https://")
        or (
            "crypto_market" in source.factor_tags
            and (source.us_eligibility is None or not source.us_eligibility_note)
        )
        for source in sources
    ):
        raise ValueError("INVALID_PUBLIC_SOURCE_METADATA")
    return sources


PUBLIC_SOURCES: tuple[PublicSourceV1, ...] = (
    PublicSourceV1(
        "sec.edgar.form4",
        "https://data.sec.gov/submissions/CIK##########.json; https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/",
        "JSON + XML",
        "No key; configured User-Agent",
        "ALLOWED",
        "https://www.sec.gov/about/developer-resources",
        1,
        "Filing-driven",
        "SEC acceptance/filing timestamp, never transaction date",
        ("insider_activity", "governance"),
    ),
    PublicSourceV1(
        "finra.regsho.daily",
        "https://cdn.finra.org/equity/regsho/daily/{market}shvol{YYYYMMDD}.txt",
        "Pipe-delimited TXT",
        "No key",
        "ALLOWED",
        "https://www.finra.org/finra-data/browse-catalog/short-sale-volume-data",
        1,
        "Daily",
        "Trade date is not knowable until file publication (FINRA states by 18:00 ET)",
        ("short_activity", "market_structure"),
    ),
    PublicSourceV1(
        "finra.otc.weekly",
        "https://api.finra.org/data/group/otcMarket/name/weeklySummary",
        "JSON/CSV",
        "FINRA OAuth 2.0 client credential",
        "REVIEW",
        "https://developer.finra.org/docs",
        2,
        "Weekly; delayed 2 or 4 weeks",
        "FINRA initialPublishedDate; retain revisions by lastUpdateDate",
        ("off_exchange_activity", "market_structure"),
    ),
    PublicSourceV1(
        "cftc.cot.legacy",
        "https://publicreporting.cftc.gov/resource/jun7-fc8e.json",
        "JSON",
        "No key; optional Socrata app token",
        "ALLOWED",
        "https://www.cftc.gov/MarketReports/CommitmentsofTraders/index.htm",
        1,
        "Weekly, released Friday",
        "COT report date is prior Tuesday positioning; knowable at publication timestamp",
        ("positioning", "macro"),
    ),
    PublicSourceV1(
        "treasury.yield_curve",
        "https://home.treasury.gov/resource-center/data-chart-center/interest-rates/pages/xml",
        "XML",
        "No key",
        "ALLOWED",
        "https://home.treasury.gov/treasury-daily-interest-rate-xml-feed",
        1,
        "Daily",
        "Treasury publication timestamp; retain curve observation date separately",
        ("rates", "macro", "discount_rate"),
    ),
    PublicSourceV1(
        "treasury.fiscal_data",
        "https://api.fiscaldata.treasury.gov/services/api/fiscal_service/",
        "JSON",
        "No key",
        "ALLOWED",
        "https://fiscaldata.treasury.gov/api-documentation/",
        1,
        "Dataset-specific",
        "Dataset publication/update timestamp, not accounting period",
        ("fiscal_flows", "macro", "liquidity"),
    ),
    PublicSourceV1(
        "bls.public_api",
        "https://api.bls.gov/publicAPI/v1/timeseries/data/",
        "JSON",
        "Public keyless limits; key optional",
        "ALLOWED",
        "https://www.bls.gov/developers/api_signature.htm",
        1,
        "Monthly/quarterly",
        "Series release timestamp/vintage, not observation period",
        ("inflation", "labor", "macro"),
    ),
    PublicSourceV1(
        "fed.fomc",
        "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm",
        "HTML/PDF",
        "No key",
        "ALLOWED",
        "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm",
        2,
        "Event-driven",
        "Statement/minutes publication timestamp",
        ("event_risk", "rates", "macro"),
    ),
    PublicSourceV1(
        "cboe.vix",
        "https://www.cboe.com/tradable_products/vix/",
        "HTML/CSV",
        "No key on public pages; redistribution terms apply",
        "REVIEW",
        "https://www.cboe.com/us/en/about/market-data/",
        2,
        "Daily/intraday by product",
        "Exchange publication timestamp for each observation",
        ("volatility", "options_sentiment"),
    ),
    PublicSourceV1(
        "house.disclosures",
        "https://disclosures-clerk.house.gov/FinancialDisclosure",
        "HTML/PDF/CSV",
        "No key",
        "REVIEW",
        "https://disclosures-clerk.house.gov/FinancialDisclosure",
        2,
        "Event-driven; statutory delay",
        "Disclosure filing/publication timestamp, not trade date",
        ("political_trades", "insider_activity"),
    ),
    PublicSourceV1(
        "kalshi.market_data",
        "https://api.elections.kalshi.com/trade-api/v2/markets",
        "JSON",
        "Public reads; terms/API policy govern",
        "REVIEW",
        "https://docs.kalshi.com/getting_started/rate_limits",
        2,
        "Live/event-driven",
        "Exchange event timestamp and retrieval time",
        ("prediction_markets", "event_risk"),
    ),
    PublicSourceV1(
        "polymarket.gamma",
        "https://gamma-api.polymarket.com/markets",
        "JSON",
        "Public reads; terms/API policy govern",
        "REVIEW",
        "https://docs.polymarket.com/quickstart/introduction/main",
        2,
        "Live/event-driven",
        "Market update timestamp; source-specific timestamp required",
        ("prediction_markets", "event_risk"),
    ),
    PublicSourceV1(
        "coinbase.exchange",
        "https://api.exchange.coinbase.com/products/{product_id}/ticker",
        "JSON",
        "Public market data; exchange terms apply",
        "ALLOWED",
        "https://www.coinbase.com/legal/user_agreement/united_states",
        1,
        "Live",
        "Exchange event timestamp, with receive timestamp distinct",
        ("crypto_market", "momentum", "liquidity"),
        us_eligibility="eligible",
        us_eligibility_note=(
            "Public Coinbase Exchange market-data API; its US individual agreement states US "
            "residents are eligible. No account or order endpoints are used."
        ),
    ),
    PublicSourceV1(
        "cme.fedwatch",
        "https://www.cmegroup.com/markets/interest-rates/cme-fedwatch-tool.html",
        "HTML",
        "Public page; terms apply",
        "EXCLUDED",
        "https://www.cmegroup.com/market-data/market-data-terms-of-use.html",
        3,
        "Event-driven",
        "Displayed update time",
        ("event_risk", "rates"),
    ),
    PublicSourceV1(
        "earnings.public_sites",
        "Source-specific public HTML",
        "HTML",
        "Varies",
        "REVIEW",
        "https://www.sec.gov/edgar/search/",
        3,
        "Event-driven",
        "Issuer/filing publication timestamp; estimate vintage required",
        ("earnings", "event_risk"),
    ),
    PublicSourceV1(
        "api_anything.learned",
        "Allowlisted learned operation only",
        "Versioned JSON response",
        "Isolated sidecar; no imported browser credentials",
        "REVIEW",
        "https://github.com/goodnight000/api-anything/blob/main/LICENSE",
        3,
        "Per operation",
        "Operation's source timestamp; fetched_at never substitutes for as_of",
        ("long_tail_public",),
    ),
    PublicSourceV1(
        "nyfed.markets",
        "https://markets.newyorkfed.org/api/{rates,rp,pd}/...",
        "JSON/CSV",
        "No key",
        "REVIEW",
        "https://markets.newyorkfed.org/static/docs/markets-api.html",
        1,
        "Daily/weekly/monthly by series",
        "Observation date is event time; publication or first capture is knowable time",
        ("rates_macro", "liquidity", "positioning"),
    ),
    PublicSourceV1(
        "treasurydirect.auctions",
        "https://api.fiscaldata.treasury.gov/.../auctions_query; TreasuryDirect query exports",
        "JSON/CSV/XML",
        "No key",
        "REVIEW",
        "https://www.treasurydirect.gov/auctions/auction-query/auction-query-help/",
        1,
        "Auction announcement and results driven",
        "Announcement publication for schedule; results only when published",
        ("rates_macro", "liquidity", "event_risk"),
    ),
    PublicSourceV1(
        "finra.short_interest",
        "https://api.finra.org/data/group/otcMarket/name/consolidatedShortInterest",
        "JSON",
        "FINRA OAuth 2.0 client credentials from project vault",
        "REVIEW",
        "https://developer.finra.org/docs",
        1,
        "Bimonthly",
        "Knowable on FINRA publication date/time, not settlement date",
        ("short_activity", "dark_pool"),
    ),
    PublicSourceV1(
        "sec.edgar.13f",
        "https://data.sec.gov/submissions/CIK##########.json; https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/",
        "JSON + XML/HTML",
        "No key; configured User-Agent",
        "ALLOWED",
        "https://www.sec.gov/about/developer-resources",
        1,
        "Quarterly filing driven",
        "SEC accepted/filed timestamp; report-period end is not knowable time",
        ("insider_activity", "positioning", "governance"),
    ),
    PublicSourceV1(
        "sec.edgar.13dg",
        "https://data.sec.gov/submissions/CIK##########.json; https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/",
        "JSON + XML",
        "No key; configured User-Agent",
        "ALLOWED",
        "https://www.sec.gov/edgar/searchedgar/accessing-edgar-data.htm",
        1,
        "Event driven",
        "SEC accepted/filed timestamp; beneficial ownership event date is separate",
        ("insider_activity", "governance", "event_risk"),
    ),
    PublicSourceV1(
        "house.ptr.bulk",
        "https://disclosures-clerk.house.gov/public_disc/financial-pdfs/{year}FD.ZIP",
        "ZIP/XML/CSV/PDF",
        "No key",
        "REVIEW",
        "https://disclosures-clerk.house.gov/FinancialDisclosure",
        2,
        "Event driven; statutory filing lag",
        "Filed/received/published timestamp; transaction date is not the knowledge time",
        ("insider_activity", "political_trades", "event_risk"),
    ),
    PublicSourceV1(
        "crypto.binance_usdm",
        "https://fapi.binance.com/fapi/v1/{fundingRate,openInterest}",
        "JSON",
        "EXCLUDED: public response does not override US-person service restrictions",
        "EXCLUDED",
        "https://www.binance.com/en/terms",
        1,
        "Disabled for US persons",
        "US-person eligibility is prohibited by Binance terms; no runtime adapter is enabled",
        ("positioning", "crypto_market"),
        us_eligibility="ineligible",
        us_eligibility_note=(
            "Binance terms restrict US persons; the fapi runtime adapter is disabled."
        ),
    ),
    PublicSourceV1(
        "coinbase.derivatives_us",
        "https://api.coinbase.com/api/v3/brokerage/market/products; "
        "https://api.exchange.fairx.net/rest/{instruments,funding-rate}",
        "JSON",
        "Public product catalog, instruments, and funding-rate resources are unauthenticated",
        "ALLOWED",
        "https://www.coinbase.com/legal/futures-account-agreement",
        1,
        "Instrument driven; hourly funding history",
        "Funding event_time is source event time; product OI is first-observed at fetch time",
        ("positioning", "crypto_market"),
        capabilities=("instruments", "funding", "open_interest"),
        us_eligibility="eligible",
        us_eligibility_note=(
            "US perpetual-style futures are a CFM/CFTC-regulated product offered to US customers; "
            "only no-auth public CDE/Advanced Trade market resources are used."
        ),
    ),
    PublicSourceV1(
        "finra.ats_weekly",
        "https://api.finra.org/data/group/otcMarket/name/weeklySummary",
        "JSON/CSV",
        "FINRA OAuth 2.0 client credentials from project vault",
        "REVIEW",
        "https://developer.finra.org/docs",
        2,
        "Weekly; delayed",
        "Initial publication date/time; retain revisions by lastUpdateDate",
        ("dark_pool", "off_exchange", "market_structure"),
    ),
    PublicSourceV1(
        "finra.otc_weekly",
        "https://api.finra.org/data/group/otcMarket/name/weeklySummary",
        "JSON/CSV",
        "FINRA OAuth 2.0 client credentials from project vault",
        "REVIEW",
        "https://developer.finra.org/docs",
        2,
        "Weekly; delayed",
        "Initial publication date/time; retain revisions by lastUpdateDate",
        ("dark_pool", "off_exchange", "market_structure"),
    ),
)
