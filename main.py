import csv
import hashlib
import hmac
import io
import json
import os
import re
import time
import uuid
from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Literal, Optional
from zoneinfo import ZoneInfo

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# =====================================================================
# Configuration & Security
# =====================================================================

def require_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


YNAB_API_TOKEN = require_env("YNAB_API_TOKEN")
YNAB_BUDGET_ID = require_env("YNAB_BUDGET_ID")
MIDDLEWARE_API_KEY = require_env("MIDDLEWARE_API_KEY")
REF_SECRET = require_env("REF_SECRET")

PUBLIC_BASE_URL = (
    os.getenv("PUBLIC_BASE_URL")
    or "https://blissful-flow-production.up.railway.app"
).strip().rstrip("/")
PRIMARY_CHECKING_NAME = (os.getenv("PRIMARY_CHECKING_NAME") or "WF Checking").strip().lower()
CHECKING_FLOOR_MILLI = int(
    (Decimal(os.getenv("CHECKING_FLOOR", "1000.00")) * 1000).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )
)
HOUSEHOLD_TIMEZONE = os.getenv("HOUSEHOLD_TIMEZONE", "America/Chicago")
HISTORY_DAYS = int(os.getenv("HISTORY_DAYS", "365"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "45"))
PROPOSAL_TTL_SECONDS = int(os.getenv("PROPOSAL_TTL_SECONDS", "900"))

# Plaid credentials are server-side only. PLAID_ACCESS_TOKEN is Item-specific
# and is created after completing Plaid Link; it is not the Plaid client secret.
PLAID_CLIENT_ID = (os.getenv("PLAID_CLIENT_ID") or "").strip()
PLAID_SECRET = (os.getenv("PLAID_SECRET") or "").strip()
PLAID_ENV = (os.getenv("PLAID_ENV") or "production").strip().lower()
PLAID_ACCESS_TOKEN = (os.getenv("PLAID_ACCESS_TOKEN") or "").strip()
PLAID_ITEM_ID = (os.getenv("PLAID_ITEM_ID") or "").strip()
PLAID_YNAB_ACCOUNT_MAP_RAW = (os.getenv("PLAID_YNAB_ACCOUNT_MAP") or "{}").strip()
PLAID_DAYS_REQUESTED = int(os.getenv("PLAID_DAYS_REQUESTED", "365"))

if PLAID_ENV not in {"sandbox", "production"}:
    raise RuntimeError("PLAID_ENV must be 'sandbox' or 'production'")
if not 1 <= PLAID_DAYS_REQUESTED <= 730:
    raise RuntimeError("PLAID_DAYS_REQUESTED must be between 1 and 730")

PLAID_BASE_URL = (
    "https://sandbox.plaid.com"
    if PLAID_ENV == "sandbox"
    else "https://production.plaid.com"
)

try:
    PLAID_YNAB_ACCOUNT_MAP = json.loads(PLAID_YNAB_ACCOUNT_MAP_RAW)
except json.JSONDecodeError as exc:
    raise RuntimeError("PLAID_YNAB_ACCOUNT_MAP must be valid JSON") from exc
if not isinstance(PLAID_YNAB_ACCOUNT_MAP, dict):
    raise RuntimeError("PLAID_YNAB_ACCOUNT_MAP must be a JSON object")

YNAB_BASE_URL = "https://api.ynab.com/v1"

app = FastAPI(
    title="YNAB Copilot Middleware",
    description="Deterministic read-model, Plaid-backed read-only reconciliation, and guarded write layer between ChatGPT and YNAB",
    version="3.4.1",
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    if PUBLIC_BASE_URL:
        schema["servers"] = [{"url": PUBLIC_BASE_URL}]
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }
    schema["security"] = [{"ApiKeyAuth": []}]

    # Public health/docs routes do not require the API key at runtime. Mark them
    # the same way in OpenAPI so Action clients do not infer a credential
    # requirement for simple connectivity tests.
    for public_path in ("/", "/healthz", "/docs", "/openapi.json", "/redoc"):
        for operation in (schema.get("paths", {}).get(public_path) or {}).values():
            if isinstance(operation, dict):
                operation["security"] = []

    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


@app.middleware("http")
async def authenticate_all_requests(request: Request, call_next):
    if request.url.path in ["/", "/healthz", "/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)

    raw_header = (
        request.headers.get("x-api-key")
        or request.headers.get("x_api_key")
        or request.headers.get("authorization")
    )
    incoming_key = raw_header
    if incoming_key:
        incoming_key = incoming_key.strip().strip('"').strip("'")
        if incoming_key.lower().startswith("bearer "):
            incoming_key = incoming_key[7:].strip()

    if not incoming_key or not hmac.compare_digest(incoming_key, MIDDLEWARE_API_KEY):
        # Never log either the configured secret or the received credential.
        print(f"AUTH REJECTED path={request.url.path}", flush=True)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid or missing X-API-Key header"},
        )

    return await call_next(request)


# =====================================================================
# Helpers
# =====================================================================

def local_today() -> date:
    return datetime.now(ZoneInfo(HOUSEHOLD_TIMEZONE)).date()


def milli_to_str(milliunits: int) -> str:
    return f"{(Decimal(milliunits) / Decimal(1000)):.2f}"


def str_to_milli(amount_str: str) -> int:
    clean = amount_str.replace("$", "").replace(",", "").strip()
    amount = Decimal(clean)
    return int((amount * 1000).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def normalize_text(value: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def load_policy() -> Dict[str, Any]:
    if os.path.exists("policy.yaml"):
        with open("policy.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {"policy_version": "default", "checking_floor": milli_to_str(CHECKING_FLOOR_MILLI)}


# =====================================================================
# In-Memory Read Cache & Opaque Aliasing
# =====================================================================

class BudgetStore:
    def __init__(self):
        self.server_knowledge: Optional[int] = None
        self.last_sync_time: float = 0.0
        self.ttl_seconds: float = CACHE_TTL_SECONDS

        self.accounts: Dict[str, dict] = {}
        self.categories: Dict[str, dict] = {}
        self.category_groups: Dict[str, dict] = {}
        self.transactions: Dict[str, dict] = {}
        self.scheduled_transactions: Dict[str, dict] = {}
        self.payees: Dict[str, dict] = {}
        self.current_month_detail: Dict[str, Any] = {}

        self.alias_to_uuid: Dict[str, str] = {}
        self.uuid_to_alias: Dict[str, str] = {}

        # IMPORTANT: for production/multiple Railway workers, persist this in Redis/Postgres.
        self.proposals: Dict[str, dict] = {}

        # Read-only external reconciliation snapshot. This is deliberately
        # ephemeral and never writes external data into YNAB.
        self.reconciliation_snapshot: Optional[Dict[str, Any]] = None

        # Runtime Plaid state. Production credentials should be persisted as
        # Railway secrets / a secret-capable datastore, not only in memory.
        self.plaid_access_token: str = PLAID_ACCESS_TOKEN
        self.plaid_item_id: str = PLAID_ITEM_ID
        self.plaid_cursor: Optional[str] = None
        self.plaid_transactions: Dict[str, dict] = {}

        # Small, non-sensitive cache of Plaid account balance metadata. This lets
        # budget/cashflow endpoints compare the bank-side balance with YNAB
        # without returning or retaining raw account credentials.
        self.plaid_account_balances: Dict[str, dict] = {}
        self.plaid_balance_sync_time: float = 0.0

    def _slugify(self, text: str) -> str:
        s = re.sub(r"[^\w\s-]", "", text.strip().lower())
        return re.sub(r"[-\s]+", "_", s)

    def register_alias(self, prefix: str, name: str, real_uuid: str) -> str:
        if real_uuid in self.uuid_to_alias:
            return self.uuid_to_alias[real_uuid]

        base_alias = f"{prefix}:{self._slugify(name)}"
        alias = base_alias
        counter = 1
        while alias in self.alias_to_uuid and self.alias_to_uuid[alias] != real_uuid:
            alias = f"{base_alias}_{counter}"
            counter += 1

        self.alias_to_uuid[alias] = real_uuid
        self.uuid_to_alias[real_uuid] = alias
        return alias

    def register_opaque_ref(self, prefix: str, real_uuid: str) -> str:
        existing = self.uuid_to_alias.get(real_uuid)
        if existing and existing.startswith(f"{prefix}:"):
            return existing

        digest = hmac.new(
            REF_SECRET.encode("utf-8"),
            real_uuid.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:10]
        ref = f"{prefix}:{digest}"
        self.alias_to_uuid[ref] = real_uuid
        self.uuid_to_alias[real_uuid] = ref
        return ref

    def transaction_ref(self, real_uuid: str) -> str:
        return self.register_opaque_ref("t", real_uuid)

    def scheduled_ref(self, real_uuid: str) -> str:
        return self.register_opaque_ref("s", real_uuid)

    def resolve_uuid(self, identifier: str) -> str:
        return self.alias_to_uuid.get(identifier, identifier)

    def remove_uuid(self, real_uuid: str) -> None:
        alias = self.uuid_to_alias.pop(real_uuid, None)
        if alias:
            self.alias_to_uuid.pop(alias, None)


store = BudgetStore()


def get_primary_checking_ids() -> set[str]:
    exact = {
        acct_id
        for acct_id, acct in store.accounts.items()
        if not acct.get("closed")
        and (acct.get("name") or "").strip().lower() == PRIMARY_CHECKING_NAME
    }
    if exact:
        return exact

    # Backward-compatible fallback, but exact naming is preferred.
    return {
        acct_id
        for acct_id, acct in store.accounts.items()
        if not acct.get("closed")
        and PRIMARY_CHECKING_NAME in (acct.get("name") or "").lower()
    }


def tx_is_transfer(tx: dict) -> bool:
    return bool(tx.get("transfer_account_id") or tx.get("transfer_transaction_id"))


def tx_display_payee(tx: dict) -> str:
    if tx_is_transfer(tx):
        transfer_id = tx.get("transfer_account_id")
        target = store.accounts.get(transfer_id, {})
        if target:
            return f"Transfer: {target.get('name', 'account')}"
        return "Transfer"

    return (
        tx.get("payee_name")
        or tx.get("import_payee_name")
        or tx.get("import_payee_name_original")
        or "Unknown payee"
    )


def category_alias(category_id: Optional[str]) -> str:
    if not category_id:
        return ""
    return store.uuid_to_alias.get(
        category_id,
        store.categories.get(category_id, {}).get("name", "Unknown category"),
    )


def policy_class_for(alias: str, policy: Dict[str, Any]) -> str:
    # Supports either:
    # category_classes: {essential: [cat:mortgage], discretionary: [...]}
    # or classes: {essential: [...], discretionary: [...]}
    classes = policy.get("category_classes") or policy.get("classes") or {}
    if isinstance(classes, dict):
        for class_name, members in classes.items():
            if isinstance(members, list) and alias in members:
                return str(class_name)

    # Also supports top-level keys:
    for class_name in ("essential", "discretionary", "savings", "debt", "true_expense"):
        members = policy.get(class_name)
        if isinstance(members, list) and alias in members:
            return class_name

    return "unclassified"


TRANSFER_HINTS = (
    "transfer",
    "payment",
    "autopay",
    "auto pay",
    "credit card",
    "card payment",
    "online payment",
)

ESTIMATE_HINTS = (
    "estimate",
    "estimated",
    "projection",
    "projected",
    "expected",
    "placeholder",
)


def tx_search_text(tx: dict) -> str:
    values = [
        tx.get("payee_name"),
        tx.get("import_payee_name"),
        tx.get("import_payee_name_original"),
        tx.get("memo"),
    ]
    return " ".join(normalize_text(v) for v in values if v)


def account_type_for(account_id: Optional[str]) -> str:
    if not account_id:
        return ""
    return str(store.accounts.get(account_id, {}).get("type") or "").lower()


def is_credit_account(account_id: Optional[str]) -> bool:
    kind = account_type_for(account_id)
    return kind in {
        "creditcard",
        "lineofcredit",
        "otherliability",
        "mortgage",
    }


def is_cash_account(account_id: Optional[str]) -> bool:
    kind = account_type_for(account_id)
    return kind in {
        "checking",
        "savings",
        "cash",
        "otherasset",
    }


def _date_distance_days(a: dict, b: dict) -> int:
    try:
        return abs((date.fromisoformat(a.get("date")) - date.fromisoformat(b.get("date"))).days)
    except Exception:
        return 9999


def build_transfer_candidate_map(transactions: Dict[str, dict]) -> Dict[str, dict]:
    """Conservatively flag likely account-to-account transfers.

    This never mutates YNAB. It only surfaces evidence so the GPT does not
    categorize likely transfer halves as spending/income.
    """
    by_abs_amount: Dict[int, List[tuple[str, dict]]] = {}
    for tx_id, tx in transactions.items():
        amount = int(tx.get("amount", 0))
        if amount == 0 or tx_is_transfer(tx):
            continue
        by_abs_amount.setdefault(abs(amount), []).append((tx_id, tx))

    candidates: Dict[str, dict] = {}

    for _, bucket in by_abs_amount.items():
        for i, (a_id, a) in enumerate(bucket):
            for b_id, b in bucket[i + 1:]:
                a_amount = int(a.get("amount", 0))
                b_amount = int(b.get("amount", 0))
                if a_amount != -b_amount:
                    continue
                if a.get("account_id") == b.get("account_id"):
                    continue

                day_gap = _date_distance_days(a, b)
                if day_gap > 2:
                    continue

                score = 3  # exact opposite amount
                reasons = ["exact opposite amounts"]

                if day_gap == 0:
                    score += 2
                    reasons.append("same date")
                elif day_gap == 1:
                    score += 1
                    reasons.append("dates one day apart")
                else:
                    reasons.append("dates two days apart")

                a_text = tx_search_text(a)
                b_text = tx_search_text(b)
                if any(hint in a_text or hint in b_text for hint in TRANSFER_HINTS):
                    score += 2
                    reasons.append("transfer/payment wording")

                a_acct = a.get("account_id")
                b_acct = b.get("account_id")
                if (
                    (is_credit_account(a_acct) and is_cash_account(b_acct))
                    or (is_credit_account(b_acct) and is_cash_account(a_acct))
                ):
                    score += 2
                    reasons.append("cash-to-credit account pair")

                if score < 5:
                    continue

                def register(tx_id: str, other_id: str):
                    current = candidates.get(tx_id)
                    record = {
                        "candidate_ref": store.transaction_ref(other_id),
                        "score": score,
                        "reason": "; ".join(reasons),
                    }
                    if not current or record["score"] > current["score"]:
                        candidates[tx_id] = record

                register(a_id, b_id)
                register(b_id, a_id)

    return candidates


def build_duplicate_candidate_map(transactions: Dict[str, dict]) -> Dict[str, dict]:
    """Flag likely imported/manual duplicates without automatically deleting them."""
    by_account: Dict[str, List[tuple[str, dict]]] = {}
    for tx_id, tx in transactions.items():
        account_id = tx.get("account_id")
        if not account_id or tx_is_transfer(tx):
            continue
        by_account.setdefault(account_id, []).append((tx_id, tx))

    candidates: Dict[str, dict] = {}

    for _, rows in by_account.items():
        rows.sort(key=lambda pair: pair[1].get("date") or "")
        for i, (a_id, a) in enumerate(rows):
            a_amount = int(a.get("amount", 0))
            for b_id, b in rows[i + 1:]:
                day_gap = _date_distance_days(a, b)
                if day_gap > 2:
                    # Rows are date-sorted; once we're beyond the window we can stop.
                    if (b.get("date") or "") >= (a.get("date") or ""):
                        break
                    continue

                b_amount = int(b.get("amount", 0))
                if (a_amount >= 0) != (b_amount >= 0):
                    continue

                amount_delta = abs(abs(a_amount) - abs(b_amount))
                if amount_delta > 100:  # <= $0.10
                    continue

                a_imported = bool(a.get("import_id"))
                b_imported = bool(b.get("import_id"))
                a_text = tx_search_text(a)
                b_text = tx_search_text(b)

                score = 0
                reasons = []

                if day_gap == 0:
                    score += 2
                    reasons.append("same date")
                elif day_gap == 1:
                    score += 1
                    reasons.append("dates one day apart")
                else:
                    reasons.append("dates two days apart")

                if amount_delta == 0:
                    score += 2
                    reasons.append("same amount")
                else:
                    score += 1
                    reasons.append(f"amounts differ by {milli_to_str(amount_delta)}")

                if a_imported != b_imported:
                    score += 2
                    reasons.append("one imported and one manual/unmatched")

                if any(hint in a_text or hint in b_text for hint in ESTIMATE_HINTS):
                    score += 2
                    reasons.append("estimated/projected wording")

                # Light textual corroboration. Avoid requiring exact payee equality
                # because imported and manual names often differ.
                a_tokens = {t for t in a_text.split() if len(t) >= 4}
                b_tokens = {t for t in b_text.split() if len(t) >= 4}
                shared = a_tokens & b_tokens
                if shared:
                    score += 1
                    reasons.append("similar payee/memo text")

                if score < 5:
                    continue

                def register(tx_id: str, other_id: str):
                    current = candidates.get(tx_id)
                    record = {
                        "candidate_ref": store.transaction_ref(other_id),
                        "score": score,
                        "reason": "; ".join(reasons),
                        "amount_difference": milli_to_str(amount_delta),
                    }
                    if not current or record["score"] > current["score"]:
                        candidates[tx_id] = record

                register(a_id, b_id)
                register(b_id, a_id)

    return candidates


# =====================================================================
# YNAB Sync Engine
# =====================================================================

async def sync_ynab(force: bool = False):
    now = time.time()
    if (
        not force
        and store.server_knowledge is not None
        and (now - store.last_sync_time < store.ttl_seconds)
    ):
        return

    headers = {"Authorization": f"Bearer {YNAB_API_TOKEN}"}
    params: Dict[str, Any] = {}
    if store.server_knowledge is not None:
        params["last_knowledge_of_server"] = store.server_knowledge

    async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=20.0) as client:
        resp = await client.get(
            f"/budgets/{YNAB_BUDGET_ID}",
            headers=headers,
            params=params,
        )
        if resp.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"YNAB sync failed: {resp.status_code}",
            )

        data = resp.json().get("data", {})
        budget = data.get("budget", {})
        if data.get("server_knowledge") is not None:
            store.server_knowledge = data["server_knowledge"]

        # Merge delta entities; never replace a cached collection with a delta subset.
        for acct in budget.get("accounts", []):
            acct_id = acct["id"]
            if acct.get("deleted", False):
                store.accounts.pop(acct_id, None)
                store.remove_uuid(acct_id)
                continue
            store.accounts[acct_id] = acct
            store.register_alias("acct", acct.get("name") or "account", acct_id)

        for group in budget.get("category_groups", []):
            group_id = group["id"]
            if group.get("deleted", False):
                store.category_groups.pop(group_id, None)
            else:
                store.category_groups[group_id] = group

            for cat in group.get("categories", []):
                cat_id = cat["id"]
                if cat.get("deleted", False):
                    store.categories.pop(cat_id, None)
                    store.remove_uuid(cat_id)
                    continue
                store.categories[cat_id] = cat
                store.register_alias("cat", cat.get("name") or "category", cat_id)

        for payee in budget.get("payees", []):
            payee_id = payee["id"]
            if payee.get("deleted", False):
                store.payees.pop(payee_id, None)
                continue
            store.payees[payee_id] = payee

        for stx in budget.get("scheduled_transactions", []):
            stx_id = stx["id"]
            if stx.get("deleted", False):
                store.scheduled_transactions.pop(stx_id, None)
                store.remove_uuid(stx_id)
                continue
            store.scheduled_transactions[stx_id] = stx
            store.scheduled_ref(stx_id)

        history_cutoff = (local_today() - timedelta(days=HISTORY_DAYS)).isoformat()
        for tx in budget.get("transactions", []):
            tx_id = tx["id"]
            if tx.get("deleted", False):
                store.transactions.pop(tx_id, None)
                store.remove_uuid(tx_id)
                continue
            if (tx.get("date") or "") >= history_cutoff:
                store.transactions[tx_id] = tx
                store.transaction_ref(tx_id)

        # Prune aging records from the local history cache.
        for tx_id, tx in list(store.transactions.items()):
            if (tx.get("date") or "") < history_cutoff:
                store.transactions.pop(tx_id, None)
                store.remove_uuid(tx_id)

        # Always fetch the explicit current month. This is the authoritative source
        # for RTA and category assigned/activity/available values.
        month_resp = await client.get(
            f"/budgets/{YNAB_BUDGET_ID}/months/current",
            headers=headers,
        )
        if month_resp.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"YNAB current-month sync failed: {month_resp.status_code}",
            )
        store.current_month_detail = month_resp.json().get("data", {}).get("month", {}) or {}

        for cat in store.current_month_detail.get("categories", []):
            cat_id = cat["id"]
            if not cat.get("deleted", False):
                store.categories[cat_id] = {**store.categories.get(cat_id, {}), **cat}
                store.register_alias("cat", cat.get("name") or "category", cat_id)

        store.last_sync_time = now


def current_month_categories() -> Dict[str, dict]:
    return {
        cat["id"]: cat
        for cat in store.current_month_detail.get("categories", [])
        if not cat.get("deleted", False) and not cat.get("hidden", False)
    }



# =====================================================================
# Read-Only External Transaction Reconciliation
# =====================================================================

class ExternalTransaction(BaseModel):
    external_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Stable transaction identifier from the external bank/card source",
    )
    account: str = Field(
        ...,
        description="YNAB account alias, e.g. acct:wf_checking",
    )
    posted_date: date
    authorized_date: Optional[date] = None
    amount: str = Field(
        ...,
        description=(
            "Signed currency amount using YNAB direction: outflow negative, inflow positive"
        ),
    )
    merchant: Optional[str] = None
    description: Optional[str] = None
    pending: bool = False
    ynab_import_id: Optional[str] = Field(
        None,
        description="Optional YNAB import_id when the external source exposes the same identifier",
    )


class ExternalTransactionBatch(BaseModel):
    source: str = Field(..., min_length=1, max_length=100)
    transactions: List[ExternalTransaction] = Field(..., min_length=1, max_length=500)


def external_transaction_ref(source: str, external_id: str) -> str:
    digest = hmac.new(
        REF_SECRET.encode("utf-8"),
        f"{source}|{external_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]
    return f"x:{digest}"


def _safe_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _text_tokens(*values: Optional[str]) -> set[str]:
    text = " ".join(normalize_text(v) for v in values if v)
    return {token for token in text.split() if len(token) >= 3}


def _external_text_tokens(tx: ExternalTransaction) -> set[str]:
    return _text_tokens(tx.merchant, tx.description)


def _ynab_text_tokens(tx: dict) -> set[str]:
    return _text_tokens(
        tx.get("payee_name"),
        tx.get("import_payee_name"),
        tx.get("import_payee_name_original"),
        tx.get("memo"),
    )


def _jaccard_similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def score_external_to_ynab(
    external: ExternalTransaction,
    ynab_tx: dict,
    account_uuid: str,
) -> Dict[str, Any]:
    """Score evidence that one external transaction corresponds to one YNAB row."""
    score = 0
    reasons: List[str] = []

    if ynab_tx.get("account_id") != account_uuid:
        return {"score": -999, "reasons": ["different account"], "date_gap": 9999}

    score += 3
    reasons.append("same account")

    external_amount = str_to_milli(external.amount)
    ynab_amount = int(ynab_tx.get("amount", 0))
    amount_delta = abs(external_amount - ynab_amount)

    if amount_delta == 0:
        score += 4
        reasons.append("exact amount")
    elif amount_delta <= 100:
        score += 1
        reasons.append("amount within $0.10")
    else:
        return {
            "score": -999,
            "reasons": ["amount mismatch"],
            "date_gap": 9999,
            "amount_delta_milli": amount_delta,
        }

    ynab_date = _safe_date(ynab_tx.get("date"))
    comparison_date = external.posted_date
    date_gap = abs((comparison_date - ynab_date).days) if ynab_date else 9999

    if date_gap == 0:
        score += 3
        reasons.append("same posted date")
    elif date_gap == 1:
        score += 2
        reasons.append("posted dates one day apart")
    elif date_gap == 2:
        score += 1
        reasons.append("posted dates two days apart")
    elif external.authorized_date and ynab_date:
        auth_gap = abs((external.authorized_date - ynab_date).days)
        if auth_gap == 0:
            score += 2
            reasons.append("YNAB date matches authorization date")
            date_gap = min(date_gap, auth_gap)
        elif auth_gap == 1:
            score += 1
            reasons.append("YNAB date within one day of authorization")
            date_gap = min(date_gap, auth_gap)

    if date_gap > 3:
        return {
            "score": -999,
            "reasons": ["date outside matching window"],
            "date_gap": date_gap,
            "amount_delta_milli": amount_delta,
        }

    if (
        external.ynab_import_id
        and ynab_tx.get("import_id")
        and external.ynab_import_id == ynab_tx.get("import_id")
    ):
        score += 10
        reasons.append("exact YNAB import identifier")

    ext_tokens = _external_text_tokens(external)
    ynab_tokens = _ynab_text_tokens(ynab_tx)
    similarity = _jaccard_similarity(ext_tokens, ynab_tokens)

    if similarity >= 0.60:
        score += 3
        reasons.append("strong merchant/payee text match")
    elif similarity >= 0.30:
        score += 2
        reasons.append("merchant/payee text match")
    elif ext_tokens & ynab_tokens:
        score += 1
        reasons.append("partial merchant/payee text match")

    return {
        "score": score,
        "reasons": reasons,
        "date_gap": date_gap,
        "amount_delta_milli": amount_delta,
        "text_similarity": round(similarity, 3),
    }


def reconciliation_confidence(score: int) -> float:
    # A compact evidence-to-confidence mapping. This is not a statistical
    # probability; it is a deterministic confidence indicator for review.
    if score >= 15:
        return 0.99
    if score >= 12:
        return 0.97
    if score >= 10:
        return 0.93
    if score >= 8:
        return 0.85
    if score >= 7:
        return 0.75
    if score >= 6:
        return 0.62
    if score >= 5:
        return 0.50
    return 0.0


def find_external_transfer_candidates(
    rows: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Find opposite-amount external rows across different accounts."""
    by_abs_amount: Dict[int, List[Dict[str, Any]]] = {}
    for row in rows:
        if row["pending"]:
            continue
        by_abs_amount.setdefault(abs(row["amount_milli"]), []).append(row)

    matches: Dict[str, Dict[str, Any]] = {}
    for bucket in by_abs_amount.values():
        for i, a in enumerate(bucket):
            for b in bucket[i + 1:]:
                if a["amount_milli"] != -b["amount_milli"]:
                    continue
                if a["account"] == b["account"]:
                    continue
                gap = abs((date.fromisoformat(a["posted_date"]) - date.fromisoformat(b["posted_date"])).days)
                if gap > 2:
                    continue
                evidence = ["exact opposite amounts", "different accounts"]
                if gap == 0:
                    evidence.append("same posted date")
                else:
                    evidence.append(f"posted dates {gap} day(s) apart")
                matches[a["external_ref"]] = {
                    "candidate_external_ref": b["external_ref"],
                    "evidence": evidence,
                }
                matches[b["external_ref"]] = {
                    "candidate_external_ref": a["external_ref"],
                    "evidence": evidence,
                }
    return matches


def reconcile_external_transactions(
    source: str,
    external_transactions: List[ExternalTransaction],
) -> Dict[str, Any]:
    """Build a read-only reconciliation report against the current YNAB cache."""
    normalized: List[Dict[str, Any]] = []
    for external in external_transactions:
        account_uuid = store.resolve_uuid(external.account)
        account = store.accounts.get(account_uuid)
        if not account or account.get("closed"):
            raise HTTPException(
                status_code=404,
                detail=f"External transaction account {external.account} not found or closed",
            )

        normalized.append({
            "external": external,
            "external_ref": external_transaction_ref(source, external.external_id),
            "account_uuid": account_uuid,
            "account": store.uuid_to_alias.get(account_uuid, external.account),
            "posted_date": external.posted_date.isoformat(),
            "authorized_date": (
                external.authorized_date.isoformat()
                if external.authorized_date else None
            ),
            "amount_milli": str_to_milli(external.amount),
            "amount": milli_to_str(str_to_milli(external.amount)),
            "merchant": external.merchant or "",
            "description": external.description or "",
            "pending": external.pending,
        })

    transfer_candidates = find_external_transfer_candidates(normalized)

    # Candidate YNAB rows are restricted to the history cache and evaluated by
    # account, amount and a narrow date window before text evidence is applied.
    result_rows: List[Dict[str, Any]] = []
    claimed_ynab: Dict[str, List[str]] = {}

    for row in normalized:
        external = row["external"]
        if external.pending:
            result_rows.append({
                "external_ref": row["external_ref"],
                "account": row["account"],
                "posted_date": row["posted_date"],
                "authorized_date": row["authorized_date"],
                "amount": row["amount"],
                "merchant": row["merchant"],
                "description": row["description"],
                "pending": True,
                "status": "pending",
                "confidence": 1.0,
                "ynab_ref": "",
                "candidate_ynab_refs": [],
                "evidence": ["external transaction is still pending"],
                "possible_transfer": bool(transfer_candidates.get(row["external_ref"])),
                "transfer_candidate_external_ref": (
                    transfer_candidates.get(row["external_ref"], {}).get(
                        "candidate_external_ref", ""
                    )
                ),
            })
            continue

        candidates = []
        for tx_id, ynab_tx in store.transactions.items():
            evidence = score_external_to_ynab(
                external=external,
                ynab_tx=ynab_tx,
                account_uuid=row["account_uuid"],
            )
            if evidence["score"] < 5:
                continue
            candidates.append({
                "tx_id": tx_id,
                "ynab_ref": store.transaction_ref(tx_id),
                **evidence,
            })

        candidates.sort(
            key=lambda c: (
                -c["score"],
                c.get("date_gap", 9999),
                c.get("amount_delta_milli", 999999999),
                c["ynab_ref"],
            )
        )

        best = candidates[0] if candidates else None
        second = candidates[1] if len(candidates) > 1 else None

        if not best:
            status_name = "bank_only"
            confidence = 0.0
            ynab_ref = ""
            evidence_list = ["no YNAB candidate met the minimum evidence threshold"]
        else:
            score = int(best["score"])
            confidence = reconciliation_confidence(score)
            ynab_ref = best["ynab_ref"]
            evidence_list = list(best["reasons"])

            exact_import = "exact YNAB import identifier" in evidence_list
            close_competitor = bool(second and (score - int(second["score"]) < 2))

            if close_competitor:
                status_name = "ambiguous"
                evidence_list.append("multiple YNAB candidates have similar evidence")
            elif exact_import or score >= 10:
                status_name = "matched"
            elif score >= 7:
                status_name = "probable_match"
            else:
                status_name = "ambiguous"

            claimed_ynab.setdefault(best["tx_id"], []).append(row["external_ref"])

        transfer = transfer_candidates.get(row["external_ref"])
        result_rows.append({
            "external_ref": row["external_ref"],
            "account": row["account"],
            "posted_date": row["posted_date"],
            "authorized_date": row["authorized_date"],
            "amount": row["amount"],
            "merchant": row["merchant"],
            "description": row["description"],
            "pending": False,
            "status": status_name,
            "confidence": confidence,
            "ynab_ref": ynab_ref,
            "candidate_ynab_refs": [c["ynab_ref"] for c in candidates[:3]],
            "evidence": evidence_list,
            "possible_transfer": bool(transfer),
            "transfer_candidate_external_ref": (
                transfer.get("candidate_external_ref", "") if transfer else ""
            ),
        })

    # If multiple external rows claim the same YNAB transaction, surface that
    # conflict explicitly rather than silently choosing one.
    conflicts = {
        tx_id: refs for tx_id, refs in claimed_ynab.items() if len(refs) > 1
    }
    if conflicts:
        conflict_refs = {ref for refs in conflicts.values() for ref in refs}
        for row in result_rows:
            if row["external_ref"] in conflict_refs and row["status"] != "pending":
                row["status"] = "possible_duplicate"
                row["confidence"] = min(row["confidence"], 0.75)
                row["evidence"].append(
                    "multiple external transactions point to the same YNAB transaction"
                )

    matched_ynab_ids = {
        store.resolve_uuid(row["ynab_ref"])
        for row in result_rows
        if row["ynab_ref"]
        and row["status"] in {"matched", "probable_match", "possible_duplicate"}
    }

    # Limit YNAB-only reporting to accounts and date span represented by posted
    # (non-pending) external data. This prevents an incomplete bank export from
    # making the entire YNAB history look unmatched.
    posted_rows = [r for r in normalized if not r["pending"]]
    ynab_only: List[Dict[str, Any]] = []
    if posted_rows:
        account_ids = {r["account_uuid"] for r in posted_rows}
        min_date = min(date.fromisoformat(r["posted_date"]) for r in posted_rows)
        max_date = max(date.fromisoformat(r["posted_date"]) for r in posted_rows)

        for tx_id, tx in store.transactions.items():
            tx_date = _safe_date(tx.get("date"))
            if (
                tx.get("account_id") not in account_ids
                or not tx_date
                or tx_date < min_date
                or tx_date > max_date
                or tx_id in matched_ynab_ids
            ):
                continue
            ynab_only.append({
                "ynab_ref": store.transaction_ref(tx_id),
                "date": tx.get("date"),
                "account": store.uuid_to_alias.get(
                    tx.get("account_id", ""), tx.get("account_name", "")
                ),
                "amount": milli_to_str(int(tx.get("amount", 0))),
                "payee": tx_display_payee(tx),
                "cleared": tx.get("cleared"),
                "approved": bool(tx.get("approved")),
            })

    counts: Dict[str, int] = {}
    for row in result_rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    counts["ynab_only"] = len(ynab_only)

    account_summaries: Dict[str, Dict[str, Any]] = {}
    for row in result_rows:
        summary = account_summaries.setdefault(
            row["account"],
            {
                "account": row["account"],
                "external_transaction_count": 0,
                "matched": 0,
                "probable_match": 0,
                "bank_only": 0,
                "ambiguous": 0,
                "possible_duplicate": 0,
                "pending": 0,
            },
        )
        summary["external_transaction_count"] += 1
        if row["status"] in summary:
            summary[row["status"]] += 1

    report = {
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "external_transaction_count": len(result_rows),
        "counts": counts,
        "accounts": sorted(account_summaries.values(), key=lambda x: x["account"]),
        "transactions": result_rows,
        "ynab_only": sorted(
            ynab_only,
            key=lambda x: (x["date"] or "", x["ynab_ref"]),
            reverse=True,
        ),
        "notes": [
            "No reconciliation result mutates YNAB.",
            "Confidence is a deterministic evidence indicator, not a statistical probability.",
            "Pending external transactions are never treated as posted matches.",
            "YNAB-only rows are limited to the accounts and posted-date span represented by the submitted external data.",
        ],
    }
    return report


def compact_reconciliation_report(
    report: Dict[str, Any],
    detail_limit: int = 25,
) -> Dict[str, Any]:
    """Return a compact API response while retaining the full report in memory."""
    transactions = report.get("transactions") or []
    ynab_only = report.get("ynab_only") or []

    attention = [row for row in transactions if row.get("status") != "matched"]
    attention.sort(
        key=lambda row: (row.get("posted_date") or "", row.get("external_ref") or ""),
        reverse=True,
    )
    ynab_only_sorted = sorted(
        ynab_only,
        key=lambda row: (row.get("date") or "", row.get("ynab_ref") or ""),
        reverse=True,
    )

    return {
        "source": report.get("source"),
        "generated_at": report.get("generated_at"),
        "read_only": report.get("read_only", True),
        "external_transaction_count": report.get(
            "external_transaction_count", len(transactions)
        ),
        "counts": report.get("counts", {}),
        "accounts": report.get("accounts", []),
        "attention_transaction_count": len(attention),
        "ynab_only_count": len(ynab_only),
        "attention_transactions": attention[:detail_limit],
        "ynab_only": ynab_only_sorted[:detail_limit],
        "detail_limit": detail_limit,
        "has_more_attention_transactions": len(attention) > detail_limit,
        "has_more_ynab_only": len(ynab_only) > detail_limit,
        "notes": report.get("notes", []),
    }


@app.post(
    "/reconciliation/transactions",
    summary="Read-only external transaction ingestion and YNAB reconciliation",
    operation_id="ingestExternalTransactions",
)
async def ingest_external_transactions(payload: ExternalTransactionBatch):
    await sync_ynab()
    report = reconcile_external_transactions(payload.source, payload.transactions)
    store.reconciliation_snapshot = report
    return compact_reconciliation_report(report, detail_limit=25)


@app.get(
    "/reconciliation/status",
    summary="Retrieve the most recent read-only reconciliation snapshot",
    operation_id="getReconciliationStatus",
)
async def get_reconciliation_status():
    if not store.reconciliation_snapshot:
        raise HTTPException(
            status_code=404,
            detail="No reconciliation snapshot is available; ingest external transactions first",
        )
    return compact_reconciliation_report(
        store.reconciliation_snapshot,
        detail_limit=25,
    )


# =====================================================================
# Plaid Read-Only Ingestion
# =====================================================================

class PlaidHostedLinkRequest(BaseModel):
    client_user_id: str = Field(
        "household",
        min_length=1,
        max_length=128,
        description="Stable non-sensitive identifier for this household",
    )


class PlaidLinkExchangeRequest(BaseModel):
    link_token: str = Field(
        ...,
        min_length=1,
        description="Hosted Link token returned by createPlaidHostedLink",
    )
    reveal_access_token: bool = Field(
        False,
        description=(
            "If true, return the newly created Item access_token once so it can "
            "be stored as a Railway secret. Do not expose this response publicly."
        ),
    )


def require_plaid_credentials() -> None:
    if not PLAID_CLIENT_ID or not PLAID_SECRET:
        raise HTTPException(
            status_code=503,
            detail="PLAID_CLIENT_ID and PLAID_SECRET must be configured in Railway",
        )


async def plaid_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    require_plaid_credentials()
    body = {
        "client_id": PLAID_CLIENT_ID,
        "secret": PLAID_SECRET,
        **payload,
    }
    async with httpx.AsyncClient(base_url=PLAID_BASE_URL, timeout=30.0) as client:
        response = await client.post(path, json=body)

    try:
        data = response.json()
    except ValueError:
        data = {}

    if response.status_code >= 400:
        error_code = data.get("error_code") or "PLAID_ERROR"
        error_message = data.get("error_message") or f"HTTP {response.status_code}"
        raise HTTPException(
            status_code=502,
            detail=f"Plaid {error_code}: {error_message}",
        )
    return data


async def refresh_plaid_account_balances(force: bool = False) -> Dict[str, dict]:
    """Refresh a compact cache of Plaid account balances.

    A Plaid balance read must never be required for ordinary YNAB reads to work.
    Callers that need graceful degradation should catch HTTPException.
    """
    access_token = store.plaid_access_token or PLAID_ACCESS_TOKEN
    if not access_token:
        raise HTTPException(status_code=409, detail="No Plaid Item access token is configured")

    now = time.time()
    if (
        not force
        and store.plaid_account_balances
        and now - store.plaid_balance_sync_time < 60
    ):
        return store.plaid_account_balances

    data = await plaid_post("/accounts/get", {"access_token": access_token})
    compact: Dict[str, dict] = {}
    for account in data.get("accounts", []):
        plaid_id = str(account.get("account_id") or "")
        if not plaid_id:
            continue
        balances = account.get("balances") or {}
        compact[plaid_id] = {
            "plaid_account_id": plaid_id,
            "name": account.get("name"),
            "official_name": account.get("official_name"),
            "type": account.get("type"),
            "subtype": account.get("subtype"),
            "mask": account.get("mask"),
            "ynab_account": PLAID_YNAB_ACCOUNT_MAP.get(plaid_id, ""),
            "mapped": plaid_id in PLAID_YNAB_ACCOUNT_MAP,
            "current": balances.get("current"),
            "available": balances.get("available"),
            "iso_currency_code": balances.get("iso_currency_code"),
        }

    store.plaid_account_balances = compact
    store.plaid_balance_sync_time = now
    return compact


def decimal_currency_to_milli(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(
            (Decimal(str(value)) * 1000).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        )
    except Exception:
        return None


async def primary_checking_balance_diagnostic(
    refresh_bank: bool = False,
) -> Dict[str, Any]:
    """Compare the mapped bank-side primary checking balance with YNAB."""
    checking_ids = get_primary_checking_ids()
    ynab_milli = sum(
        int(store.accounts[acct_id].get("balance", 0))
        for acct_id in checking_ids
    )

    result: Dict[str, Any] = {
        "ynab_balance": milli_to_str(ynab_milli),
        "bank_current_balance": None,
        "bank_available_balance": None,
        "difference_bank_minus_ynab": None,
        "bank_balance_available": False,
        "bank_balance_as_of": None,
        "mapped_plaid_accounts": 0,
    }

    if not checking_ids or not (store.plaid_access_token or PLAID_ACCESS_TOKEN):
        return result

    try:
        balances = await refresh_plaid_account_balances(force=refresh_bank)
    except HTTPException as exc:
        result["bank_balance_error"] = str(exc.detail)
        return result
    except Exception as exc:
        result["bank_balance_error"] = f"{type(exc).__name__}: {exc}"
        return result

    current_total = 0
    available_total = 0
    current_count = 0
    available_count = 0
    mapped_count = 0

    for plaid_id, row in balances.items():
        ynab_alias = PLAID_YNAB_ACCOUNT_MAP.get(plaid_id)
        if not ynab_alias:
            continue
        ynab_uuid = store.resolve_uuid(str(ynab_alias))
        if ynab_uuid not in checking_ids:
            continue

        mapped_count += 1
        current_milli = decimal_currency_to_milli(row.get("current"))
        available_milli = decimal_currency_to_milli(row.get("available"))
        if current_milli is not None:
            current_total += current_milli
            current_count += 1
        if available_milli is not None:
            available_total += available_milli
            available_count += 1

    result["mapped_plaid_accounts"] = mapped_count
    if current_count:
        result["bank_current_balance"] = milli_to_str(current_total)
        result["difference_bank_minus_ynab"] = milli_to_str(current_total - ynab_milli)
        result["bank_balance_available"] = True
    if available_count:
        result["bank_available_balance"] = milli_to_str(available_total)

    if store.plaid_balance_sync_time:
        result["bank_balance_as_of"] = datetime.fromtimestamp(
            store.plaid_balance_sync_time, tz=timezone.utc
        ).isoformat()

    return result


def plaid_amount_to_ynab_string(transaction: dict) -> str:
    """Plaid positive transaction amounts are typically money leaving the account.

    Convert into the middleware/YNAB convention: outflow negative, inflow positive.
    """
    amount = Decimal(str(transaction.get("amount", "0")))
    normalized = -amount
    return f"{normalized.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP):.2f}"


def plaid_account_alias(plaid_account_id: str) -> str:
    alias = PLAID_YNAB_ACCOUNT_MAP.get(plaid_account_id)
    if not alias:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Plaid account {plaid_account_id} has no YNAB mapping. "
                "Add it to PLAID_YNAB_ACCOUNT_MAP in Railway."
            ),
        )
    return str(alias)


def plaid_to_external_transaction(
    transaction: dict,
    ynab_account_alias: Optional[str] = None,
) -> ExternalTransaction:
    posted_date = transaction.get("date")
    if not posted_date:
        raise HTTPException(
            status_code=422,
            detail=f"Plaid transaction {transaction.get('transaction_id')} has no posted date",
        )

    plaid_account_id = str(transaction.get("account_id") or "")
    account_alias = ynab_account_alias or plaid_account_alias(plaid_account_id)

    return ExternalTransaction(
        external_id=str(transaction["transaction_id"]),
        account=account_alias,
        posted_date=date.fromisoformat(posted_date),
        authorized_date=(
            date.fromisoformat(transaction["authorized_date"])
            if transaction.get("authorized_date") else None
        ),
        amount=plaid_amount_to_ynab_string(transaction),
        merchant=transaction.get("merchant_name"),
        description=transaction.get("name"),
        pending=bool(transaction.get("pending", False)),
    )


@app.post(
    "/plaid/link/hosted",
    summary="Create a Plaid Hosted Link session",
    operation_id="createPlaidHostedLink",
)
async def create_plaid_hosted_link(payload: PlaidHostedLinkRequest):
    """Create a Plaid-hosted bank-linking URL; no custom frontend is required."""
    data = await plaid_post(
        "/link/token/create",
        {
            "user": {"client_user_id": payload.client_user_id},
            "client_name": "YNAB Budget Copilot",
            "products": ["transactions"],
            "country_codes": ["US"],
            "language": "en",
            "transactions": {"days_requested": PLAID_DAYS_REQUESTED},
            "hosted_link": {},
        },
    )
    return {
        "link_token": data.get("link_token"),
        "hosted_link_url": data.get("hosted_link_url"),
        "expiration": data.get("expiration"),
        "environment": PLAID_ENV,
    }


@app.post(
    "/plaid/link/exchange",
    summary="Exchange a completed Hosted Link session for a Plaid Item",
    operation_id="exchangePlaidHostedLink",
)
async def exchange_plaid_hosted_link(payload: PlaidLinkExchangeRequest):
    """Resolve a completed Hosted Link session and exchange its public token.

    The access token is retained in runtime memory for immediate testing. For
    durable production use, save it as PLAID_ACCESS_TOKEN in Railway (or a
    secret-capable database). It is returned only when reveal_access_token=true.
    """
    session = await plaid_post(
        "/link/token/get",
        {"link_token": payload.link_token},
    )

    # Current Plaid Hosted Link responses expose Item-add results per Link
    # session at link_sessions[].results.item_add_results[].public_token.
    # Retain legacy fallbacks for compatibility with older response shapes.
    public_tokens: List[str] = []

    def add_public_token(value: Any) -> None:
        if isinstance(value, str) and value and value not in public_tokens:
            public_tokens.append(value)

    link_sessions = session.get("link_sessions") or []
    if isinstance(link_sessions, list):
        for link_session in link_sessions:
            if not isinstance(link_session, dict):
                continue
            results = link_session.get("results") or {}
            if not isinstance(results, dict):
                continue
            item_add_results = results.get("item_add_results") or []
            if isinstance(item_add_results, list):
                for item_result in item_add_results:
                    if isinstance(item_result, dict):
                        add_public_token(item_result.get("public_token"))

    # Compatibility: accept top-level results shapes as well.
    results = session.get("results") or {}
    if isinstance(results, dict):
        item_add_results = results.get("item_add_results") or []
        if isinstance(item_add_results, list):
            for item_result in item_add_results:
                if isinstance(item_result, dict):
                    add_public_token(item_result.get("public_token"))

        legacy_tokens = results.get("public_tokens") or []
        if isinstance(legacy_tokens, list):
            for token in legacy_tokens:
                add_public_token(token)

    on_success = session.get("on_success") or {}
    if isinstance(on_success, dict):
        add_public_token(on_success.get("public_token"))

    if not public_tokens:
        session_count = len(link_sessions) if isinstance(link_sessions, list) else 0
        raise HTTPException(
            status_code=409,
            detail=(
                "Hosted Link completed but no Item public_token was found in the "
                "Plaid /link/token/get response. Checked "
                "link_sessions[].results.item_add_results[], top-level "
                "results.item_add_results[], legacy results.public_tokens, and "
                f"on_success.public_token. link_session_count={session_count}"
            ),
        )
    if len(public_tokens) != 1:
        raise HTTPException(
            status_code=422,
            detail=(
                "This middleware currently expects one Plaid Item per Hosted Link "
                "session. Create separate sessions for additional institutions."
            ),
        )

    exchanged = await plaid_post(
        "/item/public_token/exchange",
        {"public_token": public_tokens[0]},
    )
    access_token = exchanged.get("access_token") or ""
    item_id = exchanged.get("item_id") or ""
    if not access_token or not item_id:
        raise HTTPException(status_code=502, detail="Plaid token exchange returned incomplete data")

    store.plaid_access_token = access_token
    store.plaid_item_id = item_id
    store.plaid_cursor = None
    store.plaid_transactions = {}

    response = {
        "connected": True,
        "item_id": item_id,
        "access_token_configured_in_runtime": True,
        "next_step": (
            "Persist the Item access token securely as PLAID_ACCESS_TOKEN in Railway, "
            "then configure PLAID_YNAB_ACCOUNT_MAP."
        ),
    }
    if payload.reveal_access_token:
        response["access_token"] = access_token
        response["security_warning"] = (
            "Treat access_token as a password. Store it in Railway Variables and do not "
            "put it in source code, CustomGPT instructions, or chat history."
        )
    return response


@app.get(
    "/plaid/accounts",
    summary="List Plaid accounts for YNAB account mapping",
    operation_id="getPlaidAccounts",
)
async def get_plaid_accounts():
    balances = await refresh_plaid_account_balances(force=True)
    accounts = list(balances.values())
    accounts.sort(key=lambda row: ((row.get("name") or "").lower(), row["plaid_account_id"]))
    return {
        "item_id": store.plaid_item_id or PLAID_ITEM_ID,
        "balance_as_of": datetime.fromtimestamp(
            store.plaid_balance_sync_time, tz=timezone.utc
        ).isoformat() if store.plaid_balance_sync_time else None,
        "accounts": accounts,
    }



@app.post(
    "/plaid/sync",
    summary="Sync Plaid Transactions and run read-only YNAB reconciliation",
    operation_id="syncPlaidTransactions",
)
async def sync_plaid_transactions():
    await sync_ynab()
    access_token = store.plaid_access_token or PLAID_ACCESS_TOKEN
    if not access_token:
        raise HTTPException(
            status_code=409,
            detail="No Plaid access token configured; complete Plaid Link first",
        )

    cursor = store.plaid_cursor
    added_count = modified_count = removed_count = 0

    # Plaid requires repeating /transactions/sync while has_more is true.
    # MODIFIED/REMOVED updates are applied to a local read-only cache before
    # reconciliation so the current external snapshot is internally consistent.
    for _ in range(100):
        request_body: Dict[str, Any] = {
            "access_token": access_token,
            "count": 500,
        }
        if cursor:
            request_body["cursor"] = cursor

        page = await plaid_post("/transactions/sync", request_body)

        for tx in page.get("added", []):
            tx_id = str(tx["transaction_id"])
            store.plaid_transactions[tx_id] = tx
            added_count += 1

        for tx in page.get("modified", []):
            tx_id = str(tx["transaction_id"])
            store.plaid_transactions[tx_id] = tx
            modified_count += 1

        for removed in page.get("removed", []):
            tx_id = str(removed.get("transaction_id") or "")
            if tx_id:
                store.plaid_transactions.pop(tx_id, None)
                removed_count += 1

        cursor = page.get("next_cursor") or cursor
        if not page.get("has_more", False):
            break
    else:
        raise HTTPException(
            status_code=502,
            detail="Plaid transaction sync exceeded 100 pages",
        )

    store.plaid_cursor = cursor

    # Refresh mapped account balances after transaction sync. This is a small
    # response and gives downstream affordability logic a bank-side starting point.
    await refresh_plaid_account_balances(force=True)

    mapped_account_ids = set(PLAID_YNAB_ACCOUNT_MAP.keys())
    mapped_transactions = []
    skipped_unmapped_account_ids = set()
    skipped_unmapped_transaction_count = 0

    for tx in store.plaid_transactions.values():
        plaid_account_id = str(tx.get("account_id") or "")
        if plaid_account_id not in mapped_account_ids:
            if plaid_account_id:
                skipped_unmapped_account_ids.add(plaid_account_id)
            skipped_unmapped_transaction_count += 1
            continue
        mapped_transactions.append(tx)

    # Pass the already-validated YNAB alias explicitly. This makes the mapped
    # account boundary authoritative here and prevents an unmapped Plaid account
    # from reaching plaid_account_alias() during reconciliation.
    external_transactions = [
        plaid_to_external_transaction(
            tx,
            ynab_account_alias=str(
                PLAID_YNAB_ACCOUNT_MAP[str(tx.get("account_id") or "")]
            ),
        )
        for tx in mapped_transactions
    ]

    if not external_transactions:
        report = {
            "source": "plaid",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "read_only": True,
            "external_transaction_count": 0,
            "counts": {"ynab_only": 0},
            "accounts": [],
            "transactions": [],
            "ynab_only": [],
            "notes": [
                "No mapped Plaid transactions were available for reconciliation.",
                "Unmapped Plaid accounts were skipped and did not cause sync failure.",
                "No reconciliation result mutates YNAB.",
            ],
        }
    else:
        report = reconcile_external_transactions("plaid", external_transactions)

    store.reconciliation_snapshot = report
    balance_diagnostic = await primary_checking_balance_diagnostic(refresh_bank=False)

    return {
        "plaid_sync": {
            "added": added_count,
            "modified": modified_count,
            "removed": removed_count,
            "cached_transaction_count": len(store.plaid_transactions),
            "mapped_transaction_count": len(mapped_transactions),
            "skipped_unmapped_transaction_count": skipped_unmapped_transaction_count,
            "skipped_unmapped_account_ids": sorted(skipped_unmapped_account_ids),
            "mapped_account_ids": sorted(mapped_account_ids),
            "cursor_present": bool(store.plaid_cursor),
        },
        "primary_checking_balance": balance_diagnostic,
        "reconciliation": compact_reconciliation_report(
            report,
            detail_limit=25,
        ),
    }


# =====================================================================
# Forecasting & Reallocation Helpers
# =====================================================================

DEFAULT_REALLOCATION_PRIORITY = [
    "discretionary",
    "flexible_essential",
    "true_expense",
    "savings",
    "unclassified",
]
DEFAULT_PROTECTED_REALLOCATION_CLASSES = {
    "essential",
    "debt",
    "credit_card_payment",
    "business",
    "internal",
}


def reallocation_policy(policy: Dict[str, Any]) -> tuple[List[str], set[str]]:
    priority = policy.get("reallocation_priority")
    if not isinstance(priority, list) or not priority:
        priority = DEFAULT_REALLOCATION_PRIORITY

    protected = policy.get("protected_reallocation_classes")
    if not isinstance(protected, list):
        protected_set = set(DEFAULT_PROTECTED_REALLOCATION_CLASSES)
    else:
        protected_set = {str(x) for x in protected}

    return [str(x) for x in priority], protected_set


def transfer_payee_id_for_account(account_id: str) -> Optional[str]:
    """Return YNAB's special transfer payee for a target account, if present."""
    for payee_id, payee in store.payees.items():
        if payee.get("transfer_account_id") == account_id and not payee.get("deleted", False):
            return payee_id
    return None


def credit_card_account_ids() -> set[str]:
    return {
        acct_id
        for acct_id, acct in store.accounts.items()
        if not acct.get("closed")
        and str(acct.get("type") or "").lower() == "creditcard"
        and bool(acct.get("on_budget", True))
    }


def scheduled_event_payload(stx_id: str, stx: dict, event_type: str) -> dict:
    return {
        "ref": store.scheduled_ref(stx_id),
        "date": stx.get("date_next"),
        "payee": stx.get("payee_name") or "Scheduled transaction",
        "account": store.uuid_to_alias.get(
            stx.get("account_id", ""), stx.get("account_name", "")
        ),
        "amount_milli": int(stx.get("amount", 0)),
        "frequency": stx.get("frequency") or "never",
        "event_type": event_type,
    }


def add_months(d: date, months: int) -> date:
    """Advance a date by whole calendar months without overflowing month-end."""
    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    day = min(d.day, monthrange(year, month)[1])
    return date(year, month, day)


def next_scheduled_date(current: date, frequency: str) -> Optional[date]:
    """Return the next occurrence for recurrence values emitted by YNAB.

    Unknown recurrence values deliberately return None so the forecast can
    report incomplete coverage instead of inventing dates.
    """
    normalized = normalize_text(frequency).replace(" ", "")

    if normalized == "never":
        return None
    if normalized == "daily":
        return current + timedelta(days=1)
    if normalized == "weekly":
        return current + timedelta(weeks=1)
    if normalized in {"everyotherweek", "every2weeks"}:
        return current + timedelta(weeks=2)
    if normalized == "every4weeks":
        return current + timedelta(weeks=4)
    if normalized == "monthly":
        return add_months(current, 1)
    if normalized in {"everyothermonth", "every2months"}:
        return add_months(current, 2)
    if normalized == "every3months":
        return add_months(current, 3)
    if normalized == "every4months":
        return add_months(current, 4)
    if normalized in {"twiceayear", "every6months"}:
        return add_months(current, 6)
    if normalized == "yearly":
        return add_months(current, 12)
    if normalized == "everyotheryear":
        return add_months(current, 24)

    # twiceAMonth and any future/unknown YNAB frequency require explicit
    # semantics before they should be synthesized.
    return None


def expand_scheduled_transaction(
    stx_id: str,
    stx: dict,
    start_date: date,
    end_date: date,
    event_type: str,
) -> tuple[List[dict], Optional[str]]:
    """Expand one scheduled transaction through the requested forecast window.

    Returns (events, coverage_issue). A coverage issue is surfaced rather than
    silently guessing when recurrence data is missing or unsupported.
    """
    raw_next = stx.get("date_next")
    if not raw_next:
        return [], "missing_date_next"

    try:
        occurrence = date.fromisoformat(raw_next)
    except (TypeError, ValueError):
        return [], "invalid_date_next"

    frequency = str(stx.get("frequency") or "never")
    normalized_frequency = normalize_text(frequency).replace(" ", "")
    events: List[dict] = []
    max_occurrences = 500

    for occurrence_index in range(max_occurrences):
        if occurrence > end_date:
            break

        if occurrence >= start_date:
            event = scheduled_event_payload(stx_id, stx, event_type)
            event["date"] = occurrence.isoformat()
            event["occurrence_index"] = occurrence_index
            events.append(event)

        next_date = next_scheduled_date(occurrence, frequency)

        if next_date is None:
            if normalized_frequency == "never":
                break
            return events, f"unsupported_frequency:{frequency}"

        if next_date <= occurrence:
            return events, f"non_advancing_frequency:{frequency}"

        occurrence = next_date
    else:
        return events, "occurrence_limit_exceeded"

    return events, None


def build_reallocation_plan(
    target_category: str,
    amount_milli: Optional[int] = None,
    include_protected: bool = False,
) -> Dict[str, Any]:
    policy = load_policy()
    month_cats = current_month_categories()
    target_uuid = store.resolve_uuid(target_category)
    target = month_cats.get(target_uuid)
    if not target:
        raise HTTPException(status_code=404, detail=f"Category {target_category} not found")

    target_alias = category_alias(target_uuid)
    target_available = int(target.get("balance", 0))
    if amount_milli is None:
        if target_available >= 0:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"{target_alias} is not overspent; provide an explicit amount "
                    "to plan a proactive reallocation"
                ),
            )
        amount_milli = abs(target_available)

    if amount_milli <= 0:
        raise HTTPException(status_code=422, detail="Reallocation amount must be positive")

    priority, protected_classes = reallocation_policy(policy)
    rank = {cls: i for i, cls in enumerate(priority)}
    candidates = []

    for cat_id, cat in month_cats.items():
        if cat_id == target_uuid:
            continue
        available = int(cat.get("balance", 0))
        if available <= 0:
            continue

        alias = category_alias(cat_id)
        cls = policy_class_for(alias, policy)
        if cls == "internal":
            continue
        if cls in protected_classes and not include_protected:
            continue

        # A category that is currently underfunded against its YNAB goal is a
        # weaker donor than one with surplus beyond its goal requirement.
        goal_under_funded = int(cat.get("goal_under_funded") or 0)
        goal_warning = goal_under_funded > 0

        candidates.append({
            "category": alias,
            "name": cat.get("name") or alias,
            "class": cls,
            "available_milli": available,
            "goal_under_funded_milli": goal_under_funded,
            "goal_warning": goal_warning,
            "rank": rank.get(cls, len(rank) + 10),
        })

    candidates.sort(
        key=lambda x: (
            x["rank"],
            x["goal_warning"],  # prefer fully funded categories
            -x["available_milli"],
            x["name"].lower(),
        )
    )

    remaining = amount_milli
    plan = []
    for row in candidates:
        if remaining <= 0:
            break
        take = min(row["available_milli"], remaining)
        if take <= 0:
            continue
        plan.append({
            "category": row["category"],
            "name": row["name"],
            "class": row["class"],
            "available_before": milli_to_str(row["available_milli"]),
            "recommended_subtract": milli_to_str(take),
            "available_after": milli_to_str(row["available_milli"] - take),
            "goal_under_funded": milli_to_str(row["goal_under_funded_milli"]),
            "warnings": (
                ["category is currently underfunded against its YNAB goal"]
                if row["goal_warning"] else []
            ),
        })
        remaining -= take

    return {
        "target_category": target_alias,
        "target_name": target.get("name") or target_alias,
        "target_class": policy_class_for(target_alias, policy),
        "target_available_before": milli_to_str(target_available),
        "amount_requested": milli_to_str(amount_milli),
        "fully_funded": remaining == 0,
        "shortfall": milli_to_str(remaining),
        "target_available_after": milli_to_str(target_available + (amount_milli - remaining)),
        "include_protected": include_protected,
        "protected_classes": sorted(protected_classes),
        "sources": plan,
        "assignment_changes": (
            [
                {
                    "category": p["category"],
                    "operation": "subtract",
                    "amount": p["recommended_subtract"],
                }
                for p in plan
            ]
            + (
                [{
                    "category": target_alias,
                    "operation": "add",
                    "amount": milli_to_str(amount_milli - remaining),
                }]
                if amount_milli - remaining > 0 else []
            )
        ),
    }


# =====================================================================
# Read Models
# =====================================================================

@app.get(
    "/health/middleware",
    summary="Compact YNAB/Plaid/middleware capability diagnostics",
    operation_id="getMiddlewareHealth",
)
async def get_middleware_health():
    """Return non-secret operational diagnostics for this Custom GPT."""
    ynab_ok = True
    ynab_error = None
    try:
        await sync_ynab()
    except Exception as exc:
        ynab_ok = False
        ynab_error = f"{type(exc).__name__}: {exc}"

    balance_diagnostic: Dict[str, Any] = {}
    plaid_ok = bool(store.plaid_access_token or PLAID_ACCESS_TOKEN)
    plaid_error = None
    if plaid_ok and ynab_ok:
        try:
            balance_diagnostic = await primary_checking_balance_diagnostic(
                refresh_bank=True
            )
        except Exception as exc:
            plaid_ok = False
            plaid_error = f"{type(exc).__name__}: {exc}"

    snapshot = store.reconciliation_snapshot or {}
    reconciliation_available = bool(snapshot)
    reconciliation_generated_at = snapshot.get("generated_at")

    mapped_accounts = len(PLAID_YNAB_ACCOUNT_MAP)
    primary_checking_ids = get_primary_checking_ids() if ynab_ok else set()

    checks = {
        "ynab_read": ynab_ok,
        "plaid_configured": bool(store.plaid_access_token or PLAID_ACCESS_TOKEN),
        "plaid_read": plaid_ok,
        "plaid_mapping_present": mapped_accounts > 0,
        "primary_checking_found": bool(primary_checking_ids),
        "bank_balance_available": bool(
            balance_diagnostic.get("bank_balance_available")
        ),
        "reconciliation_snapshot_available": reconciliation_available,
        "guarded_writes_enabled": True,
    }
    healthy = all(
        checks[name]
        for name in (
            "ynab_read",
            "plaid_configured",
            "plaid_read",
            "plaid_mapping_present",
            "primary_checking_found",
            "bank_balance_available",
            "guarded_writes_enabled",
        )
    )

    return {
        "service": "YNAB Copilot Middleware",
        "version": app.version,
        "healthy": healthy,
        "checks": checks,
        "ynab_error": ynab_error,
        "plaid_error": plaid_error,
        "mapped_plaid_account_count": mapped_accounts,
        "primary_checking_balance": balance_diagnostic,
        "reconciliation": {
            "available": reconciliation_available,
            "generated_at": reconciliation_generated_at,
            "counts": snapshot.get("counts", {}) if snapshot else {},
        },
        "cache": {
            "ynab_last_sync_utc": (
                datetime.fromtimestamp(
                    store.last_sync_time, tz=timezone.utc
                ).isoformat()
                if store.last_sync_time else None
            ),
            "plaid_balance_last_sync_utc": (
                datetime.fromtimestamp(
                    store.plaid_balance_sync_time, tz=timezone.utc
                ).isoformat()
                if store.plaid_balance_sync_time else None
            ),
            "plaid_cached_transaction_count": len(store.plaid_transactions),
        },
        "write_safety": {
            "direct_ynab_writes_exposed": False,
            "proposal_required": True,
            "explicit_commit_required": True,
        },
    }


@app.get("/", summary="Health check", operation_id="rootHealth")
async def root():
    return {
        "status": "online",
        "service": "YNAB Copilot Middleware",
        "version": app.version,
    }


@app.get(
    "/healthz",
    summary="Unauthenticated deployment connectivity check",
    operation_id="getPublicHealth",
)
async def public_health():
    """Small public probe used only to verify deployment and Action routing."""
    return {
        "status": "online",
        "service": "YNAB Copilot Middleware",
        "version": app.version,
        "public_base_url": PUBLIC_BASE_URL,
        "authenticated_budget_endpoints": True,
    }


@app.get(
    "/ynab/current-context",
    summary="Household budget state in a single payload",
    operation_id="getCurrentContext",
)
async def get_current_context():
    await sync_ynab()
    today = local_today()
    month_cats = current_month_categories()
    policy = load_policy()

    rta_milli = int(store.current_month_detail.get("to_be_budgeted", 0))

    checking_balance_milli = sum(
        int(acct.get("balance", 0))
        for acct_id, acct in store.accounts.items()
        if acct_id in get_primary_checking_ids()
    )
    above_floor_milli = checking_balance_milli - CHECKING_FLOOR_MILLI
    balance_diagnostic = await primary_checking_balance_diagnostic(refresh_bank=False)

    bank_current_milli = (
        str_to_milli(balance_diagnostic["bank_current_balance"])
        if balance_diagnostic.get("bank_current_balance") is not None
        else None
    )
    bank_available_milli = (
        str_to_milli(balance_diagnostic["bank_available_balance"])
        if balance_diagnostic.get("bank_available_balance") is not None
        else None
    )
    conservative_bank_milli = (
        bank_available_milli
        if bank_available_milli is not None
        else bank_current_milli
    )
    bank_above_floor_milli = (
        bank_current_milli - CHECKING_FLOOR_MILLI
        if bank_current_milli is not None else None
    )
    conservative_above_floor_milli = (
        conservative_bank_milli - CHECKING_FLOOR_MILLI
        if conservative_bank_milli is not None else None
    )

    overspent = []
    overspent_total_milli = 0
    overspent_by_class_milli: Dict[str, int] = {}

    for cat_id, cat in month_cats.items():
        balance_milli = int(cat.get("balance", 0))
        if balance_milli >= 0:
            continue

        alias = category_alias(cat_id)
        cls = policy_class_for(alias, policy)

        # Internal YNAB bookkeeping categories should not inflate the household
        # overspending total used for funding/reallocation decisions.
        if cls == "internal":
            continue

        overspent_total_milli += abs(balance_milli)
        overspent_by_class_milli[cls] = (
            overspent_by_class_milli.get(cls, 0) + abs(balance_milli)
        )
        overspent.append({
            "category": alias,
            "class": cls,
            "available": milli_to_str(balance_milli),
        })

    overspent.sort(key=lambda row: Decimal(row["available"]))

    limit_14d = today + timedelta(days=14)
    scheduled_items_14d = []

    for stx_id, stx in store.scheduled_transactions.items():
        raw_date = stx.get("date_next")
        if not raw_date:
            continue
        tx_date = date.fromisoformat(raw_date)
        if not (today <= tx_date <= limit_14d):
            continue

        amount_milli = int(stx.get("amount", 0))
        direction = "inflow" if amount_milli > 0 else "outflow" if amount_milli < 0 else "zero"

        cat_id = stx.get("category_id")
        cat = month_cats.get(cat_id) if cat_id else None
        funded_status = "not_applicable" if direction == "inflow" else "unassigned"

        if direction == "outflow" and cat:
            cat_available = int(cat.get("balance", 0))
            obligation = abs(amount_milli)
            if cat_available >= obligation:
                funded_status = "fully_funded"
            elif cat_available > 0:
                funded_status = "partially_funded"
            else:
                funded_status = "unfunded"

        scheduled_items_14d.append({
            "ref": store.scheduled_ref(stx_id),
            "date": raw_date,
            "direction": direction,
            "account": store.uuid_to_alias.get(
                stx.get("account_id", ""), stx.get("account_name", "")
            ),
            "payee": stx.get("payee_name") or "Scheduled transaction",
            "amount": milli_to_str(amount_milli),
            "category": category_alias(cat_id),
            "funded_status": funded_status,
        })

    scheduled_items_14d.sort(key=lambda x: (x["date"], x["ref"]))
    scheduled_inflows_14d = [x for x in scheduled_items_14d if x["direction"] == "inflow"]
    scheduled_outflows_14d = [x for x in scheduled_items_14d if x["direction"] == "outflow"]

    return {
        "as_of": today.isoformat(),
        "ready_to_assign": milli_to_str(rta_milli),
        "checking": {
            # Backward-compatible YNAB values.
            "balance": milli_to_str(checking_balance_milli),
            "ynab_balance": milli_to_str(checking_balance_milli),
            "floor": milli_to_str(CHECKING_FLOOR_MILLI),
            "above_floor": milli_to_str(above_floor_milli),
            "floor_breached": above_floor_milli < 0,

            # Bank-side truth when Plaid is available.
            "bank_current_balance": balance_diagnostic.get("bank_current_balance"),
            "bank_available_balance": balance_diagnostic.get("bank_available_balance"),
            "bank_above_floor": (
                milli_to_str(bank_above_floor_milli)
                if bank_above_floor_milli is not None else None
            ),
            "bank_floor_breached": (
                bank_above_floor_milli < 0
                if bank_above_floor_milli is not None else None
            ),
            "difference_bank_minus_ynab": balance_diagnostic.get(
                "difference_bank_minus_ynab"
            ),
            "bank_balance_as_of": balance_diagnostic.get("bank_balance_as_of"),
            "conservative_liquidity_balance": (
                milli_to_str(conservative_bank_milli)
                if conservative_bank_milli is not None
                else milli_to_str(checking_balance_milli)
            ),
            "conservative_above_floor": (
                milli_to_str(conservative_above_floor_milli)
                if conservative_above_floor_milli is not None
                else milli_to_str(above_floor_milli)
            ),
            "conservative_floor_breached": (
                conservative_above_floor_milli < 0
                if conservative_above_floor_milli is not None
                else above_floor_milli < 0
            ),
            "balance_source_for_affordability": (
                "plaid_available"
                if bank_available_milli is not None
                else (
                    "plaid_current"
                    if bank_current_milli is not None
                    else "ynab"
                )
            ),
        },
        "overspent_category_count": len(overspent),
        "overspent_total": milli_to_str(overspent_total_milli),
        "overspent_by_class": {
            cls: milli_to_str(amount)
            for cls, amount in sorted(overspent_by_class_milli.items())
        },
        "overspent_categories": overspent,
        "scheduled_inflows_14d": scheduled_inflows_14d,
        "scheduled_outflows_14d": scheduled_outflows_14d,
        "scheduled_items_14d": scheduled_items_14d,
        # Backward-compatible name, now correctly limited to actual outflows.
        "upcoming_obligations_14d": scheduled_outflows_14d,
    }


@app.get(
    "/ynab/envelopes",
    summary="Current-month envelope balances and policy classes",
    operation_id="getEnvelopeStatus",
)
async def get_envelope_status(
    include_zero: bool = Query(True),
    include_internal: bool = Query(False),
    class_filter: Optional[str] = Query(None, alias="class"),
):
    await sync_ynab()
    policy = load_policy()
    rows = []

    group_names = {
        gid: (group.get("name") or "")
        for gid, group in store.category_groups.items()
    }

    overspent_total_milli = 0
    overspent_count = 0

    for cat_id, cat in current_month_categories().items():
        alias = category_alias(cat_id)
        cls = policy_class_for(alias, policy)

        if cls == "internal" and not include_internal:
            continue

        assigned = int(cat.get("budgeted", 0))
        activity = int(cat.get("activity", 0))
        available = int(cat.get("balance", 0))

        if not include_zero and assigned == 0 and activity == 0 and available == 0:
            continue
        if class_filter and cls != class_filter:
            continue

        if available < 0:
            overspent_count += 1
            overspent_total_milli += abs(available)

        rows.append({
            "category": alias,
            "name": cat.get("name"),
            "group": cat.get("category_group_name")
            or group_names.get(cat.get("category_group_id"), ""),
            "class": cls,
            "assigned": milli_to_str(assigned),
            "activity": milli_to_str(activity),
            "available": milli_to_str(available),
            "is_overspent": available < 0,
            "goal_type": cat.get("goal_type"),
            "goal_target": (
                milli_to_str(int(cat.get("goal_target", 0)))
                if cat.get("goal_target") is not None else None
            ),
            "goal_under_funded": (
                milli_to_str(int(cat.get("goal_under_funded", 0)))
                if cat.get("goal_under_funded") is not None else None
            ),
            "goal_snoozed_at": cat.get("goal_snoozed_at"),
        })

    rows.sort(key=lambda x: (x["class"], x["group"] or "", x["name"] or ""))
    return {
        "month": store.current_month_detail.get("month"),
        "ready_to_assign": milli_to_str(
            int(store.current_month_detail.get("to_be_budgeted", 0))
        ),
        "count": len(rows),
        "overspent_category_count": overspent_count,
        "overspent_total": milli_to_str(overspent_total_milli),
        "include_internal": include_internal,
        "categories": rows,
    }


@app.get(
    "/ynab/triage",
    summary="Actionable transaction triage with payee/import/transfer/duplicate evidence",
    operation_id="getTriage",
)
async def get_triage(
    format: Literal["csv", "json"] = "json",
    status_filter: Literal[
        "actionable",
        "needs_category",
        "needs_approval_only",
        "possible_transfer",
        "possible_duplicate",
        "unapproved",
        "uncategorized",
        "all",
    ] = Query("actionable", alias="status"),
    limit: int = Query(50, ge=1, le=100),
    since_days: int = Query(45, ge=1, le=HISTORY_DAYS),
    account: Optional[str] = Query(None),
):
    await sync_ynab()
    cutoff = (local_today() - timedelta(days=since_days)).isoformat()
    account_uuid = store.resolve_uuid(account) if account else None

    scoped_transactions = {
        tx_id: tx
        for tx_id, tx in store.transactions.items()
        if (tx.get("date") or "") >= cutoff
        and (not account_uuid or tx.get("account_id") == account_uuid)
    }

    # Transfer candidates must inspect transactions across accounts, so use the
    # full date-scoped set rather than the account-filtered subset.
    date_scoped_all = {
        tx_id: tx
        for tx_id, tx in store.transactions.items()
        if (tx.get("date") or "") >= cutoff
    }
    transfer_candidates = build_transfer_candidate_map(date_scoped_all)
    duplicate_candidates = build_duplicate_candidate_map(date_scoped_all)

    rows = []
    for tx_id, tx in scoped_transactions.items():
        is_transfer = tx_is_transfer(tx)
        is_split = bool(tx.get("subtransactions"))
        raw_needs_category = not tx.get("category_id") and not is_transfer and not is_split
        needs_approval = not bool(tx.get("approved"))

        transfer_candidate = transfer_candidates.get(tx_id)
        duplicate_candidate = duplicate_candidates.get(tx_id)
        possible_transfer = bool(transfer_candidate) and not is_transfer
        possible_duplicate = bool(duplicate_candidate)

        # Do not encourage categorization while a more fundamental transfer/
        # duplicate question is unresolved.
        needs_category = (
            raw_needs_category
            and not possible_transfer
            and not possible_duplicate
        )
        needs_approval_only = (
            needs_approval
            and not raw_needs_category
            and not possible_transfer
            and not possible_duplicate
        )

        if possible_duplicate:
            action_type = "possible_duplicate"
        elif possible_transfer:
            action_type = "possible_transfer"
        elif needs_category:
            action_type = "needs_category"
        elif needs_approval_only:
            action_type = "needs_approval_only"
        elif needs_approval:
            action_type = "needs_approval"
        else:
            action_type = "none"

        actionable = (
            possible_duplicate
            or possible_transfer
            or raw_needs_category
            or needs_approval
        )

        if status_filter == "actionable" and not actionable:
            continue
        if status_filter == "needs_category" and not needs_category:
            continue
        if status_filter == "needs_approval_only" and not needs_approval_only:
            continue
        if status_filter == "possible_transfer" and not possible_transfer:
            continue
        if status_filter == "possible_duplicate" and not possible_duplicate:
            continue
        if status_filter == "unapproved" and not needs_approval:
            continue
        if status_filter == "uncategorized" and not raw_needs_category:
            continue

        transfer_account_id = tx.get("transfer_account_id")
        matched_id = tx.get("matched_transaction_id")

        rows.append({
            "ref": store.transaction_ref(tx_id),
            "date": tx.get("date"),
            "account": store.uuid_to_alias.get(
                tx.get("account_id", ""), tx.get("account_name", "")
            ),
            "display_payee": tx_display_payee(tx),
            "payee": tx.get("payee_name"),
            "import_payee": tx.get("import_payee_name"),
            "original_payee": tx.get("import_payee_name_original"),
            "amount": milli_to_str(int(tx.get("amount", 0))),
            "cleared": tx.get("cleared"),
            "approved": bool(tx.get("approved")),
            "category": category_alias(tx.get("category_id")),
            "memo": tx.get("memo") or "",
            "action_type": action_type,
            "needs_category": needs_category,
            "needs_approval": needs_approval,
            "needs_approval_only": needs_approval_only,
            "is_transfer": is_transfer,
            "transfer_account": (
                store.uuid_to_alias.get(transfer_account_id, "")
                if transfer_account_id else ""
            ),
            "possible_transfer": possible_transfer,
            "transfer_candidate_ref": (
                transfer_candidate["candidate_ref"] if transfer_candidate else ""
            ),
            "transfer_candidate_reason": (
                transfer_candidate["reason"] if transfer_candidate else ""
            ),
            "possible_duplicate": possible_duplicate,
            "duplicate_candidate_ref": (
                duplicate_candidate["candidate_ref"] if duplicate_candidate else ""
            ),
            "duplicate_candidate_reason": (
                duplicate_candidate["reason"] if duplicate_candidate else ""
            ),
            "duplicate_amount_difference": (
                duplicate_candidate["amount_difference"] if duplicate_candidate else ""
            ),
            "is_imported": bool(tx.get("import_id")),
            "is_matched": bool(matched_id),
            "matched_ref": (
                store.transaction_ref(matched_id)
                if matched_id and matched_id in store.transactions else ""
            ),
            "is_split": is_split,
            "debt_transaction_type": tx.get("debt_transaction_type"),
        })

    action_rank = {
        "possible_duplicate": 0,
        "possible_transfer": 1,
        "needs_category": 2,
        "needs_approval_only": 3,
        "needs_approval": 4,
        "none": 5,
    }
    rows.sort(
        key=lambda r: (
            action_rank.get(r["action_type"], 9),
            -(date.fromisoformat(r["date"]).toordinal() if r["date"] else 0),
            r["ref"],
        )
    )
    rows = rows[:limit]

    if format == "json":
        return {
            "count": len(rows),
            "status_filter": status_filter,
            "transactions": rows,
        }

    fieldnames = list(rows[0].keys()) if rows else [
        "ref", "date", "account", "display_payee", "payee", "import_payee",
        "original_payee", "amount", "cleared", "approved", "category", "memo",
        "action_type", "needs_category", "needs_approval", "needs_approval_only",
        "is_transfer", "transfer_account", "possible_transfer",
        "transfer_candidate_ref", "transfer_candidate_reason",
        "possible_duplicate", "duplicate_candidate_ref",
        "duplicate_candidate_reason", "duplicate_amount_difference",
        "is_imported", "is_matched", "matched_ref", "is_split",
        "debt_transaction_type",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


class TriageQueryRequest(BaseModel):
    format: Literal["csv", "json"] = "json"
    status: Literal[
        "actionable",
        "needs_category",
        "needs_approval_only",
        "possible_transfer",
        "possible_duplicate",
        "unapproved",
        "uncategorized",
        "all",
    ] = "actionable"
    limit: int = Field(50, ge=1, le=100)
    since_days: int = Field(45, ge=1, le=HISTORY_DAYS)
    account: Optional[str] = None


@app.post(
    "/ynab/triage/query",
    summary="Actionable transaction triage using a JSON request body",
    operation_id="getTriageQuery",
)
async def get_triage_query(payload: TriageQueryRequest):
    """Body-based triage endpoint for clients that mishandle account query strings."""
    return await get_triage(
        format=payload.format,
        status_filter=payload.status,
        limit=payload.limit,
        since_days=payload.since_days,
        account=payload.account,
    )


@app.get(
    "/ynab/merchant/{name}/history",
    summary="Historical category evidence using canonical and imported payee text",
    operation_id="getMerchantHistory",
)
async def get_merchant_history(name: str):
    await sync_ynab()
    target = normalize_text(name)

    matches = []
    for tx in store.transactions.values():
        if tx_is_transfer(tx):
            continue
        candidates = [
            tx.get("payee_name"),
            tx.get("import_payee_name"),
            tx.get("import_payee_name_original"),
        ]
        if any(target and target in normalize_text(candidate) for candidate in candidates):
            matches.append(tx)

    distribution: Dict[str, int] = {}
    split_count = 0
    for tx in matches:
        if tx.get("subtransactions"):
            split_count += 1
            for sub in tx["subtransactions"]:
                cid = sub.get("category_id")
                if cid:
                    alias = category_alias(cid)
                    distribution[alias] = distribution.get(alias, 0) + 1
            continue

        cid = tx.get("category_id")
        if cid:
            alias = category_alias(cid)
            distribution[alias] = distribution.get(alias, 0) + 1

    categorized_samples = sum(distribution.values())
    return {
        "payee_query": name,
        "history_days": HISTORY_DAYS,
        "sample_size": len(matches),
        "categorized_samples": categorized_samples,
        "split_transaction_count": split_count,
        "category_distribution": distribution,
        "is_single_category": len(distribution) == 1 and categorized_samples >= 2,
    }


@app.get(
    "/ynab/cashflow",
    summary="Checking cashflow forecast with credit-card liability exposure",
    operation_id="getCashflow",
)
async def get_cashflow(days: int = Query(30, ge=7, le=90)):
    await sync_ynab()

    today = local_today()
    end_date = today + timedelta(days=days)
    checking_ids = get_primary_checking_ids()
    card_ids = credit_card_account_ids()

    if not checking_ids:
        raise HTTPException(status_code=500, detail="Primary checking account not found")

    ynab_starting_milli = sum(
        int(store.accounts[acct_id].get("balance", 0))
        for acct_id in checking_ids
    )
    balance_diagnostic = await primary_checking_balance_diagnostic(refresh_bank=False)
    bank_starting_milli = (
        str_to_milli(balance_diagnostic["bank_current_balance"])
        if balance_diagnostic.get("bank_current_balance") is not None
        else None
    )

    # Prefer the bank-side current balance for liquidity decisions when Plaid is
    # available. Fall back to YNAB so the endpoint remains useful during Plaid outages.
    starting_milli = (
        bank_starting_milli
        if bank_starting_milli is not None
        else ynab_starting_milli
    )
    starting_source = "plaid_current" if bank_starting_milli is not None else "ynab"

    # Existing credit-card debt is future cash exposure even when the actual
    # checking payment has not yet been scheduled. We report it separately and
    # in a conservative liquidity-adjusted scenario rather than pretending it
    # is already a dated checking outflow.
    starting_card_debt_milli = sum(
        max(0, -int(store.accounts[acct_id].get("balance", 0)))
        for acct_id in card_ids
    )

    checking_events = []
    card_events = []
    coverage_issues = []

    for stx_id, stx in store.scheduled_transactions.items():
        account_id = stx.get("account_id")

        if account_id in checking_ids:
            event_type = "checking"
            destination = checking_events
        elif account_id in card_ids:
            event_type = "credit_card"
            destination = card_events
        else:
            continue

        events, issue = expand_scheduled_transaction(
            stx_id=stx_id,
            stx=stx,
            start_date=today,
            end_date=end_date,
            event_type=event_type,
        )
        destination.extend(events)

        if issue:
            coverage_issues.append({
                "ref": store.scheduled_ref(stx_id),
                "frequency": stx.get("frequency") or "never",
                "issue": issue,
            })

    checking_events.sort(key=lambda x: (x["date"], x["ref"]))
    card_events.sort(key=lambda x: (x["date"], x["ref"]))

    running = starting_milli
    lowest = starting_milli
    inflows = 0
    outflows = 0
    rendered_checking = []

    for event in checking_events:
        amount = event["amount_milli"]
        running += amount
        lowest = min(lowest, running)
        if amount >= 0:
            inflows += amount
        else:
            outflows += abs(amount)

        rendered_checking.append({
            "ref": event["ref"],
            "date": event["date"],
            "payee": event["payee"],
            "account": event["account"],
            "amount": milli_to_str(amount),
            "frequency": event["frequency"],
            "projected_balance_after": milli_to_str(running),
        })

    # Card purchases increase future cash liability; card inflows/payments reduce it.
    scheduled_card_purchases = sum(
        abs(e["amount_milli"]) for e in card_events if e["amount_milli"] < 0
    )
    scheduled_card_credits_or_payments = sum(
        e["amount_milli"] for e in card_events if e["amount_milli"] > 0
    )
    projected_card_debt_end = max(
        0,
        starting_card_debt_milli
        + scheduled_card_purchases
        - scheduled_card_credits_or_payments,
    )

    rendered_card = [
        {
            "ref": e["ref"],
            "date": e["date"],
            "payee": e["payee"],
            "account": e["account"],
            "amount": milli_to_str(e["amount_milli"]),
            "frequency": e["frequency"],
            "liability_effect": (
                "increase" if e["amount_milli"] < 0 else "decrease"
            ),
        }
        for e in card_events
    ]

    checking_buffer_milli = lowest - CHECKING_FLOOR_MILLI

    # Conservative scenario: if all projected card debt had to be paid from
    # primary checking within the forecast window, what would remain?
    conservative_lowest = lowest - projected_card_debt_end
    conservative_buffer = conservative_lowest - CHECKING_FLOOR_MILLI

    if conservative_buffer < 0:
        risk = "breached"
    elif conservative_buffer < 300_000:
        risk = "tight"
    else:
        risk = "comfortable"

    coverage_complete = len(coverage_issues) == 0
    if not checking_events and not card_events:
        risk = "insufficient_data"
    elif not coverage_complete and risk != "breached":
        risk = "incomplete"

    return {
        "forecast_days": days,
        "starting_checking": milli_to_str(starting_milli),
        "starting_checking_source": starting_source,
        "ynab_starting_checking": milli_to_str(ynab_starting_milli),
        "bank_current_checking": balance_diagnostic.get("bank_current_balance"),
        "bank_available_checking": balance_diagnostic.get("bank_available_balance"),
        "immediate_liquidity_checking": (
            balance_diagnostic.get("bank_available_balance")
            or balance_diagnostic.get("bank_current_balance")
            or milli_to_str(ynab_starting_milli)
        ),
        "immediate_liquidity_source": (
            "plaid_available"
            if balance_diagnostic.get("bank_available_balance") is not None
            else (
                "plaid_current"
                if balance_diagnostic.get("bank_current_balance") is not None
                else "ynab"
            )
        ),
        "bank_minus_ynab": balance_diagnostic.get("difference_bank_minus_ynab"),
        "bank_balance_as_of": balance_diagnostic.get("bank_balance_as_of"),
        "known_checking_inflows": milli_to_str(inflows),
        "known_checking_outflows": milli_to_str(outflows),
        # Backward-compatible fields.
        "known_inflows": milli_to_str(inflows),
        "known_outflows": milli_to_str(outflows),
        "lowest_projected_checking": milli_to_str(lowest),
        "lowest_projected_balance": milli_to_str(lowest),
        "checking_floor": milli_to_str(CHECKING_FLOOR_MILLI),
        "checking_only_buffer": milli_to_str(checking_buffer_milli),
        "minimum_buffer": milli_to_str(conservative_buffer),
        "credit_cards": {
            "starting_debt": milli_to_str(starting_card_debt_milli),
            "scheduled_purchases": milli_to_str(scheduled_card_purchases),
            "scheduled_credits_or_payments": milli_to_str(scheduled_card_credits_or_payments),
            "projected_debt_end": milli_to_str(projected_card_debt_end),
        },
        "conservative_liquidity": {
            "assumption": "all projected credit-card debt is paid from primary checking within the forecast window",
            "lowest_after_card_debt": milli_to_str(conservative_lowest),
            "buffer_above_floor": milli_to_str(conservative_buffer),
        },
        "risk": risk,
        "coverage_complete": coverage_complete,
        "scheduled_checking_event_count": len(checking_events),
        "scheduled_card_event_count": len(card_events),
        "scheduled_event_count": len(checking_events) + len(card_events),
        "coverage": {
            "scheduled_recurrence_expansion_complete": coverage_complete,
            "issues": coverage_issues,
        },
        # Deprecated compatibility field. Unsupported recurrence refs remain
        # visible here for existing clients while the richer coverage object is adopted.
        "unexpanded_recurring_refs": sorted({
            issue["ref"] for issue in coverage_issues
        }),
        "events": rendered_checking,
        "credit_card_events": rendered_card,
    }


@app.get(
    "/ynab/reallocation-options",
    summary="Policy-aware funding sources for a category shortfall or planned reallocation",
    operation_id="getFundingOptions",
)
async def get_funding_options(
    target: str = Query(..., description="Target category alias"),
    amount: Optional[str] = Query(
        None,
        description="Optional positive amount. If omitted, covers the target's current overspending.",
    ),
    include_protected: bool = Query(False),
):
    await sync_ynab()
    amount_milli = str_to_milli(amount) if amount is not None else None
    return build_reallocation_plan(
        target_category=target,
        amount_milli=amount_milli,
        include_protected=include_protected,
    )


# =====================================================================
# Proposal Models & Guarded Writes
# =====================================================================

class SplitChangeItem(BaseModel):
    category: str = Field(..., description="Category alias for this split line")
    amount: str = Field(
        ...,
        description="Signed decimal amount; split amounts must sum exactly to the parent transaction amount",
    )
    memo: Optional[str] = None


class TransactionChangeItem(BaseModel):
    ref: str = Field(..., description="Opaque transaction ref, e.g. t:abc123")
    operation: Literal["update", "delete", "split", "transfer"] = "update"
    category: Optional[str] = Field(None, description="Target category alias for update")
    memo: Optional[str] = Field(None, description="Memo to set")
    approve: bool = True
    transfer_account: Optional[str] = Field(
        None,
        description="Target account alias for transfer operations",
    )
    splits: Optional[List[SplitChangeItem]] = Field(
        None,
        min_length=2,
        max_length=20,
        description="Split lines for split operations",
    )


class TransactionProposalPayload(BaseModel):
    changes: List[TransactionChangeItem] = Field(..., min_length=1, max_length=50)


class AssignmentChangeItem(BaseModel):
    category: str = Field(..., description="Category alias, e.g. cat:groceries")
    operation: Literal["add", "subtract", "set"]
    amount: str = Field(..., description="Positive decimal currency string")


class AssignmentProposalPayload(BaseModel):
    changes: List[AssignmentChangeItem] = Field(..., min_length=1, max_length=25)


class TransactionProposalSummary(BaseModel):
    ref: str
    operation: Literal["update", "delete", "split", "transfer"]
    payee: str
    amount: str
    current_category: str
    target_category: str
    proposed_memo: Optional[str] = None
    approve: bool
    transfer_account: Optional[str] = None
    splits: Optional[List[Dict[str, str]]] = None
    warnings: List[str] = Field(default_factory=list)


class TransactionProposalResponse(BaseModel):
    proposal_id: str
    kind: Literal["transactions"]
    expires_in_minutes: int
    status: Literal["staged"]
    summary: List[TransactionProposalSummary]


class AssignmentProposalSummary(BaseModel):
    category: str
    class_name: str = Field(alias="class")
    operation: Literal["add", "subtract", "set"]
    amount: str
    previous_assigned: str
    new_assigned: str
    projected_available: str
    warnings: List[str]

    model_config = {"populate_by_name": True}


class AssignmentProposalResponse(BaseModel):
    proposal_id: str
    kind: Literal["assignments"]
    expires_in_minutes: int
    status: Literal["staged"]
    ready_to_assign_before: str
    ready_to_assign_after: str
    summary: List[AssignmentProposalSummary]


class CommitResponse(BaseModel):
    status: Literal["committed"]
    proposal_id: str
    kind: Optional[Literal["transactions", "assignments"]] = None
    records_updated: int
    idempotent_replay: bool = False


def new_proposal_id() -> str:
    return f"p:{uuid.uuid4().hex[:10]}"


def proposal_expired(proposal: dict) -> bool:
    return time.time() > proposal["created_at"] + PROPOSAL_TTL_SECONDS


def get_live_proposal(proposal_id: str) -> dict:
    proposal = store.proposals.get(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal_expired(proposal):
        store.proposals.pop(proposal_id, None)
        raise HTTPException(status_code=410, detail="Proposal has expired")
    return proposal


@app.post(
    "/ynab/transactions/propose",
    summary="Stage transaction updates, deletes, splits, or transfers for explicit review",
    operation_id="proposeTransactions",
    response_model=TransactionProposalResponse,
)
async def propose_transaction_changes(payload: TransactionProposalPayload):
    await sync_ynab()
    proposal_id = new_proposal_id()
    verified = []

    transfer_candidates = build_transfer_candidate_map(store.transactions)
    duplicate_candidates = build_duplicate_candidate_map(store.transactions)
    month_cats = current_month_categories()

    for item in payload.changes:
        tx_uuid = store.resolve_uuid(item.ref)
        tx = store.transactions.get(tx_uuid)
        if not tx:
            raise HTTPException(status_code=404, detail=f"Transaction {item.ref} not found")

        operation = item.operation
        old_cat_id = tx.get("category_id")
        warnings: List[str] = []

        if operation == "update":
            if item.transfer_account is not None or item.splits is not None:
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: transfer_account/splits require transfer or split operation",
                )

            if item.category and tx_uuid in duplicate_candidates:
                candidate = duplicate_candidates[tx_uuid]
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{item.ref} is a possible duplicate of "
                        f"{candidate['candidate_ref']}; resolve the duplicate before categorizing"
                    ),
                )

            if item.category and tx_uuid in transfer_candidates and not tx_is_transfer(tx):
                candidate = transfer_candidates[tx_uuid]
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{item.ref} is a possible transfer paired with "
                        f"{candidate['candidate_ref']}; resolve the transfer before categorizing"
                    ),
                )

            if item.category and tx_is_transfer(tx):
                raise HTTPException(
                    status_code=409,
                    detail=f"{item.ref} is a transfer; category changes are not permitted",
                )
            if item.category and tx.get("subtransactions"):
                raise HTTPException(
                    status_code=409,
                    detail=f"{item.ref} is a split transaction; parent category cannot be replaced",
                )

            target_cat_uuid = old_cat_id
            if item.category is not None:
                target_cat_uuid = store.resolve_uuid(item.category)
                if target_cat_uuid not in month_cats:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Category {item.category} not found in current month",
                    )

            verified.append({
                "ref": item.ref,
                "operation": operation,
                "real_tx_id": tx_uuid,
                "payee": tx_display_payee(tx),
                "amount": milli_to_str(int(tx.get("amount", 0))),
                "current_category": category_alias(old_cat_id) or "Uncategorized",
                "target_category": item.category or category_alias(old_cat_id) or "Uncategorized",
                "target_category_uuid": target_cat_uuid,
                "new_memo": item.memo if item.memo is not None else tx.get("memo"),
                "approve": item.approve,
                "transfer_account": None,
                "transfer_account_uuid": None,
                "transfer_payee_id": None,
                "splits": None,
                "warnings": warnings,
                "expected": {
                    "date": tx.get("date"),
                    "amount": int(tx.get("amount", 0)),
                    "category_id": old_cat_id,
                    "memo": tx.get("memo"),
                    "approved": bool(tx.get("approved")),
                    "payee_id": tx.get("payee_id"),
                    "is_split": bool(tx.get("subtransactions")),
                },
            })
            continue

        if operation == "delete":
            if item.category is not None or item.transfer_account is not None or item.splits is not None:
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: delete operation cannot include category, transfer_account, or splits",
                )
            if tx_is_transfer(tx):
                warnings.append("deleting one side of a transfer may affect the linked transfer transaction")
            if tx_uuid not in duplicate_candidates:
                warnings.append("transaction is not currently flagged as a possible duplicate")

            verified.append({
                "ref": item.ref,
                "operation": operation,
                "real_tx_id": tx_uuid,
                "payee": tx_display_payee(tx),
                "amount": milli_to_str(int(tx.get("amount", 0))),
                "current_category": category_alias(old_cat_id) or "Uncategorized",
                "target_category": "DELETE",
                "target_category_uuid": None,
                "new_memo": tx.get("memo"),
                "approve": item.approve,
                "transfer_account": None,
                "transfer_account_uuid": None,
                "transfer_payee_id": None,
                "splits": None,
                "warnings": warnings,
                "expected": {
                    "date": tx.get("date"),
                    "amount": int(tx.get("amount", 0)),
                    "category_id": old_cat_id,
                    "memo": tx.get("memo"),
                    "approved": bool(tx.get("approved")),
                    "payee_id": tx.get("payee_id"),
                    "is_split": bool(tx.get("subtransactions")),
                },
            })
            continue

        if operation == "split":
            if tx_is_transfer(tx):
                raise HTTPException(
                    status_code=409,
                    detail=f"{item.ref} is already a transfer and cannot be converted to a split",
                )
            if tx.get("subtransactions"):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{item.ref} is already split; YNAB's public API does not support "
                        "updating existing split lines"
                    ),
                )
            if not item.splits:
                raise HTTPException(status_code=422, detail=f"{item.ref}: split operation requires splits")
            if item.category is not None or item.transfer_account is not None:
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: split operation cannot include parent category or transfer_account",
                )

            split_rows = []
            split_total = 0
            for split in item.splits:
                cat_uuid = store.resolve_uuid(split.category)
                if cat_uuid not in month_cats:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Split category {split.category} not found",
                    )
                split_amount = str_to_milli(split.amount)
                split_total += split_amount
                split_rows.append({
                    "category": split.category,
                    "category_uuid": cat_uuid,
                    "amount": milli_to_str(split_amount),
                    "amount_milli": split_amount,
                    "memo": split.memo,
                })

            parent_amount = int(tx.get("amount", 0))
            if split_total != parent_amount:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"{item.ref}: split lines total {milli_to_str(split_total)} "
                        f"but transaction amount is {milli_to_str(parent_amount)}"
                    ),
                )

            verified.append({
                "ref": item.ref,
                "operation": operation,
                "real_tx_id": tx_uuid,
                "payee": tx_display_payee(tx),
                "amount": milli_to_str(parent_amount),
                "current_category": category_alias(old_cat_id) or "Uncategorized",
                "target_category": "Split",
                "target_category_uuid": None,
                "new_memo": item.memo if item.memo is not None else tx.get("memo"),
                "approve": item.approve,
                "transfer_account": None,
                "transfer_account_uuid": None,
                "transfer_payee_id": None,
                "splits": split_rows,
                "warnings": warnings,
                "expected": {
                    "date": tx.get("date"),
                    "amount": parent_amount,
                    "category_id": old_cat_id,
                    "memo": tx.get("memo"),
                    "approved": bool(tx.get("approved")),
                    "payee_id": tx.get("payee_id"),
                    "is_split": False,
                },
            })
            continue

        if operation == "transfer":
            if not item.transfer_account:
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: transfer operation requires transfer_account",
                )
            if item.category is not None or item.splits is not None:
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: transfer operation cannot include category or splits",
                )
            if tx.get("subtransactions"):
                raise HTTPException(
                    status_code=409,
                    detail=f"{item.ref} is a split transaction and cannot be converted to a transfer",
                )

            target_account_uuid = store.resolve_uuid(item.transfer_account)
            target_account = store.accounts.get(target_account_uuid)
            if not target_account or target_account.get("closed"):
                raise HTTPException(
                    status_code=404,
                    detail=f"Transfer account {item.transfer_account} not found or closed",
                )
            if target_account_uuid == tx.get("account_id"):
                raise HTTPException(
                    status_code=422,
                    detail=f"{item.ref}: transfer target cannot be the same account",
                )

            transfer_payee_id = transfer_payee_id_for_account(target_account_uuid)
            if not transfer_payee_id:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"No YNAB transfer payee found for {item.transfer_account}; "
                        "sync the account/payee data and re-propose"
                    ),
                )

            verified.append({
                "ref": item.ref,
                "operation": operation,
                "real_tx_id": tx_uuid,
                "payee": tx_display_payee(tx),
                "amount": milli_to_str(int(tx.get("amount", 0))),
                "current_category": category_alias(old_cat_id) or "Uncategorized",
                "target_category": "Transfer",
                "target_category_uuid": None,
                "new_memo": item.memo if item.memo is not None else tx.get("memo"),
                "approve": item.approve,
                "transfer_account": item.transfer_account,
                "transfer_account_uuid": target_account_uuid,
                "transfer_payee_id": transfer_payee_id,
                "splits": None,
                "warnings": warnings,
                "expected": {
                    "date": tx.get("date"),
                    "amount": int(tx.get("amount", 0)),
                    "category_id": old_cat_id,
                    "memo": tx.get("memo"),
                    "approved": bool(tx.get("approved")),
                    "payee_id": tx.get("payee_id"),
                    "is_split": bool(tx.get("subtransactions")),
                },
            })
            continue

        raise HTTPException(status_code=422, detail=f"Unsupported operation {operation}")

    proposal = {
        "proposal_id": proposal_id,
        "kind": "transactions",
        "created_at": time.time(),
        "status": "staged",
        "changes": verified,
    }
    store.proposals[proposal_id] = proposal

    return {
        "proposal_id": proposal_id,
        "kind": "transactions",
        "expires_in_minutes": PROPOSAL_TTL_SECONDS // 60,
        "status": "staged",
        "summary": [
            {
                "ref": c["ref"],
                "operation": c["operation"],
                "payee": c["payee"],
                "amount": c["amount"],
                "current_category": c["current_category"],
                "target_category": c["target_category"],
                "proposed_memo": c["new_memo"],
                "approve": c["approve"],
                "transfer_account": c["transfer_account"],
                "splits": (
                    [
                        {
                            "category": s["category"],
                            "amount": s["amount"],
                            "memo": s["memo"] or "",
                        }
                        for s in c["splits"]
                    ]
                    if c["splits"] else None
                ),
                "warnings": c["warnings"],
            }
            for c in verified
        ],
    }


@app.post(
    "/ynab/assignments/propose",
    summary="Stage current-month category assignment changes for review",
    operation_id="proposeAssignments",
    response_model=AssignmentProposalResponse,
)
async def propose_assignment_changes(payload: AssignmentProposalPayload):
    await sync_ynab()
    month_cats = current_month_categories()
    policy = load_policy()
    rta_before = int(store.current_month_detail.get("to_be_budgeted", 0))
    total_assignment_delta = 0
    verified = []

    # Track multiple changes to the same category within one proposal deterministically.
    staged_budgeted: Dict[str, int] = {
        cid: int(cat.get("budgeted", 0)) for cid, cat in month_cats.items()
    }
    staged_available: Dict[str, int] = {
        cid: int(cat.get("balance", 0)) for cid, cat in month_cats.items()
    }
    seen_categories: set[str] = set()

    for item in payload.changes:
        cat_uuid = store.resolve_uuid(item.category)
        if cat_uuid in seen_categories:
            raise HTTPException(
                status_code=422,
                detail=f"Duplicate assignment change for {item.category}; combine it into one operation",
            )
        seen_categories.add(cat_uuid)
        cat = month_cats.get(cat_uuid)
        if not cat:
            raise HTTPException(status_code=404, detail=f"Category {item.category} not found")

        amount_milli = str_to_milli(item.amount)
        if amount_milli < 0:
            raise HTTPException(status_code=422, detail="Assignment amount must be positive")

        previous = staged_budgeted[cat_uuid]
        if item.operation == "add":
            new_budgeted = previous + amount_milli
        elif item.operation == "subtract":
            new_budgeted = previous - amount_milli
        else:
            new_budgeted = amount_milli

        if new_budgeted < 0:
            raise HTTPException(
                status_code=409,
                detail=f"{item.category} would have negative assigned dollars",
            )

        delta = new_budgeted - previous
        projected_available = staged_available[cat_uuid] + delta
        if projected_available < 0:
            raise HTTPException(
                status_code=409,
                detail=f"{item.category} would become overspent after this assignment change",
            )

        staged_budgeted[cat_uuid] = new_budgeted
        staged_available[cat_uuid] = projected_available
        total_assignment_delta += delta

        cls = policy_class_for(item.category, policy)
        warnings = []
        if delta < 0 and cls == "essential":
            warnings.append("reduces an essential category")

        verified.append({
            "category": item.category,
            "real_category_id": cat_uuid,
            "class": cls,
            "operation": item.operation,
            "amount": milli_to_str(amount_milli),
            "previous_assigned": milli_to_str(previous),
            "new_assigned": milli_to_str(new_budgeted),
            "projected_available": milli_to_str(projected_available),
            "expected_budgeted": previous,
            "new_budgeted_milli": new_budgeted,
            "warnings": warnings,
        })

    rta_after = rta_before - total_assignment_delta

    # Never worsen a negative RTA, and never create a new negative RTA.
    if rta_after < min(0, rta_before):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Proposal would worsen Ready to Assign from "
                f"{milli_to_str(rta_before)} to {milli_to_str(rta_after)}"
            ),
        )

    proposal_id = new_proposal_id()
    proposal = {
        "proposal_id": proposal_id,
        "kind": "assignments",
        "created_at": time.time(),
        "status": "staged",
        "month": store.current_month_detail.get("month"),
        "rta_before": rta_before,
        "rta_after": rta_after,
        "changes": verified,
    }
    store.proposals[proposal_id] = proposal

    return {
        "proposal_id": proposal_id,
        "kind": "assignments",
        "expires_in_minutes": PROPOSAL_TTL_SECONDS // 60,
        "status": "staged",
        "ready_to_assign_before": milli_to_str(rta_before),
        "ready_to_assign_after": milli_to_str(rta_after),
        "summary": [
            {
                "category": c["category"],
                "class": c["class"],
                "operation": c["operation"],
                "amount": c["amount"],
                "previous_assigned": c["previous_assigned"],
                "new_assigned": c["new_assigned"],
                "projected_available": c["projected_available"],
                "warnings": c["warnings"],
            }
            for c in verified
        ],
    }


@app.get(
    "/ynab/proposals/{proposal_id}",
    summary="Retrieve a staged proposal for review or recovery",
    operation_id="getProposal",
)
async def get_proposal(proposal_id: str):
    proposal = get_live_proposal(proposal_id)
    if proposal["kind"] == "transactions":
        summary = [
            {
                "ref": c["ref"],
                "operation": c["operation"],
                "payee": c["payee"],
                "amount": c["amount"],
                "current_category": c["current_category"],
                "target_category": c["target_category"],
                "proposed_memo": c["new_memo"],
                "approve": c["approve"],
                "transfer_account": c.get("transfer_account"),
                "splits": (
                    [
                        {
                            "category": s["category"],
                            "amount": s["amount"],
                            "memo": s["memo"] or "",
                        }
                        for s in (c.get("splits") or [])
                    ]
                    or None
                ),
                "warnings": c.get("warnings", []),
            }
            for c in proposal["changes"]
        ]
    else:
        summary = [
            {
                "category": c["category"],
                "class": c["class"],
                "operation": c["operation"],
                "amount": c["amount"],
                "previous_assigned": c["previous_assigned"],
                "new_assigned": c["new_assigned"],
                "projected_available": c["projected_available"],
                "warnings": c["warnings"],
            }
            for c in proposal["changes"]
        ]

    return {
        "proposal_id": proposal_id,
        "kind": proposal["kind"],
        "status": proposal["status"],
        "expires_in_seconds": max(
            0, int(proposal["created_at"] + PROPOSAL_TTL_SECONDS - time.time())
        ),
        "summary": summary,
    }


@app.post(
    "/ynab/proposals/{proposal_id}/commit",
    summary="Commit a previously staged proposal after explicit user approval",
    operation_id="commitProposal",
    response_model=CommitResponse,
)
async def commit_proposal(proposal_id: str):
    proposal = get_live_proposal(proposal_id)
    if proposal.get("status") == "committed":
        return {
            "status": "committed",
            "proposal_id": proposal_id,
            "records_updated": len(proposal["changes"]),
            "idempotent_replay": True,
        }

    await sync_ynab(force=True)
    headers = {"Authorization": f"Bearer {YNAB_API_TOKEN}"}

    if proposal["kind"] == "transactions":
        # Optimistic concurrency validation before any writes.
        for item in proposal["changes"]:
            tx = store.transactions.get(item["real_tx_id"])
            if not tx:
                raise HTTPException(status_code=409, detail=f"{item['ref']} no longer exists")

            expected = item["expected"]
            live = {
                "date": tx.get("date"),
                "amount": int(tx.get("amount", 0)),
                "category_id": tx.get("category_id"),
                "memo": tx.get("memo"),
                "approved": bool(tx.get("approved")),
                "payee_id": tx.get("payee_id"),
                "is_split": bool(tx.get("subtransactions")),
            }
            if live != expected:
                raise HTTPException(
                    status_code=409,
                    detail=f"{item['ref']} changed after proposal creation; re-propose",
                )

        updates = []
        deletes = []
        for item in proposal["changes"]:
            operation = item["operation"]

            if operation == "delete":
                deletes.append(item)
                continue

            patch = {
                "id": item["real_tx_id"],
                "approved": item["approve"],
            }

            if operation == "update":
                tx = store.transactions[item["real_tx_id"]]
                if item["target_category_uuid"] != tx.get("category_id"):
                    patch["category_id"] = item["target_category_uuid"]
                if item["new_memo"] != tx.get("memo"):
                    patch["memo"] = item["new_memo"]

            elif operation == "split":
                patch["category_id"] = None
                patch["subtransactions"] = [
                    {
                        "amount": s["amount_milli"],
                        "category_id": s["category_uuid"],
                        "memo": s["memo"],
                    }
                    for s in item["splits"]
                ]
                tx = store.transactions[item["real_tx_id"]]
                if item["new_memo"] != tx.get("memo"):
                    patch["memo"] = item["new_memo"]

            elif operation == "transfer":
                patch["payee_id"] = item["transfer_payee_id"]
                patch["category_id"] = None
                tx = store.transactions[item["real_tx_id"]]
                if item["new_memo"] != tx.get("memo"):
                    patch["memo"] = item["new_memo"]

            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unknown transaction operation {operation}",
                )

            updates.append(patch)

        async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=20.0) as client:
            if updates:
                resp = await client.patch(
                    f"/budgets/{YNAB_BUDGET_ID}/transactions",
                    headers=headers,
                    json={"transactions": updates},
                )
                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail=f"YNAB transaction batch update failed: {resp.status_code}",
                    )

            # DELETE is only available as a single-transaction endpoint.
            # If a later delete fails after an earlier update/delete succeeds,
            # mark the proposal partial_failure so it cannot be blindly replayed.
            for item in deletes:
                resp = await client.delete(
                    f"/budgets/{YNAB_BUDGET_ID}/transactions/{item['real_tx_id']}",
                    headers=headers,
                )
                if resp.status_code != 200:
                    proposal["status"] = "partial_failure"
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            f"Delete failed for {item['ref']}; re-sync and re-propose "
                            "before retrying"
                        ),
                    )

    elif proposal["kind"] == "assignments":
        month_cats = current_month_categories()
        for item in proposal["changes"]:
            live = month_cats.get(item["real_category_id"])
            if not live:
                raise HTTPException(
                    status_code=409,
                    detail=f"{item['category']} no longer exists in the current month",
                )
            if int(live.get("budgeted", 0)) != item["expected_budgeted"]:
                raise HTTPException(
                    status_code=409,
                    detail=f"{item['category']} changed after proposal creation; re-propose",
                )

        async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=20.0) as client:
            for item in proposal["changes"]:
                resp = await client.patch(
                    (
                        f"/budgets/{YNAB_BUDGET_ID}/months/current/categories/"
                        f"{item['real_category_id']}"
                    ),
                    headers=headers,
                    json={"category": {"budgeted": item["new_budgeted_milli"]}},
                )
                if resp.status_code != 200:
                    proposal["status"] = "partial_failure"
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            f"Assignment update failed for {item['category']}; "
                            "re-sync and re-propose before retrying"
                        ),
                    )
    else:
        raise HTTPException(status_code=500, detail="Unknown proposal kind")

    proposal["status"] = "committed"
    proposal["committed_at"] = time.time()
    await sync_ynab(force=True)

    return {
        "status": "committed",
        "proposal_id": proposal_id,
        "kind": proposal["kind"],
        "records_updated": len(proposal["changes"]),
    }


# Backward-compatible route for an existing GPT schema. Hide it from the new OpenAPI.
@app.post("/ynab/transactions/commit/{proposal_id}", include_in_schema=False)
async def legacy_commit_transaction_proposal(proposal_id: str):
    return await commit_proposal(proposal_id)


# Fail closed if an old schema tries to use the former direct-write assignment endpoint.
@app.post("/ynab/assignment", include_in_schema=False)
async def deprecated_direct_assignment():
    raise HTTPException(
        status_code=409,
        detail="Direct assignment writes are disabled. Use /ynab/assignments/propose then commitProposal.",
    )


@app.get(
    "/ynab/policy",
    summary="Get canonical household policy",
    operation_id="getPolicy",
)
async def get_policy():
    policy = load_policy()
    policy.setdefault("checking_floor", milli_to_str(CHECKING_FLOOR_MILLI))
    return policy
