import csv
import hashlib
import hmac
import io
import os
import re
import time
import uuid
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

PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/")
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

YNAB_BASE_URL = "https://api.ynab.com/v1"

app = FastAPI(
    title="YNAB Copilot Middleware",
    description="Deterministic read-model and guarded write layer between ChatGPT and YNAB",
    version="2.0.0",
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
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


@app.middleware("http")
async def authenticate_all_requests(request: Request, call_next):
    if request.url.path in ["/", "/docs", "/openapi.json", "/redoc"]:
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
        self.current_month_detail: Dict[str, Any] = {}

        self.alias_to_uuid: Dict[str, str] = {}
        self.uuid_to_alias: Dict[str, str] = {}

        # IMPORTANT: for production/multiple Railway workers, persist this in Redis/Postgres.
        self.proposals: Dict[str, dict] = {}

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
# Read Models
# =====================================================================

@app.get("/", summary="Health check")
async def root():
    return {"status": "online", "service": "YNAB Copilot Middleware", "version": app.version}


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
            "balance": milli_to_str(checking_balance_milli),
            "floor": milli_to_str(CHECKING_FLOOR_MILLI),
            "above_floor": milli_to_str(above_floor_milli),
            "floor_breached": above_floor_milli < 0,
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
    summary="Checking-only scheduled cashflow forecast with coverage diagnostics",
    operation_id="getCashflow",
)
async def get_cashflow(days: int = Query(30, ge=7, le=90)):
    await sync_ynab()

    today = local_today()
    end_date = today + timedelta(days=days)
    checking_ids = get_primary_checking_ids()

    if not checking_ids:
        raise HTTPException(status_code=500, detail="Primary checking account not found")

    starting_milli = sum(
        int(store.accounts[acct_id].get("balance", 0))
        for acct_id in checking_ids
    )

    events = []
    unexpanded_recurring = []
    for stx_id, stx in store.scheduled_transactions.items():
        if stx.get("account_id") not in checking_ids:
            continue

        d_str = stx.get("date_next")
        if not d_str:
            continue
        next_date = date.fromisoformat(d_str)
        if not (today <= next_date <= end_date):
            continue

        frequency = stx.get("frequency") or "never"
        if frequency != "never":
            # We intentionally do not synthesize future recurrences from one API row.
            # The result therefore reports incomplete coverage instead of false confidence.
            unexpanded_recurring.append(store.scheduled_ref(stx_id))

        events.append({
            "ref": store.scheduled_ref(stx_id),
            "date": d_str,
            "payee": stx.get("payee_name") or "Scheduled transaction",
            "amount_milli": int(stx.get("amount", 0)),
            "frequency": frequency,
        })

    events.sort(key=lambda x: (x["date"], x["ref"]))

    running = starting_milli
    lowest = starting_milli
    inflows = 0
    outflows = 0
    rendered_events = []

    for event in events:
        amount = event["amount_milli"]
        running += amount
        lowest = min(lowest, running)
        if amount >= 0:
            inflows += amount
        else:
            outflows += abs(amount)

        rendered_events.append({
            "ref": event["ref"],
            "date": event["date"],
            "payee": event["payee"],
            "amount": milli_to_str(amount),
            "frequency": event["frequency"],
            "projected_balance_after": milli_to_str(running),
        })

    buffer_milli = lowest - CHECKING_FLOOR_MILLI
    base_risk = "breached" if buffer_milli < 0 else "tight" if buffer_milli < 300_000 else "comfortable"

    coverage_complete = len(unexpanded_recurring) == 0
    if not events:
        risk = "insufficient_data"
    elif not coverage_complete and base_risk != "breached":
        risk = "incomplete"
    else:
        risk = base_risk

    return {
        "forecast_days": days,
        "starting_checking": milli_to_str(starting_milli),
        "known_inflows": milli_to_str(inflows),
        "known_outflows": milli_to_str(outflows),
        "lowest_projected_balance": milli_to_str(lowest),
        "checking_floor": milli_to_str(CHECKING_FLOOR_MILLI),
        "minimum_buffer": milli_to_str(buffer_milli),
        "risk": risk,
        "coverage_complete": coverage_complete,
        "scheduled_event_count": len(events),
        "unexpanded_recurring_refs": unexpanded_recurring,
        "events": rendered_events,
    }


# =====================================================================
# Proposal Models & Guarded Writes
# =====================================================================

class TransactionChangeItem(BaseModel):
    ref: str = Field(..., description="Opaque transaction ref, e.g. t:abc123")
    category: Optional[str] = Field(None, description="Target category alias")
    memo: Optional[str] = Field(None, description="Memo to set")
    approve: bool = True


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
    payee: str
    amount: str
    current_category: str
    target_category: str
    proposed_memo: Optional[str] = None
    approve: bool


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
    summary="Stage transaction changes for explicit review before commit",
    operation_id="proposeTransactions",
    response_model=TransactionProposalResponse,
)
async def propose_transaction_changes(payload: TransactionProposalPayload):
    await sync_ynab()
    proposal_id = new_proposal_id()
    verified = []

    transfer_candidates = build_transfer_candidate_map(store.transactions)
    duplicate_candidates = build_duplicate_candidate_map(store.transactions)

    for item in payload.changes:
        tx_uuid = store.resolve_uuid(item.ref)
        tx = store.transactions.get(tx_uuid)
        if not tx:
            raise HTTPException(status_code=404, detail=f"Transaction {item.ref} not found")

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

        old_cat_id = tx.get("category_id")
        target_cat_uuid = old_cat_id
        if item.category is not None:
            target_cat_uuid = store.resolve_uuid(item.category)
            if target_cat_uuid not in current_month_categories():
                raise HTTPException(
                    status_code=404,
                    detail=f"Category {item.category} not found in current month",
                )

        verified.append({
            "ref": item.ref,
            "real_tx_id": tx_uuid,
            "payee": tx_display_payee(tx),
            "amount": milli_to_str(int(tx.get("amount", 0))),
            "current_category": category_alias(old_cat_id) or "Uncategorized",
            "target_category": item.category or category_alias(old_cat_id) or "Uncategorized",
            "target_category_uuid": target_cat_uuid,
            "new_memo": item.memo if item.memo is not None else tx.get("memo"),
            "approve": item.approve,
            "expected": {
                "date": tx.get("date"),
                "amount": int(tx.get("amount", 0)),
                "category_id": old_cat_id,
                "memo": tx.get("memo"),
                "approved": bool(tx.get("approved")),
            },
        })

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
                "payee": c["payee"],
                "amount": c["amount"],
                "current_category": c["current_category"],
                "target_category": c["target_category"],
                "proposed_memo": c["new_memo"],
                "approve": c["approve"],
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
                "payee": c["payee"],
                "amount": c["amount"],
                "current_category": c["current_category"],
                "target_category": c["target_category"],
                "proposed_memo": c["new_memo"],
                "approve": c["approve"],
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
        patches = []
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
            }
            if live != expected:
                raise HTTPException(
                    status_code=409,
                    detail=f"{item['ref']} changed after proposal creation; re-propose",
                )

            patch = {
                "id": item["real_tx_id"],
                "approved": item["approve"],
            }
            if item["target_category_uuid"] != tx.get("category_id"):
                patch["category_id"] = item["target_category_uuid"]
            if item["new_memo"] != tx.get("memo"):
                patch["memo"] = item["new_memo"]
            patches.append(patch)

        async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=20.0) as client:
            resp = await client.patch(
                f"/budgets/{YNAB_BUDGET_ID}/transactions",
                headers=headers,
                json={"transactions": patches},
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"YNAB transaction batch update failed: {resp.status_code}",
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
