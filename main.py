import os
import re
import time
import uuid
import yaml
from datetime import date, timedelta
from typing import Any, Dict, List, Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# =====================================================================
# Configuration & Security
# =====================================================================
YNAB_API_TOKEN = os.getenv(
    "YNAB_API_TOKEN", "P3y9tco7TMrKSp9-D2GJuzmf-qbZ73XBM6QhxfkHCQY"
).strip()

YNAB_BUDGET_ID = os.getenv(
    "YNAB_BUDGET_ID", "dc750713-861c-4b5a-9ca2-e69584dab745"
).strip()

_raw_key = (
    os.getenv("MIDDLEWARE_API_KEY")
    or os.getenv("API_KEY")
    or "H6PBUZLYadD28acfC*dR"
)
MIDDLEWARE_API_KEY = _raw_key.strip().strip('"').strip("'")

PRIMARY_CHECKING_NAME = os.getenv(
    "PRIMARY_CHECKING_NAME", "WF Checking"
).strip().lower()

CHECKING_FLOOR = float(os.getenv("CHECKING_FLOOR", "1000.00"))

YNAB_BASE_URL = "https://api.ynab.com/v1"

app = FastAPI(
    title="YNAB Copilot Middleware",
    description="Deterministic read-model and safety layer between ChatGPT and YNAB",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def authenticate_all_requests(request: Request, call_next):
    """Direct ASGI-level interceptor.

    Evaluates headers before endpoint dependencies and normalizes formatting
    variations (case, Bearer prefixes, quotes).
    """
    # Allow public endpoints and schema docs
    if request.url.path in ["/", "/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)

    # Search headers case-insensitively
    raw_header = (
        request.headers.get("x-api-key")
        or request.headers.get("X-API-Key")
        or request.headers.get("x_api_key")
        or request.headers.get("authorization")
    )

    incoming_key = raw_header
    if incoming_key:
        incoming_key = incoming_key.strip().strip('"').strip("'")
        if incoming_key.lower().startswith("bearer "):
            incoming_key = incoming_key[7:].strip()

    if not incoming_key or incoming_key != MIDDLEWARE_API_KEY:
        print(
            f"AUTH REJECTED -> Expected: '{MIDDLEWARE_API_KEY}' | Received:"
            f" '{raw_header}' | Path: {request.url.path}",
            flush=True,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid or missing X-API-Key header"},
        )

    return await call_next(request)


# =====================================================================
# In-Memory Cache & Bidirectional Aliasing
# =====================================================================
class BudgetStore:

  def __init__(self):
    self.server_knowledge: Optional[int] = None
    self.last_sync_time: float = 0.0
    self.ttl_seconds: float = 45.0

    self.accounts: Dict[str, dict] = {}
    self.categories: Dict[str, dict] = {}
    self.transactions: Dict[str, dict] = {}
    self.scheduled_transactions: List[dict] = []
    self.month_detail: Dict[str, Any] = {}

    self.alias_to_uuid: Dict[str, str] = {}
    self.uuid_to_alias: Dict[str, str] = {}
    self.ref_counter: int = 100

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

  def get_transaction_ref(self, real_uuid: str) -> str:
    if real_uuid in self.uuid_to_alias:
      return self.uuid_to_alias[real_uuid]
    self.ref_counter += 1
    ref = f"t:{self.ref_counter}"
    self.alias_to_uuid[ref] = real_uuid
    self.uuid_to_alias[real_uuid] = ref
    return ref

  def resolve_uuid(self, identifier: str) -> str:
    return self.alias_to_uuid.get(identifier, identifier)


store = BudgetStore()


# =====================================================================
# YNAB HTTP Client & Sync Engine
# =====================================================================
async def sync_ynab(force: bool = False):
  if not YNAB_API_TOKEN:
    raise HTTPException(
        status_code=500,
        detail="YNAB_API_TOKEN is not configured on Railway.",
    )

  now = time.time()
  if (
      not force
      and store.server_knowledge is not None
      and (now - store.last_sync_time < store.ttl_seconds)
  ):
    return

  headers = {"Authorization": f"Bearer {YNAB_API_TOKEN}"}
  params = {}
  if store.server_knowledge is not None:
    params["last_knowledge_of_server"] = store.server_knowledge

  async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=15.0) as client:
    resp = await client.get(
        f"/budgets/{YNAB_BUDGET_ID}", headers=headers, params=params
    )

    if resp.status_code == 304:
      store.last_sync_time = now
      return

    if resp.status_code != 200:
      raise HTTPException(
          status_code=502,
          detail=f"YNAB sync failed: {resp.status_code} {resp.text}",
      )

    data = resp.json().get("data", {})
    budget = data.get("budget", {})
    store.server_knowledge = data.get("server_knowledge")
    store.last_sync_time = now

    for acct in budget.get("accounts", []):
      if not acct.get("deleted", False):
        store.accounts[acct["id"]] = acct
        store.register_alias("acct", acct["name"], acct["id"])

    for group in budget.get("category_groups", []):
      for cat in group.get("categories", []):
        if not cat.get("deleted", False) and not cat.get("hidden", False):
          store.categories[cat["id"]] = cat
          store.register_alias("cat", cat["name"], cat["id"])

    if "scheduled_transactions" in budget:
      store.scheduled_transactions = [
          tx
          for tx in budget["scheduled_transactions"]
          if not tx.get("deleted", False)
      ]

    cutoff = (date.today() - timedelta(days=60)).isoformat()
    for tx in budget.get("transactions", []):
      if not tx.get("deleted", False) and tx.get("date", "") >= cutoff:
        store.transactions[tx["id"]] = tx
        store.get_transaction_ref(tx["id"])

    months = budget.get("months", [])
    if months:
      store.month_detail = months[0]


def milli_to_str(milliunits: int) -> str:
  return f"{(milliunits / 1000.0):.2f}"


def str_to_milli(amount_str: str) -> int:
  clean = amount_str.replace("$", "").replace(",", "").strip()
  return int(round(float(clean) * 1000))


# =====================================================================
# Intent-Shaped Endpoints
# =====================================================================
@app.get("/", summary="Health check")
async def root():
  return {"status": "online", "service": "YNAB Copilot Middleware"}


@app.get("/ynab/current-context", summary="Household budget state in a single payload")
async def get_current_context():
  await sync_ynab()

  rta_milli = store.month_detail.get("to_be_budgeted", 0)

  checking_balance = 0.0
  for acct in store.accounts.values():
    if not acct.get("closed") and PRIMARY_CHECKING_NAME in acct["name"].lower():
      checking_balance += acct["balance"] / 1000.0

  above_floor = checking_balance - CHECKING_FLOOR

  overspent = []
  for cat in store.categories.values():
    balance_milli = cat.get("balance", 0)
    if balance_milli < 0:
      alias = store.uuid_to_alias.get(cat["id"], cat["name"])
      overspent.append([alias, milli_to_str(balance_milli)])

  today = date.today()
  limit_14d = (today + timedelta(days=14)).isoformat()
  upcoming_14d = []
  for stx in store.scheduled_transactions:
    tx_date = stx.get("date_next", "")
    if today.isoformat() <= tx_date <= limit_14d:
      cat_id = stx.get("category_id")
      funded_status = "unassigned"
      if cat_id and cat_id in store.categories:
        cat_bal = store.categories[cat_id]["balance"]
        if cat_bal >= abs(stx["amount"]):
          funded_status = "fully_funded"
        elif cat_bal > 0:
          funded_status = "partially_funded"
        else:
          funded_status = "unfunded"

      payee = stx.get("payee_name") or "Scheduled Transaction"
      upcoming_14d.append(
          [payee, tx_date, milli_to_str(stx["amount"]), funded_status]
      )

  return {
      "as_of": today.isoformat(),
      "ready_to_assign": milli_to_str(rta_milli),
      "checking": {
          "balance": f"{checking_balance:.2f}",
          "floor": f"{CHECKING_FLOOR:.2f}",
          "above_floor": f"{above_floor:.2f}",
          "floor_breached": above_floor < 0,
      },
      "overspent_categories": overspent,
      "upcoming_obligations_14d": upcoming_14d,
  }


@app.get(
    "/ynab/triage",
    summary="Pending and unapproved transactions formatted for categorization",
)
async def get_triage(format: Literal["csv", "json"] = "csv"):
  await sync_ynab()

  pending = []
  for tx in store.transactions.values():
    if not tx.get("approved") or not tx.get("category_id"):
      ref = store.get_transaction_ref(tx["id"])
      acct_alias = store.uuid_to_alias.get(
          tx.get("account_id", ""), tx.get("account_name", "")
      )
      cat_alias = (
          store.uuid_to_alias.get(tx.get("category_id", ""), "")
          if tx.get("category_id")
          else ""
      )

      pending.append({
          "ref": ref,
          "date": tx.get("date"),
          "account": acct_alias,
          "payee": tx.get("payee_name") or "",
          "amount": milli_to_str(tx.get("amount", 0)),
          "approved": tx.get("approved", False),
          "category": cat_alias,
          "memo": (tx.get("memo") or "").replace(",", " "),
      })

  if format == "json":
    return {"count": len(pending), "transactions": pending}

  lines = ["ref,date,account,payee,amount,approved,category,memo"]
  for row in pending:
    lines.append(
        f"{row['ref']},{row['date']},{row['account']},{row['payee']},{row['amount']},{str(row['approved']).lower()},{row['category']},{row['memo']}"
    )
  return "\n".join(lines)


@app.get(
    "/ynab/merchant/{name}/history",
    summary="Payee category distribution evidence for safe categorization",
)
async def get_merchant_history(name: str):
  await sync_ynab()

  target = name.lower()
  matches = [
      tx
      for tx in store.transactions.values()
      if target in (tx.get("payee_name") or "").lower()
  ]

  distribution: Dict[str, int] = {}
  for tx in matches:
    cid = tx.get("category_id")
    cat_name = (
        store.uuid_to_alias.get(cid, store.categories[cid]["name"])
        if cid and cid in store.categories
        else "Uncategorized"
    )
    distribution[cat_name] = distribution.get(cat_name, 0) + 1

  return {
      "payee_query": name,
      "sample_size": len(matches),
      "category_distribution": distribution,
      "is_single_category": len(distribution) == 1 and len(matches) >= 2,
  }


@app.get(
    "/ynab/cashflow",
    summary="Deterministic cashflow forecast relative to checking floor",
)
async def get_cashflow(days: int = Query(30, ge=7, le=90)):
  await sync_ynab()

  today = date.today()
  end_date = today + timedelta(days=days)

  starting_checking = 0.0
  for acct in store.accounts.values():
    if not acct.get("closed") and PRIMARY_CHECKING_NAME in acct["name"].lower():
      starting_checking += acct["balance"] / 1000.0

  inflows = 0.0
  outflows = 0.0
  running_balance = starting_checking
  lowest_projected = starting_checking

  for stx in sorted(
      store.scheduled_transactions, key=lambda x: x.get("date_next", "")
  ):
    d_str = stx.get("date_next", "")
    if today.isoformat() <= d_str <= end_date.isoformat():
      val = stx["amount"] / 1000.0
      if val > 0:
        inflows += val
      else:
        outflows += val
      running_balance += val
      if running_balance < lowest_projected:
        lowest_projected = running_balance

  min_buffer = lowest_projected - CHECKING_FLOOR
  risk_level = (
      "breached"
      if min_buffer < 0
      else "tight"
      if min_buffer < 300
      else "comfortable"
  )

  return {
      "forecast_days": days,
      "starting_checking": f"{starting_checking:.2f}",
      "known_inflows": f"{inflows:.2f}",
      "known_outflows": f"{outflows:.2f}",
      "lowest_projected_balance": f"{lowest_projected:.2f}",
      "checking_floor": f"{CHECKING_FLOOR:.2f}",
      "minimum_buffer": f"{min_buffer:.2f}",
      "risk": risk_level,
  }


# =====================================================================
# Safe Operations & Write Guardrails
# =====================================================================
class AssignmentRequest(BaseModel):
  category: str = Field(
      ..., description="Category alias (e.g. cat:groceries) or UUID"
  )
  operation: Literal["add", "subtract", "set"]
  amount: str = Field(
      ..., description="Positive decimal currency string, e.g. '50.00'"
  )


@app.post(
    "/ynab/assignment",
    summary="Relative category budget modification preventing replacement bugs",
)
async def safe_assignment(req: AssignmentRequest):
  await sync_ynab()

  cat_uuid = store.resolve_uuid(req.category)
  if cat_uuid not in store.categories:
    raise HTTPException(
        status_code=404, detail=f"Category '{req.category}' not found"
    )

  current_cat = store.categories[cat_uuid]
  current_budgeted_milli = current_cat.get("budgeted", 0)
  delta_milli = str_to_milli(req.amount)

  if req.operation == "add":
    new_budgeted_milli = current_budgeted_milli + delta_milli
  elif req.operation == "subtract":
    new_budgeted_milli = current_budgeted_milli - delta_milli
  else:
    new_budgeted_milli = delta_milli

  current_month_iso = date.today().replace(day=1).isoformat()
  url = (
      f"/budgets/{YNAB_BUDGET_ID}/months/{current_month_iso}/categories/{cat_uuid}"
  )

  async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=10.0) as client:
    resp = await client.patch(
        url,
        headers={"Authorization": f"Bearer {YNAB_API_TOKEN}"},
        json={"category": {"budgeted": new_budgeted_milli}},
    )

    if resp.status_code != 200:
      raise HTTPException(
          status_code=resp.status_code,
          detail=f"YNAB assignment update failed: {resp.text}",
      )

  await sync_ynab(force=True)

  return {
      "category": req.category,
      "previous_assigned": milli_to_str(current_budgeted_milli),
      "new_assigned": milli_to_str(new_budgeted_milli),
      "status": "success",
  }


class TransactionChangeItem(BaseModel):
  ref: str = Field(..., description="Transaction ref (e.g. t:101)")
  category: Optional[str] = Field(
      None, description="Target category alias (e.g. cat:groceries)"
  )
  memo: Optional[str] = Field(None, description="Memo to set on transaction")
  approve: bool = True


class ProposalPayload(BaseModel):
  changes: List[TransactionChangeItem]


@app.post(
    "/ynab/transactions/propose",
    summary="Create a preview proposal before applying writes",
)
async def propose_transaction_changes(payload: ProposalPayload):
  await sync_ynab()

  proposal_id = f"p:{str(uuid.uuid4())[:8]}"
  verified_changes = []

  for item in payload.changes:
    tx_uuid = store.resolve_uuid(item.ref)
    if tx_uuid not in store.transactions:
      raise HTTPException(
          status_code=404, detail=f"Transaction reference {item.ref} not found"
      )

    tx = store.transactions[tx_uuid]
    old_cat_id = tx.get("category_id")
    old_cat_alias = (
        store.uuid_to_alias.get(old_cat_id, "Uncategorized")
        if old_cat_id
        else "Uncategorized"
    )

    new_cat_uuid = (
        store.resolve_uuid(item.category) if item.category else old_cat_id
    )

    verified_changes.append({
        "ref": item.ref,
        "real_tx_id": tx_uuid,
        "payee": tx.get("payee_name"),
        "amount": milli_to_str(tx.get("amount", 0)),
        "current_category": old_cat_alias,
        "target_category_alias": item.category or old_cat_alias,
        "target_category_uuid": new_cat_uuid,
        "new_memo": item.memo if item.memo is not None else tx.get("memo"),
        "approve": item.approve,
    })

  store.proposals[proposal_id] = {
      "created_at": time.time(),
      "changes": verified_changes,
  }

  return {
      "proposal_id": proposal_id,
      "expires_in_minutes": 15,
      "summary": verified_changes,
  }


@app.post(
    "/ynab/transactions/commit/{proposal_id}",
    summary="Execute an approved write proposal",
)
async def commit_transaction_proposal(proposal_id: str):
  if proposal_id not in store.proposals:
    raise HTTPException(
        status_code=404, detail="Proposal not found or has expired"
    )

  proposal = store.proposals.pop(proposal_id)
  headers = {"Authorization": f"Bearer {YNAB_API_TOKEN}"}

  async with httpx.AsyncClient(base_url=YNAB_BASE_URL, timeout=15.0) as client:
    for item in proposal["changes"]:
      patch_data = {
          "category_id": item["target_category_uuid"],
          "approved": item["approve"],
      }
      if item["new_memo"] is not None:
        patch_data["memo"] = item["new_memo"]

      resp = await client.put(
          f"/budgets/{YNAB_BUDGET_ID}/transactions/{item['real_tx_id']}",
          headers=headers,
          json={"transaction": patch_data},
      )

      if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Failed updating {item['ref']}: {resp.text}",
        )

  await sync_ynab(force=True)
  return {
      "status": "committed",
      "proposal_id": proposal_id,
      "records_updated": len(proposal["changes"]),
  }


@app.get("/ynab/policy", summary="Get canonical household policy version")
async def get_policy():
  if os.path.exists("policy.yaml"):
    with open("policy.yaml", "r") as f:
      return yaml.safe_load(f)
  return {"policy_version": "default", "checking_floor": CHECKING_FLOOR}