# YNAB Budget Copilot Middleware

FastAPI middleware that combines YNAB budget data with read-only Plaid bank data,
reconciliation, cash-flow diagnostics, and guarded YNAB write proposals.

## v3.6 architecture

The middleware supports multiple Plaid Items at the same time (for example Wells
Fargo, Citi, Chase, Bank of America, and other Plaid-supported institutions).

When `DATABASE_URL` is configured, the middleware automatically persists:

- Plaid Item IDs and access tokens
- institution metadata
- Plaid-account-to-YNAB-account mappings
- explicit external-account exclusions (for example a business account)

The older `PLAID_ACCESS_TOKEN`, `PLAID_ITEM_ID`, `PLAID_ITEMS_JSON`, and
`PLAID_YNAB_ACCOUNT_MAP` variables are still accepted as migration seeds. Database
rows win after migration.

No Plaid access token, Plaid secret, YNAB API token, middleware API key, or
database credential should ever be committed to Git.

## Railway deployment

1. Deploy this repository to Railway.
2. Add a PostgreSQL service to the same Railway project.
3. Link/reference the PostgreSQL service from the middleware so Railway provides
   `DATABASE_URL`.
4. Keep the existing required Railway variables:
   `YNAB_API_TOKEN`, `YNAB_BUDGET_ID`, `MIDDLEWARE_API_KEY`, `REF_SECRET`,
   `PLAID_CLIENT_ID`, `PLAID_SECRET`, and `PLAID_ENV`.
5. Redeploy.

On startup, the app creates its persistence tables automatically. Existing legacy
Plaid Item and account-map variables are inserted only if the corresponding
database rows do not already exist.

## Connecting institutions

1. Call `createPlaidHostedLink`.
2. Complete the hosted Plaid flow.
3. Call `exchangePlaidHostedLink` with the completed Link token.
4. With PostgreSQL enabled, the resulting Item is persisted automatically.
5. Call `getPlaidMappings` to see every discovered external account alongside
   every active YNAB account.
6. Call `setPlaidAccountMapping` for each household account.
7. To keep an account visible but outside household reconciliation, set
   `include_in_household=false`.

`syncPlaidTransactions` then syncs every active Plaid Item and reconciles only
mapped household accounts. Excluded accounts remain visible in diagnostics but
are not treated as household spending.

## Safety

Plaid reads never write to YNAB.

YNAB transaction/category writes remain proposal-based:

1. stage with a proposal endpoint;
2. review the returned proposal;
3. commit only through the explicit commit endpoint.

The middleware intentionally exposes no direct bypass around this workflow.

## Local start

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Use `.env.example` only as a variable-name reference. Do not place real secrets
in the repository.
