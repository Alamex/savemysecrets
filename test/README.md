# End-to-End Testing

This directory contains comprehensive end-to-end tests for Save My Secrets.

## Prerequisites

```bash
npm install -D wrangler playwright @playwright/test
npx playwright install chromium
```

## Running Tests Locally

### 1. Start the development server

```bash
# Initialize local database
npx wrangler d1 execute savemysecrets --local --file=schema.sql

# Create dev secrets
echo 'APP_SECRET=dev-secret-local-only
ADMIN_TOKEN=admin-dev-token' > .dev.vars

# Start dev server (in background or separate terminal)
npx wrangler pages dev public --port 8787
```

### 2. Run API tests

The comprehensive API test suite (`e2e.mjs`) tests all backend functionality:

```bash
# Run against local server
node test/e2e.mjs

# Or specify custom URL and admin token
B=http://localhost:8787 ADM=admin-dev-token node test/e2e.mjs
```

This tests:
- Waitlist and invites
- User registration and 2FA setup
- Vault encryption and sealing
- Nominee management
- Nominee questions (answer-based vault keys)
- Check-in escalation timeline
- Full claim flow (claimant verification, AI interview, document upload, admin approval)
- Veto window and release
- Recovery codes
- Rate limiting

### 3. Run UI tests

The Playwright UI test suite (`full-e2e-playwright.mjs`) tests the interface on desktop and mobile:

```bash
# Run against local server
BASE_URL=http://localhost:8787 ADM=admin-dev-token node test/full-e2e-playwright.mjs
```

This tests:
- UI loads correctly on desktop (1280x720) and mobile (390x844) viewports
- All user journeys through the interface
- No SMS/WhatsApp mentions (email-only)
- Manual review messaging is present
- No passport/ID verification promises
- Screenshots saved to `./test-screenshots/`

### 4. Other test files

- `journey.mjs` - Full owner journey from signup to vault management
- `ui.mjs` - Mobile UI test with screenshots
- `nominee-ui.mjs` - Nominee-specific UI flows

Run them with:
```bash
node test/journey.mjs
node test/ui.mjs
```

## Testing Against Production

Never run tests against the production database. To test a deployed site:

```bash
# Read-only tests only
B=https://your-preview.savemysecrets.pages.dev ADM=your-admin-token node test/e2e.mjs
```

## CI/CD Integration

These tests can be integrated into CI:

```bash
#!/bin/bash
set -e

# Start local dev server
npx wrangler d1 execute savemysecrets --local --file=schema.sql
echo 'APP_SECRET=ci-test-secret
ADMIN_TOKEN=ci-admin-token' > .dev.vars
npx wrangler pages dev public --port 8787 &
DEV_PID=$!

# Wait for server
sleep 10

# Run tests
B=http://localhost:8787 ADM=ci-admin-token node test/e2e.mjs
TEST_EXIT=$?

# Cleanup
kill $DEV_PID

exit $TEST_EXIT
```

## Test Output

- **e2e.mjs**: Console output with PASS/FAIL for each test
- **full-e2e-playwright.mjs**: Console output + screenshots in `test-screenshots/`
- Exit code 0 = all pass, 1 = at least one failure

## Known Test Requirements

- Tests create users with timestamp-based email addresses
- Admin token must match `.dev.vars` ADMIN_TOKEN
- Local D1 database must be seeded with schema.sql
- Tests are idempotent (can run multiple times)
