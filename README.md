# Save My Secrets

Leave what matters to the people who matter. Save My Secrets is a digital legacy vault: you store personal messages, final wishes, passwords, account details and documents, name the people who should receive them, and we pass them on only when it's truly time.

Live at [savemysecrets.com](https://savemysecrets.com). **This is an alpha.** Please don't store anything mission critical yet.

We publish all of our code so that anyone can check how your data is handled, rather than taking our word for it.

## How your data is protected

**Your vault is encrypted before it leaves your phone or laptop.**

1. When you create an account, your browser turns your master password into two keys (PBKDF2-SHA256, 600,000 iterations, see `public/crypto.js`):
   - an **authentication key**, which is sent to us and hashed again on our side, so we can check it's you;
   - an **owner key**, which never leaves your device.
2. Your vault is encrypted with a random **vault key** using AES-256-GCM, in your browser.
3. The vault key is itself encrypted with your owner key. We store only the encrypted vault and the encrypted vault key, and neither is readable without your master password.
4. Two-factor login (TOTP) is strongly recommended and is the default next step at signup. Owners can choose "Skip for now" and turn it on later from the dashboard (always with a fresh secret); once on, it can't be turned off. With 2FA on you get ten one-off recovery codes in case you lose your phone; using one emails you and makes you set up two-factor login again (skipping isn't offered then). The admin area is separate and uses its own admin token.

You can verify this in `public/crypto.js` (all encryption) and `public/app.html` (what is sent to the server). The server code is in `src/worker.js`; it only ever receives ciphertext for vault contents.

## How your nominee gets access

- **Nominee questions (required for every nominee).** When adding each nominee the owner writes three questions. For every pair of answers (any two of three), and every alternative spelling the owner lists, the browser wraps the vault key with a key made from our server share plus the two answers (`PBKDF2-SHA256`, 200,000 iterations per answer, then `SHA-256`). See `buildNomineeKeys` in `public/crypto.js`. The answers never leave the owner's or nominee's device.
- **We never hold a copy we could open.** New vaults are sealed with no release copy of the vault key, and a nominee can only be added together with their questions. Vaults sealed before this change kept a standard-mode copy; it is still deleted automatically once every nominee has questions, and the owner is asked to set them.
- **Release:** after the checks, the nominee sees the questions and types answers on their own device. Their browser sends us a proof derived from the answers; if it matches, we release our share and the matching locked copy, and the vault is decrypted in their browser. Wrong answers get escalating waits: two free tries, then an hour, a day, then a week each time. Attempts are counted atomically, so parallel requests can't skip the waits.
- **At rest:** our server share and the answer verifiers are protected with a key held only as a Worker secret, so a copy of the database alone is not enough to test guesses.

**Stated plainly, the limits:**
- Answers are words, not long random codes. Anyone with both our database and our Worker secret (including us, in theory) could try guessing them offline. Choose answers nobody could guess or look up.
- Older vaults only: until every nominee has questions, we hold a copy we could open (standard mode). New vaults never have one.
- The website delivers the encryption code, so you are trusting the code we serve. It is published here so it can be checked.
- If none of a nominee's answers can be recalled, that nominee cannot open the vault. That is deliberate.

## How a nominee asks for access

1. The nominee creates an account by confirming their email address with a 6-digit code (5 wrong tries and the code is dead).
2. They enter the owner's email address. Unless they are one of the owner's listed nominees, with that exact email address, they get the same generic "no match" reply, so the site can't be used to find out who has an account.
3. The owner is alerted straight away by email, text and WhatsApp. One tap from them closes the request.
4. An AI interview, then automated checks, then a final check period in which we keep trying to reach the owner.

Code requests, logins and lookups are rate limited per email address and per IP address.

**Alpha note:** while the release key is still held by us, a release also needs an approval step in our admin tool. It will be removed when nominee questions ship.

## Check-ins

The owner is checked in with on a schedule they choose (monthly to yearly). Missed check-ins are followed up with the owner by email, text and WhatsApp for a period they choose (2 to 12 weeks) before any nominee is contacted. Logging in, tapping the link in a check-in email, or pressing "I'm fine" resets everything and cancels any claim in progress. Check-in links expire after 45 days and work once; using one also cancels any older link.

## Repository layout

| Path | What it is |
|---|---|
| `public/` | The website and app (static HTML, CSS and JavaScript) |
| `public/crypto.js` | All client-side encryption |
| `functions/[[path]].js` | Cloudflare Pages entry point |
| `src/worker.js` | API: accounts, 2FA, vault storage (ciphertext only), nominees, check-ins, claims |
| `schema.sql` | Database schema (Cloudflare D1) |
| `cron/` | Daily scheduled job that runs the check-in escalation |
| `test/` | End-to-end and mobile UI tests (`B=https://... ADM=... node test/e2e.mjs` runs them against a deployed site) |

## Running locally

```
npm i -D wrangler playwright
npx wrangler d1 execute savemysecrets --local --file=schema.sql
printf 'APP_SECRET=dev\nADMIN_TOKEN=admin-dev-token\n' > .dev.vars
npx wrangler dev --port 8787
node test/e2e.mjs
node test/ui.mjs       # iPhone-sized browser test, screenshots in shots/
node test/journey.mjs  # full owner journey: sign up, vault, log out and in, lost-phone recovery
```

## Privacy

See [savemysecrets.com/privacy](https://savemysecrets.com/privacy) and [/terms](https://savemysecrets.com/terms).

## Reporting a security issue

Please email support@savemysecrets.com. We'd rather hear about a problem from you than from anyone else.

## Licence

AGPL-3.0. You can read, run and modify this code. If you run a modified version as a service, you must publish your changes too.

Save My Secrets is an Alamex Ltd project.
