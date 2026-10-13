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
4. Two-factor login (TOTP) is required for every account. You get ten one-off recovery codes in case you lose your phone; using one emails you and makes you set up two-factor login again.

You can verify this in `public/crypto.js` (all encryption) and `public/app.html` (what is sent to the server). The server code is in `src/worker.js`; it only ever receives ciphertext for vault contents.

## How your nominee gets access

The release design is being finalised during the alpha. **Current alpha behaviour, stated plainly:**

- In the default mode, the vault key is also wrapped with a release key that the service holds. That means **during the alpha we could technically open a vault**. We only release after the checks below, but it is a policy promise, not a cryptographic one. This is one reason alpha testers are asked not to store anything mission critical.
- An optional mode adds a printed code held by the nominee. With it, neither we nor the nominee can open the vault alone.

**The design we are building next** (see the homepage):

- The owner writes three questions only their nominee could answer. The nominee's copy of the vault key is locked with a key made from those answers plus our release share. Any two correct answers unlock it.
- Answers are typed and checked on the nominee's own device and never sent to us. Without them, nobody can open the vault, including us. If the nominee can't answer, the vault cannot be recovered. That is deliberate.
- Release is fully automated, with no human review. Before our share is released, the nominee must pass an AI interview, a passport check against details the owner provided, the owner's proof rules (such as an automatically checked death certificate), and one final check that the owner doesn't respond. Face matching follows in the beta.

## How a nominee asks for access

1. The nominee creates an account by confirming their email address with a 6-digit code (5 wrong tries and the code is dead).
2. They enter the owner's email address. Unless they are one of the owner's listed nominees, with that exact email address, they get the same generic "no match" reply, so the site can't be used to find out who has an account.
3. The owner is alerted straight away by email, text and WhatsApp. One tap from them closes the request.
4. An AI interview, then any proof the owner asked for (such as a death certificate, checked automatically), then a final check period in which we keep trying to reach the owner.

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
node test/ui.mjs     # iPhone-sized browser test, screenshots in shots/
```

## Privacy

See [savemysecrets.com/privacy](https://savemysecrets.com/privacy) and [/terms](https://savemysecrets.com/terms).

## Reporting a security issue

Please email savemysecrets@alamex.com. We'd rather hear about a problem from you than from anyone else.

## Licence

AGPL-3.0. You can read, run and modify this code. If you run a modified version as a service, you must publish your changes too.

Save My Secrets is an Alamex Ltd project.
