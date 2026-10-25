# File Exchange (Cloudflare Workers)

Send and receive files through a Cloudflare Worker. Sign-in uses a one-time
code emailed to an allow-listed address (`youness.sakhi@gmail.com`).

Live: https://files.cf-sakhi.com (also reachable at https://file-exchange.youness-sakhi.workers.dev,
which bypasses the zone's WAF and bot rules)

## How it works

| Piece | Cloudflare product | Binding |
|---|---|---|
| File storage | R2 bucket `file-exchange` | `FILES` |
| OTP codes, sessions, share and upload links | KV namespace `file-exchange-auth` | `AUTH` |
| OTP emails from `noreply@cf-sakhi.com` | Email Service (Email Sending) | `EMAIL` |

**Sign-in.** Enter your email and the Worker emails a 6-digit code. The code is
valid for 10 minutes and allows 5 attempts, and you can request a new one once a
minute. Only a salted SHA-256 hash of the code is stored. A correct code starts a
12-hour session in an `HttpOnly; Secure; SameSite=Strict` cookie. If you enter an
address that is not allowed, the page shows the same message but no email is sent.

**Sending files.** Upload files by dragging them onto the page or using the file
picker. Files over 20 MB are uploaded in parallel R2 multipart chunks, so large
files work. To give someone a file, use **Share** to create a download link that
expires and can optionally allow a set number of downloads.

**Receiving files.** Use **Receive files from someone** to create an upload link.
Anyone with the link can upload into `inbox/<label>/` until it expires, without
signing in. They can't see or download anything.

You can revoke any link from **Active links**.

## Configuration

`wrangler.jsonc`:

- `ALLOWED_EMAILS` is a comma-separated list of addresses allowed to sign in.
- `MAIL_FROM` is the sender address. It must be on a domain onboarded to Email Sending.
- `send_email.allowed_destination_addresses` also limits the binding to those
  addresses. Keep it in sync with `ALLOWED_EMAILS`.

## Develop and deploy

```bash
npm install
npm run dev      # local; emails are printed to the console instead of being sent
npm run deploy   # wrangler deploy (needs `wrangler login` or CLOUDFLARE_API_TOKEN)
```

## API

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/request` `{email}` | none | Email a sign-in code |
| `POST /api/auth/verify` `{email, code}` | none | Start a session |
| `POST /api/auth/logout` | session | End the session |
| `GET /api/files` | session | List files |
| `GET /api/file?key=` / `DELETE /api/file?key=` | session | Download / delete |
| `PUT /api/upload/single?name=` | session or upload link | Upload a file of up to 20 MB |
| `POST /api/upload/create`, `PUT /api/upload/part`, `POST /api/upload/complete`, `POST /api/upload/abort` | session or upload link | Multipart upload |
| `POST /api/share` `{key, hours, maxDownloads}` | session | Create download link `/s/<token>` |
| `POST /api/upload-link` `{label, hours}` | session | Create upload link `/u/<token>` |
| `GET /api/links` / `DELETE /api/links?id=` | session | List / revoke links |

Every non-GET API call must send the header `x-fx: 1`. This blocks CSRF, along
with the SameSite cookie. Upload-link calls send the link token in
`x-upload-token`.
