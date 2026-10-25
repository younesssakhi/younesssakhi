// File exchange on Cloudflare Workers.
// Files live in R2, OTP codes / sessions / links live in KV, and one-time
// codes are emailed through the Cloudflare Email Service `send_email` binding.

import INDEX_HTML from "../public/index.html";
import APP_JS from "../public/client.js";
import APP_CSS from "../public/app.css";

const OTP_TTL = 600; // seconds a code stays valid
const OTP_COOLDOWN = 60; // seconds between two code requests
const OTP_MAX_ATTEMPTS = 5;
const SESSION_TTL = 12 * 3600;
const COOKIE = "__Host-fx_session";

export default {
  async fetch(request, env, ctx) {
    try {
      const res = await route(request, env, ctx);
      return withSecurityHeaders(res);
    } catch (err) {
      if (err instanceof HttpError) return withSecurityHeaders(json({ error: err.message }, err.status));
      console.error(err);
      return withSecurityHeaders(json({ error: "Internal error" }, 500));
    }
  },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  // Static UI
  if (method === "GET" && (pathname === "/" || pathname.startsWith("/u/"))) {
    return new Response(INDEX_HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
  }
  if (method === "GET" && pathname === "/app.js") {
    return new Response(APP_JS, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" } });
  }
  if (method === "GET" && pathname === "/app.css") {
    return new Response(APP_CSS, { headers: { "content-type": "text/css; charset=utf-8", "cache-control": "no-cache" } });
  }

  // Public share download
  if (method === "GET" && pathname.startsWith("/s/")) return shareDownload(env, pathname.slice(3));

  if (!pathname.startsWith("/api/")) return json({ error: "Not found" }, 404);

  // Every state-changing API call must come from our own page (CSRF guard on top of SameSite=Strict).
  if (method !== "GET" && request.headers.get("x-fx") !== "1") throw new HttpError(403, "Missing request header");

  // Auth
  if (pathname === "/api/auth/request" && method === "POST") return otpRequest(request, env, ctx);
  if (pathname === "/api/auth/verify" && method === "POST") return otpVerify(request, env);
  if (pathname === "/api/auth/logout" && method === "POST") return logout(request, env);
  if (pathname === "/api/me" && method === "GET") {
    const s = await getSession(request, env);
    return json({ email: s ? s.email : null });
  }

  // Guest upload-link info
  if (pathname === "/api/guest" && method === "GET") {
    const g = await getGuest(request, env);
    if (!g) throw new HttpError(404, "This upload link is invalid or has expired");
    return json({ label: g.label, expires: g.expires });
  }

  // Uploads: owner (session) or guest (upload link token)
  if (pathname.startsWith("/api/upload/")) {
    const actor = await requireActor(request, env);
    return upload(request, env, url, actor);
  }

  // Owner-only API
  const session = await getSession(request, env);
  if (!session) throw new HttpError(401, "Not signed in");

  if (pathname === "/api/files" && method === "GET") return listFiles(env, url);
  if (pathname === "/api/file" && method === "GET") return ownerDownload(env, url);
  if (pathname === "/api/file" && method === "DELETE") {
    await env.FILES.delete(requireKey(url.searchParams.get("key")));
    return json({ ok: true });
  }
  if (pathname === "/api/share" && method === "POST") return createShare(request, env, url);
  if (pathname === "/api/upload-link" && method === "POST") return createUploadLink(request, env, url);
  if (pathname === "/api/links" && method === "GET") return listLinks(env);
  if (pathname === "/api/links" && method === "DELETE") {
    const id = url.searchParams.get("id") || "";
    if (!/^(share|ulink):[A-Za-z0-9_-]{20,}$/.test(id)) throw new HttpError(400, "Bad link id");
    await env.AUTH.delete(id);
    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
}

/* ---------------------------------------------------------------- OTP auth */

function allowedEmails(env) {
  return (env.ALLOWED_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
}

async function otpRequest(request, env, ctx) {
  const { email } = await readJson(request);
  const addr = String(email || "").trim().toLowerCase();
  // Same answer whether or not the address is allowed, so the endpoint can't be used to probe for accounts.
  const generic = json({ ok: true, message: "If this address is allowed, a code has been sent." });
  if (!allowedEmails(env).includes(addr)) return generic;

  const cooldownKey = `otp_cd:${addr}`;
  if (await env.AUTH.get(cooldownKey)) throw new HttpError(429, "Please wait a minute before requesting another code");

  const code = String(randomInt(1_000_000)).padStart(6, "0");
  const salt = randomToken(16);
  await env.AUTH.put(`otp:${addr}`, JSON.stringify({ salt, hash: await sha256(`${salt}:${code}`), attempts: 0 }), { expirationTtl: OTP_TTL });
  await env.AUTH.put(cooldownKey, "1", { expirationTtl: OTP_COOLDOWN });

  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  await env.EMAIL.send({
    to: addr,
    from: { email: env.MAIL_FROM, name: env.APP_NAME || "File Exchange" },
    subject: `${code} is your ${env.APP_NAME || "File Exchange"} sign-in code`,
    text: `Your sign-in code is ${code}\n\nIt expires in ${OTP_TTL / 60} minutes.\nRequested from IP ${ip}.\nIf you did not request it, ignore this email.`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:420px">
      <p>Your sign-in code for <b>${escapeHtml(env.APP_NAME || "File Exchange")}</b>:</p>
      <p style="font-size:32px;font-weight:700;letter-spacing:8px;margin:16px 0">${code}</p>
      <p style="color:#666">It expires in ${OTP_TTL / 60} minutes. Requested from IP ${escapeHtml(ip)}.<br>If you did not request it, ignore this email.</p>
    </div>`,
  });
  return generic;
}

async function otpVerify(request, env) {
  const { email, code } = await readJson(request);
  const addr = String(email || "").trim().toLowerCase();
  const key = `otp:${addr}`;
  const raw = await env.AUTH.get(key);
  if (!raw) throw new HttpError(401, "Code expired or not requested");
  const rec = JSON.parse(raw);

  const ok = /^\d{6}$/.test(String(code || "")) && timingSafeEqualHex(await sha256(`${rec.salt}:${code}`), rec.hash);
  if (!ok) {
    rec.attempts += 1;
    if (rec.attempts >= OTP_MAX_ATTEMPTS) await env.AUTH.delete(key);
    else await env.AUTH.put(key, JSON.stringify(rec), { expirationTtl: OTP_TTL });
    throw new HttpError(401, rec.attempts >= OTP_MAX_ATTEMPTS ? "Too many attempts, request a new code" : "Wrong code");
  }
  await env.AUTH.delete(key);

  const token = randomToken(32);
  await env.AUTH.put(`sess:${await sha256(token)}`, JSON.stringify({ email: addr, created: Date.now() }), { expirationTtl: SESSION_TTL });
  return json({ ok: true, email: addr }, 200, {
    "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`,
  });
}

async function logout(request, env) {
  const token = getCookie(request, COOKIE);
  if (token) await env.AUTH.delete(`sess:${await sha256(token)}`);
  return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
}

async function getSession(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || !/^[A-Za-z0-9_-]{20,}$/.test(token)) return null;
  const raw = await env.AUTH.get(`sess:${await sha256(token)}`);
  return raw ? JSON.parse(raw) : null;
}

async function getGuest(request, env) {
  const token = request.headers.get("x-upload-token") || "";
  if (!/^[A-Za-z0-9_-]{20,}$/.test(token)) return null;
  const raw = await env.AUTH.get(`ulink:${token}`);
  return raw ? JSON.parse(raw) : null;
}

async function requireActor(request, env) {
  const s = await getSession(request, env);
  if (s) return { kind: "owner", email: s.email, prefix: "" };
  const g = await getGuest(request, env);
  if (g) return { kind: "guest", email: `guest:${g.label}`, prefix: g.prefix };
  throw new HttpError(401, "Not signed in");
}

/* ------------------------------------------------------------------ files */

async function listFiles(env, url) {
  const prefix = url.searchParams.get("prefix") || "";
  const files = [];
  let cursor;
  do {
    const page = await env.FILES.list({ prefix, cursor, include: ["httpMetadata", "customMetadata"] });
    for (const o of page.objects) {
      files.push({ key: o.key, size: o.size, uploaded: o.uploaded, type: o.httpMetadata?.contentType || "", by: o.customMetadata?.by || "" });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  files.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
  return json({ files });
}

async function ownerDownload(env, url) {
  const key = requireKey(url.searchParams.get("key"));
  return serveObject(env, key);
}

async function serveObject(env, key) {
  const obj = await env.FILES.get(key);
  if (!obj) throw new HttpError(404, "File not found");
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("content-length", String(obj.size));
  headers.set("content-disposition", contentDisposition(key.split("/").pop()));
  if (!headers.get("content-type")) headers.set("content-type", "application/octet-stream");
  headers.set("cache-control", "private, no-store");
  return new Response(obj.body, { headers });
}

async function upload(request, env, url, actor) {
  const action = url.pathname.slice("/api/upload/".length);
  const method = request.method;

  if (action === "single" && method === "PUT") {
    const key = buildKey(actor, url.searchParams.get("name"));
    const type = request.headers.get("content-type") || "application/octet-stream";
    await env.FILES.put(key, request.body, { httpMetadata: { contentType: type }, customMetadata: { by: actor.email } });
    return json({ ok: true, key });
  }
  if (action === "create" && method === "POST") {
    const { name, type } = await readJson(request);
    const key = buildKey(actor, name);
    const mpu = await env.FILES.createMultipartUpload(key, {
      httpMetadata: { contentType: type || "application/octet-stream" },
      customMetadata: { by: actor.email },
    });
    return json({ key: mpu.key, uploadId: mpu.uploadId });
  }
  if (action === "part" && method === "PUT") {
    const key = ownKey(actor, url.searchParams.get("key"));
    const uploadId = url.searchParams.get("uploadId");
    const partNumber = Number(url.searchParams.get("part"));
    if (!uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) throw new HttpError(400, "Bad part");
    if (!request.body) throw new HttpError(400, "Missing body");
    const part = await env.FILES.resumeMultipartUpload(key, uploadId).uploadPart(partNumber, request.body);
    return json(part);
  }
  if (action === "complete" && method === "POST") {
    const { key, uploadId, parts } = await readJson(request);
    const k = ownKey(actor, key);
    if (!Array.isArray(parts) || !parts.length) throw new HttpError(400, "Missing parts");
    const obj = await env.FILES.resumeMultipartUpload(k, uploadId).complete(parts);
    return json({ ok: true, key: obj.key, size: obj.size });
  }
  if (action === "abort" && method === "POST") {
    const { key, uploadId } = await readJson(request);
    await env.FILES.resumeMultipartUpload(ownKey(actor, key), uploadId).abort();
    return json({ ok: true });
  }
  throw new HttpError(404, "Not found");
}

// Object key for a new upload: owners write under files/, guests under their link's inbox prefix.
function buildKey(actor, name) {
  const clean = sanitizeName(name);
  if (!clean) throw new HttpError(400, "Missing file name");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return actor.kind === "owner" ? `files/${clean}` : `${actor.prefix}${stamp}_${clean}`;
}

function ownKey(actor, key) {
  const k = requireKey(key);
  if (actor.kind === "guest" && !k.startsWith(actor.prefix)) throw new HttpError(403, "Forbidden");
  return k;
}

function requireKey(key) {
  if (!key || key.length > 1024 || key.includes("..") || key.startsWith("/")) throw new HttpError(400, "Bad key");
  return key;
}

function sanitizeName(name) {
  return String(name || "")
    .split(/[\\/]/).pop()
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/^\.+/, "")
    .trim()
    .slice(0, 200);
}

/* ------------------------------------------------------------------ links */

async function createShare(request, env, url) {
  const { key, hours, maxDownloads } = await readJson(request);
  const k = requireKey(key);
  const head = await env.FILES.head(k);
  if (!head) throw new HttpError(404, "File not found");
  const ttl = clampHours(hours) * 3600;
  const token = randomToken(24);
  const rec = { key: k, expires: Date.now() + ttl * 1000, maxDownloads: Number(maxDownloads) > 0 ? Number(maxDownloads) : 0, downloads: 0 };
  await env.AUTH.put(`share:${token}`, JSON.stringify(rec), { expirationTtl: ttl, metadata: { type: "share", key: k, expires: rec.expires } });
  return json({ url: `${url.origin}/s/${token}`, expires: rec.expires });
}

async function shareDownload(env, token) {
  if (!/^[A-Za-z0-9_-]{20,}$/.test(token)) throw new HttpError(404, "Link not found");
  const id = `share:${token}`;
  const raw = await env.AUTH.get(id);
  if (!raw) return htmlMessage("This link is invalid or has expired.", 404);
  const rec = JSON.parse(raw);
  if (rec.maxDownloads) {
    // KV is eventually consistent, so the limit is best-effort rather than exact.
    rec.downloads += 1;
    if (rec.downloads >= rec.maxDownloads) await env.AUTH.delete(id);
    else {
      const ttl = Math.max(60, Math.floor((rec.expires - Date.now()) / 1000));
      await env.AUTH.put(id, JSON.stringify(rec), { expirationTtl: ttl, metadata: { type: "share", key: rec.key, expires: rec.expires } });
    }
  }
  return serveObject(env, rec.key);
}

async function createUploadLink(request, env, url) {
  const { label, hours } = await readJson(request);
  const clean = sanitizeName(label).replace(/[^\w .@-]/g, "").slice(0, 60) || "guest";
  const ttl = clampHours(hours) * 3600;
  const token = randomToken(24);
  const rec = { label: clean, prefix: `inbox/${clean}/`, expires: Date.now() + ttl * 1000 };
  await env.AUTH.put(`ulink:${token}`, JSON.stringify(rec), { expirationTtl: ttl, metadata: { type: "upload", label: clean, expires: rec.expires } });
  return json({ url: `${url.origin}/u/${token}`, expires: rec.expires });
}

async function listLinks(env) {
  const links = [];
  for (const prefix of ["share:", "ulink:"]) {
    let cursor;
    do {
      const page = await env.AUTH.list({ prefix, cursor });
      for (const k of page.keys) links.push({ id: k.name, ...(k.metadata || {}) });
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
  }
  return json({ links });
}

function clampHours(h) {
  const n = Number(h);
  return Math.min(Math.max(Number.isFinite(n) && n > 0 ? n : 24, 1), 24 * 30);
}

/* ---------------------------------------------------------------- helpers */

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });
}

function htmlMessage(msg, status) {
  return new Response(`<!doctype html><meta charset="utf-8"><title>File Exchange</title><p style="font-family:system-ui;padding:2rem">${escapeHtml(msg)}</p>`, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function withSecurityHeaders(res) {
  const r = new Response(res.body, res);
  r.headers.set("x-content-type-options", "nosniff");
  r.headers.set("referrer-policy", "no-referrer");
  r.headers.set("x-frame-options", "DENY");
  r.headers.set("strict-transport-security", "max-age=31536000");
  r.headers.set("content-security-policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  return r;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function contentDisposition(filename) {
  const ascii = filename.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

function randomToken(bytes) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Uniform random integer in [0, max) without modulo bias.
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % max;
}

async function sha256(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  const enc = new TextEncoder();
  return crypto.subtle.timingSafeEqual(enc.encode(a), enc.encode(b));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
