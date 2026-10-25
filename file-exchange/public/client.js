"use strict";

const CHUNK = 20 * 1024 * 1024; // R2 multipart part size (min 5 MiB, all parts equal except the last)
const PARALLEL = 3;

const $ = (id) => document.getElementById(id);
const guestToken = location.pathname.startsWith("/u/") ? location.pathname.slice(3) : null;

async function api(path, opts = {}) {
  const headers = { "x-fx": "1", ...(opts.headers || {}) };
  if (guestToken) headers["x-upload-token"] = guestToken;
  if (opts.json !== undefined) {
    headers["content-type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : {};
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 3500);
}

function fmtSize(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
const fmtDate = (d) => new Date(d).toLocaleString();

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

/* ------------------------------------------------------------------ auth */

let pendingEmail = "";

$("email-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  btn.disabled = true;
  setLoginMsg("");
  pendingEmail = $("email").value.trim();
  try {
    const r = await api("/api/auth/request", { method: "POST", json: { email: pendingEmail } });
    $("code-to").textContent = pendingEmail;
    $("email-form").hidden = true;
    $("code-form").hidden = false;
    $("code").focus();
    setLoginMsg(r.message);
  } catch (e) {
    setLoginMsg(e.message, true);
  } finally {
    btn.disabled = false;
  }
});

$("code-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  btn.disabled = true;
  try {
    await api("/api/auth/verify", { method: "POST", json: { email: pendingEmail, code: $("code").value.trim() } });
    $("code").value = "";
    setLoginMsg("");
    await boot();
  } catch (e) {
    setLoginMsg(e.message, true);
  } finally {
    btn.disabled = false;
  }
});

$("back").addEventListener("click", () => {
  $("code-form").hidden = true;
  $("email-form").hidden = false;
  setLoginMsg("");
});

$("logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" }).catch(() => {});
  location.reload();
});

function setLoginMsg(msg, err = false) {
  $("login-msg").textContent = msg || "";
  $("login-msg").className = err ? "msg err" : "msg";
}

/* ---------------------------------------------------------------- upload */

function xhrPut(url, body, contentType, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("PUT", url);
    x.setRequestHeader("x-fx", "1");
    if (guestToken) x.setRequestHeader("x-upload-token", guestToken);
    if (contentType) x.setRequestHeader("content-type", contentType);
    x.upload.onprogress = (e) => onProgress(e.loaded);
    x.onload = () => {
      let data = {};
      try { data = JSON.parse(x.responseText); } catch {}
      x.status < 300 ? resolve(data) : reject(new Error(data.error || `HTTP ${x.status}`));
    };
    x.onerror = () => reject(new Error("Network error"));
    x.send(body);
  });
}

async function uploadFile(file, container) {
  const bar = el("i");
  const label = el("span", {}, `${file.name} — 0%`);
  const row = el("div", { class: "prog" }, label, el("div", { class: "bar" }, bar));
  container.prepend(row);
  const show = (loaded) => {
    const pct = file.size ? Math.min(100, Math.round((loaded / file.size) * 100)) : 100;
    bar.style.width = pct + "%";
    label.textContent = `${file.name} — ${pct}% of ${fmtSize(file.size)}`;
  };

  try {
    if (file.size <= CHUNK) {
      await xhrPut(`/api/upload/single?name=${encodeURIComponent(file.name)}`, file, file.type || "application/octet-stream", show);
    } else {
      const { key, uploadId } = await api("/api/upload/create", { method: "POST", json: { name: file.name, type: file.type } });
      const count = Math.ceil(file.size / CHUNK);
      const loaded = new Array(count).fill(0);
      const parts = [];
      let next = 0;
      const worker = async () => {
        while (next < count) {
          const i = next++;
          const blob = file.slice(i * CHUNK, Math.min(file.size, (i + 1) * CHUNK));
          const q = `key=${encodeURIComponent(key)}&uploadId=${encodeURIComponent(uploadId)}&part=${i + 1}`;
          let attempt = 0;
          for (;;) {
            try {
              parts[i] = await xhrPut(`/api/upload/part?${q}`, blob, "application/octet-stream", (l) => {
                loaded[i] = l;
                show(loaded.reduce((a, b) => a + b, 0));
              });
              break;
            } catch (e) {
              if (++attempt >= 3) throw e;
            }
          }
        }
      };
      try {
        await Promise.all(Array.from({ length: Math.min(PARALLEL, count) }, worker));
        await api("/api/upload/complete", { method: "POST", json: { key, uploadId, parts } });
      } catch (e) {
        api("/api/upload/abort", { method: "POST", json: { key, uploadId } }).catch(() => {});
        throw e;
      }
    }
    show(file.size);
    label.textContent = `${file.name} — uploaded (${fmtSize(file.size)})`;
    return true;
  } catch (e) {
    row.classList.add("err");
    label.textContent = `${file.name} — failed: ${e.message}`;
    return false;
  }
}

function wireDrop(dropId, inputId, progressId, after) {
  const drop = $(dropId);
  const input = $(inputId);
  const run = async (files) => {
    for (const f of files) await uploadFile(f, $(progressId));
    after && after();
  };
  input.addEventListener("change", () => { run([...input.files]); input.value = ""; });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => run([...e.dataTransfer.files]));
}

/* ----------------------------------------------------------------- files */

async function loadFiles() {
  const { files } = await api("/api/files");
  const tbody = $("files");
  tbody.replaceChildren();
  $("empty").hidden = files.length > 0;
  for (const f of files) {
    const dl = `/api/file?key=${encodeURIComponent(f.key)}`;
    tbody.append(
      el("tr", {},
        el("td", { class: "name", title: f.by ? `Uploaded by ${f.by}` : "" }, el("a", { href: dl }, f.key)),
        el("td", {}, fmtSize(f.size)),
        el("td", {}, fmtDate(f.uploaded)),
        el("td", { class: "actions" },
          el("button", { class: "ghost small", onclick: () => openShare(f.key) }, "Share"),
          el("button", { class: "ghost small danger", onclick: () => removeFile(f.key) }, "Delete"),
        ),
      ),
    );
  }
}

async function removeFile(key) {
  if (!confirm(`Delete ${key}?`)) return;
  try {
    await api(`/api/file?key=${encodeURIComponent(key)}`, { method: "DELETE" });
    loadFiles();
  } catch (e) { toast(e.message); }
}

let shareKey = "";
function openShare(key) {
  shareKey = key;
  $("share-name").textContent = key.split("/").pop();
  $("share-dlg").showModal();
}

$("share-dlg").addEventListener("close", async () => {
  if ($("share-dlg").returnValue !== "ok") return;
  try {
    const r = await api("/api/share", { method: "POST", json: { key: shareKey, hours: Number($("share-hours").value), maxDownloads: Number($("share-max").value) } });
    await copy(r.url);
    loadLinks();
  } catch (e) { toast(e.message); }
});

$("ulink-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/upload-link", { method: "POST", json: { label: $("ulink-label").value, hours: Number($("ulink-hours").value) } });
    $("ulink-label").value = "";
    await copy(r.url);
    loadLinks();
  } catch (e) { toast(e.message); }
});

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`Link copied: ${text}`);
  } catch {
    prompt("Copy this link:", text);
  }
}

async function loadLinks() {
  const { links } = await api("/api/links");
  const tbody = $("links");
  tbody.replaceChildren();
  if (!links.length) tbody.append(el("tr", {}, el("td", { colspan: "4", class: "muted" }, "No active links.")));
  for (const l of links) {
    tbody.append(
      el("tr", {},
        el("td", {}, l.type === "upload" ? "Upload" : "Download"),
        el("td", { class: "name" }, l.type === "upload" ? `inbox/${l.label}/` : l.key || ""),
        el("td", {}, l.expires ? fmtDate(l.expires) : ""),
        el("td", { class: "actions" },
          el("button", {
            class: "ghost small danger",
            onclick: async () => {
              await api(`/api/links?id=${encodeURIComponent(l.id)}`, { method: "DELETE" }).catch((e) => toast(e.message));
              loadLinks();
            },
          }, "Revoke"),
        ),
      ),
    );
  }
}

$("refresh").addEventListener("click", loadFiles);
$("refresh-links").addEventListener("click", loadLinks);

/* ------------------------------------------------------------------ boot */

async function boot() {
  if (guestToken) {
    $("guest").hidden = false;
    try {
      const g = await api("/api/guest");
      $("guest-info").textContent = `Files you add here are delivered securely. This link expires ${fmtDate(g.expires)}.`;
      wireDrop("guest-drop", "guest-input", "guest-progress");
    } catch (e) {
      $("guest-info").textContent = e.message;
      $("guest-drop").hidden = true;
    }
    return;
  }
  const { email } = await api("/api/me");
  $("login").hidden = !!email;
  $("app").hidden = !email;
  $("who").hidden = !email;
  if (email) {
    $("who-email").textContent = email;
    await Promise.all([loadFiles(), loadLinks()]);
  }
}

if (!guestToken) wireDrop("drop", "file-input", "progress", loadFiles);
boot().catch((e) => toast(e.message));
