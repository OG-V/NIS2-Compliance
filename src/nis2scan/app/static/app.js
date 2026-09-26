/* NIS2 Evidence Console: walks a consultant through an engagement, step by step. */
"use strict";

// --- helpers ---------------------------------------------------------------------------------
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const icon = (n, cls = "") => `<svg class="i ${cls}"><use href="#i-${n}"/></svg>`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const qs = (o) => new URLSearchParams(o).toString();
const clone = (o) => JSON.parse(JSON.stringify(o));
const plural = (n, word, many = word + "s") => `${n} ${n === 1 ? word : many}`;
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

function fmtDate(iso, withTime = true) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const opts = { day: "numeric", month: "short", year: "numeric" };
  if (withTime) Object.assign(opts, { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleString(undefined, opts);
}
function getPath(obj, path) {
  return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function setPath(obj, path, value) {
  const keys = path.split(".");
  let o = obj;
  keys.slice(0, -1).forEach((k, i) => {
    if (o[k] == null) o[k] = /^\d+$/.test(keys[i + 1]) ? [] : {};
    o = o[k];
  });
  o[keys.at(-1)] = value;
}

let loading = 0;
function busy(delta) {
  loading = Math.max(0, loading + delta);
  $("#loader").classList.toggle("on", loading > 0);
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  busy(1);
  try {
    const r = await fetch(path, opt);
    let data;
    try { data = await r.json(); } catch { data = { error: `The app did not answer (HTTP ${r.status}).` }; }
    if (!r.ok || data.error) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  } finally { busy(-1); }
}

async function runJob(kind, body, onEvent) {
  const { job } = await api(`/api/jobs/${kind}`, body);
  let since = 0;
  busy(1);
  try {
    for (;;) {
      const r = await fetch(`/api/jobs/${job}?since=${since}`);
      const v = await r.json();
      if (v.error && !v.state) throw new Error(v.error);
      since = v.next;
      v.events.forEach((e) => onEvent && onEvent(e));
      if (v.state === "done") return v.result;
      if (v.state === "failed") throw new Error(v.error);
      await sleep(300);
    }
  } finally { busy(-1); }
}

function toast(message, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = icon(kind === "error" ? "alert" : "check") + `<div>${esc(message)}</div>`;
  $("#toasts").append(el);
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 260); },
    kind === "error" ? 7000 : 3200);
}

function withBusy(btn, fn) {
  return async (...args) => {
    btn?.classList.add("busy");
    try { return await fn(...args); }
    catch (e) { toast(e.message, "error"); }
    finally { btn?.classList.remove("busy"); }
  };
}

function countUp(el, to) {
  if (REDUCED || !to) { el.textContent = to; return; }
  const start = performance.now(), dur = 900;
  const tick = (now) => {
    const p = Math.min(1, (now - start) / dur);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// --- state -------------------------------------------------------------------------------------
const S = {
  info: null, schema: null,
  folder: null, win: null, exists: false,
  raw: null, savedJSON: "", problems: [], secrets: {}, pending: {},
  runs: [], step: "home",
  access: null, accessView: null,
  scanView: { phase: "idle" },
  register: null, suggestions: null, docFiles: [], docTab: "setup",
  run: null, reportMode: "report", diffAgainst: null,
};

const STEPS = [
  { id: "engagement", label: "Engagement",
    sub: () => S.raw?.engagement?.client || "Client and authorisation" },
  { id: "systems", label: "Systems in scope",
    sub: () => (systemCount() ? plural(systemCount(), "system") : "What to scan") },
  { id: "documents", label: "Documents & reviews",
    sub: () => (S.raw?.documents?.dir ? (S.register?.reviews?.length
      ? plural(S.register.reviews.length, "review") : "Folder chosen") : "Policies and records") },
  { id: "access", label: "Access check",
    sub: () => (S.access ? (S.access.ready ? "All systems ready" : "Needs attention") : "Test the access granted") },
  { id: "scan", label: "Run scan",
    sub: () => (S.scanView.phase === "running" ? "Scanning…" :
      S.runs.length ? `${plural(S.runs.length, "scan")} so far` : "Collect evidence") },
  { id: "report", label: "Report",
    sub: () => (S.runs.length ? "Latest " + fmtDate(S.runs[0].started_at, false) : "Findings and gaps") },
];

function systemCount() {
  if (!S.raw || !S.schema) return 0;
  return S.schema.sections.reduce((n, s) => n + (S.raw[s.key]?.length || 0), 0);
}
function withLists(raw) {
  for (const s of S.schema.sections) raw[s.key] = raw[s.key] || [];
  return raw;
}
function dirty() {
  return S.raw && (JSON.stringify(S.raw) !== S.savedJSON || Object.keys(S.pending).length > 0);
}
function authState() {
  const e = S.raw?.engagement || {};
  if (!e.client || !e.authorised_by || !e.authorised_on || !e.valid_until) return "incomplete";
  const today = S.info.today;
  if (today < String(e.authorised_on)) return "future";
  if (today > String(e.valid_until)) return "expired";
  return "valid";
}
function stepState(id) {
  if (!S.folder) return "locked";
  const needsTarget = ["access", "scan", "report"].includes(id);
  if (needsTarget && !S.exists) return "locked";
  if (id === "report" && !S.runs.length) return "locked";
  const done = {
    engagement: S.exists && authState() === "valid",
    systems: S.exists && systemCount() > 0,
    documents: S.exists && !!S.raw?.documents?.dir,
    access: S.access?.ready,
    scan: S.runs.length > 0,
    report: false,
  }[id];
  if (id === "access" && S.access && !S.access.ready) return "warn";
  if (id === "engagement" && S.exists && ["expired", "future"].includes(authState())) return "warn";
  return done ? "done" : "";
}

// --- shell -----------------------------------------------------------------------------------------
function renderRail() {
  const items = STEPS.map((s, i) => {
    const st = stepState(s.id);
    const dot = st === "done" ? icon("check") : st === "warn" ? "!" : i + 1;
    return `<li class="step ${st} ${S.step === s.id ? "active" : ""}" data-go="${s.id}"
      ${st === "locked" ? 'aria-disabled="true"' : ""}>
      <span class="dot">${dot}</span>
      <span class="lbl"><b>${esc(s.label)}</b><span>${esc(s.sub())}</span></span></li>`;
  }).join("");
  const foot = S.folder ? `<div class="foot">Engagement folder
      <div class="path">${esc(S.win || S.folder)}</div>
      <a data-act="reveal">Open in Explorer</a> · <a data-act="home">Switch</a></div>`
    : `<div class="foot">Version ${esc(S.info?.version || "")}</div>`;
  $("#rail").innerHTML = `<h6>Engagement steps</h6><ol class="steps">${items}</ol>${foot}`;
  const chip = S.folder && S.raw
    ? `<div class="eng-chip">${icon("folder")}<b>${esc(S.raw.engagement?.client || S.raw.name || "New engagement")}</b></div>` : "";
  $("#engChip").innerHTML = chip;
}

let transitioning = false;
async function go(step, { force = false } = {}) {
  if (transitioning) return;
  if (!force && step !== "home" && stepState(step) === "locked") {
    toast(!S.exists ? "Save the engagement details first." : "Run a scan first.", "error");
    return;
  }
  if (!force && dirty() && ["engagement", "systems", "documents"].includes(S.step) && step !== S.step) {
    const ok = await save(true);
    if (!ok) {
      render();
      toast("Some details need attention before you continue.", "error");
      return;
    }
  }
  transitioning = true;
  const page = $("#main .page");
  if (page && !REDUCED) { page.classList.add("leave"); await sleep(150); }
  S.step = step;
  render();
  $("#main").scrollTop = 0;
  transitioning = false;
  onEnter(step);
}

function render() {
  renderRail();
  const view = VIEWS[S.step] || VIEWS.home;
  $("#main").innerHTML = view();
  const page = $("#main .page");
  page?.classList.add("enter");
  afterRender[S.step]?.();
}

function onEnter(step) {
  if (step === "documents") loadDocuments();
  if (step === "report") loadReport();
}

function pageHead(n, title, lead) {
  return `<div class="eyebrow">Step ${n} of ${STEPS.length}</div><h1>${esc(title)}</h1>
    <p class="lead">${lead}</p>`;
}
function actionbar(back, next, nextLabel = "Continue") {
  const dirtyNote = dirty() ? `<span class="dirty">Unsaved changes</span>` : "";
  return `<div class="actionbar">
    ${back ? `<button class="btn" data-go="${back}">${icon("arrow-left")}Back</button>` : ""}
    <div class="grow"></div>${dirtyNote}
    ${["engagement", "systems", "documents"].includes(S.step)
      ? `<button class="btn" data-act="save">Save</button>` : ""}
    ${next ? `<button class="btn primary" data-go="${next}">${esc(nextLabel)}${icon("arrow-right")}</button>` : ""}
  </div>`;
}
function refreshActionbar() {
  const bar = $(".actionbar");
  if (!bar) return;
  const has = !!$(".dirty", bar);
  if (dirty() && !has) {
    const el = document.createElement("span");
    el.className = "dirty"; el.textContent = "Unsaved changes";
    bar.querySelector(".grow").after(el);
  } else if (!dirty() && has) $(".dirty", bar).remove();
}

// --- fields --------------------------------------------------------------------------------------------
function problemsAt(path) {
  const parts = path.split(".");
  return S.problems.filter((p) => parts.every((k, i) => p.loc[i] === k) && p.loc.length === parts.length)
    .map((p) => p.message);
}
function fieldHTML(f, path, { wide = false } = {}) {
  const value = getPath(S.raw, path);
  const errs = problemsAt(path);
  const req = f.required ? '<span class="req">*</span>' : "";
  const id = "f-" + path.replace(/\W/g, "-");
  let control;
  if (f.kind === "bool") {
    return `<div class="field ${wide ? "wide" : ""}"><label class="switch" for="${id}">
      <input type="checkbox" id="${id}" data-path="${path}" data-kind="bool" ${value ? "checked" : ""}>
      <span class="track"></span><span><b>${esc(f.label)}</b>
      ${f.help ? `<div class="help">${esc(f.help)}</div>` : ""}</span></label></div>`;
  }
  if (f.kind === "textarea") {
    control = `<textarea class="input" id="${id}" data-path="${path}">${esc(value)}</textarea>`;
  } else if (f.kind === "secret") {
    const pending = S.pending[path];
    const state = pending ? `<span class="secret-state ok">Will be saved</span>`
      : value && S.secrets[value] ? `<span class="secret-state ok">${icon("lock")}Stored</span>`
      : value ? `<span class="secret-state missing">Not set</span>` : "";
    control = `<input class="input" type="password" id="${id}" data-secret="${path}" autocomplete="new-password"
      value="${esc(pending || "")}" placeholder="${value && S.secrets[value] ? "Stored securely. Type to replace." : "Enter the credential"}">`;
    return `<div class="field ${wide ? "wide" : ""} ${errs.length ? "invalid" : ""}">
      <label for="${id}">${esc(f.label)}${state}</label>${control}
      <div class="help">${esc(f.help || "Kept in the engagement's secrets file, never in the target or report.")}</div>
      ${errs.map((e) => `<div class="err">${esc(e)}</div>`).join("")}</div>`;
  } else if (f.kind === "folder") {
    control = `<div class="input-group"><input class="input" id="${id}" data-path="${path}" value="${esc(value)}"
      placeholder="Choose the folder the client provided">
      <button class="btn" data-act="pickDocs">${icon("folder")}Browse</button></div>`;
  } else if (f.kind === "file") {
    const opts = S.docFiles.map((n) => `<option value="${esc(n)}" ${n === value ? "selected" : ""}>${esc(n)}</option>`);
    if (value && !S.docFiles.includes(value)) opts.unshift(`<option value="${esc(value)}" selected>${esc(value)} (not found)</option>`);
    control = `<select class="input" id="${id}" data-path="${path}">
      <option value="">${f.required ? "Choose a file…" : "None"}</option>${opts.join("")}</select>`;
  } else {
    const type = f.kind === "number" ? "number" : f.kind === "date" ? "date" : "text";
    const v = value ?? (f.default ?? "");
    control = `<input class="input" type="${type}" id="${id}" data-path="${path}" data-kind="${f.kind}"
      value="${esc(v)}" placeholder="${esc(f.placeholder || "")}">`;
  }
  return `<div class="field ${wide ? "wide" : ""} ${errs.length ? "invalid" : ""}">
    <label for="${id}">${esc(f.label)}${req}</label>${control}
    ${f.help ? `<div class="help">${esc(f.help)}</div>` : ""}
    ${errs.map((e) => `<div class="err">${esc(e)}</div>`).join("")}</div>`;
}

function onInput(e) {
  const el = e.target;
  if (el.dataset.secret) {
    if (el.value) S.pending[el.dataset.secret] = el.value; else delete S.pending[el.dataset.secret];
  } else if (el.dataset.path) {
    let v = el.dataset.kind === "bool" ? el.checked : el.value;
    if (el.dataset.kind === "number") v = v === "" ? "" : Number(v);
    setPath(S.raw, el.dataset.path, v);
    if (el.dataset.path.endsWith(".product")) rerenderAsset(el.dataset.path);
    if (el.dataset.path === "documents.dir") scheduleDocFiles();
    if (el.dataset.path.startsWith("engagement.")) refreshAuthBanner();
  } else return;
  el.closest(".field")?.classList.remove("invalid");
  refreshActionbar();
  renderRail();
}

async function save(quiet = false) {
  const missing = missingRequired();
  if (missing.length) { S.problems = missing; return false; }
  const secrets = Object.entries(S.pending).map(([k, value]) => {
    const [section, index, field] = k.split(".");
    return { section, index: Number(index), field, value };
  });
  const r = await api("/api/save", { folder: S.folder, raw: S.raw, secrets });
  S.problems = r.problems;
  if (r.saved) {
    S.raw = withLists(r.raw); S.savedJSON = JSON.stringify(S.raw); S.pending = {}; S.secrets = r.secrets;
    const first = !S.exists;
    S.exists = true; S.access = null;
    if (!quiet) toast(first ? "Engagement created." : "Saved.");
  }
  return r.saved;
}

// --- home -------------------------------------------------------------------------------------------------
const VIEWS = {};
const afterRender = {};

VIEWS.home = () => {
  const recent = (S.info.recent || []).map((r) => `
    <button data-open="${esc(r.path)}">${icon("folder")}
      <span class="grow"><b>${esc(r.label)}</b><span class="mono">${esc(r.path)}</span></span>
      <span class="faint small">${esc(fmtDate(r.opened, false))}</span>${icon("arrow-right")}</button>`).join("");
  return `<div class="page">
    <div class="eyebrow">NIS2 Evidence Console</div>
    <h1>Start or continue an engagement</h1>
    <p class="lead">Each client engagement lives in its own folder: the systems in scope, the client's
      authorisation, credentials, document reviews and every scan with its report.</p>
    <div class="hero stagger">
      <button class="tile" data-act="newEngagement"><div class="ic">${icon("folder-plus")}</div>
        <h2>New engagement</h2><p>Create a folder for a new client and walk through setup.</p></button>
      <button class="tile" data-act="openEngagement"><div class="ic">${icon("folder")}</div>
        <h2>Open engagement folder</h2><p>Continue an engagement, or open a folder a colleague prepared.</p></button>
    </div>
    ${recent ? `<p class="section-title">Recent engagements</p><div class="recent stagger">${recent}</div>` : ""}
    <div class="principles">
      <div><b>Evidence, not certification</b>The tool reports what it could verify. It never declares a client compliant.</div>
      <div><b>Authorised scope only</b>Scans run only inside the client's written authorisation window.</div>
      <div><b>People decide</b>AI can point to evidence and draft explanations. Verdicts come from checks and reviewers.</div>
    </div></div>`;
};

async function openFolder(path) {
  const r = await api("/api/open", { folder: path });
  Object.assign(S, {
    folder: r.folder, win: r.windows, exists: r.exists, raw: withLists(r.raw), savedJSON: "",
    problems: r.problems, secrets: r.secrets, pending: {}, runs: r.runs, access: null, accessView: null,
    scanView: { phase: "idle" }, register: null, suggestions: null, docFiles: [], run: r.runs[0]?.id || null,
    reportMode: "report",
  });
  S.savedJSON = r.exists ? JSON.stringify(S.raw) : "";
  if (S.raw.documents?.dir) loadDocFiles();
  go(r.exists ? (r.runs.length ? "report" : "access") : "engagement", { force: true });
  if (r.exists) toast(`Opened ${S.raw.engagement?.client || S.raw.name}.`);
}

// --- folder browser ------------------------------------------------------------------------------------------
function modal(title, body, footer, { wide = false } = {}) {
  closeOverlay(true);
  $("#overlay").innerHTML = `<div class="scrim" data-act="closeOverlay"></div>
    <div class="modal" role="dialog" aria-label="${esc(title)}" ${wide ? 'style="width:min(900px,calc(100vw - 40px))"' : ""}>
      <header><h2>${esc(title)}</h2><button class="icon-btn" style="color:var(--muted)" data-act="closeOverlay">${icon("x")}</button></header>
      <div class="body">${body}</div><footer>${footer}</footer></div>`;
}
function drawer(title, body, footer) {
  closeOverlay(true);
  $("#overlay").innerHTML = `<div class="scrim" data-act="closeOverlay"></div>
    <aside class="drawer" role="dialog" aria-label="${esc(title)}">
      <header><h2>${esc(title)}</h2><button class="icon-btn" style="color:var(--muted)" data-act="closeOverlay">${icon("x")}</button></header>
      <div class="body">${body}</div><footer>${footer}</footer></aside>`;
}
async function closeOverlay(now = false) {
  const o = $("#overlay");
  if (!o.innerHTML) return;
  if (!now && !REDUCED) { o.classList.add("closing"); await sleep(200); }
  o.classList.remove("closing");
  o.innerHTML = "";
}

const Browser = { path: null, entries: [], parent: null, mode: "open", onPick: null };

async function browse(mode, onPick, start) {
  Object.assign(Browser, { mode, onPick });
  const titles = { open: "Open engagement folder", create: "New engagement", docs: "Choose the documents folder" };
  const footer = mode === "create"
    ? `<input class="input" id="newName" placeholder="Folder name, e.g. Acme Corp NIS2 2026" style="flex:1">
       <button class="btn" data-act="closeOverlay">Cancel</button>
       <button class="btn primary" data-act="createHere">Create engagement</button>`
    : `<span class="grow small muted" id="browseHint"></span><button class="btn" data-act="closeOverlay">Cancel</button>
       <button class="btn primary" data-act="pickHere">${mode === "open" ? "Open this folder" : "Use this folder"}</button>`;
  const places = S.info.places.map((p) => `<button data-browse="${esc(p.path)}">${icon(p.label === "Home" ? "home" : "folder")}${esc(p.label)}</button>`).join("");
  modal(titles[mode], `<div class="input-group" style="margin-bottom:12px">
      <input class="input mono" id="browsePath" placeholder="Type or paste a path, e.g. C:\\Users\\you\\Engagements">
      <button class="btn" data-act="browseGo">Go</button></div>
    <div class="browser"><div class="places">${places}</div><div class="dirlist" id="dirlist"></div></div>`, footer, { wide: true });
  const docs = S.info.places.find((p) => p.label === "Windows Documents");
  await browseTo(start || (docs || S.info.places[0]).path);
  if (mode === "create") $("#newName").focus();
}
async function browseTo(path) {
  try {
    const r = await api("/api/fs?" + qs({ path }));
    Object.assign(Browser, { path: r.path, entries: r.entries, parent: r.parent });
    $("#browsePath").value = r.path;
    const up = r.parent ? `<button class="up" data-browse="${esc(r.parent)}">${icon("arrow-up")}Up one level</button>` : "";
    const rows = r.entries.map((e) => `<button data-browse="${esc(e.path)}">${icon("folder")}
      <span style="flex:1">${esc(e.name)}</span>${e.engagement ? '<span class="pill info">Engagement</span>' : ""}</button>`).join("");
    $("#dirlist").innerHTML = up + (rows || `<div class="empty" style="margin:12px">No subfolders</div>`);
    const hint = $("#browseHint");
    if (hint) hint.textContent = r.engagement ? "This folder is an engagement." :
      Browser.mode === "open" ? "No engagement here yet: opening it starts a new one." : "";
  } catch (e) { toast(e.message, "error"); }
}

// --- engagement ---------------------------------------------------------------------------------------------
function authBanner() {
  const st = authState();
  const e = S.raw.engagement || {};
  const msg = {
    incomplete: ["info", "info", "Record the client's written authorisation. Scans are refused without it."],
    future: ["warn", "clock", `The authorisation starts on ${esc(e.authorised_on)}. Scans are refused until then.`],
    expired: ["error", "alert", `The authorisation ended on ${esc(e.valid_until)}. Ask the client to extend it before scanning.`],
    valid: ["ok", "shield", `Scans are authorised from ${esc(fmtDate(e.authorised_on, false))} to ${esc(fmtDate(e.valid_until, false))}.
      ${e.active_tests ? "Active tests are allowed." : "Active tests are not allowed."}`],
  }[st];
  return `<div class="banner ${msg[0]}" id="authBanner">${icon(msg[1])}<div>${msg[2]}</div></div>`;
}
function refreshAuthBanner() {
  const el = $("#authBanner");
  if (el) el.outerHTML = authBanner();
}
function problemLabel(loc) {
  const [head, i, key] = loc;
  if (head === "name") return "Reference";
  if (head === "engagement") return S.schema.engagement.find((f) => f.key === i)?.label || "Authorisation";
  if (head === "documents") return S.schema.documents.find((f) => f.key === i)?.label || "Documents";
  const section = S.schema.sections.find((s) => s.key === head);
  if (!section) return loc.join(" › ");
  const asset = S.raw[head]?.[Number(i)];
  const where = `${section.label}: ${asset?.name || "entry " + (Number(i) + 1)}`;
  return key ? `${where}, ${section.fields.find((f) => f.key === key)?.label || key}` : where;
}
function generalProblems(prefixes) {
  const shown = S.problems.filter((p) => prefixes.includes(p.loc[0]));
  if (!shown.length) return "";
  return `<div class="banner error">${icon("alert")}<div><b>Please check these details.</b><ul>
    ${shown.map((p) => `<li>${esc(problemLabel(p.loc))}: ${esc(p.message)}</li>`).join("")}</ul></div></div>`;
}

VIEWS.engagement = () => {
  const f = S.schema.engagement;
  const fields = f.map((x) => fieldHTML(x, `engagement.${x.key}`, { wide: ["notes", "active_tests"].includes(x.key) })).join("");
  return `<div class="page">${pageHead(1, "Engagement and authorisation",
    "Who the client is and who authorised the scan, for how long. The tool refuses to scan outside this window.")}
    ${generalProblems(["name", "engagement"])}
    <div class="stagger">
    ${authBanner()}
    <div class="card"><div class="card-head"><div class="ic">${icon("shield")}</div><div class="grow">
      <h2>Client and authorisation</h2><p>As agreed in the engagement letter.</p></div></div>
      <div class="grid">${fields}</div></div>
    <div class="card"><div class="card-head"><div class="ic">${icon("folder")}</div><div class="grow">
      <h2>Engagement reference</h2><p>Used to name result folders. Letters, digits and dashes work best.</p></div></div>
      <div class="grid">${fieldHTML({ key: "name", label: "Reference", required: true }, "name")}
      <div class="field"><label>Folder</label><div class="mono muted" style="padding-top:9px;word-break:break-all">${esc(S.win || S.folder)}</div></div></div></div>
    </div>${actionbar(null, "systems")}</div>`;
};

// --- systems ------------------------------------------------------------------------------------------------
function visibleFields(section, product) {
  const seen = new Set();
  return section.fields.filter((f) => !f.products || f.products.includes(product))
    .filter((f) => !seen.has(f.key) && seen.add(f.key));
}
function missingRequired() {
  const out = [];
  const empty = (v) => v === undefined || v === null || v === "";
  const need = (loc, f, value) => f.required && f.kind !== "secret" && empty(value) &&
    out.push({ loc, message: "Required" });
  S.schema.engagement.forEach((f) => need(["engagement", f.key], f, S.raw.engagement?.[f.key]));
  if (empty(S.raw.name)) out.push({ loc: ["name"], message: "Required" });
  for (const section of S.schema.sections) {
    (S.raw[section.key] || []).forEach((a, i) => visibleFields(section, a.product || "auto")
      .forEach((f) => need([section.key, String(i), f.key], f, a[f.key])));
  }
  if (S.raw.documents) S.schema.documents.forEach((f) => need(["documents", f.key], f, S.raw.documents[f.key]));
  return out;
}
function assetHTML(section, i) {
  const a = S.raw[section.key][i];
  const product = a.product || "auto";
  const unique = visibleFields(section, product);
  const basic = unique.filter((f) => !f.advanced), adv = unique.filter((f) => f.advanced);
  const productPicker = section.products ? `<div class="field wide"><label>Product</label>
    <div class="segmented" role="radiogroup">${section.products.map((p) =>
      `<button type="button" class="${p.value === product ? "on" : ""}" data-product="${section.key}.${i}" data-value="${esc(p.value)}">${esc(p.label)}</button>`).join("")}</div>
    ${product === "auto" ? `<div class="help">The access check identifies the product. Choose it here to enter the credentials it needs.</div>` : ""}</div>` : "";
  return `<div class="asset" data-asset="${section.key}.${i}">
    <div class="asset-head">${icon(section.icon)}<b>${esc(a.name || "New " + section.label.toLowerCase().replace(/s$/, ""))}</b>
      <button class="btn ghost sm danger" data-remove="${section.key}.${i}">${icon("trash")}Remove</button></div>
    <div class="grid fields-swap">${productPicker}
      ${basic.map((f) => fieldHTML(f, `${section.key}.${i}.${f.key}`)).join("")}</div>
    ${adv.length ? `<details class="adv"><summary>Advanced settings</summary><div class="grid">
      ${adv.map((f) => fieldHTML(f, `${section.key}.${i}.${f.key}`)).join("")}</div></details>` : ""}</div>`;
}
function sectionHTML(section) {
  const assets = S.raw[section.key] || [];
  return `<div class="card section-card" id="sec-${section.key}">
    <div class="card-head"><div class="ic">${icon(section.icon)}</div><div class="grow">
      <h2>${esc(section.label)}<span class="count">${assets.length}</span></h2><p>${esc(section.blurb)}</p></div>
      <button class="btn" data-add="${section.key}">${icon("plus")}Add</button></div>
    <div class="assets">${assets.map((_, i) => assetHTML(section, i)).join("") ||
      `<div class="empty">None in scope. Checks that need one are reported as not applicable.</div>`}</div></div>`;
}
VIEWS.systems = () => {
  return `<div class="page">${pageHead(2, "Systems in scope",
    "Add every system the client has put in scope. Products are detected automatically where possible; " +
    "credentials go to the engagement's secrets file.")}
    ${generalProblems(S.schema.sections.map((s) => s.key))}
    <div class="summary-chips">${chipsHTML()}</div>
    <div class="stagger">${S.schema.sections.map(sectionHTML).join("")}</div>
    ${actionbar("engagement", "documents")}</div>`;
};
function chipsHTML() {
  return S.schema.sections.map((s) => `<span>${esc(s.label)} <b>${S.raw[s.key]?.length || 0}</b></span>`).join("");
}
function rerenderSection(key) {
  const section = S.schema.sections.find((s) => s.key === key);
  const card = $(`#sec-${key}`);
  if (card) card.outerHTML = sectionHTML(section);
  const chips = $(".summary-chips");
  if (chips) chips.innerHTML = chipsHTML();
}
function rerenderAsset(path) {
  const [key, i] = path.split(".");
  const section = S.schema.sections.find((s) => s.key === key);
  const el = $(`[data-asset="${key}.${i}"]`);
  if (el) { el.outerHTML = assetHTML(section, Number(i)); $(`[data-asset="${key}.${i}"]`).style.animation = "none"; }
}

// --- documents ----------------------------------------------------------------------------------------------
let docTimer = null;
function scheduleDocFiles() { clearTimeout(docTimer); docTimer = setTimeout(loadDocFiles, 500); }
async function loadDocFiles() {
  const dir = S.raw?.documents?.dir;
  if (!dir) { S.docFiles = []; return; }
  try {
    const r = await api("/api/files?" + qs({ folder: S.folder, dir }));
    S.docFiles = r.files;
  } catch { S.docFiles = []; }
  if (S.step === "documents" && S.docTab === "setup") {
    const holder = $("#docFields");
    if (holder) holder.innerHTML = docFieldsHTML();
  }
}
function docFieldsHTML() {
  return S.schema.documents.filter((f) => f.key !== "dir")
    .map((f) => fieldHTML(f, `documents.${f.key}`)).join("");
}
async function loadDocuments() {
  if (!S.exists || !S.raw.documents?.dir || dirty()) return;
  try {
    S.register = await api("/api/register?" + qs({ folder: S.folder }));
    S.suggestions = (await api("/api/suggestions?" + qs({ folder: S.folder }))).documents;
  } catch (e) { S.register = { error: e.message }; }
  if (S.step === "documents") { renderDocTab(); renderRail(); }
}
VIEWS.documents = () => {
  const tabs = [["setup", "Documents folder"], ["reviews", "Document reviews"], ["suggest", "AI suggestions"]];
  return `<div class="page">${pageHead(3, "Documents and reviews",
    "Most of NIS2 is organisational. Point the tool at the client's documents, then record your review of " +
    "each requirement no automated check can reach.")}
    <div class="tabs">${tabs.map(([k, l]) => `<button class="${S.docTab === k ? "on" : ""}" data-tab="${k}">${l}</button>`).join("")}</div>
    <div id="docTab"></div>${actionbar("systems", "access")}</div>`;
};
afterRender.documents = () => renderDocTab();
function renderDocTab() {
  const el = $("#docTab");
  if (!el) return;
  el.innerHTML = { setup: docSetupHTML, reviews: reviewsHTML, suggest: suggestHTML }[S.docTab]();
}
function docSetupHTML() {
  const dirField = S.schema.documents.find((f) => f.key === "dir");
  const on = !!S.raw.documents;
  return `<div class="stagger">${generalProblems(["documents"])}
    <div class="card"><div class="card-head"><div class="ic">${icon("file")}</div><div class="grow">
      <h2>Client documents</h2><p>The folder with the policies, plans and records the client provided.
      Documents are hashed at every scan, so later changes are visible.</p></div></div>
      ${on ? `<div class="grid">${fieldHTML(dirField, "documents.dir", { wide: true })}<div class="grid wide" id="docFields" style="padding:0">${docFieldsHTML()}</div></div>
        <div class="row end" style="margin-top:14px"><button class="btn ghost sm danger" data-act="removeDocs">${icon("trash")}Remove documents from scope</button></div>`
      : `<div class="empty">No documents in scope yet.<div style="margin-top:10px"><button class="btn primary" data-act="addDocs">${icon("folder")}Choose the documents folder</button></div></div>`}
    </div></div>`;
}
function needsSavedDocs() {
  if (!S.raw.documents?.dir) return `<div class="empty">Choose the documents folder first.</div>`;
  if (dirty() || !S.exists) return `<div class="banner info">${icon("info")}<div>Save your changes to continue.
    <div style="margin-top:8px"><button class="btn sm" data-act="saveDocs">Save</button></div></div></div>`;
  if (!S.register) return `<div class="card"><div class="skeleton" style="position:static;padding:0"><i class="w60"></i><i></i><i class="w40"></i></div></div>`;
  if (S.register.error) return `<div class="banner error">${icon("alert")}<div>${esc(S.register.error)}</div></div>`;
  return "";
}
function reviewsHTML() {
  const blocked = needsSavedDocs();
  if (blocked) return blocked;
  const R = S.register;
  if (!R.exists) return `<div class="card"><div class="empty">
    <p style="margin:0 0 10px">No evidence register yet. It lists the ${R.requirements.length} requirements no automated check covers.</p>
    <button class="btn primary" data-act="createRegister">${icon("plus")}Start an evidence register</button></div></div>`;
  const counts = {};
  R.reviews.forEach((r) => (counts[r.counts_as] = (counts[r.counts_as] || 0) + 1));
  const summary = ["evidenced", "partially_evidenced", "not_satisfied", "not_assessed"].filter((k) => counts[k])
    .map((k) => `<span class="pill ${k}">${counts[k]} ${k.replace(/_/g, " ")}</span>`).join(" ");
  const problems = R.problems.length ? `<div class="banner warn">${icon("alert")}<div><b>Entries that will not be applied</b>
    <ul>${R.problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></div></div>` : "";
  const list = R.reviews.map((r) => `<div class="review">
    <div class="top"><b>${esc(r.title || r.requirement)}</b><span class="pill ${r.counts_as}">${esc(r.counts_as.replace(/_/g, " "))}</span></div>
    <div class="small faint mono">${esc(r.requirement)} · ${esc(r.documents.map((d) => d.path).join(", ") || "no documents")}</div>
    <p>${esc(r.reason.charAt(0).toUpperCase() + r.reason.slice(1))}</p></div>`).join("");
  return `${problems}<div class="card"><div class="card-head"><div class="ic">${icon("clipboard")}</div><div class="grow">
    <h2>Evidence register</h2><p>${plural(R.reviews.length, "review")} of ${R.requirements.length} reviewable requirements. ${summary}</p></div>
    <button class="btn primary" data-act="newReview">${icon("plus")}Record a review</button></div>
    ${list || `<div class="empty">No reviews recorded yet.</div>`}</div>`;
}
function suggestHTML() {
  const blocked = needsSavedDocs();
  if (blocked) return blocked;
  const keyNote = S.info.api_key ? "" : `<div class="banner warn">${icon("alert")}<div>Add an Anthropic API key in
    Settings to use AI suggestions. <a href="#" data-act="settings">Open settings</a></div></div>`;
  const R = S.register;
  const docs = S.docFiles.filter((d) => /\.(md|txt|docx|pdf|rst)$/i.test(d)).filter((d) => d !== S.raw.documents.evidence_register);
  const picks = docs.map((d) => `<label><input type="checkbox" value="${esc(d)}" class="sugDoc">${icon("file")}${esc(d)}</label>`).join("");
  const reviewed = new Set((R.reviews || []).map((r) => r.requirement));
  const results = (S.suggestions || []).map((doc) => {
    const items = (doc.accepted || []).map((s) => `<div class="suggestion">
      <div class="row between"><b>${esc(s.title || s.requirement_id)}</b>
        ${reviewed.has(s.requirement_id) ? '<span class="pill ok">Reviewed</span>'
          : `<button class="btn sm" data-suggest-review="${esc(s.requirement_id)}" data-doc="${esc(doc.document)}">Review this</button>`}</div>
      <div class="small faint mono">${esc(s.requirement_id)}</div>
      ${(s.excerpts || [s.excerpt]).filter(Boolean).map((x) => `<blockquote>${esc(x)}</blockquote>`).join("")}
      <div class="small muted">${esc(s.addresses)}</div></div>`).join("");
    return `<div class="card"><div class="card-head"><div class="ic">${icon("file")}</div><div class="grow">
      <h2>${esc(doc.document)}</h2><p>${doc.error ? esc(doc.error) : plural(doc.accepted.length, "suggestion")}
      ${doc.model ? ` · <span class="ai-note">${icon("sparkle")}Suggested by ${esc(doc.model)}, not reviewed</span>` : ""}</p></div></div>
      ${items || '<div class="empty">Nothing in this document bears on an unchecked requirement.</div>'}</div>`;
  }).join("");
  return `${keyNote}<div class="card"><div class="card-head"><div class="ic">${icon("sparkle")}</div><div class="grow">
    <h2>Find evidence in documents</h2><p>The model points to passages that may bear on requirements no check covers.
    Every excerpt is verified against the document. It never records a verdict: you do.</p></div></div>
    ${picks ? `<div class="checklist">${picks}</div>
      <div class="row between" style="margin-top:12px"><span class="small muted" id="sugStatus"></span>
      <button class="btn primary" data-act="runSuggest" ${S.info.api_key ? "" : "disabled"}>${icon("sparkle")}Suggest evidence</button></div>`
      : `<div class="empty">No readable documents (.md, .txt, .docx, .pdf) in the folder.</div>`}</div>
    <div id="sugResults" class="stagger">${results}</div>`;
}
function reviewDrawer(prefill = {}) {
  const R = S.register;
  const reviewed = new Set(R.reviews.map((r) => r.requirement));
  const byArticle = {};
  R.requirements.filter((r) => !reviewed.has(r.id)).forEach((r) => (byArticle[r.article] ||= []).push(r));
  const options = Object.keys(byArticle).sort().map((a) => `<optgroup label="NIS2 Art. ${esc(a)}">
    ${byArticle[a].map((r) => `<option value="${esc(r.id)}" ${r.id === prefill.requirement ? "selected" : ""}>${esc(r.title)} (${esc(r.id.replace("REQ-", ""))})</option>`).join("")}</optgroup>`).join("");
  const docs = S.docFiles.filter((d) => d !== S.raw.documents.evidence_register).map((d) => `<label>
    <input type="checkbox" class="revDoc" value="${esc(d)}" ${(prefill.documents || []).includes(d) ? "checked" : ""}>${esc(d)}</label>`).join("");
  let reviewer = "";
  try { reviewer = localStorage.getItem("reviewer") || ""; } catch { /* storage unavailable */ }
  drawer("Record a document review", `
    <p class="muted small" style="margin-top:0">Your decision is recorded with your name and the documents' fingerprints.
      It applies to the next scan and counts only while it is valid.</p>
    <div class="grid" style="grid-template-columns:1fr">
      <div class="field"><label>Requirement<span class="req">*</span></label><select class="input" id="revReq">${options}</select></div>
      <div class="field"><label>Documents reviewed</label><div class="checklist">${docs || '<span class="faint small">No files in the folder</span>'}</div>
        <div class="help">Required unless you found no document that addresses the requirement.</div></div>
      <div class="field"><label>Verdict<span class="req">*</span></label><div class="segmented" id="revVerdict">
        <button type="button" data-v="evidenced">Evidenced</button><button type="button" data-v="partially_evidenced">Partially evidenced</button>
        <button type="button" data-v="not_satisfied">Not satisfied</button></div></div>
      <div class="field"><label>Reviewed by<span class="req">*</span></label><input class="input" id="revBy" value="${esc(reviewer)}" placeholder="Your name and role"></div>
      <div class="grid" style="padding:0"><div class="field"><label>Reviewed on<span class="req">*</span></label><input class="input" type="date" id="revOn" value="${esc(S.info.today)}"></div>
      <div class="field"><label>Valid until</label><input class="input" type="date" id="revUntil"></div></div>
      <div class="field"><label>Rationale<span class="req">*</span></label><textarea class="input" id="revWhy" placeholder="What the documents show, and what they do not."></textarea></div>
    </div>`, `<button class="btn" data-act="closeOverlay">Cancel</button><button class="btn primary" data-act="submitReview">Record review</button>`);
}

// --- access check ---------------------------------------------------------------------------------------------
VIEWS.access = () => `<div class="page">${pageHead(4, "Access check",
  "Before scanning, confirm that every system is reachable and every credential works. " +
  "Anything missing is a request to the client, not a finding.")}
  <div id="accessBody">${accessBody()}</div>${actionbar("documents", "scan")}</div>`;
function accessBody() {
  const v = S.accessView;
  if (!v) {
    return `<div class="card" style="text-align:center;padding:40px 24px">
      <div class="card-head" style="justify-content:center"><div class="ic" style="width:56px;height:56px">${icon("key")}</div></div>
      <h2>Test the access the client has granted</h2>
      <p class="muted" style="max-width:560px;margin:6px auto 20px">The check connects to each system, identifies products,
        confirms credentials are set and documents exist. It reads only; nothing on the client's systems changes.</p>
      <button class="btn primary lg" data-act="runAccess">${icon("play")}Run access check</button></div>`;
  }
  return `${accessSummary()}<div class="list" id="accessList">${accessRows()}</div>
      <div class="row end" style="margin-top:14px">
        ${v.done && !S.access?.ready ? `<button class="btn" data-act="copyChecklist">${icon("clipboard")}Copy checklist for the client</button>` : ""}
        <button class="btn" data-act="runAccess" ${v.done ? "" : "disabled"}>${icon("refresh")}Check again</button></div>`;
}
function accessSummary() {
  const v = S.accessView;
  if (!v.done) return `<div class="banner info">${icon("info")}<div>Checking ${plural(v.total || 0, "system")}…</div></div>`;
  if (v.error) return `<div class="banner error">${icon("alert")}<div>${esc(v.error)}</div></div>`;
  const missing = v.systems.flatMap((s) => (s.access || []).filter((a) => a.status === "missing")).length +
    (v.auth?.status === "missing" ? 1 : 0);
  return missing ? `<div class="banner warn">${icon("alert")}<div><b>${plural(missing, "item needs", "items need")} the client's action.</b>
      You can still scan: affected checks are reported as not assessed.</div></div>`
    : `<div class="banner ok">${icon("check")}<div><b>All systems are ready.</b> Continue to the scan.</div></div>`;
}
function statusIcon(state) {
  if (state === "wait") return `<span class="status-ic" style="background:var(--grey-bg)"></span>`;
  if (state === "probe") return `<span class="status-ic wait"><span class="spinner"></span></span>`;
  const name = state === "ok" ? "check" : state === "warn" ? "alert" : "x";
  return `<span class="status-ic ${state === "ok" ? "ok" : state === "warn" ? "warn" : "bad"}"><svg class="i draw"><use href="#i-${name}"/></svg></span>`;
}
const KIND = { web: "Web endpoint", ssh: "SSH host", idp: "Identity provider", logs: "Log store",
  backup: "Backup repository", docker: "Docker project", documents: "Documents" };
function accessRows() {
  const v = S.accessView;
  const rows = [];
  if (v.auth) {
    const a = v.auth;
    rows.push(`<div class="list-row ${v.fresh === "auth" ? "appear" : ""}">${statusIcon(a.status === "ok" ? "ok" : "bad")}
      <div class="grow"><b>Written authorisation</b><div class="sub">${esc(a.what)}${a.note ? " · " + esc(a.note) : ""}</div></div></div>`);
  }
  for (const [section, name] of v.plan || []) {
    const s = v.systems.find((x) => x.section === section && x.name === name);
    const probing = v.probing === `${section}/${name}`;
    const state = s ? (s.ready ? "ok" : s.access.some((a) => a.status === "missing") ? "bad" : "warn") : probing ? "probe" : "wait";
    const items = s ? `<ul class="access-items">${s.access.map((a) => `<li><span class="pill ${a.status === "not checked" ? "pending" : a.status}">${esc(a.status)}</span>
      <span>${esc(a.what)}${a.note ? ` <span class="faint">· ${esc(a.note)}</span>` : ""}</span></li>`).join("")}</ul>` : "";
    rows.push(`<div class="list-row ${v.fresh === `${section}/${name}` ? "appear" : ""}" style="align-items:flex-start">${statusIcon(state)}
      <div class="grow"><b>${esc(name)}</b> <span class="faint small">${esc(s?.kind || KIND[section] || section)}${s?.product ? " · " + esc(s.product) : ""}</span>
      ${items}</div></div>`);
  }
  return rows.join("");
}
function refreshAccess() {
  if (S.step !== "access") return;
  const holder = $("#accessBody");
  if (holder) holder.innerHTML = accessBody();
}

// --- scan ----------------------------------------------------------------------------------------------------------
const CIRC = 2 * Math.PI * 96;
VIEWS.scan = () => `<div class="page">${pageHead(5, "Run the scan",
  "The scanner collects evidence from each system, runs every check and records the verdict for each requirement, " +
  "with the evidence behind it.")}<div id="scanBody">${scanBody()}</div>${actionbar("access", S.runs.length ? "report" : null, "View report")}</div>`;
function scanBody() {
  const v = S.scanView;
  if (v.phase === "idle" || v.phase === "error") {
    const e = S.raw.engagement || {};
    const ready = S.access ? (S.access.ready ? `<span class="pill ok">Access check passed</span>` : `<span class="pill partially_evidenced">Access check: items missing</span>`)
      : `<span class="pill pending">Access not checked</span>`;
    return `${v.phase === "error" ? `<div class="banner error">${icon("alert")}<div><b>The scan did not complete.</b> ${esc(v.error)}</div></div>` : ""}
      <div class="card"><div class="row between"><div>
        <h2>${esc(e.client || S.raw.name)}</h2>
        <p class="muted" style="margin:4px 0 0">${plural(systemCount(), "system")} in scope ·
          ${S.raw.documents?.dir ? "documents included" : "no documents"} · active tests ${e.active_tests ? "allowed" : "not allowed"}</p>
        <div class="row" style="margin-top:10px">${ready}${authState() === "valid" ? '<span class="pill ok">Authorised today</span>' : '<span class="pill fail">Not authorised today</span>'}</div>
      </div><button class="btn primary lg" data-act="runScan" ${authState() === "valid" ? "" : "disabled"}>${icon("play")}Start scan</button></div></div>
      ${S.runs.length ? `<p class="section-title" style="margin-top:22px">Earlier scans</p><div class="list">${S.runs.slice(0, 5).map((r) => `
        <div class="list-row"><span class="status-ic ok">${icon("report")}</span><div class="grow"><b>${esc(fmtDate(r.started_at))}</b>
        <div class="sub">${verdictLine(r.verdicts)}</div></div><button class="btn sm" data-view-run="${esc(r.id)}">Open report</button></div>`).join("")}</div>` : ""}`;
  }
  if (v.phase === "running") {
    const pct = Math.min(99, Math.round((100 * (v.done || 0)) / (v.total || 1)));
    return `<div class="card"><div class="scan-stage">
      <div class="ring pulse"><svg viewBox="0 0 220 220"><circle class="track" cx="110" cy="110" r="96"/>
        <circle class="bar" id="ringBar" cx="110" cy="110" r="96" stroke-dasharray="${CIRC}" stroke-dashoffset="${CIRC * (1 - pct / 100)}"/></svg>
        <div class="center"><div><span class="pct" id="ringPct">${pct}%</span><small>evidence collected</small></div></div></div>
      <div><div class="eyebrow">Scanning ${esc(S.raw.engagement?.client || S.raw.name)}</div>
        <div class="now" id="scanNow">${esc(v.now || "Preparing")}</div>
        <div class="small muted"><span id="scanCount">${v.done || 0} of ${v.total || "…"}</span> collection steps ·
          <span class="elapsed" id="scanElapsed">0:00</span> elapsed</div>
        <div class="feed" id="scanFeed">${(v.feed || []).map(feedRow).join("")}</div></div></div></div>`;
  }
  const r = v.result;
  const order = ["evidenced", "partially_evidenced", "not_satisfied", "not_assessed"];
  const labels = { evidenced: "Evidenced", partially_evidenced: "Partially evidenced", not_satisfied: "Not satisfied", not_assessed: "Not assessed" };
  const checks = r.checks || {};
  return `<div class="card"><div class="row between"><div>
      <div class="done-mark"><svg class="i draw"><use href="#i-check"/></svg></div>
      <h2 style="font-size:20px">Scan complete</h2>
      <p class="muted" style="margin:2px 0 0">${esc(v.elapsed)} · ${checks.pass || 0} checks passed, ${checks.fail || 0} failed${checks.error ? `, ${checks.error} could not run` : ""}.</p></div>
      <button class="btn primary lg" data-view-run="${esc(r.run)}">${icon("report")}Open the report</button></div>
    <div class="results">${order.map((k) => `<div class="metric ${k}"><div class="n" data-count="${r.verdicts[k] || 0}">0</div><div class="l">${labels[k]}</div></div>`).join("")}</div>
    ${r.gaps.length ? `<p class="section-title">Most important gaps (${r.gap_count})</p><div class="list">${r.gaps.map((g) => `
      <div class="list-row"><div class="grow"><b><span class="sev ${esc(g.severity)}"></span>${esc(g.title)}</b>
      <div class="sub">${esc(g.topic)}${g.action ? " · " + esc(g.action) : ""}</div></div><span class="pill ${g.severity === "critical" || g.severity === "high" ? "fail" : "pending"}">${esc(g.severity)}</span></div>`).join("")}</div>`
      : `<div class="banner ok">${icon("check")}<div>No failing checks.</div></div>`}</div>`;
}
function verdictLine(v) {
  const parts = [["evidenced", "evidenced"], ["partially_evidenced", "partial"], ["not_satisfied", "not satisfied"]]
    .filter(([k]) => v[k]).map(([k, l]) => `${v[k]} ${l}`);
  return parts.join(" · ") || "Nothing assessed";
}
function feedRow(e) {
  return `<div class="feed-row">${statusIcon(e.ok === undefined ? "probe" : e.ok ? "ok" : "warn")}<span>${esc(e.label)}</span>
    <span class="asset-name">${esc(e.asset)}</span></div>`;
}
afterRender.scan = () => {
  $$("[data-count]").forEach((el) => countUp(el, Number(el.dataset.count)));
  if (S.scanView.phase === "running") tickElapsed();
};
let elapsedTimer = null;
function tickElapsed() {
  clearInterval(elapsedTimer);
  elapsedTimer = setInterval(() => {
    const el = $("#scanElapsed");
    if (!el || S.scanView.phase !== "running") return clearInterval(elapsedTimer);
    const s = Math.round((Date.now() - S.scanView.started) / 1000);
    el.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  }, 500);
}
function onScanEvent(e) {
  const v = S.scanView;
  if (e.type === "start") v.total = e.total;
  if (e.type === "collect") {
    v.now = e.label;
    v.feed = [{ label: e.label, asset: e.asset, collector: e.collector }, ...(v.feed || [])].slice(0, 9);
  }
  if (e.type === "collected") {
    v.done = e.done; v.total = Math.max(e.total, e.done);
    const row = (v.feed || []).find((f) => f.collector === e.collector && f.asset === e.asset && f.ok === undefined);
    if (row) row.ok = e.ok;
  }
  if (e.type === "stage") { v.now = e.label; v.done = v.total; }
  if (S.step !== "scan") { renderRail(); return; }
  const pct = Math.min(e.type === "stage" ? 100 : 99, Math.round((100 * (v.done || 0)) / (v.total || 1)));
  const bar = $("#ringBar");
  if (bar) bar.style.strokeDashoffset = CIRC * (1 - pct / 100);
  const p = $("#ringPct"); if (p) p.textContent = pct + "%";
  const c = $("#scanCount"); if (c) c.textContent = `${v.done || 0} of ${v.total || "…"}`;
  const now = $("#scanNow");
  if (now && now.textContent !== v.now) { now.textContent = v.now; now.classList.remove("swap"); void now.offsetWidth; now.classList.add("swap"); }
  const feed = $("#scanFeed");
  if (feed && e.type === "collect") feed.insertAdjacentHTML("afterbegin", feedRow(v.feed[0]));
  if (feed && e.type === "collected") {
    const idx = v.feed.findIndex((f) => f.collector === e.collector && f.asset === e.asset);
    const el = feed.children[idx];
    if (el) el.outerHTML = feedRow(v.feed[idx]);
    while (feed.children.length > 9) feed.lastElementChild.remove();
  }
}

// --- report ----------------------------------------------------------------------------------------------------------
VIEWS.report = () => {
  const runs = S.runs.map((r) => `<option value="${esc(r.id)}" ${r.id === S.run ? "selected" : ""}>${esc(fmtDate(r.started_at))} · ${esc(verdictLine(r.verdicts))}</option>`).join("");
  const current = S.runs.find((r) => r.id === S.run);
  const others = S.runs.filter((r) => r.id !== S.run && r.started_at < (current?.started_at || ""));
  const compare = others.length ? `<select class="input run-select" id="diffSelect" title="Compare">
      <option value="">Compare with…</option>${others.map((r) => `<option value="${esc(r.id)}" ${r.id === S.diffAgainst ? "selected" : ""}>${esc(fmtDate(r.started_at))}</option>`).join("")}</select>` : "";
  const narr = S.reportMode === "diff" ? "" : current?.narrative ? `<span class="pill doc">${icon("sparkle")}Narrative added</span>`
    : `<button class="btn" data-act="narrate" ${S.info.api_key ? "" : 'title="Add an API key in Settings"'}>${icon("sparkle")}Add AI narrative</button>`;
  return `<div class="page wide enter"><div class="report-bar">
      <div><div class="eyebrow">Step 6 of 6</div><h1 style="margin:2px 0 0;font-size:22px">${S.reportMode === "diff" ? "Progress between scans" : "Gap report"}</h1></div>
      <div class="grow"></div>
      ${S.reportMode === "diff" ? `<button class="btn" data-act="showReport">${icon("arrow-left")}Back to report</button>` : ""}
      <div class="tools"><select class="input run-select" id="runSelect" title="Scan">${runs}</select>${compare}${narr}
      <button class="btn square" data-act="revealRun" title="Open the scan folder">${icon("folder")}</button>
      <button class="btn square" data-act="popout" title="Open in a separate window">${icon("external")}</button></div></div>
    <div class="viewer"><div class="skeleton" id="skel"><i class="w40"></i><i class="big"></i><i></i><i class="w60"></i><i class="big"></i><i class="w40"></i></div>
      <iframe id="reportFrame" title="Report"></iframe></div></div>`;
};
function reportURL() {
  return "/report?" + qs({ folder: S.folder, run: S.run, file: S.reportMode === "diff" ? "diff.html" : "report.html" });
}
function loadReport() {
  if (!S.run) S.run = S.runs[0]?.id;
  const frame = $("#reportFrame");
  if (!frame || !S.run) return;
  frame.classList.remove("ready"); $("#skel")?.classList.remove("gone");
  frame.onload = () => { frame.classList.add("ready"); $("#skel")?.classList.add("gone"); };
  frame.src = reportURL();
}

// --- settings -------------------------------------------------------------------------------------------------------------
function settings() {
  modal("Settings", `<div class="grid" style="grid-template-columns:1fr">
    <div class="field"><label>Anthropic API key ${S.info.api_key ? '<span class="secret-state ok">Stored</span>' : '<span class="secret-state missing">Not set</span>'}</label>
      <input class="input" type="password" id="apiKey" autocomplete="off" placeholder="${S.info.api_key ? "Stored. Paste a new key to replace it." : "sk-ant-…"}">
      <div class="help">Used only for the optional AI features: evidence suggestions and the report narrative. Stored in your
        user profile, readable only by you.</div></div>
    <div class="field"><label>Desktop shortcut</label>
      <div class="row"><button class="btn" data-act="shortcut">${icon("home")}Add to Windows desktop</button></div>
      <div class="help">Opens the console directly, without a terminal.</div></div>
    <div class="small faint">NIS2 Evidence Console ${esc(S.info.version)} · internal use only</div></div>`,
  `<button class="btn" data-act="closeOverlay">Close</button><button class="btn primary" data-act="saveSettings">Save</button>`);
}

// --- actions ------------------------------------------------------------------------------------------------------------------
const ACTIONS = {
  home: () => { if (dirty() && !confirm("Leave without saving your changes?")) return; S.folder = null; S.raw = null; S.info.recent = null; refreshState().then(() => go("home", { force: true })); },
  closeOverlay: () => closeOverlay(),
  newEngagement: () => browse("create"),
  openEngagement: () => browse("open"),
  browseGo: () => browseTo($("#browsePath").value),
  pickHere: async () => {
    const path = Browser.path;
    if (Browser.mode === "docs") {
      await closeOverlay();
      Browser.onPick(path);
    } else { await closeOverlay(); openFolder(path).catch((e) => toast(e.message, "error")); }
  },
  createHere: async (btn) => {
    const name = $("#newName").value.trim();
    if (!name) { $("#newName").focus(); return toast("Name the engagement folder.", "error"); }
    await withBusy(btn, async () => {
      const r = await api("/api/mkdir", { parent: Browser.path, name });
      await closeOverlay();
      await openFolder(r.path);
    })();
  },
  reveal: () => api("/api/reveal", { folder: S.folder }).catch((e) => toast(e.message, "error")),
  revealRun: () => api("/api/reveal", { folder: S.folder, run: S.run }).catch((e) => toast(e.message, "error")),
  save: (btn) => withBusy(btn, async () => {
    const ok = await save();
    render();
    if (!ok) toast("Some details need attention.", "error");
    else if (S.step === "documents") { S.register = null; loadDocuments(); }
  })(),
  saveDocs: (btn) => withBusy(btn, async () => { if (await save()) { S.register = null; renderDocTab(); loadDocuments(); } else { S.docTab = "setup"; render(); } })(),
  addDocs: () => browse("docs", (path) => {
    S.raw.documents = { dir: relToFolder(path), ir_plan: "", asset_inventory: "" };
    renderDocTab(); loadDocFiles(); refreshActionbar(); renderRail();
  }, S.folder),
  pickDocs: () => browse("docs", (path) => {
    S.raw.documents.dir = relToFolder(path);
    renderDocTab(); loadDocFiles(); refreshActionbar();
  }, S.folder),
  removeDocs: () => { delete S.raw.documents; S.register = null; renderDocTab(); refreshActionbar(); renderRail(); },
  createRegister: (btn) => withBusy(btn, async () => {
    if (dirty() && !(await save(true))) throw new Error("Save your changes first.");
    const r = await api("/api/register/create", { folder: S.folder });
    const o = await api("/api/open", { folder: S.folder });
    S.raw = withLists(o.raw); S.savedJSON = JSON.stringify(S.raw);
    await loadDocFiles();
    await loadDocuments();
    toast(`Started ${r.register}.`);
  })(),
  newReview: () => reviewDrawer(),
  submitReview: (btn) => withBusy(btn, async () => {
    const entry = {
      requirement: $("#revReq").value,
      documents: $$(".revDoc:checked").map((x) => x.value),
      verdict: $("#revVerdict .on")?.dataset.v || "",
      reviewed_by: $("#revBy").value.trim(),
      reviewed_on: $("#revOn").value,
      valid_until: $("#revUntil").value,
      rationale: $("#revWhy").value.trim(),
    };
    if (!entry.verdict) throw new Error("Choose a verdict.");
    S.register = await api("/api/register/review", { folder: S.folder, entry });
    try { localStorage.setItem("reviewer", entry.reviewed_by); } catch { /* storage unavailable */ }
    await closeOverlay();
    toast("Review recorded. It applies from the next scan.");
    renderDocTab(); renderRail();
  })(),
  runSuggest: (btn) => withBusy(btn, async () => {
    const documents = $$(".sugDoc:checked").map((x) => x.value);
    if (!documents.length) throw new Error("Choose at least one document.");
    const status = $("#sugStatus");
    const r = await runJob("suggest", { folder: S.folder, documents }, (e) => {
      if (e.type === "document" && status) status.textContent = `Reading ${e.name} (${e.index} of ${e.total})…`;
    });
    const byDoc = Object.fromEntries((S.suggestions || []).map((d) => [d.document, d]));
    r.documents.forEach((d) => (byDoc[d.document] = d));
    S.suggestions = Object.values(byDoc);
    renderDocTab();
    const n = r.documents.reduce((k, d) => k + d.accepted.length, 0);
    toast(`${plural(n, "suggestion")} ready for your review.`);
  })(),
  runAccess: async (btn) => {
    if (dirty() && !(await save(true))) { toast("Save your changes first.", "error"); return; }
    S.accessView = { done: false, systems: [], plan: [], total: 0 };
    render();
    try {
      const r = await runJob("access", { folder: S.folder }, (e) => {
        const v = S.accessView;
        if (e.type === "authorisation") { v.auth = e.access; v.fresh = "auth"; }
        if (e.type === "plan") { v.plan = e.systems; v.total = e.total; v.fresh = null; }
        if (e.type === "probing") { v.probing = `${e.section}/${e.name}`; v.fresh = null; }
        if (e.type === "system") { v.systems.push(e.system); v.probing = null; v.fresh = `${e.system.section}/${e.system.name}`; }
        refreshAccess();
      });
      S.access = r; S.accessView.done = true; S.accessView.fresh = null;
    } catch (e) { S.accessView.done = true; S.accessView.error = e.message; }
    refreshAccess(); renderRail();
    if (S.access?.ready) toast("All systems are ready.");
  },
  copyChecklist: () => {
    const v = S.accessView;
    const lines = [`Access needed for the NIS2 evidence scan (${S.raw.engagement?.client || S.raw.name})`, ""];
    if (v.auth?.status !== "ok") lines.push(`- Written authorisation: ${v.auth?.what} ${v.auth?.note || ""}`.trim());
    v.systems.forEach((s) => s.access.filter((a) => a.status === "missing")
      .forEach((a) => lines.push(`- ${s.name} (${s.kind}): ${a.what}${a.note ? " (" + a.note + ")" : ""}`)));
    navigator.clipboard.writeText(lines.join("\n")).then(() => toast("Checklist copied."), () => toast("Could not copy.", "error"));
  },
  runScan: async () => {
    if (dirty() && !(await save(true))) { toast("Save your changes first.", "error"); return; }
    S.scanView = { phase: "running", done: 0, total: 0, feed: [], now: "Preparing", started: Date.now() };
    render(); tickElapsed();
    try {
      const r = await runJob("scan", { folder: S.folder }, onScanEvent);
      const s = Math.round((Date.now() - S.scanView.started) / 1000);
      S.scanView = { phase: "done", result: r, elapsed: `${Math.floor(s / 60)}m ${s % 60}s` };
      S.runs = (await api("/api/runs?" + qs({ folder: S.folder }))).runs;
      S.run = r.run; S.reportMode = "report"; S.diffAgainst = null;
      toast("Scan complete. The report is ready.");
    } catch (e) {
      S.scanView = { phase: "error", error: e.message };
    }
    if (S.step === "scan") render(); else renderRail();
  },
  narrate: (btn) => withBusy(btn, async () => {
    if (!S.info.api_key) { settings(); throw new Error("Add an Anthropic API key first."); }
    toast("Drafting the narrative. This takes a minute or two.");
    const r = await runJob("narrate", { folder: S.folder, run: S.run });
    S.runs = (await api("/api/runs?" + qs({ folder: S.folder }))).runs;
    render(); loadReport();
    if (r.status === "accepted") toast(`Narrative accepted on attempt ${r.attempts}.`);
    else toast("The narrative did not pass validation, so the report is shown without it.", "error");
  })(),
  showReport: () => { S.reportMode = "report"; S.diffAgainst = null; render(); loadReport(); },
  popout: () => window.open(reportURL(), "_blank", "noopener"),
  settings: () => settings(),
  saveSettings: (btn) => withBusy(btn, async () => {
    const key = $("#apiKey").value.trim();
    if (key) S.info.api_key = (await api("/api/settings", { api_key: key })).api_key;
    await closeOverlay();
    toast("Settings saved.");
    if (S.step === "documents") renderDocTab();
  })(),
  shortcut: (btn) => withBusy(btn, async () => {
    const r = await api("/api/shortcut", {});
    toast(`Shortcut created: ${r.path}`);
  })(),
};

function relToFolder(path) {
  const base = S.folder.replace(/\/$/, "") + "/";
  return path.startsWith(base) ? path.slice(base.length) : path === S.folder ? "." : path;
}

// --- events ---------------------------------------------------------------------------------------------------------------------
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-act],[data-go],[data-open],[data-browse],[data-add],[data-remove],[data-product],[data-tab],[data-view-run],[data-suggest-review],#revVerdict button");
  if (!t) return;
  if (t.tagName === "A") e.preventDefault();
  if (t.dataset.act) return ACTIONS[t.dataset.act]?.(t);
  if (t.dataset.go) return go(t.dataset.go);
  if (t.dataset.open) return openFolder(t.dataset.open).catch((err) => toast(err.message, "error"));
  if (t.dataset.browse) return browseTo(t.dataset.browse);
  if (t.dataset.tab) {
    S.docTab = t.dataset.tab;
    $$(".tabs button").forEach((b) => b.classList.toggle("on", b === t));
    renderDocTab();
    return;
  }
  if (t.dataset.add) {
    const key = t.dataset.add;
    const section = S.schema.sections.find((s) => s.key === key);
    const fresh = { name: "" };
    section.fields.forEach((f) => { if (f.default !== undefined) fresh[f.key] = f.default; });
    if (section.products) fresh.product = "auto";
    S.raw[key].push(fresh);
    rerenderSection(key); refreshActionbar(); renderRail();
    const last = $$(`#sec-${key} .asset`).at(-1);
    last?.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "center" });
    last?.querySelector("input")?.focus({ preventScroll: true });
    return;
  }
  if (t.dataset.remove) {
    const [key, i] = t.dataset.remove.split(".");
    const el = t.closest(".asset");
    el.classList.add("removing");
    setTimeout(() => {
      S.raw[key].splice(Number(i), 1);
      const pending = {};
      for (const [p, v] of Object.entries(S.pending)) {
        const [s, j, f] = p.split(".");
        if (s !== key) pending[p] = v;
        else if (Number(j) < Number(i)) pending[p] = v;
        else if (Number(j) > Number(i)) pending[`${s}.${Number(j) - 1}.${f}`] = v;
      }
      S.pending = pending;
      S.problems = S.problems.filter((p) => p.loc[0] !== key);
      rerenderSection(key); refreshActionbar(); renderRail();
    }, REDUCED ? 0 : 230);
    return;
  }
  if (t.dataset.product) {
    setPath(S.raw, `${t.dataset.product}.product`, t.dataset.value);
    rerenderAsset(`${t.dataset.product}.product`);
    refreshActionbar();
    return;
  }
  if (t.dataset.viewRun) {
    S.run = t.dataset.viewRun; S.reportMode = "report"; S.diffAgainst = null;
    return go("report");
  }
  if (t.dataset.suggestReview) {
    reviewDrawer({ requirement: t.dataset.suggestReview, documents: [t.dataset.doc] });
    return;
  }
  if (t.closest("#revVerdict")) {
    $$("#revVerdict button").forEach((b) => b.classList.toggle("on", b === t));
  }
});
document.addEventListener("input", onInput);
document.addEventListener("change", async (e) => {
  if (e.target.matches("select[data-path], input[type=checkbox][data-path], input[type=date][data-path]")) onInput(e);
  if (e.target.id === "runSelect") { S.run = e.target.value; S.reportMode = "report"; S.diffAgainst = null; render(); loadReport(); }
  if (e.target.id === "diffSelect" && e.target.value) {
    try {
      const r = await api("/api/diff", { folder: S.folder, before: e.target.value, after: S.run });
      S.reportMode = "diff"; S.diffAgainst = e.target.value;
      render(); loadReport();
      toast(`${r.fixed} fixed, ${r.still_open} still open, ${r.new} new.`);
    } catch (err) { toast(err.message, "error"); }
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("#overlay").innerHTML) closeOverlay();
  if (e.key === "Enter" && e.target.id === "browsePath") browseTo(e.target.value);
  if (e.key === "Enter" && e.target.id === "newName") ACTIONS.createHere($("[data-act=createHere]"));
});
$("#homeBtn").addEventListener("click", () => ACTIONS.home());
$("#settingsBtn").addEventListener("click", () => settings());
window.addEventListener("beforeunload", (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } });
window.addEventListener("pagehide", () => navigator.sendBeacon("/api/bye"));
setInterval(() => fetch("/api/heartbeat", { method: "POST" }).catch(() => {}), 10000);

async function refreshState() { S.info = await api("/api/state"); }

(async function start() {
  try {
    [S.info, S.schema] = await Promise.all([api("/api/state"), api("/api/schema")]);
  } catch (e) {
    $("#main").innerHTML = `<div class="page"><div class="banner error">${icon("alert")}<div>${esc(e.message)}</div></div></div>`;
    return;
  }
  S.step = "home";
  render();
})();
