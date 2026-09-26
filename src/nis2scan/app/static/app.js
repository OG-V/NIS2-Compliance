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
  if (!force && S.step === "documents" && step !== "documents" && reviewChanges().length &&
      !confirm("Leave this document without saving your changes?")) return;
  if (step !== "documents") S.review = null;
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
  $$("body > .gap-bar").forEach((x) => x.remove());
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
    review: null, docTab: r.raw.documents?.dir ? "review" : "setup",
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
  const tabs = [["setup", "Documents folder"], ["review", "Review documents"], ["coverage", "Coverage"]];
  const reading = S.docTab === "review" && S.review;
  return `<div class="page ${reading ? "page-reading" : ""}">${reading ? "" : pageHead(3, "Documents and reviews",
    "Most of NIS2 is organisational. Open each document the client provided and tick the requirements it " +
    "gives evidence for. The scan records your decisions with your name and the documents' fingerprints.")}
    ${reading ? "" : `<div class="tabs">${tabs.map(([k, l]) => `<button class="${S.docTab === k ? "on" : ""}" data-tab="${k}">${l}</button>`).join("")}</div>`}
    <div id="docTab"></div>${reading ? readingBar() : actionbar("systems", "access")}</div>`;
};
afterRender.documents = () => renderDocTab();
function renderDocTab() {
  const el = $("#docTab");
  if (!el) return;
  el.innerHTML = { setup: docSetupHTML, review: reviewTabHTML, coverage: coverageHTML }[S.docTab]();
  if (S.docTab === "review" && S.review) afterReading();
  // The selection bar floats over the page, so it must not live inside the animated page.
  $$("body > .gap-bar").forEach((x) => x.remove());
  const bar = $("#docTab #gapBar");
  if (bar) document.body.append(bar);
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
  if (!S.register.exists) return `<div class="card"><div class="empty">
    <p style="margin:0 0 10px">Reviews are kept in an evidence register in the documents folder. It lists the
      ${S.register.requirements.length} requirements no automated check covers.</p>
    <button class="btn primary" data-act="createRegister">${icon("plus")}Start the evidence register</button></div></div>`;
  return "";
}

// The reviewer's name is asked once and remembered on this computer.
function reviewer() {
  if (S.reviewer === undefined) {
    try { S.reviewer = localStorage.getItem("reviewer") || ""; } catch { S.reviewer = ""; }
  }
  return S.reviewer;
}
function reviewerHTML() {
  const R = S.register;
  const done = R.reviews.length, total = R.requirements.length;
  return `<div class="card reviewer-card"><div class="row">
      <div class="field" style="flex:1;min-width:260px;margin:0"><label for="reviewerName">Reviewing as<span class="req">*</span></label>
        <input class="input" id="reviewerName" value="${esc(reviewer())}" placeholder="Your name and role, e.g. Jane Smith, senior consultant"></div>
      <div class="progress-block"><div class="small muted">${done} of ${total} requirements reviewed</div>
        <div class="progress"><i style="width:${Math.round((100 * done) / (total || 1))}%"></i></div></div></div></div>`;
}

// --- review tab: pick a document -------------------------------------------------------------------
function reviewableDocs() {
  return S.docFiles.filter((d) => d !== S.raw.documents?.evidence_register);
}
function citing(path) {
  return (S.register?.reviews || []).filter((r) => r.documents.some((d) => d.path === path));
}
function suggestionsFor(path) {
  return (S.suggestions || []).find((d) => d.document === path);
}
function reviewTabHTML() {
  const blocked = needsSavedDocs();
  if (blocked) return blocked;
  if (S.review) return readingHTML();
  const cards = reviewableDocs().map((d) => {
    const cites = citing(d).length;
    const sug = suggestionsFor(d)?.accepted?.length || 0;
    const parts = d.split("/");
    const ext = (d.split(".").pop() || "").toUpperCase();
    return `<button class="doc-card" data-doc-open="${esc(d)}">
      <span class="doc-ic">${icon("file")}<small>${esc(ext.slice(0, 4))}</small></span>
      <span class="grow"><b>${esc(parts.at(-1))}</b>${parts.length > 1 ? `<span class="faint small">${esc(parts.slice(0, -1).join("/"))}/</span>` : ""}
        <span class="doc-badges">${cites ? `<span class="pill ok">${icon("check")}Evidence for ${cites}</span>` : `<span class="pill pending">Not reviewed</span>`}
        ${sug ? `<span class="ai-note">${icon("sparkle")}${sug} suggested</span>` : ""}</span></span>
      ${icon("arrow-right")}</button>`;
  }).join("");
  return `<div class="stagger">${reviewerHTML()}
    <p class="section-title">${plural(reviewableDocs().length, "document")} in the folder</p>
    <div class="doc-grid">${cards || '<div class="empty">No documents in the folder.</div>'}</div></div>`;
}

// --- review tab: one document --------------------------------------------------------------------------
async function openDocument(path) {
  if (S.review && reviewChanges().length && !confirm("Leave this document without saving your changes?")) return;
  const doc = await api("/api/document?" + qs({ folder: S.folder, path }));
  const R = S.register;
  const items = {};
  for (const req of R.requirements) {
    const existing = R.reviews.find((r) => r.requirement === req.id);
    const linked = !!existing?.documents.some((d) => d.path === path);
    const item = { checked: linked, verdict: existing?.verdict || "", rationale: existing?.rationale || "",
      valid_until: existing?.valid_until || "", existing };
    item.orig = JSON.stringify([item.checked, item.verdict, item.rationale, item.valid_until]);
    items[req.id] = item;
  }
  const sug = suggestionsFor(path);
  S.review = { path, doc, items, filter: "", linked: Object.keys(items).filter((id) => items[id].checked),
    suggested: (sug?.accepted || []).map((s) => s.requirement_id).filter((id) => items[id] && !items[id].checked) };
  S.docTab = "review";
  render();
  $("#main").scrollTop = 0;
}
function readingBar() {
  const docs = reviewableDocs();
  const i = docs.indexOf(S.review.path);
  const n = reviewChanges().length;
  return `<div class="actionbar">
    <button class="btn" data-act="closeDocument">${icon("arrow-left")}All documents</button>
    <div class="grow"></div>
    <span class="dirty ${n ? "" : "hidden"}" id="changeCount">${plural(n, "unsaved change")}</span>
    <button class="btn" data-act="saveReview" ${n ? "" : "disabled"}>Save</button>
    <button class="btn primary" data-act="saveNext">${i < docs.length - 1 ? "Save and open next document" : "Save and finish"}${icon("arrow-right")}</button></div>`;
}
function readingHTML() {
  const { path, doc } = S.review;
  const docs = reviewableDocs();
  const i = docs.indexOf(path);
  const sug = suggestionsFor(path);
  const aiButton = sug ? `<span class="ai-note">${icon("sparkle")}${plural(sug.accepted.length, "suggestion")} from ${esc(sug.model || "AI")}</span>`
    : `<button class="btn sm" data-act="askAI" ${S.info.api_key ? "" : 'disabled title="Add an Anthropic API key in Settings"'}>${icon("sparkle")}Ask AI which requirements this covers</button>`;
  return `<div class="reading">
    <div class="reading-head">
      <div><div class="eyebrow">Document ${i + 1} of ${docs.length}</div><h1 class="doc-title">${esc(path.split("/").at(-1))}</h1>
        <div class="small faint mono">${esc(path)} · sha256 ${esc(doc.sha256.slice(0, 12))}…</div></div>
      <div class="grow"></div>${aiButton}
      <button class="btn square" data-doc-open="${esc(docs[i - 1] || "")}" ${i > 0 ? "" : "disabled"} title="Previous document">${icon("arrow-left")}</button>
      <button class="btn square" data-doc-open="${esc(docs[i + 1] || "")}" ${i < docs.length - 1 ? "" : "disabled"} title="Next document">${icon("arrow-right")}</button>
    </div>
    <div class="split">
      <section class="paper" id="paper">${doc.error ? `<div class="banner warn">${icon("alert")}<div>${esc(doc.error)}. You can still record what it evidences.</div></div>` : highlighted(doc.text, sug)}
        ${doc.truncated ? '<div class="faint small">The document is long; only its beginning is shown.</div>' : ""}</section>
      <section class="checklist-pane">
        <div class="field" style="margin:0 0 6px"><label for="reviewerName">Reviewing as<span class="req">*</span></label>
          <input class="input" id="reviewerName" value="${esc(reviewer())}" placeholder="Your name and role"></div>
        <p class="small muted" style="margin:4px 0 12px">Tick each requirement this document gives evidence for, then choose a verdict and say why.</p>
        <input class="input" id="reqFilter" placeholder="Filter requirements, e.g. backup or 21.2.D" value="${esc(S.review.filter)}">
        <div id="reqList">${reqListHTML()}</div>
      </section>
    </div></div>`;
}
function afterReading() {
  const bar = $(".actionbar");
  if (bar) bar.outerHTML = readingBar();
}

// Excerpts the AI suggested are marked in the text, matched with flexible whitespace.
function highlighted(text, sug) {
  const ranges = [];
  for (const s of sug?.accepted || []) {
    for (const ex of s.excerpts || [s.excerpt].filter(Boolean)) {
      const words = ex.trim().split(/\s+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      const m = new RegExp(words.join("\\s+")).exec(text);
      if (m) ranges.push([m.index, m.index + m[0].length, s.requirement_id]);
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];  // overlapping passages become one highlight for several requirements
  for (const [a, b, id] of ranges) {
    const last = merged.at(-1);
    if (last && a < last[1]) { last[1] = Math.max(last[1], b); last[2].add(id); }
    else merged.push([a, b, new Set([id])]);
  }
  let out = "", at = 0;
  for (const [a, b, ids] of merged) {
    out += esc(text.slice(at, a)) + `<mark data-mark="${esc([...ids].join(" "))}">${esc(text.slice(a, b))}</mark>`;
    at = b;
  }
  return `<div class="doc-text">${out + esc(text.slice(at))}</div>`;
}

function reqListHTML() {
  const R = S.register, rv = S.review;
  const byId = Object.fromEntries(R.requirements.map((r) => [r.id, r]));
  const f = rv.filter.trim().toLowerCase();
  const match = (r) => !f || `${r.id} ${r.title} ${r.article}`.toLowerCase().includes(f);
  const pinned = new Set([...rv.linked, ...rv.suggested]);
  const section = (title, ids, note) => {
    const rows = ids.map((id) => byId[id]).filter(match);
    return rows.length ? `<div class="req-section"><div class="req-section-title">${title}${note ? ` <span class="faint">${note}</span>` : ""}</div>
      ${rows.map(reqItemHTML).join("")}</div>` : "";
  };
  const byArticle = {};
  R.requirements.filter((r) => !pinned.has(r.id) && match(r)).forEach((r) => (byArticle[r.article] ||= []).push(r));
  const groups = Object.keys(byArticle).sort().map((a) => {
    const rows = byArticle[a];
    const ticked = rows.filter((r) => rv.items[r.id].checked).length;
    return `<details class="req-group" ${f || ticked ? "open" : ""}><summary><span>NIS2 Art. ${esc(a)}</span>
      <span class="faint small">${rows.length}${ticked ? ` · ${ticked} ticked` : ""}</span></summary>${rows.map(reqItemHTML).join("")}</details>`;
  }).join("");
  const out = section("Evidenced by this document", rv.linked, "from earlier reviews") +
    section(`${icon("sparkle")} Suggested by AI`, rv.suggested, "verify against the text") +
    (groups ? `<div class="req-section"><div class="req-section-title">${pinned.size ? "Other requirements" : "Requirements"}</div>${groups}</div>` : "");
  return out || `<div class="empty">No requirement matches “${esc(rv.filter)}”.</div>`;
}
const VERDICTS = [["evidenced", "Evidenced"], ["partially_evidenced", "Partially"], ["not_satisfied", "Not satisfied"]];
function reqItemHTML(r) {
  const it = S.review.items[r.id];
  const ex = it.existing;
  const others = ex ? ex.documents.map((d) => d.path).filter((p) => p !== S.review.path) : [];
  const sug = suggestionsFor(S.review.path)?.accepted?.find((s) => s.requirement_id === r.id);
  const status = ex ? `<span class="pill ${ex.counts_as}" title="${esc(ex.reason)}">${esc(ex.verdict.replace(/_/g, " "))}</span>` : "";
  const changed = JSON.stringify([it.checked, it.verdict, it.rationale, it.valid_until]) !== it.orig;
  return `<div class="req-item ${it.checked ? "on" : ""} ${changed ? "changed" : ""} ${it.error ? "invalid" : ""}" data-req="${esc(r.id)}">
    <label class="req-row"><input type="checkbox" data-req-check="${esc(r.id)}" ${it.checked ? "checked" : ""}>
      <span class="req-main"><b>${esc(r.title)}</b><span class="mono faint">${esc(r.id.replace("REQ-", ""))}</span></span>${status}</label>
    ${sug && !it.checked ? `<div class="req-hint">${icon("sparkle")}<span>${esc(sug.addresses)}
      <a href="#" data-show-mark="${esc(r.id)}">Show in document</a></span></div>` : ""}
    ${it.checked ? `<div class="req-editor">
      <div class="segmented">${VERDICTS.map(([v, l]) => `<button type="button" class="${it.verdict === v ? "on" : ""}" data-verdict="${esc(r.id)}" data-v="${v}">${l}</button>`).join("")}</div>
      <textarea class="input" data-rationale="${esc(r.id)}" rows="2" placeholder="${esc(sug?.addresses ? "Why? AI note: " + sug.addresses : "Why? What the document shows, and what it does not.")}">${esc(it.rationale)}</textarea>
      <div class="row small muted"><label>Valid until <input type="date" class="input input-sm" data-valid="${esc(r.id)}" value="${esc(it.valid_until)}"></label>
        ${others.length ? `<span>Also cites ${others.map(esc).join(", ")}</span>` : ""}</div>
      ${it.error ? `<div class="err">${esc(it.error)}</div>` : ""}</div>`
    : ex && ex.documents.some((d) => d.path === S.review.path) ? `<div class="req-hint warn-hint">${icon("alert")}<span>${others.length
        ? `Saving removes this document from the review; it keeps ${others.map(esc).join(", ")}.`
        : ex.verdict === "not_satisfied" ? "Saving removes this document from the review." : "Saving deletes this review: no other document supports it."}</span></div>`
    : ex && ex.documents.length === 0 ? `<div class="req-hint">Reviewed without a document: ${esc(ex.verdict.replace(/_/g, " "))}.</div>` : ""}
  </div>`;
}
function rerenderReq(id) {
  const el = $(`.req-item[data-req="${CSS.escape(id)}"]`);
  const r = S.register.requirements.find((x) => x.id === id);
  if (el && r) el.outerHTML = reqItemHTML(r);
  updateChangeCount();
}
function updateChangeCount() {
  const bar = $(".actionbar");
  if (bar && S.review) bar.outerHTML = readingBar();
}

// What saving this document's checklist would change in the register.
function reviewChanges() {
  if (!S.review) return [];
  const { path, items } = S.review;
  const changes = [];
  for (const [id, it] of Object.entries(items)) {
    if (JSON.stringify([it.checked, it.verdict, it.rationale, it.valid_until]) === it.orig) continue;
    const ex = it.existing;
    const docs = (ex?.documents || []).map((d) => d.path).filter((p) => p !== path);
    const base = { requirement: id, reviewed_by: reviewer(), reviewed_on: S.info.today };
    if (it.checked) {
      changes.push({ requirement: id, entry: { ...base, documents: [...docs, path], verdict: it.verdict,
        rationale: it.rationale.trim(), valid_until: it.valid_until || null } });
    } else if (ex) {
      if (!docs.length && ex.verdict !== "not_satisfied") changes.push({ requirement: id, delete: true });
      else changes.push({ requirement: id, entry: { ...base, documents: docs, verdict: ex.verdict,
        rationale: ex.rationale, valid_until: ex.valid_until || null } });
    }
  }
  return changes;
}
async function saveReview() {
  const rv = S.review;
  if (!reviewer().trim()) { $("#reviewerName")?.focus(); throw new Error("Enter your name and role as the reviewer."); }
  let firstBad = null;
  for (const [id, it] of Object.entries(rv.items)) {
    const was = it.error;
    it.error = it.checked && (!it.verdict ? "Choose a verdict." : !it.rationale.trim() ? "Say why: the rationale is part of the record." : "");
    if (it.error && !firstBad) firstBad = id;
    if (it.error || was) rerenderReq(id);
  }
  if (firstBad) {
    $(`.req-item[data-req="${CSS.escape(firstBad)}"]`)?.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "center" });
    throw new Error("Some ticked requirements need a verdict and a reason.");
  }
  const changes = reviewChanges();
  if (!changes.length) return 0;
  S.register = await api("/api/register/batch", { folder: S.folder, changes });
  try { localStorage.setItem("reviewer", reviewer()); } catch { /* storage unavailable */ }
  return changes.length;
}

// --- coverage tab ------------------------------------------------------------------------------------------
function coverageHTML() {
  const blocked = needsSavedDocs();
  if (blocked) return blocked;
  const R = S.register;
  S.gapPick = S.gapPick || new Set();
  const reviews = Object.fromEntries(R.reviews.map((r) => [r.requirement, r]));
  const counts = {};
  R.reviews.forEach((r) => (counts[r.counts_as] = (counts[r.counts_as] || 0) + 1));
  const pills = ["evidenced", "partially_evidenced", "not_satisfied", "not_assessed"].filter((k) => counts[k])
    .map((k) => `<span class="pill ${k}">${counts[k]} ${k.replace(/_/g, " ")}</span>`).join(" ");
  const problems = R.problems.length ? `<div class="banner warn">${icon("alert")}<div><b>Entries that will not be applied</b>
    <ul>${R.problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></div></div>` : "";
  const byArticle = {};
  R.requirements.forEach((r) => (byArticle[r.article] ||= []).push(r));
  const groups = Object.keys(byArticle).sort().map((a) => {
    const rows = byArticle[a].map((r) => {
      const rev = reviews[r.id];
      if (rev) {
        const docs = rev.documents.map((d) => d.path).join(", ") || "no document";
        return `<div class="cov-row" data-review="${esc(r.id)}"><span class="status-ic ${rev.counts_as === "not_satisfied" ? "bad" : rev.counts_as === "not_assessed" ? "warn" : "ok"}">${icon(rev.counts_as === "not_satisfied" ? "x" : rev.counts_as === "not_assessed" ? "alert" : "check")}</span>
          <div class="grow"><b>${esc(r.title)}</b><div class="sub">${esc(r.id.replace("REQ-", ""))} · ${esc(docs)} · ${esc(rev.reviewed_by)}, ${esc(rev.reviewed_on)}</div>
          ${rev.counts_as !== rev.verdict ? `<div class="sub" style="color:var(--amber)">${esc(rev.reason)}</div>` : ""}</div>
          <span class="pill ${rev.counts_as}">${esc(rev.counts_as.replace(/_/g, " "))}</span>
          <span class="review-actions"><button class="btn ghost sm" data-edit-review="${esc(r.id)}">Edit</button>
          <button class="btn ghost sm danger" data-delete-review="${esc(r.id)}">Delete</button></span></div>`;
      }
      return `<label class="cov-row open"><input type="checkbox" data-gap="${esc(r.id)}" ${S.gapPick.has(r.id) ? "checked" : ""}>
        <div class="grow"><b>${esc(r.title)}</b><div class="sub">${esc(r.id.replace("REQ-", ""))} · not reviewed yet</div></div>
        <span class="pill pending">open</span></label>`;
    }).join("");
    const done = byArticle[a].filter((r) => reviews[r.id]).length;
    return `<details class="cov-group" open><summary><b>NIS2 Art. ${esc(a)}</b><span class="faint small">${done} of ${byArticle[a].length} reviewed</span></summary>${rows}</details>`;
  }).join("");
  const n = S.gapPick.size;
  return `${problems}${reviewerHTML()}
    <div class="card"><div class="card-head"><div class="ic">${icon("clipboard")}</div><div class="grow">
      <h2>Every requirement no check covers</h2><p>${pills || "No reviews yet."} Tick requirements for which the client
      provided no document at all to record them as not satisfied in one step.</p></div></div>
      ${groups}</div>
    <div class="gap-bar ${n ? "on" : ""}" id="gapBar">
      <b>${plural(n, "requirement")} selected</b>
      <input class="input" id="gapWhy" value="The organisation provided no document that addresses this requirement.">
      <button class="btn primary" data-act="markGaps">Record as not satisfied</button></div>`;
}
function reviewDrawer(prefill = {}, editing = null) {
  const R = S.register;
  S.editing = editing;
  const reviewed = new Set(R.reviews.map((r) => r.requirement).filter((id) => id !== editing));
  const byArticle = {};
  R.requirements.filter((r) => !reviewed.has(r.id)).forEach((r) => (byArticle[r.article] ||= []).push(r));
  const options = Object.keys(byArticle).sort().map((a) => `<optgroup label="NIS2 Art. ${esc(a)}">
    ${byArticle[a].map((r) => `<option value="${esc(r.id)}" ${r.id === prefill.requirement ? "selected" : ""}>${esc(r.title)} (${esc(r.id.replace("REQ-", ""))})</option>`).join("")}</optgroup>`).join("");
  const docs = S.docFiles.filter((d) => d !== S.raw.documents.evidence_register).map((d) => `<label>
    <input type="checkbox" class="revDoc" value="${esc(d)}" ${(prefill.documents || []).includes(d) ? "checked" : ""}>${esc(d)}</label>`).join("");
  let reviewer = prefill.reviewed_by || "";
  if (!reviewer) try { reviewer = localStorage.getItem("reviewer") || ""; } catch { /* storage unavailable */ }
  const on = (v) => (prefill.verdict === v ? "on" : "");
  drawer(editing ? "Edit document review" : "Record a document review", `
    <p class="muted small" style="margin-top:0">Your decision is recorded with your name and the documents' fingerprints.
      It applies to the next scan and counts only while it is valid.</p>
    <div class="grid" style="grid-template-columns:1fr">
      <div class="field"><label>Requirement<span class="req">*</span></label><select class="input" id="revReq" ${editing ? "disabled" : ""}>${options}</select>
        ${editing ? `<div class="help">To review another requirement, delete this review and record a new one.</div>` : ""}</div>
      <div class="field"><label>Documents reviewed</label><div class="checklist">${docs || '<span class="faint small">No files in the folder</span>'}</div>
        <div class="help">Required unless you found no document that addresses the requirement.</div></div>
      <div class="field"><label>Verdict<span class="req">*</span></label><div class="segmented" id="revVerdict">
        <button type="button" class="${on("evidenced")}" data-v="evidenced">Evidenced</button><button type="button" class="${on("partially_evidenced")}" data-v="partially_evidenced">Partially evidenced</button>
        <button type="button" class="${on("not_satisfied")}" data-v="not_satisfied">Not satisfied</button></div></div>
      <div class="field"><label>Reviewed by<span class="req">*</span></label><input class="input" id="revBy" value="${esc(reviewer)}" placeholder="Your name and role"></div>
      <div class="grid" style="padding:0"><div class="field"><label>Reviewed on<span class="req">*</span></label><input class="input" type="date" id="revOn" value="${esc(editing ? S.info.today : prefill.reviewed_on || S.info.today)}"></div>
      <div class="field"><label>Valid until</label><input class="input" type="date" id="revUntil" value="${esc(prefill.valid_until || "")}"></div></div>
      ${editing ? `<div class="help" style="margin-top:-8px">Previously reviewed on ${esc(prefill.reviewed_on)}. Saving records today as the review date; change it if needed.</div>` : ""}
      <div class="field"><label>Rationale<span class="req">*</span></label><textarea class="input" id="revWhy" placeholder="What the documents show, and what they do not.">${esc(prefill.rationale || "")}</textarea></div>
    </div>`, `<button class="btn" data-act="closeOverlay">Cancel</button><button class="btn primary" data-act="submitReview">${editing ? "Save changes" : "Record review"}</button>`);
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
  confirmDelete: (btn) => withBusy(btn, async () => {
    const id = S.deleting;
    await closeOverlay();
    const card = $(`[data-review="${CSS.escape(id)}"]`);
    if (card && !REDUCED) { card.classList.add("removing"); await sleep(230); }
    S.register = await api("/api/register/delete", { folder: S.folder, requirement: id });
    renderDocTab(); renderRail();
    toast("Review deleted. The next scan reports the requirement as not assessed.");
  })(),
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
    const editing = S.editing;
    S.register = await api("/api/register/review", { folder: S.folder, entry, replace: editing });
    try { localStorage.setItem("reviewer", entry.reviewed_by); } catch { /* storage unavailable */ }
    await closeOverlay();
    toast(editing ? "Review updated. The change applies from the next scan." : "Review recorded. It applies from the next scan.");
    renderDocTab(); renderRail();
  })(),
  closeDocument: () => {
    if (reviewChanges().length && !confirm("Leave this document without saving your changes?")) return;
    S.review = null; render();
  },
  saveReview: (btn) => withBusy(btn, async () => {
    const n = await saveReview();
    const path = S.review.path;
    S.review = null;
    await openDocument(path);
    renderRail();
    toast(n ? `${plural(n, "review")} saved. They apply from the next scan.` : "Nothing to save.");
  })(),
  saveNext: (btn) => withBusy(btn, async () => {
    const n = await saveReview();
    const docs = reviewableDocs();
    const next = docs[docs.indexOf(S.review.path) + 1];
    S.review = null;
    renderRail();
    if (n) toast(`${plural(n, "review")} saved.`);
    if (next) await openDocument(next);
    else { S.docTab = "coverage"; render(); toast("All documents seen. Check the coverage for anything left open."); }
  })(),
  askAI: (btn) => withBusy(btn, async () => {
    const path = S.review.path;
    btn.textContent = "Reading the document…";
    const r = await runJob("suggest", { folder: S.folder, documents: [path] });
    const byDoc = Object.fromEntries((S.suggestions || []).map((d) => [d.document, d]));
    r.documents.forEach((d) => (byDoc[d.document] = d));
    S.suggestions = Object.values(byDoc);
    const doc = r.documents[0];
    if (doc.error) throw new Error(doc.error);
    const items = S.review.items;
    S.review.suggested = doc.accepted.map((x) => x.requirement_id).filter((id) => items[id] && !S.review.linked.includes(id));
    renderDocTab();
    toast(`${plural(doc.accepted.length, "suggestion")}: verify each against the text before ticking it.`);
  })(),
  markGaps: (btn) => withBusy(btn, async () => {
    if (!reviewer().trim()) { $("#reviewerName")?.focus(); throw new Error("Enter your name and role as the reviewer."); }
    const why = $("#gapWhy").value.trim();
    if (!why) throw new Error("Give the reason.");
    const changes = [...S.gapPick].map((id) => ({ requirement: id, entry: { requirement: id, documents: [],
      verdict: "not_satisfied", reviewed_by: reviewer(), reviewed_on: S.info.today, rationale: why } }));
    S.register = await api("/api/register/batch", { folder: S.folder, changes });
    try { localStorage.setItem("reviewer", reviewer()); } catch { /* storage unavailable */ }
    S.gapPick = new Set();
    renderDocTab(); renderRail();
    toast(`${plural(changes.length, "requirement")} recorded as not satisfied.`);
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
  const t = e.target.closest("[data-act],[data-go],[data-open],[data-browse],[data-add],[data-remove],[data-product],[data-tab],[data-view-run],[data-edit-review],[data-delete-review],[data-doc-open],[data-verdict],[data-show-mark],#revVerdict button");
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
  if (t.dataset.editReview) {
    const r = S.register.reviews.find((x) => x.requirement === t.dataset.editReview);
    reviewDrawer({ ...r, documents: r.documents.map((d) => d.path) }, r.requirement);
    return;
  }
  if (t.dataset.deleteReview) {
    const r = S.register.reviews.find((x) => x.requirement === t.dataset.deleteReview);
    S.deleting = r.requirement;
    modal("Delete this review?", `<p style="margin-top:0"><b>${esc(r.title || r.requirement)}</b></p>
      <p class="muted">The review by ${esc(r.reviewed_by)} on ${esc(r.reviewed_on)} is removed from the register.
      From the next scan, this requirement is reported as not assessed until it is reviewed again.
      Earlier reports keep the review they were made with.</p>`,
      `<button class="btn" data-act="closeOverlay">Cancel</button><button class="btn primary" style="background:var(--red);border-color:var(--red)" data-act="confirmDelete">Delete review</button>`);
    return;
  }
  if (t.dataset.docOpen !== undefined) {
    if (t.dataset.docOpen) openDocument(t.dataset.docOpen).catch((err) => toast(err.message, "error"));
    return;
  }
  if (t.dataset.verdict) {
    const it = S.review.items[t.dataset.verdict];
    it.verdict = t.dataset.v; it.error = "";
    rerenderReq(t.dataset.verdict);
    $(`[data-rationale="${CSS.escape(t.dataset.verdict)}"]`)?.focus();
    return;
  }
  if (t.dataset.showMark) {
    const mark = $(`mark[data-mark~="${CSS.escape(t.dataset.showMark)}"]`);
    if (!mark) return toast("The passage is not in the displayed text.", "error");
    mark.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "center" });
    mark.classList.remove("flash"); void mark.offsetWidth; mark.classList.add("flash");
    return;
  }
  if (t.closest("#revVerdict")) {
    $$("#revVerdict button").forEach((b) => b.classList.toggle("on", b === t));
  }
});
document.addEventListener("input", onInput);
// The document review: reviewer, filter, rationale and dates are kept as they are typed.
document.addEventListener("input", (e) => {
  const el = e.target;
  if (el.id === "reviewerName") { S.reviewer = el.value; $$("#reviewerName").forEach((x) => x !== el && (x.value = el.value)); }
  if (!S.review) return;
  if (el.id === "reqFilter") { S.review.filter = el.value; $("#reqList").innerHTML = reqListHTML(); }
  if (el.dataset.rationale) {
    const it = S.review.items[el.dataset.rationale];
    it.rationale = el.value;
    el.closest(".req-item").classList.toggle("changed", JSON.stringify([it.checked, it.verdict, it.rationale, it.valid_until]) !== it.orig);
    updateChangeCount();
  }
  if (el.dataset.valid) { S.review.items[el.dataset.valid].valid_until = el.value; updateChangeCount(); }
});
document.addEventListener("change", async (e) => {
  if (e.target.matches("select[data-path], input[type=checkbox][data-path], input[type=date][data-path]")) onInput(e);
  if (e.target.dataset.reqCheck) {
    const id = e.target.dataset.reqCheck, it = S.review.items[id];
    it.checked = e.target.checked; it.error = "";
    if (it.checked && !it.verdict) it.verdict = "";
    rerenderReq(id);
    if (it.checked) $(`[data-req="${CSS.escape(id)}"] .req-editor`)?.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "nearest" });
  }
  if (e.target.dataset.gap) {
    S.gapPick[e.target.checked ? "add" : "delete"](e.target.dataset.gap);
    const bar = $("#gapBar");
    bar.classList.toggle("on", S.gapPick.size > 0);
    bar.querySelector("b").textContent = `${plural(S.gapPick.size, "requirement")} selected`;
  }
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
