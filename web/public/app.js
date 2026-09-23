/* PRAHARI dashboard.
   Talks to the same API the server and the Vercel functions expose. Live mode
   (Server-Sent Events from a real capture) only exists when the live endpoints
   are present; on the static viewer that tab explains why and offers replay
   instead. No framework, no CDN — one file, so it loads behind an air gap. */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const CLASS_LABEL = {
  volumetric_ddos: "Volumetric DDoS", c2_beaconing: "C2 beaconing",
  dga_resolution: "DGA resolution", dns_tunnelling: "DNS tunnelling",
  encrypted_malware: "Malware in TLS", recon_scanning: "Recon scanning",
  data_exfiltration: "Data exfiltration", benign: "Benign",
};
const label = (c) => CLASS_LABEL[c] || c;

// Deterministic colour per threat class for the by-class legend dots. These are
// identity hues (categorical), distinct from the severity ramp.
const CLASS_HUE = {
  volumetric_ddos: "#ff5c7a", c2_beaconing: "#7c8bff", dga_resolution: "#35d6a4",
  dns_tunnelling: "#4bb8f0", encrypted_malware: "#ff9f52", recon_scanning: "#f5c542",
  data_exfiltration: "#e879f9",
};
const SEV_ICON = { critical: "i-alert", high: "i-alert", medium: "i-bolt", low: "i-info" };
const svg = (id, cls = "ico") => `<svg class="${cls}"><use href="#${id}"/></svg>`;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok && r.headers.get("content-type")?.includes("json")) return r.json();
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}

/* ---------- theme ---------- */
(function theme() {
  const saved = (() => { try { return localStorage.getItem("prahari-theme"); } catch { return null; } })();
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  $("#theme-btn").addEventListener("click", () => {
    // Dark is the app default (no attribute renders dark), so flip against that.
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("prahari-theme", next); } catch {}
  });
})();

/* ---------- tabs ---------- */
$$("#tabs button").forEach((btn) => btn.addEventListener("click", () => {
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b === btn));
  const tab = btn.dataset.tab;
  $$(".tabpane").forEach((p) => (p.hidden = p.id !== `tab-${tab}`));
  if (tab === "degraded") loadDegraded();
  if (tab === "metrics") loadMetrics();
  if (tab === "replay") ensureScenarios();
  try { localStorage.setItem("prahari-tab", tab); } catch {}
}));

/* ---------- shared renderers ---------- */
function sevBadge(sev) {
  return `<span class="sev ${esc(sev)}">${svg(SEV_ICON[sev] || "i-info", "ico")}${esc(sev)}</span>`;
}
function evidenceText(ev) {
  return Object.entries(ev || {}).slice(0, 3)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.length : v}`).join(", ");
}
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0").slice(0, 2);
}
function alertRow(a) {
  return `<tr class="clickable" data-alert='${esc(JSON.stringify(a))}'>
    <td class="mono">${fmtTime(a.ts)}</td>
    <td>${sevBadge(a.severity)}</td>
    <td>${esc(label(a.threat_class))}</td>
    <td class="mono">${esc(a.src_ip)} → ${esc(a.dst_ip ?? "—")}</td>
    <td class="evidence">${esc(evidenceText(a.evidence))}</td>
    <td class="num mono">${a.confidence.toFixed(2)}</td>
  </tr>`;
}
function wireRows(tbody) {
  $$("tr.clickable", tbody).forEach((tr) => tr.addEventListener("click", () =>
    openDrawer(JSON.parse(tr.dataset.alert))));
}
function statTiles(el, items) {
  el.innerHTML = items.map(([b, l]) =>
    `<div class="stat"><b>${esc(b)}</b><span>${esc(l)}</span></div>`).join("");
}
function byClassBars(el, byClass) {
  const entries = Object.entries(byClass || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { el.innerHTML = `<p class="empty" style="padding:8px 0">No detections yet.</p>`; return; }
  const max = Math.max(...entries.map((e) => e[1]));
  el.innerHTML = entries.map(([c, n]) => {
    const hue = CLASS_HUE[c] || "var(--accent)";
    return `<div class="bar-row">
      <span class="lbl"><span class="dot" style="background:${hue}"></span>${esc(label(c))}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, (n / max) * 100)}%;background:${hue}"></div></div>
      <span class="val">${n}</span></div>`;
  }).join("");
}
function incidentList(el, incs) {
  if (!incs || !incs.length) { el.innerHTML = `<p class="empty" style="padding:8px 0">No multi-stage host yet.</p>`; return; }
  el.innerHTML = incs.map((i) => `<div class="incident">
    <div style="display:flex;gap:8px;align-items:center">${sevBadge(i.severity)}<span class="ent">${esc(i.entity)}</span>
      <span class="grow"></span><span class="mono muted">score ${i.score.toFixed(2)}</span></div>
    <div class="chain">${i.classes.map((c, k) =>
      `${k ? '<span class="arr">→</span>' : ""}<span class="step">${esc(label(c))}</span>`).join("")}</div>
  </div>`).join("");
}

/* ---------- drawer ---------- */
function openDrawer(a) {
  $("#drawer-title").textContent = `${label(a.threat_class)} · ${a.severity}`;
  const ev = Object.entries(a.evidence || {}).map(([k, v]) =>
    `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? JSON.stringify(v) : v)}</dd>`).join("");
  const rec = a.record ? `<h2 style="font-size:11px;margin:18px 0 8px" class="muted">RAW ALERT RECORD (ECS-ALIGNED)</h2>
    <pre class="raw">${esc(JSON.stringify(a.record, null, 2))}</pre>` : "";
  $("#drawer-content").innerHTML =
    (a.caveat ? `<div class="banner info">${svg("i-info")}<span>${esc(a.caveat)}</span></div>` : "") +
    `<dl class="kv">
      <dt>flow id</dt><dd>${esc((a.flow_ids || [])[0] || "—")}</dd>
      <dt>source</dt><dd>${esc(a.src_ip)}</dd>
      <dt>destination</dt><dd>${esc(a.dst_ip ?? "—")}</dd>
      <dt>detector</dt><dd>${esc(a.detector || "—")}</dd>
      <dt>confidence</dt><dd>${a.confidence?.toFixed(3)}</dd>
      <dt>observed flows</dt><dd>${a.observed_flows ?? 1}</dd>
    </dl>
    <h2 style="font-size:11px;margin:18px 0 8px" class="muted">EVIDENCE THAT FIRED THIS ALERT</h2>
    <dl class="kv">${ev}</dl>${rec}`;
  $("#drawer").hidden = false; $("#scrim").hidden = false;
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
function closeDrawer() { $("#drawer").hidden = true; $("#scrim").hidden = true; }

/* ========================= LIVE ========================= */
const Live = (() => {
  let es = null, running = false, alerts = [], byClass = {}, incidents = [];
  const MAX = 200;

  async function init() {
    let st;
    try { st = await api("/api/live/status"); }
    catch {
      // Static viewer (e.g. Vercel): no live endpoints. Explain and stand down.
      showUnavailable("This is the static viewer — it cannot tap a live NIC. " +
        "Live capture runs on the deployed sensor; here, use Replay scenarios, " +
        "which run the same engine on demand.");
      $("#mode-chip").textContent = "static viewer";
      $("#live-toggle").disabled = true;
      $("#live-toggle").textContent = "Live sensor runs on the server";
      $("#live-clock").textContent = "";
      $("#attack-buttons").closest(".field").hidden = true;
      return;
    }

    const buttons = ["syn_flood", "port_scan", "c2_beacon", "dns_tunnel", "malware_tls", "exfil", "benign"];
    const TIP = { exfil: "baseline-relative — best shown in Replay on a loopback demo; fires live on a real span port" };
    $("#attack-buttons").innerHTML = buttons.map((n) =>
      `<button class="btn ghost" data-atk="${n}"${TIP[n] ? ` title="${TIP[n]}"` : ""}>${n.replace("_", " ")}</button>`).join("");
    $$("#attack-buttons button").forEach((b) => b.addEventListener("click", () => launch(b.dataset.atk, b)));

    if (!st.capture_available) {
      showUnavailable(`Live capture unavailable on this host: ${esc(st.capture_reason)}. ` +
        `The sensor needs a Linux host and CAP_NET_RAW. Replay scenarios still work everywhere.`);
      $("#mode-chip").textContent = "replay only";
      $("#live-toggle").disabled = true;
      $$("#attack-buttons button").forEach((b) => (b.disabled = !st.attack_available));
    } else {
      $("#mode-chip").textContent = "live capable";
      $("#mode-chip").classList.add("ok");
    }
    render(st.status || {});
    $("#live-toggle").addEventListener("click", toggle);
  }

  function showUnavailable(msg) {
    const el = $("#live-unavailable");
    el.innerHTML = msg; el.hidden = false;
  }

  async function toggle() {
    if (running) {
      await api("/api/live/stop", { method: "POST" });
      stopStream(); running = false; $("#live-toggle").innerHTML = svg("i-play") + "Start sensor";
      $("#live-clock").textContent = "stopped";
    } else {
      const r = await api("/api/live/start", { method: "POST" });
      if (!r.started) { showUnavailable("Could not start the sensor (needs root)."); return; }
      running = true; $("#live-toggle").innerHTML = svg("i-stop") + "Stop sensor";
      startStream();
    }
  }

  async function launch(name, btn) {
    if (!running) { await toggle(); }
    btn.disabled = true; setTimeout(() => (btn.disabled = false), 1200);
    await api(`/api/live/attack?name=${encodeURIComponent(name)}`, { method: "POST" });
  }

  function startStream() {
    stopStream();
    es = new EventSource("/api/live/stream");
    es.addEventListener("alert", (e) => onAlert(JSON.parse(e.data)));
    es.addEventListener("stats", (e) => render(JSON.parse(e.data)));
    es.addEventListener("status", (e) => render(JSON.parse(e.data)));
    es.addEventListener("incidents", (e) => { incidents = JSON.parse(e.data); incidentList($("#live-incidents"), incidents); });
    es.onerror = () => { $("#live-clock").textContent = running ? "reconnecting…" : "stopped"; };
  }
  function stopStream() { if (es) { es.close(); es = null; } }

  function onAlert(a) {
    alerts.unshift(a); if (alerts.length > MAX) alerts.pop();
    byClass[a.threat_class] = (byClass[a.threat_class] || 0) + 1;
    const body = $("#live-alerts");
    if (alerts.length === 1) body.innerHTML = "";
    body.insertAdjacentHTML("afterbegin", alertRow(a));
    const row = body.firstElementChild;
    row.classList.add("fresh");
    row.onclick = () => openDrawer(a);
    if (body.children.length > MAX) body.lastElementChild.remove();
    $("#live-alert-count").textContent = `(${alerts.length})`;
    byClassBars($("#live-byclass"), byClass);
  }

  function render(st) {
    running = !!st.running;
    $("#live-toggle").innerHTML = running ? svg("i-stop") + "Stop sensor" : svg("i-play") + "Start sensor";
    if (running) $("#live-clock").textContent = `live · ${Math.floor(st.uptime || 0)}s · ${st.clients || 0} watching`;
    const eng = st.engine || {};
    statTiles($("#live-stats"), [
      [String(st.flows_total ?? 0), "flows assembled"],
      [String(st.alerts_total ?? 0), "alerts raised"],
      [String(Object.keys(st.by_class || {}).length), "threat classes seen"],
      [eng.flows_per_sec ? Math.round(eng.flows_per_sec).toLocaleString() : "—", "flows / sec"],
      [st.iface || "—", "interface"],
    ]);
    if (st.by_class && Object.keys(st.by_class).length) byClassBars($("#live-byclass"), st.by_class);
  }

  return { init };
})();

/* ========================= REPLAY ========================= */
let scenariosLoaded = false;
async function ensureScenarios() {
  if (scenariosLoaded) return; scenariosLoaded = true;
  let data;
  try { data = await api("/api/scenarios"); }
  catch { data = await api("data/scenarios.json"); }
  $("#scenario").innerHTML = data.scenarios.map((s) =>
    `<option value="${s.id}">${esc(s.title)}</option>`).join("");
  updateBlurb(data);
  $("#scenario").addEventListener("change", () => updateBlurb(data));
  $("#jitter").addEventListener("input", () => $("#jitter-val").textContent = $("#jitter").value + "%");
  $("#jitter-val").textContent = "20%";
  $("#run-replay").addEventListener("click", runReplay);
  $("#pcap-file").addEventListener("change", runPcap);
  function updateBlurb(d) {
    const s = d.scenarios.find((x) => x.id === $("#scenario").value);
    $("#replay-blurb").textContent = s ? s.blurb : "";
  }
}
async function runReplay() {
  const btn = $("#run-replay"); btn.disabled = true; btn.textContent = "Analysing…";
  const q = new URLSearchParams({
    scenario: $("#scenario").value,
    jitter: (+$("#jitter").value / 100).toString(),
    single_direction: $("#single-dir").checked ? "1" : "0",
  });
  let data;
  try { data = await api(`/api/analyze?${q}`); }
  catch { data = await api(`data/scenario-${$("#scenario").value}.json`); }
  renderReplay(data);
  btn.disabled = false; btn.textContent = "Analyse";
}
async function runPcap(e) {
  const f = e.target.files[0]; if (!f) return;
  const btn = $("#run-replay"); btn.disabled = true;
  $("#replay-blurb").innerHTML = `<span class="spinner"></span> parsing ${esc(f.name)} on the server…`;
  try {
    const buf = await f.arrayBuffer();
    const data = await api(`/api/pcap?single_direction=${$("#single-dir").checked ? 1 : 0}`,
      { method: "POST", body: buf });
    if (data.error) { $("#replay-blurb").textContent = "Error: " + data.error; }
    else { $("#replay-blurb").textContent = `${data.flows} flows from ${(data.bytes / 1e6).toFixed(1)} MB of your capture.`; renderReplay(data); }
  } catch (err) { $("#replay-blurb").textContent = "Upload failed: " + err.message; }
  btn.disabled = false;
}
function renderReplay(d) {
  statTiles($("#replay-stats"), [
    [String(d.flows), "flows"], [String(d.alerts_total), "alerts"],
    [String(Object.keys(d.by_class || {}).length), "classes"],
    [String(d.hosts ?? "—"), "hosts"], [(d.wall_seconds ?? 0) + "s", "analysis time"],
  ]);
  const body = $("#replay-alerts");
  body.innerHTML = d.alerts.length
    ? d.alerts.slice().sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.ts - b.ts).map(alertRow).join("")
    : `<tr><td colspan="6" class="empty">No alerts — on clean traffic that is the correct answer.</td></tr>`;
  wireRows(body);
  $("#replay-alert-count").textContent = `(${d.alerts_total})`;
  incidentList($("#replay-incidents"), d.incidents);
  byClassBars($("#replay-byclass"), d.by_class);
}

/* ========================= DEGRADED ========================= */
let degradedLoaded = false;
async function loadDegraded() {
  if (degradedLoaded) return; degradedLoaded = true;
  let d;
  try { d = await api("data/degraded.json"); }
  catch { d = await api("/api/degraded"); }
  statTiles($("#degraded-stats"), [
    [Math.round(d.retained * 100) + "%", "detections retained"],
    [`${d.total_one_way}/${d.total_both}`, "one-way vs both"],
    [String(d.seeds.length), "held-out captures"],
  ]);
  $("#degraded-rows").innerHTML = d.rows.map((r) =>
    `<tr><td>${esc(label(r.threat_class))}</td>
      <td class="num mono">${r.both}/${r.of}</td>
      <td class="num mono">${r.one_way < r.both ? `<span class="fail">${svg("i-x","ico-sm")}${r.one_way}/${r.of}</span>` : `<span class="pass">${svg("i-check","ico-sm")}${r.one_way}/${r.of}</span>`}</td>
      <td class="muted" style="font-size:11.5px">${esc(r.lost)}</td></tr>`).join("");
  $("#degraded-note").textContent = d.note;
}

/* ========================= METRICS ========================= */
let metricsLoaded = false;
async function loadMetrics() {
  if (metricsLoaded) return; metricsLoaded = true;
  let d;
  try { d = await api("data/metrics.json"); }
  catch { d = await api("/api/metrics"); }
  $("#metrics-rows").innerHTML = d.per_class.map((r) =>
    `<tr><td>${esc(label(r.threat_class))}</td>
      <td class="num mono">${r.precision.toFixed(3)}</td>
      <td class="num mono">${r.recall.toFixed(3)}</td>
      <td class="num mono">${r.f1.toFixed(3)}</td>
      <td class="num mono muted">${r.tp}/${r.fp}/${r.fn}</td></tr>`).join("");
  statTiles($("#metrics-stats"), [
    [d.macro_f1.toFixed(3), "macro F1"],
    [String(d.alerts), "alerts / " + d.simulated_hours + "h"],
    [d.alerts_per_hour + "/h", "alert volume"],
  ]);
  $("#metrics-caveats").innerHTML = d.caveats.map((c) =>
    `<li><span class="muted">▸</span> ${esc(c)}</li>`).join("");
  drawSweep(d.jitter_sweep);
}
function drawSweep(pts) {
  if (!pts || !pts.length) return;
  const W = 460, H = 190, pad = 34;
  const x = (j) => pad + (j / 0.5) * (W - pad - 12);
  const y = (r) => H - pad - r * (H - pad - 12);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${x(p.jitter).toFixed(1)},${y(p.recall).toFixed(1)}`).join(" ");
  const dots = pts.map((p) => `<circle cx="${x(p.jitter).toFixed(1)}" cy="${y(p.recall).toFixed(1)}" r="3.5" fill="var(--accent)"/>`).join("");
  const yticks = [0, 0.5, 1].map((v) =>
    `<line x1="${pad}" y1="${y(v)}" x2="${W - 12}" y2="${y(v)}" stroke="var(--border)"/>
     <text x="${pad - 6}" y="${y(v) + 3}" text-anchor="end" font-size="10" fill="var(--ink-3)">${v.toFixed(1)}</text>`).join("");
  const xticks = [0, 0.25, 0.5].map((v) =>
    `<text x="${x(v)}" y="${H - pad + 15}" text-anchor="middle" font-size="10" fill="var(--ink-3)">${(v * 100).toFixed(0)}%</text>`).join("");
  $("#sweep-chart").innerHTML =
    `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Beacon recall stays at 1.0 across 0 to 50 percent jitter">
      ${yticks}${xticks}
      <path d="${line}" fill="none" stroke="var(--accent)" stroke-width="2"/>${dots}
      <text x="${pad}" y="14" font-size="10" fill="var(--ink-3)">recall</text>
      <text x="${W - 12}" y="${H - 4}" text-anchor="end" font-size="10" fill="var(--ink-3)">C2 jitter</text>
    </svg>`;
}

/* ========================= LEDGER ========================= */
$("#verify-clean").addEventListener("click", () => verifyLedger(false));
$("#verify-tamper").addEventListener("click", () => verifyLedger(true));
async function verifyLedger(tamper) {
  $("#ledger-result").innerHTML = `<p class="note"><span class="spinner"></span> building ${tamper ? "and tampering with " : ""}a chain…</p>`;
  const d = await api(`/api/verify?tamper=${tamper ? 1 : 0}`);
  const ok = d.verified;
  const banner = tamper
    ? (ok ? `<div class="banner crit">${svg("i-alert")}<span>Unexpected: tampering was not detected.</span></div>`
      : `<div class="banner good">${svg("i-check")}<span><b>Tampering detected.</b> Record #${d.tampered_index} was quietly downgraded
         (${esc(d.original_value)} → ${esc(d.altered_value)}); re-walking the chain broke at alert
         <span class="mono">${esc(d.first_bad_alert_id)}</span>.</span></div>`)
    : `<div class="banner good">${svg("i-check")}<span><b>Chain verified.</b> All ${d.records} records intact.</span></div>`;
  $("#ledger-result").innerHTML = banner +
    `<dl class="kv" style="margin-top:12px">
      <dt>records</dt><dd>${d.records}</dd>
      <dt>verified</dt><dd>${ok ? '<span class="pass">'+svg("i-check","ico-sm")+'yes</span>' : '<span class="fail">'+svg("i-x","ico-sm")+'broken</span>'}</dd>
      <dt>head hash</dt><dd>${esc((d.head_hash || "").slice(0, 32))}…</dd>
      <dt>retention</dt><dd>${d.retention_days} days (CERT-In)</dd>
    </dl><p class="note">${esc(d.note)}</p>`;
}

/* ========================= PROOF ========================= */
$("#run-selftest").addEventListener("click", async () => {
  $("#proof-result").innerHTML = `<p class="note"><span class="spinner"></span> scanning the detection path…</p>`;
  let d;
  try { d = await api("/api/selftest"); }
  catch { d = await api("data/selftest.json"); }
  const checks = d.checks.map((c) => {
    const mark = c.informational ? '<span class="muted">ⓘ</span>'
      : c.passed ? '<span class="pass">'+svg("i-check","ico-sm")+'</span>' : '<span class="fail">'+svg("i-x","ico-sm")+'</span>';
    return `<li style="display:flex;gap:8px;align-items:flex-start">${mark}
      <span><b>${esc(c.name)}</b><br><span class="muted" style="font-size:11.5px">${esc(c.detail)}</span></span></li>`;
  }).join("");
  $("#proof-result").innerHTML =
    `<div class="banner ${d.passed ? "good" : "crit"}">${svg(d.passed ? "i-check" : "i-alert")}<b>${d.passed ? "Read-only properties hold." : "CHECK FAILED"}</b></div>
     <ul class="posture" style="margin-top:12px">${checks}</ul>
     <h2 style="font-size:11px;margin:16px 0 8px" class="muted">MODULES SCANNED (${d.modules.length})</h2>
     <div class="tablewrap"><table><thead><tr><th>Module</th><th>Imports</th></tr></thead><tbody>${
       d.modules.map((m) => `<tr><td class="mono">${esc(m.module)}</td>
         <td class="mono muted" style="font-size:11px">${esc(m.imports.join(", ") || "—")}</td></tr>`).join("")
     }</tbody></table></div>
     <p class="note">${esc(d.note)}</p>`;
});

/* ---------- boot ---------- */
(function boot() {
  try {
    const t = localStorage.getItem("prahari-tab");
    if (t) $(`#tabs button[data-tab="${t}"]`)?.click();
  } catch {}
  Live.init();
})();
