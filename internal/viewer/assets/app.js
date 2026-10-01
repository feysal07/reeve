// Every value from the records is inserted with textContent and never as markup: a
// command line is whatever an agent typed, and a page that parsed it as HTML would run
// it. A test fails if this file ever uses innerHTML, outerHTML or insertAdjacentHTML.
"use strict";

// The token is in the fragment, which the browser never sends to a server. Read once,
// then removed from the address bar so it is not left on screen or in history.
const token = new URLSearchParams(location.hash.slice(1)).get("t") || "";
history.replaceState(null, "", location.pathname);

const $ = (id) => document.getElementById(id);

async function api(path) {
  const r = await fetch(path, { headers: { "X-Reeve-Token": token }, cache: "no-store" });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || (r.status === 401
    ? "Open the address the terminal printed: this page needs the token in it."
    : "The viewer answered " + r.status + "."));
  return body;
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function count(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(n || 0);
}

function when(t) {
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleString();
}

function who(s) {
  if (!s.who) return "–";
  return s.identity === "asserted" ? s.who + " (asserted)" : s.who;
}

function setStatus(text) { $("status").textContent = text; $("status").hidden = !text; }

function showNotes(notes, unplaced) {
  const ul = $("notes");
  ul.replaceChildren();
  (notes || []).forEach((n) => ul.appendChild(el("li", n)));
  if (unplaced) ul.appendChild(el("li", unplaced + " record(s) carry no session id and are in no session."));
}

async function showList() {
  $("detail-view").hidden = true;
  $("list-view").hidden = false;
  setStatus("Loading…");
  try {
    const doc = await api("/api/sessions");
    const tbody = $("sessions").querySelector("tbody");
    tbody.replaceChildren();
    doc.sessions.forEach((s) => {
      const tr = document.createElement("tr");
      const idCell = el("td");
      const a = el("a", s.id.slice(0, 12));
      a.href = "#";
      a.title = s.id;
      a.addEventListener("click", (e) => { e.preventDefault(); showSession(s.id); });
      idCell.appendChild(a);
      tr.appendChild(idCell);
      tr.appendChild(el("td", (s.agents || []).join(", ")));
      tr.appendChild(el("td", who(s)));
      tr.appendChild(el("td", when(s.end)));
      tr.appendChild(el("td", s.decisions, "n"));
      tr.appendChild(el("td", s.denied, s.denied ? "n deny" : "n"));
      tr.appendChild(el("td", s.asked, s.asked ? "n ask" : "n"));
      tr.appendChild(el("td", count(s.tokens), "n"));
      tr.appendChild(el("td", (s.sources || []).join(" + "), s.sources && s.sources.length === 1 ? "partial-cell" : ""));
      tbody.appendChild(tr);
    });
    setStatus(doc.sessions.length ? "" : "No sessions in the files read.");
    showNotes(doc.notes, doc.unplaced);
  } catch (e) {
    setStatus(e.message);
  }
}

let current = null;

async function showSession(id) {
  setStatus("Loading…");
  try {
    const doc = await api("/api/session?id=" + encodeURIComponent(id));
    current = doc;
    $("list-view").hidden = true;
    $("detail-view").hidden = false;
    $("notes").replaceChildren();
    renderSession();
    setStatus("");
  } catch (e) {
    setStatus(e.message);
  }
}

function renderSession() {
  const s = current.session;
  $("detail-title").textContent = "Session " + s.id;
  const dl = $("detail-facts");
  dl.replaceChildren();
  [["Agent", (s.agents || []).join(", ")], ["Who", who(s)], ["From", when(s.start)], ["To", when(s.end)],
   ["Decisions", s.decisions + " (" + s.denied + " denied, " + s.asked + " asked)"],
   ["Requests", s.requests + ", " + count(s.tokens) + " tokens"]].forEach(([k, v]) => {
    dl.appendChild(el("dt", k));
    dl.appendChild(el("dd", v));
  });
  const p = $("partial");
  p.hidden = !current.partial;
  p.textContent = current.partial ? "Partial: " + current.partial + "." : "";

  const only = $("stopped").checked;
  const ol = $("timeline");
  ol.replaceChildren();
  let day = "";
  let hidden = 0;
  (s.entries || []).forEach((e) => {
    const isRuling = e.source === "guard" && e.effect && e.effect !== "allow";
    if (only && !isRuling) { hidden++; return; }
    const d = new Date(e.time);
    const dayText = d.toLocaleDateString();
    if (dayText !== day) { day = dayText; ol.appendChild(el("li", dayText, "day")); }
    const li = el("li", null, "entry " + e.source + (isRuling ? " " + e.effect : ""));
    li.appendChild(el("span", d.toLocaleTimeString(), "time"));
    const mark = e.source === "guard" ? (e.dryRun && e.effect === "deny" ? "would deny" : e.effect) : e.kind;
    li.appendChild(el("span", mark, "mark"));
    li.appendChild(el("span", e.kind, "kind"));
    const summary = (e.summary || "").split(/\s+/).join(" ");
    li.appendChild(el("code", e.tokens ? summary + "  ·  " + count(e.tokens) + " tokens" : summary, "summary"));
    if (e.ruleId) li.appendChild(el("span", "rule " + e.ruleId, "rule"));
    if (e.reason && isRuling) li.appendChild(el("span", e.reason, "reason"));
    ol.appendChild(li);
  });
  if (hidden) ol.appendChild(el("li", hidden + " allowed or telemetry entries hidden.", "day"));
}

$("back").addEventListener("click", (e) => { e.preventDefault(); showList(); });
$("stopped").addEventListener("change", () => current && renderSession());
showList();
