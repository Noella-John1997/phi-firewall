const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SAMPLE = `Discharge note
Patient: Jane Doe, DOB: 04/12/1987, MRN: AB123456.
Contact: jane.doe@gmail.com, +91 98765 43210. Aadhaar 2345 6789 0124, PAN ABCPE1234F.
Admitted March 3, 2025 with community-acquired pneumonia. Treated with IV ceftriaxone,
switched to oral amoxicillin on day 3. Seen by Dr. Mehta (NPI 1234567893).
Follow up in 2 weeks. No known drug allergies.`;
const post = (url, body) => fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});

function highlight(text, spans) {
  let out = "", pos = 0;
  for (const s of spans) {
    out += esc(text.slice(pos, s.start));
    out += `<mark class="${s.action}" title="${s.entity} · ${s.action}">${esc(text.slice(s.start, s.end))}<sup>${s.entity}</sup></mark>`;
    pos = s.end;
  }
  return out + esc(text.slice(pos));
}
// Underline the values the firewall put back, so you can see the round trip.
function restored(answer, text, spans) {
  const vals = [...new Set(spans.filter((s) => s.action === "tokenize").map((s) => text.slice(s.start, s.end)))]
    .sort((a, b) => b.length - a.length);
  let html = esc(answer);
  vals.forEach((v) => { const e = esc(v); html = html.split(e).join(`<mark class="allow" title="restored by the firewall">${e}</mark>`); });
  return html;
}
const tokens = (t) => esc(t).replace(/\[\[([A-Z_]+_\d+)\]\]/g, '<span class="tok">[[$1]]</span>').replace(/\[([A-Z_]+)\]/g, '<span class="msk">[$1]</span>');

async function loadPolicy() {
  const p = await (await fetch("/v1/policy")).json();
  const tone = {tokenize: "acc", mask: "warn", block: "bad", allow: "ok"};
  $("#policy").innerHTML = Object.entries(p.entities).map(([k, v]) => `<span class="chip ${tone[v]}">${k}: ${v}</span>`).join("");
  return p;
}
async function loadAudit() {
  const r = await fetch("/v1/audit/tail?n=8");
  if (!r.ok) { $("#audit").innerHTML = `<tr><td colspan="4" class="muted">Audit view needs an API key on this server.</td></tr>`; return; }
  const {records} = await r.json();
  $("#audit").innerHTML = records.length ? records.map((x) => `<tr><td>${new Date(x.ts * 1000).toLocaleTimeString()}</td>
    <td><span class="chip ${x.event === "blocked" ? "bad" : "acc"}">${esc(x.event)}</span></td>
    <td>${esc(Array.isArray(x.entities) ? x.entities.join(", ") : Object.entries(x.entities || {}).map(([k, v]) => `${k}×${v}`).join(", ") || "—")}</td>
    <td class="h">${esc(x.hash.slice(0, 10))}…</td></tr>`).join("") : `<tr><td colspan="4" class="muted">No records yet.</td></tr>`;
}

async function send() {
  const text = $("#text").value;
  if (!text.trim()) return;
  const btn = $("#send"); btn.disabled = true; $("#status").innerHTML = '<span class="spinner"></span>';
  try {
    const scan = await (await post("/v1/scan", {text})).json();
    $("#detected").innerHTML = highlight(text, scan.spans) || '<span class="muted">Nothing sensitive found.</span>';
    const counts = {};
    scan.spans.forEach((s) => { counts[s.entity] = counts[s.entity] || {n: 0, action: s.action}; counts[s.entity].n++; });
    const tone = {tokenize: "acc", mask: "warn", block: "bad", allow: "ok"};
    $("#ents").innerHTML = Object.entries(counts).map(([k, v]) => `<tr><td>${k}</td><td>${v.n}</td><td><span class="chip ${tone[v.action]}">${v.action}</span></td></tr>`).join("")
      || `<tr><td colspan="3" class="muted">None</td></tr>`;

    const r = await post("/v1/chat/completions", {model: "mock", messages: [
      {role: "system", content: "Summarize the note."}, {role: "user", content: text}]});
    const body = await r.json();
    if (r.status === 422) {
      $("#llm").innerHTML = `<span class="chip bad">Request blocked</span>\n\nNothing was sent to the LLM because the text contains: ${esc(body.entities.join(", "))}.`;
      $("#back").innerHTML = `<span class="chip bad">HTTP 422</span>\n\nYour app receives an error (blocked_by_policy) instead of an answer.`;
      $("#status").textContent = "Blocked by policy.";
    } else if (!r.ok) {
      throw new Error(body.detail || r.statusText);
    } else {
      $("#llm").innerHTML = tokens(scan.redacted);
      $("#back").innerHTML = restored(body.choices[0].message.content, text, scan.spans);
      $("#status").textContent = `Found: ${(r.headers.get("X-PHI-Entities") || "").split(",").join(", ")}`;
    }
  } catch (e) { $("#status").textContent = "Error: " + e.message; }
  finally { btn.disabled = false; loadAudit(); }
}

$("#sample").onclick = () => ($("#text").value = SAMPLE);
$("#card").onclick = () => ($("#text").value += "\nPlease bill card 4111 1111 1111 1111.");
$("#clear").onclick = () => ($("#text").value = "");
$("#send").onclick = send;
$("#verifyBtn").onclick = async () => {
  const r = await fetch("/v1/audit/verify");
  if (!r.ok) { $("#verify").innerHTML = '<span class="chip warn">needs API key</span>'; return; }
  const v = await r.json();
  $("#verify").innerHTML = v.ok ? '<span class="chip ok">chain intact</span>' : `<span class="chip bad">broken at line ${v.first_bad_line}</span>`;
};
$("#text").value = SAMPLE;
loadPolicy(); loadAudit();
