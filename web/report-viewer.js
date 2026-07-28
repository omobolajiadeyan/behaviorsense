const byId = (id) => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element: ${id}`);
  return element;
};

const formatPercent = (value) => `${Math.round(value * 100)}%`;
const formatBytes = (value) => new Intl.NumberFormat().format(value);

function riskBadge(level) {
  return `<span class="risk ${level}">${level}</span>`;
}

function renderList(items) {
  if (!items.length) return "<p>No items reported.</p>";
  return `<ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>`;
}

function renderReport(report) {
  const sorted = [...report.results].sort((a, b) => b.risk_score - a.risk_score);
  const critical = sorted.filter((result) => result.risk_level === "CRITICAL").length;
  const highest = sorted[0];

  byId("total-events").textContent = String(report.total_events);
  byId("total-entities").textContent = String(report.total_entities);
  byId("critical-count").textContent = String(critical);
  byId("highest-risk").textContent = highest ? highest.risk_level : "-";

  byId("entity-list").innerHTML = sorted.map((result) => {
    const signals = result.signals.map((signal) => `${signal.name.replaceAll("_", " ")}: ${signal.detail}`);
    const techniques = result.technique_hints.map((hint) => `${hint.id} ${hint.name}: ${hint.why}`);

    return `
      <article class="entity-card">
        <div class="entity-top">
          <div>
            <h3 class="entity-name">${result.entity}</h3>
            <p>Top anomaly: <strong>${result.top_anomaly.replaceAll("_", " ")}</strong></p>
          </div>
          ${riskBadge(result.risk_level)}
        </div>
        <div class="metrics">
          <div class="metric"><span>Risk Score</span><strong>${formatPercent(result.risk_score)}</strong></div>
          <div class="metric"><span>Events</span><strong>${result.event_count}</strong></div>
          <div class="metric"><span>Failed Logins</span><strong>${result.failed_logins}</strong></div>
          <div class="metric"><span>Unique IPs</span><strong>${result.unique_ips}</strong></div>
          <div class="metric"><span>Bytes</span><strong>${formatBytes(result.total_bytes)}</strong></div>
        </div>
        <div class="columns">
          <div><h3>Signals</h3>${renderList(signals)}</div>
          <div><h3>Technique Hints</h3>${renderList(techniques)}</div>
          <div><h3>Recommended Actions</h3>${renderList(result.recommended_actions)}</div>
        </div>
      </article>
    `;
  }).join("");
}

async function loadSample() {
  const response = await fetch("sample-report.json");
  renderReport(await response.json());
}

async function loadFile(file) {
  renderReport(JSON.parse(await file.text()));
}

byId("load-sample").addEventListener("click", () => void loadSample());
byId("report-file").addEventListener("change", (event) => {
  const input = event.currentTarget;
  if (input.files?.[0]) void loadFile(input.files[0]);
});

void loadSample();
