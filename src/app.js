const FILES = [
  "kpis",
  "annual_trend",
  "cvss_bands",
  "severity_distribution",
  "attack_vector_distribution",
  "weakness_ranking",
  "domain_ranking",
  "domain_severity_matrix",
  "triage_queue",
];

// Which columns each table shows, as [key, header].
const PANELS = {
  severity_distribution: [["severity", "Severity"], ["count", "Records"], ["share", "Share"]],
  cvss_bands: [["band", "Band"], ["range", "Score"], ["count", "Records"], ["share", "Share"]],
  attack_vector_distribution: [["attack_vector", "Vector"], ["count", "Records"], ["share", "Share"]],
  weakness_ranking: [["Weakness", "CWE"], ["name", "Weakness"], ["cve_count", "Records"], ["high_critical_count", "High or critical"]],
  domain_ranking: [["Keyword", "Domain"], ["cve_count", "Records"], ["priority_score", "Priority score"], ["network_rate", "Network-reachable"]],
  triage_queue: [["CVE_ID", "CVE"], ["Severity", "Severity"], ["Keyword", "Domain"], ["CVSS_Score", "CVSS"], ["triage_score", "Score"]],
};

// The column in each table that gets a small bar, sized against the column's biggest value.
const BAR_COLUMN = {
  cvss_bands: "share",
  severity_distribution: "share",
  attack_vector_distribution: "share",
  weakness_ranking: "high_critical_count",
  domain_ranking: "priority_score",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A"];

// Plain-English names for the weaknesses in the ranking. Unknown IDs show no name.
const CWE_NAMES = {
  "CWE-22": "Path traversal",
  "CWE-74": "Injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-119": "Memory buffer errors",
  "CWE-255": "Credentials management",
  "CWE-434": "Unrestricted file upload",
  "CWE-787": "Out-of-bounds write",
  "CWE-862": "Missing authorization",
  "NVD-CWE-noinfo": "Not enough information",
};

async function loadData() {
  const data = {};
  for (const name of FILES) {
    const response = await fetch(`data/processed/${name}.json`);
    if (!response.ok) {
      throw new Error(`could not load ${name}.json (HTTP ${response.status})`);
    }
    data[name] = await response.json();
  }
  return data;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function percent(value) {
  return `${Math.round(value * 100)}%`;
}

function formatCell(key, value) {
  if (value === null || value === undefined) return "";
  if (key === "share" || key === "network_rate") return percent(value);
  if (typeof value === "number") return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(1);
  return String(value);
}

function setText(id, text) {
  document.querySelector(`#${id}`).textContent = text;
}

// "CRITICAL" -> "Critical". "N/A" stays as it is and maps to the "na" class.
function severity(label) {
  const na = label === "N/A";
  return el("span", `sev-${na ? "na" : label.toLowerCase()}`, na ? label : label[0] + label.slice(1).toLowerCase());
}

function barCell(text, fraction) {
  const bar = el("span", "bar");
  bar.style.width = `${Math.round(fraction * 100)}%`;
  const track = el("span", "track");
  track.setAttribute("aria-hidden", "true");
  track.append(bar);
  const wrap = el("div", "bar-cell");
  wrap.append(el("span", "", text), track);
  return wrap;
}

// The big number and one sentence instead of a row of KPI cards.
function renderMasthead(kpis) {
  const kpi = Object.fromEntries(kpis.map((row) => [row.metric, row.value]));
  setText("total-cves", kpi.total_cves.toLocaleString());
  setText(
    "dek",
    `${kpi.critical_cves} are critical. ${percent(kpi.high_critical_rate)} are high or critical severity, ` +
      `${percent(kpi.network_vector_rate)} can be reached over a network, and ` +
      `${kpi.high_critical_network_count.toLocaleString()} are both.`
  );
}

function renderTakeaways(data) {
  const peak = data.annual_trend.reduce((best, row) => (row.total_cves > best.total_cves ? row : best));
  setText(
    "trend-takeaway",
    `A trickle until 2016, then a climb. Publications peaked at ${peak.total_cves} in ${peak.Published_Year}, ` +
      `${percent(peak.high_critical_network / peak.total_cves)} of them high or critical and network-reachable.`
  );

  const medium = data.severity_distribution.find((row) => row.severity === "MEDIUM");
  const network = data.attack_vector_distribution.find((row) => row.attack_vector === "NETWORK");
  setText(
    "severity-takeaway",
    `Most records are medium severity (${percent(medium.share)}), but ${percent(network.share)} can be reached over a network.`
  );

  const [first, second] = data.weakness_ranking;
  setText(
    "weakness-takeaway",
    `${CWE_NAMES[first.Weakness] ?? first.Weakness} accounts for ${first.high_critical_count} high or critical records, ` +
      `${(first.high_critical_count / second.high_critical_count).toFixed(1)}× the next weakness.`
  );

  const top = data.domain_ranking[0];
  setText(
    "domain-takeaway",
    `Records tagged "${top.Keyword}" lead with ${top.cve_count}, ${percent(top.network_rate)} of them network-reachable. ` +
      `The priority score weighs severity, network reach, and CVSS.`
  );
}

function renderTable(id, rows, columns) {
  const barKey = BAR_COLUMN[id];
  const barMax = barKey ? Math.max(...rows.map((row) => row[barKey] ?? 0)) : 0;
  const table = el("table");
  const header = el("tr");
  for (const [, title] of columns) header.append(el("th", "", title));
  table.append(header);

  for (const row of rows) {
    const tr = el("tr");
    for (const [key] of columns) {
      const text = formatCell(key, row[key]);
      const td = el("td");
      if (key === "Severity" || key === "severity") {
        td.append(severity(text || "N/A"));
      } else if (key === "name") {
        td.className = "name";
        td.textContent = CWE_NAMES[row.Weakness] ?? "";
      } else if (key === "CVE_ID") {
        const link = el("a", "", text);
        link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(text)}`;
        td.append(link);
      } else if (key === barKey && barMax > 0) {
        td.append(barCell(text, (row[key] ?? 0) / barMax));
      } else {
        td.textContent = text;
      }
      tr.append(td);
    }
    table.append(tr);
  }
  document.querySelector(`#${id}`).append(table);
}

// A column per year. The red part of each bar is the high/critical network share.
function renderTrend(rows) {
  const max = Math.max(...rows.map((row) => row.total_cves));
  const chart = el("div", "trend");
  chart.setAttribute("role", "img");
  chart.setAttribute("aria-label", "Records per publication year");
  for (const row of rows) {
    const year = row.Published_Year ?? "N/A";
    const bar = el("div", "trend-bar");
    bar.style.height = `${(row.total_cves / max) * 100}%`;
    const urgent = el("div", "trend-urgent");
    urgent.style.height = `${row.total_cves ? (row.high_critical_network / row.total_cves) * 100 : 0}%`;
    bar.append(urgent, el("span", "trend-value", row.total_cves));
    const track = el("div", "trend-track");
    track.append(bar);
    const col = el("div", "trend-col");
    col.title = `${year}: ${row.total_cves} records, ${row.high_critical_network} high/critical and network-reachable`;
    col.append(track, el("span", "trend-year", year));
    chart.append(col);
  }
  document.querySelector("#annual_trend").append(chart);
  // On narrow screens the chart scrolls; start at the most recent years.
  chart.scrollLeft = chart.scrollWidth;
}

// A heatmap: each cell is shaded by its count against the biggest count in the matrix.
function renderMatrix(rows) {
  const found = Object.keys(rows[0] ?? {}).filter((key) => key !== "Keyword");
  const severities = [
    ...SEVERITY_ORDER.filter((label) => found.includes(label)),
    ...found.filter((label) => !SEVERITY_ORDER.includes(label)),
  ];
  const max = Math.max(...rows.flatMap((row) => severities.map((label) => row[label] ?? 0)));
  const table = el("table", "heatmap");
  const header = el("tr");
  header.append(el("th", "", "Domain"));
  for (const label of severities) {
    const th = el("th");
    th.append(severity(label));
    header.append(th);
  }
  table.append(header);

  for (const row of rows) {
    const tr = el("tr");
    tr.append(el("td", "", row.Keyword));
    for (const label of severities) {
      const value = row[label] ?? 0;
      const heat = max > 0 ? value / max : 0;
      const td = el("td", heat > 0.5 ? "heat hot" : "heat", value);
      td.style.setProperty("--heat", heat);
      tr.append(td);
    }
    table.append(tr);
  }
  document.querySelector("#domain_severity_matrix").append(table);
}

async function main() {
  const status = document.querySelector("#status");
  try {
    const data = await loadData();
    renderMasthead(data.kpis);
    renderTakeaways(data);
    for (const [name, columns] of Object.entries(PANELS)) {
      renderTable(name, data[name], columns);
    }
    renderTrend(data.annual_trend);
    renderMatrix(data.domain_severity_matrix);
    status.textContent = "";
  } catch (error) {
    status.textContent = `Could not load the dashboard: ${error.message}`;
  }
}

main();
