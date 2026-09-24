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

// Plain-English names for the weaknesses that show up in the ranking.
const CWE_NAMES = {
  "CWE-20": "Improper input validation",
  "CWE-22": "Path traversal",
  "CWE-74": "Injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-119": "Memory buffer errors",
  "CWE-255": "Credentials management",
  "CWE-287": "Improper authentication",
  "CWE-306": "Missing authentication",
  "CWE-352": "Cross-site request forgery",
  "CWE-434": "Unrestricted file upload",
  "CWE-787": "Out-of-bounds write",
  "CWE-798": "Hard-coded credentials",
  "CWE-862": "Missing authorization",
  "NVD-CWE-noinfo": "Not enough information",
  "NVD-CWE-Other": "Other",
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

function percent(value) {
  return `${Math.round(value * 100)}%`;
}

function formatCell(key, value) {
  if (value === null || value === undefined) {
    return "";
  }
  if (key === "share" || key === "network_rate") {
    return percent(value);
  }
  if (typeof value === "number" && !Number.isInteger(value)) {
    return value.toFixed(1);
  }
  if (typeof value === "number") {
    return value.toLocaleString();
  }
  return String(value);
}

function setText(id, text) {
  document.querySelector(`#${id}`).textContent = text;
}

// "CRITICAL" -> "Critical". "N/A" stays as it is and maps to the "na" class.
function severity(label) {
  const span = document.createElement("span");
  span.className = `sev sev-${label === "N/A" ? "na" : label.toLowerCase()}`;
  span.textContent = label === "N/A" ? "N/A" : label[0] + label.slice(1).toLowerCase();
  return span;
}

function barCell(text, fraction) {
  const wrap = document.createElement("div");
  wrap.className = "bar-cell";
  const label = document.createElement("span");
  label.textContent = text;
  const track = document.createElement("span");
  track.className = "track";
  track.setAttribute("aria-hidden", "true");
  const bar = document.createElement("span");
  bar.className = "bar";
  bar.style.width = `${Math.round(fraction * 100)}%`;
  track.append(bar);
  wrap.append(label, track);
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

  const table = document.createElement("table");
  const header = document.createElement("tr");
  for (const [key, title] of columns) {
    const th = document.createElement("th");
    th.textContent = title;
    if (key === barKey) th.className = "bar-head";
    header.append(th);
  }
  table.append(header);

  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const [key] of columns) {
      const td = document.createElement("td");
      const text = formatCell(key, row[key]);
      if (key === "Severity" || key === "severity") {
        td.append(severity(text || "N/A"));
      } else if (key === "name") {
        td.textContent = CWE_NAMES[row.Weakness] ?? "";
        td.className = "name";
      } else if (key === "CVE_ID") {
        const link = document.createElement("a");
        link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(text)}`;
        link.textContent = text;
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
  const chart = document.createElement("div");
  chart.className = "trend";
  chart.setAttribute("role", "img");
  chart.setAttribute("aria-label", "Records per publication year");
  for (const row of rows) {
    const year = row.Published_Year ?? "N/A";
    const col = document.createElement("div");
    col.className = "trend-col";
    col.title = `${year}: ${row.total_cves} records, ${row.high_critical_network} high/critical and network-reachable`;

    const track = document.createElement("div");
    track.className = "trend-track";
    const bar = document.createElement("div");
    bar.className = "trend-bar";
    bar.style.height = `${(row.total_cves / max) * 100}%`;
    const urgent = document.createElement("div");
    urgent.className = "trend-urgent";
    urgent.style.height = `${row.total_cves ? (row.high_critical_network / row.total_cves) * 100 : 0}%`;
    const value = document.createElement("span");
    value.className = "trend-value";
    value.textContent = row.total_cves;
    bar.append(urgent, value);
    track.append(bar);

    const label = document.createElement("span");
    label.className = "trend-year";
    label.textContent = year;
    col.append(track, label);
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

  const table = document.createElement("table");
  table.className = "heatmap";
  const header = document.createElement("tr");
  const corner = document.createElement("th");
  corner.textContent = "Domain";
  header.append(corner);
  for (const label of severities) {
    const th = document.createElement("th");
    th.append(severity(label));
    header.append(th);
  }
  table.append(header);

  for (const row of rows) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = row.Keyword;
    tr.append(name);
    for (const label of severities) {
      const td = document.createElement("td");
      const value = row[label] ?? 0;
      const heat = max > 0 ? value / max : 0;
      td.textContent = value;
      td.className = heat > 0.5 ? "heat hot" : "heat";
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
