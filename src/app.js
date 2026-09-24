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
  cvss_bands: [["band", "Band"], ["range", "Range"], ["count", "Count"], ["share", "Share"]],
  severity_distribution: [["severity", "Severity"], ["count", "Count"], ["share", "Share"]],
  attack_vector_distribution: [["attack_vector", "Vector"], ["count", "Count"], ["share", "Share"]],
  weakness_ranking: [["Weakness", "Weakness"], ["cve_count", "CVEs"], ["high_critical_count", "High/Crit"]],
  domain_ranking: [["Keyword", "Domain"], ["priority_score", "Priority"], ["network_rate", "Network Rate"]],
  triage_queue: [["CVE_ID", "CVE"], ["Severity", "Severity"], ["Keyword", "Domain"], ["triage_score", "Score"]],
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
  return String(value);
}

// "N/A" is not a valid class name, so it maps to "na".
function severityClass(label) {
  return `sev sev-${label === "N/A" ? "na" : label.toLowerCase()}`;
}

function badge(label) {
  const span = document.createElement("span");
  span.className = severityClass(label);
  span.textContent = label;
  return span;
}

function barCell(text, fraction) {
  const wrap = document.createElement("div");
  wrap.className = "bar-cell";
  const bar = document.createElement("span");
  bar.className = "bar";
  bar.style.width = `${Math.round(fraction * 100)}%`;
  bar.setAttribute("aria-hidden", "true");
  const label = document.createElement("span");
  label.textContent = text;
  wrap.append(bar, label);
  return wrap;
}

function renderKpis(kpis) {
  const container = document.querySelector("#kpi-cards");
  for (const kpi of kpis) {
    const card = document.createElement("div");
    card.className = "kpi-card";
    card.dataset.metric = kpi.metric;

    const label = document.createElement("p");
    label.textContent = kpi.label;

    const value = document.createElement("strong");
    value.textContent = kpi.format === "percent" ? percent(kpi.value) : kpi.value.toLocaleString();

    card.append(label, value);
    container.append(card);
  }
}

function renderTable(id, rows, columns) {
  const barKey = BAR_COLUMN[id];
  const barMax = barKey ? Math.max(...rows.map((row) => row[barKey] ?? 0)) : 0;

  const table = document.createElement("table");
  const header = document.createElement("tr");
  for (const [, title] of columns) {
    const th = document.createElement("th");
    th.textContent = title;
    header.append(th);
  }
  table.append(header);

  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const [key] of columns) {
      const td = document.createElement("td");
      const text = formatCell(key, row[key]);
      if (key === "Severity" || key === "severity") {
        td.append(badge(text || "N/A"));
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

// A column per year. The darker part of each bar is the high/critical network share.
function renderTrend(rows) {
  const max = Math.max(...rows.map((row) => row.total_cves));
  const chart = document.createElement("div");
  chart.className = "trend";
  chart.setAttribute("role", "img");
  chart.setAttribute("aria-label", "CVEs per publication year");
  for (const row of rows) {
    const year = row.Published_Year ?? "N/A";
    const col = document.createElement("div");
    col.className = "trend-col";
    col.title = `${year}: ${row.total_cves} CVEs, ${row.high_critical_network} high/critical network`;

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
    th.append(badge(label));
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
      td.textContent = value;
      td.className = "heat";
      td.style.setProperty("--heat", max > 0 ? value / max : 0);
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
    renderKpis(data.kpis);
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
