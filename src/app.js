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
  annual_trend: [["Published_Year", "Year"], ["total_cves", "Total CVEs"], ["high_critical_network", "High/Critical Network"]],
  cvss_bands: [["band", "Band"], ["range", "Range"], ["count", "Count"], ["share", "Share"]],
  severity_distribution: [["severity", "Severity"], ["count", "Count"], ["share", "Share"]],
  attack_vector_distribution: [["attack_vector", "Vector"], ["count", "Count"], ["share", "Share"]],
  weakness_ranking: [["Weakness", "Weakness"], ["cve_count", "CVEs"], ["high_critical_count", "High/Crit"]],
  domain_ranking: [["Keyword", "Domain"], ["priority_score", "Priority"], ["network_rate", "Network Rate"]],
  triage_queue: [["CVE_ID", "CVE"], ["Severity", "Severity"], ["Keyword", "Domain"], ["triage_score", "Score"]],
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
  return String(value);
}

function renderKpis(kpis) {
  const container = document.querySelector("#kpi-cards");
  for (const kpi of kpis) {
    const card = document.createElement("div");
    card.className = "kpi-card";

    const label = document.createElement("p");
    label.textContent = kpi.label;

    const value = document.createElement("strong");
    value.textContent = kpi.format === "percent" ? percent(kpi.value) : kpi.value.toLocaleString();

    card.append(label, value);
    container.append(card);
  }
}

function renderTable(id, rows, columns) {
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
      td.textContent = formatCell(key, row[key]);
      tr.append(td);
    }
    table.append(tr);
  }
  document.querySelector(`#${id}`).append(table);
}

// The matrix has one column per severity label found in the data.
function matrixColumns(rows) {
  const severities = Object.keys(rows[0] ?? {}).filter((key) => key !== "Keyword");
  return [["Keyword", "Domain"], ...severities.map((key) => [key, key])];
}

async function main() {
  const status = document.querySelector("#status");
  try {
    const data = await loadData();
    renderKpis(data.kpis);
    for (const [name, columns] of Object.entries(PANELS)) {
      renderTable(name, data[name], columns);
    }
    renderTable("domain_severity_matrix", data.domain_severity_matrix, matrixColumns(data.domain_severity_matrix));
    status.textContent = "";
  } catch (error) {
    status.textContent = `Could not load the dashboard: ${error.message}`;
  }
}

main();
