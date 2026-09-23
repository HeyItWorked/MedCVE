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

async function main() {
  const status = document.querySelector("#status");
  try {
    const data = await loadData();
    renderKpis(data.kpis);
    status.textContent = "";
  } catch (error) {
    status.textContent = `Could not load the dashboard: ${error.message}`;
  }
}

main();
