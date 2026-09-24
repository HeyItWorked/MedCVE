<h1 align="center">MedCVE</h1>

<p align="center">
  <a href="https://github.com/HeyItWorked/MedCVE/actions/workflows/ci.yml"><img src="https://github.com/HeyItWorked/MedCVE/actions/workflows/ci.yml/badge.svg" alt="CI status" /></a>
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/pandas-3.0-150458?style=flat&logo=pandas&logoColor=white" alt="pandas 3.0" />
  <img src="https://img.shields.io/badge/license-MIT-1c1b19?style=flat" alt="License: MIT" />
  <img src="https://img.shields.io/badge/data-CC0-9e2a1f?style=flat" alt="Data: CC0" />
</p>

<p align="center">
  <strong>What 1,515 healthcare CVEs say, on one static page.</strong><br/>
  A pandas analysis of public vulnerability records tagged to hospitals, EHRs, DICOM, pharmacies, and labs — exported to JSON and shown in a dashboard with no build step.
</p>

<h3 align="center"><a href="https://heyitworked.github.io/MedCVE/"><ins>Open the live dashboard</ins></a></h3>

<p align="center">
  <img src=".github/assets/hero.png" alt="The MedCVE dashboard: the headline count, a one-sentence summary, and the annual trend chart" width="960" />
</p>

## What's on the Dashboard

Each section leads with its point, computed from the data, and puts the evidence beside it.

<table>
<tr>
<td width="50%" valign="middle">

### One Number Up Front

The page opens with the count and a single sentence instead of a row of KPI cards: 151 critical, 42% high or critical, 84% reachable over a network, and 574 that are both.

</td>
<td width="50%">
  <img src=".github/assets/masthead.png" alt="Masthead reading 1,515 known vulnerabilities touch healthcare software" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### When They Were Published

Records per publication year from 2004 to 2026. The red part of each bar is the high/critical, network-reachable share. A trickle until 2016, then a climb to a peak of 279 in 2025.

</td>
<td width="50%">
  <img src=".github/assets/trend.png" alt="Annual column chart with the urgent share in red" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### How Severe, and How Reachable

Severity, CVSS score bands, and attack vector side by side. Most records are medium severity, but 84% can be reached over a network.

</td>
<td width="50%">
  <img src=".github/assets/severity.png" alt="Severity, CVSS band, and attack vector tables with thin share bars" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### What Breaks

Weaknesses ranked by high and critical records, with plain-English names next to each CWE. SQL injection (CWE-89) accounts for 190, 2.8× the next weakness.

</td>
<td width="50%">
  <img src=".github/assets/weakness.png" alt="Weakness ranking with CWE IDs, names, and bars" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### Where It Hits

Healthcare domains ranked by a priority score that weighs severity, network reach, and CVSS. Records tagged "hospital" lead, followed by "patient", OpenEMR, and DICOM.

</td>
<td width="50%">
  <img src=".github/assets/domains.png" alt="Domain ranking with record counts, priority bars, and network-reachable share" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### Where Severity Clusters

A heatmap of the ten highest-priority domains by severity, shaded in a single red ramp, so you can see where the critical and high findings pile up.

</td>
<td width="50%">
  <img src=".github/assets/matrix.png" alt="Domain by severity heatmap in shades of red" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### Review First

The fifteen records a simple triage score puts at the top of the queue. Each CVE links to its NVD entry.

</td>
<td width="50%">
  <img src=".github/assets/triage.png" alt="Triage queue of critical CVEs linked to NVD" width="100%" />
</td>
</tr>
</table>

**Also in the box:**

- **No rows dropped** — every count and share uses all 1,515 records, missing values included.
- **Exports pinned by tests** — `pytest` rebuilds all nine JSON files from the raw CSV and fails if a committed export drifts.
- **Strict JSON** — no `NaN` ever reaches the browser; nulls export as `null`.
- **No build step** — one HTML file, one stylesheet, and plain JavaScript that reads `data/processed/`.
- **Works on a phone** — sections stack, wide tables scroll inside their column, and the trend chart opens on the most recent years.
- **A written analysis** — the notebook walks through the questions, cleaning, metric definitions, and plots.

---

## Built With

<p>
  <a href="https://www.python.org"><kbd><img src="https://www.google.com/s2/favicons?domain=python.org&sz=64" alt="Python logo" width="16" valign="middle" /> Python</kbd></a> &nbsp;
  <a href="https://pandas.pydata.org"><kbd><img src="https://www.google.com/s2/favicons?domain=pandas.pydata.org&sz=64" alt="pandas logo" width="16" valign="middle" /> pandas</kbd></a> &nbsp;
  <a href="https://numpy.org"><kbd><img src="https://www.google.com/s2/favicons?domain=numpy.org&sz=64" alt="NumPy logo" width="16" valign="middle" /> NumPy</kbd></a> &nbsp;
  <a href="https://matplotlib.org"><kbd><img src="https://matplotlib.org/stable/_static/favicon.ico" alt="Matplotlib logo" width="16" valign="middle" /> Matplotlib</kbd></a> &nbsp;
  <a href="https://seaborn.pydata.org"><kbd><img src="https://www.google.com/s2/favicons?domain=seaborn.pydata.org&sz=64" alt="seaborn logo" width="16" valign="middle" /> seaborn</kbd></a> &nbsp;
  <a href="https://jupyter.org"><kbd><img src="https://www.google.com/s2/favicons?domain=jupyter.org&sz=64" alt="Jupyter logo" width="16" valign="middle" /> Jupyter</kbd></a> &nbsp;
  <a href="https://pytest.org"><kbd><img src="https://www.google.com/s2/favicons?domain=pytest.org&sz=64" alt="pytest logo" width="16" valign="middle" /> pytest</kbd></a> &nbsp;
  <a href="https://docs.astral.sh/ruff/"><kbd><img src="https://www.google.com/s2/favicons?domain=astral.sh&sz=64" alt="Ruff logo" width="16" valign="middle" /> Ruff</kbd></a> &nbsp;
  <a href="https://pages.github.com"><kbd><img src="https://www.google.com/s2/favicons?domain=github.com&sz=64" alt="GitHub logo" width="16" valign="middle" /> GitHub Pages</kbd></a>
</p>

---

## Quick Start

**View the dashboard** — no install needed; the page reads the committed exports:

```bash
git clone https://github.com/HeyItWorked/MedCVE.git && cd MedCVE
python3 -m http.server 8000     # then open http://localhost:8000/
```

**Run the analysis and tests** — needs Python 3.12:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

<details>
<summary><strong>How the pieces fit</strong></summary>

<br/>

- `analysis/metrics.py` holds each metric as a plain function: KPIs, annual trend, distributions, CVSS bands, rankings, the domain × severity matrix, and the triage queue.
- `notebooks/healthcare_cve_analysis.ipynb` imports those functions, adds the plots and write-up, and exports the nine JSON files to `data/processed/`. Open it with `jupyter lab` and run all cells to regenerate them.
- `index.html`, `src/app.js`, and `src/styles.css` render the exports. GitHub Pages serves the repo root.
- `tests/` checks the builders against a small synthetic CSV and checks the committed exports against the raw data. CI runs Ruff and pytest on pushes to `main` and on pull requests.

</details>

---

## Reading the Numbers

- **The two scores are ordering heuristics, not security scores.** Domain priority adds severity points (critical 4, high 3, medium 2, low 1), +1 for a network vector, and +1 for CVSS ≥ 9, summed across a domain's records. The triage score uses critical 5, high 4, medium 2, low 1, +2 for network, +2 for CVSS ≥ 9, and +1 for CVSS ≥ 7, for a maximum of 10. Neither measures security or patient risk.
- **Missing values stay in.** pandas reads an empty field and the string `N/A` as the same missing value, and those records appear as `N/A` rows instead of disappearing.
- **CVSS bands can add up to less than 100%.** A score of exactly 0.0, or a missing score, falls in no band.

## Data

`data/raw/healthcare_cybersecurity_10k.csv` comes from the [Healthcare Cybersecurity Vulnerabilities Dataset](https://www.kaggle.com/datasets/chuneeb/healthcare-cybersecurity-vulnerabilities-dataset), published on Kaggle by Uneeb Zulfiqar under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) and derived from the [NIST National Vulnerability Database](https://nvd.nist.gov/). Despite `10k` in the upstream filename, the only published version has 1,515 records. It is public CVE data, not patient records.

## License

The code is under the [MIT License](LICENSE). The dataset stays under its upstream CC0 1.0 terms.
