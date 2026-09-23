"""Metric builders for the MedCVE dashboard."""

from __future__ import annotations

import pandas as pd

SEVERITY_LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def load_records(path) -> pd.DataFrame:
    """Read the raw CVE CSV with default ``pandas.read_csv`` settings."""
    return pd.read_csv(path)


def clean_records(raw: pd.DataFrame) -> pd.DataFrame:
    """Produce the canonical analysis frame."""
    clean = raw.copy()
    # errors="coerce" turns invalid values into missing ones instead of failing.
    clean["Published"] = pd.to_datetime(clean["Published"], errors="coerce")
    clean["Last_Modified"] = pd.to_datetime(clean["Last_Modified"], errors="coerce")
    clean["CVSS_Score"] = pd.to_numeric(clean["CVSS_Score"], errors="coerce")
    clean["Published_Year"] = clean["Published"].dt.year
    return clean


def headline_metrics(records: pd.DataFrame) -> dict:
    """Core dashboard numbers shared by the KPI row."""
    high_critical = records["Severity"].isin(["HIGH", "CRITICAL"])
    network = records["Attack_Vector"].eq("NETWORK")

    return {
        "total_cves": len(records),
        "critical_cves": int(records["Severity"].eq("CRITICAL").sum()),
        "high_critical_rate": float(high_critical.mean()),
        "network_vector_rate": float(network.mean()),
        "high_critical_network_count": int((high_critical & network).sum()),
    }


def build_kpis(records: pd.DataFrame) -> pd.DataFrame:
    """The headline KPI row, five rows with dashboard-facing labels."""
    metrics = headline_metrics(records)

    return pd.DataFrame(
        [
            {
                "metric": "total_cves",
                "label": "Total CVEs",
                "value": metrics["total_cves"],
                "format": "count",
            },
            {
                "metric": "critical_cves",
                "label": "Critical CVEs",
                "value": metrics["critical_cves"],
                "format": "count",
            },
            {
                "metric": "high_critical_rate",
                "label": "High/Critical Rate",
                "value": metrics["high_critical_rate"],
                "format": "percent",
            },
            {
                "metric": "network_vector_rate",
                "label": "Network Vector Rate",
                "value": metrics["network_vector_rate"],
                "format": "percent",
            },
            {
                "metric": "high_critical_network_count",
                "label": "High/Critical Network CVEs",
                "value": metrics["high_critical_network_count"],
                "format": "count",
            },
        ]
    )
