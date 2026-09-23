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


def build_annual_trend(records: pd.DataFrame) -> pd.DataFrame:
    """CVEs per publication year, including the null-year group last."""
    frame = records.copy()
    high_critical = frame["Severity"].isin(["HIGH", "CRITICAL"])
    network = frame["Attack_Vector"].eq("NETWORK")
    frame["high_critical_network"] = high_critical & network

    return (
        frame.groupby("Published_Year", dropna=False)
        .agg(
            total_cves=("CVE_ID", "count"),
            high_critical_network=("high_critical_network", "sum"),
        )
        .reset_index()
    )


def _label_distribution(records: pd.DataFrame, column: str, label: str) -> pd.DataFrame:
    """Count occurrences of each label, keeping the null group as ``"N/A"``."""
    counts = (
        records[column]
        .value_counts(dropna=False)
        .rename_axis(label)
        .reset_index(name="count")
    )

    counts[label] = counts[label].fillna("N/A")
    counts["share"] = counts["count"] / len(records)
    return counts


def build_severity_distribution(records: pd.DataFrame) -> pd.DataFrame:
    """How much of the dataset falls into each severity tier."""
    return _label_distribution(records, "Severity", "severity")


def build_attack_vector_distribution(records: pd.DataFrame) -> pd.DataFrame:
    """Whether network-reachable issues dominate the dataset."""
    return _label_distribution(records, "Attack_Vector", "attack_vector")


def build_cvss_bands(records: pd.DataFrame) -> pd.DataFrame:
    """Four fixed CVSS score bands with both bounds inclusive."""
    bands = pd.DataFrame(
        {
            "band": ["Low", "Medium", "High", "Critical"],
            "range": ["0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"],
            "count": [
                records["CVSS_Score"].between(0.1, 3.9, inclusive="both").sum(),
                records["CVSS_Score"].between(4.0, 6.9, inclusive="both").sum(),
                records["CVSS_Score"].between(7.0, 8.9, inclusive="both").sum(),
                records["CVSS_Score"].between(9.0, 10.0, inclusive="both").sum(),
            ],
        }
    )

    # A score of 0.0 or a missing score falls in no band, so shares can sum to less than 1.
    bands["share"] = bands["count"] / len(records)
    return bands
