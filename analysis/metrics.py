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
