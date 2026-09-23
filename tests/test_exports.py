"""The committed dashboard files must match what the metrics produce from the raw CSV."""

import json
from pathlib import Path

import pytest

from analysis import (
    build_annual_trend,
    build_attack_vector_distribution,
    build_cvss_bands,
    build_domain_ranking,
    build_domain_severity_matrix,
    build_kpis,
    build_severity_distribution,
    build_triage_queue,
    build_weakness_ranking,
    clean_records,
    export_rows,
    load_records,
)

ROOT = Path(__file__).parent.parent
PROCESSED = ROOT / "data" / "processed"


def build_outputs():
    records = clean_records(
        load_records(ROOT / "data" / "raw" / "healthcare_cybersecurity_10k.csv")
    )
    domains = build_domain_ranking(records)
    frames = {
        "kpis": build_kpis(records),
        "annual_trend": build_annual_trend(records),
        "severity_distribution": build_severity_distribution(records),
        "attack_vector_distribution": build_attack_vector_distribution(records),
        "cvss_bands": build_cvss_bands(records),
        "weakness_ranking": build_weakness_ranking(records),
        "domain_ranking": domains,
        "domain_severity_matrix": build_domain_severity_matrix(
            records, domains
        ).reset_index(),
        "triage_queue": build_triage_queue(records),
    }
    return {name: export_rows(frame) for name, frame in frames.items()}


OUTPUTS = build_outputs()


@pytest.mark.parametrize("name", sorted(OUTPUTS))
def test_committed_export_matches(name):
    committed = json.loads((PROCESSED / f"{name}.json").read_text())
    assert OUTPUTS[name] == committed
