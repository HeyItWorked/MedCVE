import json

import pandas as pd

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
    export_rows,
)


def test_clean_keeps_every_row_and_parses_types(records, raw_records):
    assert len(records) == len(raw_records) == 30
    assert pd.api.types.is_datetime64_any_dtype(records["Published"])
    assert pd.api.types.is_numeric_dtype(records["CVSS_Score"])


def test_na_and_empty_keyword_become_one_missing_group(raw_records):
    assert raw_records["Keyword"].isna().sum() == 2


def test_kpis_are_five_rows_in_order(records):
    kpis = build_kpis(records)
    assert list(kpis["metric"]) == [
        "total_cves",
        "critical_cves",
        "high_critical_rate",
        "network_vector_rate",
        "high_critical_network_count",
    ]
    assert kpis.loc[0, "value"] == 30


def test_annual_trend_counts_every_row_with_null_year_last(records):
    annual = build_annual_trend(records)
    assert annual["total_cves"].sum() == len(records)
    assert pd.isna(annual["Published_Year"].iloc[-1])


def test_distributions_count_every_row(records):
    for build in (build_severity_distribution, build_attack_vector_distribution):
        assert build(records)["count"].sum() == len(records)


def test_cvss_bands_leave_out_zero_and_missing_scores(records):
    bands = build_cvss_bands(records)
    assert list(bands["band"]) == ["Low", "Medium", "High", "Critical"]
    assert bands["count"].sum() < len(records)


def test_rankings_keep_nested_counts(records):
    for ranking in (build_weakness_ranking(records), build_domain_ranking(records)):
        assert len(ranking) <= 10
        assert (ranking["critical_count"] <= ranking["high_critical_count"]).all()
        assert (ranking["high_critical_count"] <= ranking["cve_count"]).all()


def test_matrix_rows_follow_domain_ranking(records):
    ranking = build_domain_ranking(records)
    matrix = build_domain_severity_matrix(records, ranking)
    assert list(matrix.index) == ranking["Keyword"].tolist()


def test_triage_score_stacks_every_term(records):
    # CRITICAL + NETWORK + CVSS 9.9: severity 5 + network 2 + critical 2 + high 1
    single = records[records["CVE_ID"] == "CVE-2099-0025"]
    assert build_triage_queue(single).iloc[0]["triage_score"] == 10


def test_exports_are_strict_json_with_null_dates(records):
    rows = export_rows(build_triage_queue(records)) + export_rows(
        build_annual_trend(records)
    )
    json.dumps(rows, allow_nan=False)
    assert any(row.get("Published_Year", 0) is None for row in rows)
