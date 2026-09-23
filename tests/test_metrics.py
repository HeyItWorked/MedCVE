import pandas as pd


def test_clean_keeps_every_row_and_parses_types(records, raw_records):
    assert len(records) == len(raw_records) == 30
    assert pd.api.types.is_datetime64_any_dtype(records["Published"])
    assert pd.api.types.is_numeric_dtype(records["CVSS_Score"])


def test_na_and_empty_keyword_become_one_missing_group(raw_records):
    assert raw_records["Keyword"].isna().sum() == 2
