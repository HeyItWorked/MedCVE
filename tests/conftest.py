from pathlib import Path

import pytest

from analysis import clean_records, load_records

FIXTURE_CSV = Path(__file__).parent / "synthetic_cves.csv"


@pytest.fixture(scope="session")
def raw_records():
    return load_records(FIXTURE_CSV)


@pytest.fixture(scope="session")
def records(raw_records):
    return clean_records(raw_records)
