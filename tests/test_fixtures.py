"""Every fixture case goes through pipeline.adjudicate, the same entry
point main.py uses for a real SAST report."""
import pytest

from dvl import pipeline
from dvl.schema import Verdict

from fixture_cases import all_cases, build_finding, case_id, load_profile


def _params():
    params = []
    for fixture_dir, case in all_cases():
        marks = []
        if case.get("expected_engine_tier") == "B_partial_dynamic":
            marks.append(pytest.mark.slow)
        if case.get("xfail"):
            marks.append(pytest.mark.xfail(reason=case["xfail"], strict=True))
        params.append(pytest.param(fixture_dir, case, id=case_id(fixture_dir, case), marks=marks))
    return params


@pytest.mark.parametrize("fixture_dir, case", _params())
def test_fixture_case(fixture_dir, case):
    gt, finding = build_finding(fixture_dir, case)
    record = pipeline.adjudicate(gt, finding, load_profile(fixture_dir, case))

    detail = f"[{record.engine_tier.value}/{record.evidence.kind}] {record.evidence.detail}"
    assert record.verdict == Verdict(case["expected_verdict"]), detail
    if "expected_confidence" in case:
        assert record.confidence == case["expected_confidence"], detail
    if "expected_engine_tier" in case:
        assert record.engine_tier.value == case["expected_engine_tier"], detail
