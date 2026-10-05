from dvl.ingest import parse_findings


def test_converted_report_format():
    data = {"findings": [{
        "cwe_id": "CWE_789", "cwe_name": "Memory Allocation with Excessive Size Value",
        "addresses": ["0x1c5c0"], "symbols": [], "tids": ["instr_0x0001c5c0_9"],
        "description": "Potential stack memory exhaustion", "ai_audit": {"confidence": 0.3},
    }]}
    (f,) = parse_findings(data)
    assert f.address == 0x1c5c0
    assert f.cwe_id == "CWE-789"
    assert f.finding_id == "instr_0x0001c5c0_9"
    assert f.confidence == 0.3


def test_raw_cwe_checker_output_uses_decimal_addresses():
    data = [
        {"name": "CWE215", "version": "0.2", "addresses": [], "tids": [], "symbols": [],
         "other": [], "description": "(Information Exposure Through Debug Information) ..."},
        {"name": "CWE476", "version": "0.2", "addresses": ["172"],
         "tids": ["instr_0x000000ac_0_load0"], "symbols": [], "other": [],
         "description": "(NULL Pointer Dereference) Memory access at 172 may result in a NULL dereference"},
    ]
    (f,) = parse_findings(data)
    assert f.address == 0xAC
    assert f.cwe_id == "CWE-476"
    assert f.cwe_name == "NULL Pointer Dereference"


def test_bare_hex_digits_disambiguated_by_tid():
    data = [{"name": "CWE121", "addresses": ["1000"], "tids": ["instr_0x00001000_2"]}]
    (f,) = parse_findings(data)
    assert f.address == 0x1000


def test_duplicate_ids_are_made_unique():
    rec = {"cwe_id": "CWE_121", "addresses": ["0x10"], "tids": ["same"]}
    ids = [f.finding_id for f in parse_findings({"findings": [rec, rec]})]
    assert ids == ["same", "same#1"]


def test_skipped_reasons_and_alternate_shapes():
    skipped = []
    data = {"results": [{"address": "0x10", "cwe_id": "CWE-476"}, {"cwe_id": "CWE-476"}]}
    (f,) = parse_findings(data, skipped)
    assert f.address == 0x10
    assert skipped == ["record 1: no 'addresses'"]


def _run_cli(tmp_path, report_data, monkeypatch):
    import json
    from dvl import cli
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(report_data) if report_data is not None else "{not json")
    out = tmp_path / "out.json"
    monkeypatch.setattr("sys.argv", ["dvl", "fw.elf", str(rep), "--json", str(out)])
    try:
        cli.main()
        code = 0
    except SystemExit as e:
        code = e.code
    return code, out


def test_cli_empty_report_is_clean(tmp_path, monkeypatch):
    code, out = _run_cli(tmp_path, {"findings": []}, monkeypatch)
    assert code == 0 and out.read_text().strip() == "[]"


def test_cli_unusable_records_fail(tmp_path, monkeypatch):
    code, _ = _run_cli(tmp_path, {"findings": [{"cwe_id": "CWE-476"}]}, monkeypatch)
    assert code == 1


def test_cli_unrecognized_shape_and_bad_json_fail(tmp_path, monkeypatch):
    assert _run_cli(tmp_path, {"something": []}, monkeypatch)[0] == 1
    assert _run_cli(tmp_path, None, monkeypatch)[0] == 2
