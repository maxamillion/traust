"""One-shot repair of evidence blocks using undeclared keys."""

from __future__ import annotations

import json

import pytest

from traust.migrations import repair_evidence_block_keys as mig


def _report(*blocks):
    return {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [{"id": "F-1", "evidence": list(blocks)}],
    }


def test_lang_is_renamed_because_language_is_always_absent():
    block = {"code": "echo hi", "lang": "shell", "type": "poc"}
    assert mig.repair_block(block) == ["lang->language", "type:poc->caption"]
    assert block == {"code": "echo hi", "language": "shell", "caption": "Proof of concept"}


def test_type_is_folded_into_caption_not_dropped():
    """A silent drop of evidence semantics is what nobody reviews."""
    block = {"code": "x", "type": "poc"}
    mig.repair_block(block)
    assert block["caption"] == "Proof of concept"
    assert "type" not in block


def test_a_conflicting_rename_is_refused_and_reported():
    """Never overwrite a real value to satisfy a schema."""
    block = {"code": "x", "lang": "shell", "language": "yaml"}
    assert "lang-and-language-both-present" in mig.repair_block(block)
    assert block["lang"] == "shell" and block["language"] == "yaml"


def test_an_existing_caption_is_not_overwritten():
    block = {"code": "x", "type": "poc", "caption": "Existing caption"}
    assert "caption-already-set" in mig.repair_block(block)
    assert block["caption"] == "Existing caption" and block["type"] == "poc"


def test_an_unmapped_type_is_left_alone_and_reported():
    """The corpus only has 'poc'. Anything else is a decision, not a rename."""
    block = {"code": "x", "type": "screenshot"}
    assert "unmapped-type:screenshot" in mig.repair_block(block)
    assert block["type"] == "screenshot"


def test_already_declared_blocks_are_untouched():
    document = _report({"code": "x", "language": "go", "caption": "c"})
    before = json.dumps(document)
    assert mig.repair_report(document) == (0, [], set())
    assert json.dumps(document) == before


def test_dry_run_writes_nothing(tmp_path, capsys):
    path = tmp_path / "a-findings-current.json"
    path.write_text(json.dumps(_report({"code": "x", "lang": "shell", "type": "poc"})))
    before = path.read_text()

    assert mig.main([str(tmp_path)]) == 0
    assert "dry run" in capsys.readouterr().out
    assert path.read_text() == before

    assert mig.main([str(tmp_path), "--write"]) == 0
    block = json.loads(path.read_text())["findings"][0]["evidence"][0]
    assert block == {"code": "x", "language": "shell", "caption": "Proof of concept"}


def test_repair_touches_only_the_evidence_block(tmp_path):
    """No identity, fingerprint or disposition may move."""
    document = _report({"code": "x", "lang": "shell", "type": "poc"})
    document["findings"][0]["fingerprint"] = "a" * 64
    document["findings"][0]["fingerprint_algo"] = "v3"
    document["findings"][0]["disposition"] = {"validity": "confirmed"}
    path = tmp_path / "a-findings-current.json"
    path.write_text(json.dumps(document))

    mig.main([str(tmp_path), "--write"])
    finding = json.loads(path.read_text())["findings"][0]
    assert finding["fingerprint"] == "a" * 64
    assert finding["fingerprint_algo"] == "v3"
    assert finding["disposition"] == {"validity": "confirmed"}


def test_repaired_blocks_validate_against_the_real_contract(tmp_path):
    import jsonschema
    from traust_contracts.paths import schema_dir

    schema = json.loads((schema_dir() / "report.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/evidence_block", "$defs": schema["$defs"]}
    )
    block = {"code": "echo hi", "lang": "shell", "type": "poc"}
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(block)
    mig.repair_block(block)
    validator.validate(block)
