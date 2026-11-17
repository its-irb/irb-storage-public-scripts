from meta_fields import TAG_KEY_MAX, check_tag_value, validate_tagset


def test_value_length_boundary():
    assert check_tag_value("a" * 256) is None
    assert check_tag_value("a" * 257) is not None


def test_key_length_boundary():
    assert check_tag_value("k" * 128, TAG_KEY_MAX) is None
    assert check_tag_value("k" * 129, TAG_KEY_MAX) is not None


def test_invalid_characters_rejected():
    for bad in ["scRNA-seq 3'", "Takara (x)", "a,b", 'a"b']:
        assert check_tag_value(bad) is not None
    assert check_tag_value("") is None


def test_validate_tagset_reports_key_and_value():
    errs = validate_tagset({"k" * 129: "ok", "good": "v" * 257, "x": "ok"})
    assert len(errs) == 2
    assert any("good" in e for e in errs)
