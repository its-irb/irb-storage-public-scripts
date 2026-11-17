import pytest

from meta_fields import (
    TAG_KEY_MAX,
    TAG_PROFILES,
    FieldType,
    apply_provider,
    check_tag_value,
    detect_profile,
    missing_required,
    profile_fields,
    validate_profile_tagset,
    validate_tagset,
)

IRB = "IRB Standard"
HISTO = "Histopathology IRB Core Facility"
COMMON = {"owner": "bbg", "users": "u", "date": "2026-01-01", "species": "human", "sample_type": "RNA"}


# ── Task 1: validación unificada ────────────────────────────────────────────

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


# ── Task 2: el nombre del perfil es el valor de provider ────────────────────

@pytest.mark.parametrize("name", list(TAG_PROFILES))
def test_profile_name_is_valid_tag_value(name):
    assert check_tag_value(name) is None


@pytest.mark.parametrize("name", list(TAG_PROFILES))
def test_provider_is_automatic_and_locked_to_name(name):
    assert "provider" not in [f[1] for f in TAG_PROFILES[name]]
    first = profile_fields(name)[0]
    assert first[1] == "provider" and first[4] == [name]


def test_detect_by_provider_ignores_key_order():
    assert detect_profile({**COMMON, "provider": HISTO}) == HISTO
    assert detect_profile({"project_name": "p", "provider": IRB}) == IRB


def test_detect_falls_back_to_keys():
    assert detect_profile({"instrument": "Phenoimager"}) == HISTO      # antiguo sin provider
    assert detect_profile({"project_name": "p"}) == IRB                # antiguo sin provider
    assert detect_profile({"provider": "Unknown", "instrument": "Nanozoomer"}) == HISTO
    assert detect_profile({}) is None


def test_prefill_forces_provider_to_profile_name():
    assert apply_provider(HISTO, {"provider": "Unknown", "instrument": "Nanozoomer"}) == \
        {"provider": HISTO, "instrument": "Nanozoomer"}
    assert apply_provider(IRB, {"project_name": "p"}) == {"project_name": "p", "provider": IRB}


# ── Task 3: campos obligatorios ─────────────────────────────────────────────

A_REQUIRED = ("A", "a", FieldType.TEXT, False, None, None, True)
B_OPTIONAL = ("B", "b", FieldType.TEXT, False, None, None)


def test_missing_required(monkeypatch):
    monkeypatch.setitem(TAG_PROFILES, "T", [A_REQUIRED, B_OPTIONAL])
    assert missing_required("T", {"provider": "T", "a": "", "b": ""}) == ["A"]
    assert missing_required("T", {"provider": "T", "b": "x"}) == ["A"]     # ausente
    assert missing_required("T", {"provider": "T", "a": "x", "b": ""}) == []


def test_validate_profile_tagset_combines_all_errors(monkeypatch):
    monkeypatch.setitem(TAG_PROFILES, "T", [A_REQUIRED, B_OPTIONAL])
    errs = validate_profile_tagset("T", {"provider": "T", "a": "", "b": "x" * 257})
    assert any("Missing required fields" in e and "A" in e for e in errs)
    assert any("b" in e for e in errs)                                  # longitud
    assert validate_profile_tagset("T", {"provider": "T", "a": "x", "b": ""}) == []


# ── Task 4: perfil Genomics ─────────────────────────────────────────────────

GENO = "Advanced Genomic Technologies IRB Core Facility"


def test_genomics_profile_shape():
    keys = [f[1] for f in profile_fields(GENO)]
    assert keys == ["provider", "owner", "users", "date", "application",
                    "library_kit", "species", "sample_type", "comments"]
    required = {f[1] for f in profile_fields(GENO) if len(f) > 6 and f[6]}
    assert required == set(keys) - {"comments"}


def test_genomics_options_are_valid_s3_values():
    for f in profile_fields(GENO):
        for opt in (f[4] or []):
            value = opt[0] if isinstance(opt, tuple) else opt
            assert check_tag_value(value) is None, (f[1], value)


def test_application_all_joined_exceeds_limit():
    app = next(f for f in profile_fields(GENO) if f[1] == "application")[4]
    assert len(app) == 26
    assert check_tag_value(":".join(sorted(app))) is not None


def test_detect_genomics_by_provider():
    assert detect_profile({**COMMON, "provider": GENO}) == GENO


def test_provider_with_foreign_keys_is_not_a_profile():
    # un objeto con tags que el perfil no conoce se abre en modo raw (None): guardar en
    # modo perfil los borraría sin aviso
    assert detect_profile({"provider": GENO, "owner": "bbg", "batch": "42"}) is None
    assert detect_profile({"provider": GENO, "custom_tag": "x"}) is None
