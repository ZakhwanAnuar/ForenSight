"""Case management tests (spec section 65)."""
import pytest

from forensight import case_manager
from forensight.case_manager import CaseError


def test_valid_case_creation(tmp_path):
    case = case_manager.create_case("My Case", "CL-1", "Ann", "EX1", "Org", tmp_path)
    assert (case.root / "CaseData" / "crime_lens_case.db").exists()
    assert (case.root / "CaseData" / "case_config.json").exists()
    info = case.db.get_case_info()
    assert info["case_name"] == "My Case"
    assert info["case_status"] == "OPEN"
    case.close_db()


def test_missing_required_field(tmp_path):
    with pytest.raises(CaseError):
        case_manager.create_case("", "CL-2", "Ann", "EX1", "Org", tmp_path)


def test_case_name_sanitised_to_folder(tmp_path):
    case = case_manager.create_case("Laptop / Phone #1", "CL-3", "Ann", "EX1", "Org", tmp_path)
    assert case.root.name == "Laptop_Phone_1"
    # Original name preserved in metadata.
    assert case.db.get_case_info()["case_name"] == "Laptop / Phone #1"
    case.close_db()


def test_refuses_to_overwrite_existing_case(tmp_path):
    case = case_manager.create_case("Dup", "CL-4", "Ann", "EX1", "Org", tmp_path)
    case.close_db()
    with pytest.raises(CaseError):
        case_manager.create_case("Dup", "CL-5", "Ann", "EX1", "Org", tmp_path)


def test_open_existing_case(tmp_path):
    case = case_manager.create_case("Reopen", "CL-6", "Ann", "EX1", "Org", tmp_path)
    root = case.root
    case.close_db()
    reopened = case_manager.open_case(root)
    assert reopened.case_id == "CL-6"
    reopened.close_db()


def test_open_missing_database_raises(tmp_path):
    case = case_manager.create_case("NoDb", "CL-7", "Ann", "EX1", "Org", tmp_path)
    root = case.root
    case.close_db()
    (root / "CaseData" / "crime_lens_case.db").unlink()
    with pytest.raises(CaseError):
        case_manager.open_case(root)
