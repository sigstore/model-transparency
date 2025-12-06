# tests/test_model_card.py
import pytest
from pydantic import ValidationError
from model_signing.model_card import ModelCardMetadata

def test_valid_metadata():
    data = {
        "model_id": "test-model",
        "co2_emitted": 50.5,
        "tags": ["a", "b"]
    }
    model = ModelCardMetadata(**data)
    assert model.model_id == "test-model"
    assert model.co2_emitted == 50.5

def test_invalid_type():
    data = {"co2_emitted": "not-a-number"}
    with pytest.raises(ValidationError):
        ModelCardMetadata(**data)

def test_extra_fields_allowed():
    # Hugging Face allows custom fields, check if we allow them
    data = {"custom_field": "value"}
    model = ModelCardMetadata(**data)
    assert model.model_extra["custom_field"] == "value"