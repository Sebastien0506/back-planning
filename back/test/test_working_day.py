import pytest
from back.serializer import WorkingDaySerializer
from datetime import time
#Test pour vérifier le serializer
@pytest.mark.django_db
def test_working_day_serializer_valid():
    data = {
        "working_day": ["Lundi", "Mardi", "Mercredi"],
        "start_job": "09:00",
        "end_job": "17:00",
    }
    serializer = WorkingDaySerializer(data=data)
    assert serializer.is_valid(), serializer.errors

@pytest.mark.django_db
def test_working_day_serializer_invalid_day_characters():
    data = {
        "working_day": ["Lundi", "Mard1"],
        "start_job": "20:00",
        "end_job": "17:00",
    }
    serializer = WorkingDaySerializer(data=data)
    assert not serializer.is_valid()
    assert "working_day" in serializer.errors