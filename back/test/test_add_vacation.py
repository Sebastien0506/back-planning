import pytest
from back.serializer import CheckVacationSerializer
from datetime import date

@pytest.mark.django_db
def test_vacation_valid():
    data = {
        "start_day": "2025-04-10",
        "end_day": "2025-05-20"
    }

    serializer = CheckVacationSerializer(data=data)
    assert serializer.is_valid(), serializer.errors

@pytest.mark.django_db
def test_vacation_invalid() :
    data =  {
        "start_day" : "2025-04-05",
        "end_day" : "2025-03-29"
    }
    serializer = CheckVacationSerializer(data=data)
    assert not serializer.is_valid()
    assert "non_field_errors" in serializer.errors