import pytest
from back.serializer import AddEmployerSerializer
from back.models import Magasin, Contrat
from datetime import time
#Test pour vérifier le serializer
@pytest.mark.django_db
def test_valid_add_employer():
    shop = Magasin.objects.create(shop_name="boutique1")
    contrat = Contrat.objects.create(contrat_name="cdi")
    data = {
        "username" : "Tom",
        "last_name" : "holland",
        "email" : "tomholland@gmail.com",
        "working_day" : {
            "working_day" : ["Lundi", "Mardi", "Mercredi"],
            "start_job" : "09:00",
            "end_job" : "17:00"
        },
        "shops" : [shop.id],
        "contrat" : contrat.id
    }
    serializer = AddEmployerSerializer(data=data)
    assert serializer.is_valid(), serializer.errors

@pytest.mark.django_db
def test_invalid_add_employer():
    shop = Magasin.objects.create(shop_name="boutique1")
    contrat = Contrat.objects.create(contrat_name="cdi")
    data = {
        "username" : "Tom",
        "last_name" : "holland",
        "email" : "tomhollandgmail.com",
        "working_day" : {
            "working_day" : ["Lundi", "Mardi", "Mercredi"],
            "start_job" : "09:00",
            "end_job" : "17:00"
        },
        "shops" : [shop.id],
        "contrat" : contrat.id
    }
    serializer = AddEmployerSerializer(data=data)
    assert not serializer.is_valid()
    assert "email" in serializer.errors