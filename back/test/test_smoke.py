from django.test import Client

def test_csrf_endpoint_ok():
    c = Client()
    r = c.get("/csrf/")
    assert r.status_code == 200