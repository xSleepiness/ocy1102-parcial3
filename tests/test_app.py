"""Pruebas funcionales de Sistema Alumnos (deben pasar antes y después de corregir)."""
import re

import pytest

import app as modulo_app


@pytest.fixture
def client():
    modulo_app.app.config["TESTING"] = True
    with modulo_app.app.test_client() as c:
        yield c


def test_portada(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Sistema Alumnos" in r.data


def test_hello_saluda(client):
    r = client.get("/hello?name=Ana")
    assert r.status_code == 200
    assert "Ana" in r.get_data(as_text=True)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"estado": "ok"}


def test_version(client):
    r = client.get("/version")
    assert r.get_json()["aplicacion"] == "Sistema Alumnos"


def test_listar_alumnos(client):
    r = client.get("/alumnos")
    assert r.status_code == 200
    assert len(r.get_json()) == 4


def test_obtener_alumno(client):
    assert client.get("/alumnos/1").get_json()["nombre"] == "Ana Pérez"
    assert client.get("/alumnos/999").status_code == 404


def test_buscar_alumno(client):
    r = client.get("/alumnos/buscar?nombre=Camila")
    assert r.status_code == 200
    assert [a["nombre"] for a in r.get_json()] == ["Camila Soto"]


def test_login_incorrecto(client):
    # Si la portada trae un token anti-CSRF, se envía (así la prueba sirve antes y después de corregir).
    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/").get_data(as_text=True))
    datos = {"usuario": "admin", "clave": "mala", **({"csrf_token": token.group(1)} if token else {})}
    r = client.post("/login", data=datos)
    assert r.status_code == 401


def test_metricas(client):
    client.get("/alumnos")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"http_requests_total" in r.data
    assert b"login_fallidos_total" in r.data
