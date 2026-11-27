"""Escaneo dinámico (DAST) con OWASP ZAP a través de su API.

Uso: python3 scripts/zap_scan.py <url_objetivo>

1. Spider: recorre los enlaces y formularios de la app.
2. Escaneo pasivo: revisa cabeceras y respuestas sin atacar.
3. Escaneo activo: envía ataques (XSS, inyección SQL, ...) a cada parámetro.
4. Guarda reports/zap-report.html, reports/zap-alertas.json y reports/zap-resumen.txt.

Termina con código 2 si hay alertas de riesgo High o Medium (el pipeline marca UNSTABLE).
ZAP corre en su propio contenedor; la clave de su API se lee de /run/secrets/zap_api_key.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

ZAP = os.environ.get("ZAP_URL", "http://zap:8080")
CLAVE = Path(os.environ.get("ZAP_API_KEY_FILE", "/run/secrets/zap_api_key")).read_text().strip()
MINUTOS_ACTIVO = int(os.environ.get("ZAP_MINUTOS_ACTIVO", "6"))
FALLA_EN = {"High", "Medium"}
REPORTES = Path("reports")


def api(ruta, formato="JSON", **parametros):
    """Llama a la API de ZAP y devuelve JSON (o texto para los reportes)."""
    parametros["apikey"] = CLAVE
    url = f"{ZAP}/{formato}/{ruta}/?{urllib.parse.urlencode(parametros)}"
    with urllib.request.urlopen(url, timeout=60) as respuesta:
        cuerpo = respuesta.read().decode("utf-8")
    return json.loads(cuerpo) if formato == "JSON" else cuerpo


def esperar(nombre, estado, id_escaneo, limite_s):
    """Muestra el avance de un escaneo hasta que llegue a 100 % o se agote el tiempo."""
    inicio = time.time()
    while True:
        avance = int(api(estado, scanId=id_escaneo)["status"])
        print(f"   {nombre}: {avance}%", flush=True)
        if avance >= 100:
            return
        if time.time() - inicio > limite_s:
            print(f"   {nombre}: tiempo agotado, se continúa con lo encontrado", flush=True)
            return
        time.sleep(5)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Uso: zap_scan.py <url_objetivo>")
    objetivo = sys.argv[1].rstrip("/")
    REPORTES.mkdir(exist_ok=True)

    print(f">> ZAP {api('core/view/version')['version']} - objetivo {objetivo}", flush=True)
    api("core/action/newSession", overwrite="true")
    api("core/action/accessUrl", url=objetivo + "/", followRedirects="true")

    print(">> 1/3 Spider (descubre URLs y formularios)", flush=True)
    esperar("spider", "spider/view/status", api("spider/action/scan", url=objetivo)["scan"], 180)
    urls = api("core/view/urls", baseurl=objetivo)["urls"]
    print(f"   {len(urls)} URLs encontradas", flush=True)

    print(">> 2/3 Escaneo pasivo (cabeceras y respuestas)", flush=True)
    for _ in range(60):
        if int(api("pscan/view/recordsToScan")["recordsToScan"]) == 0:
            break
        time.sleep(2)

    print(">> 3/3 Escaneo activo (ataques controlados)", flush=True)
    api("ascan/action/setOptionMaxScanDurationInMins", Integer=str(MINUTOS_ACTIVO))
    id_activo = api("ascan/action/scan", url=objetivo, recurse="true")["scan"]
    esperar("activo", "ascan/view/status", id_activo, MINUTOS_ACTIVO * 60 + 60)

    alertas = api("core/view/alerts", baseurl=objetivo, start="0", count="9999")["alerts"]
    (REPORTES / "zap-alertas.json").write_text(json.dumps(alertas, indent=2, ensure_ascii=False), encoding="utf-8")
    (REPORTES / "zap-report.html").write_text(api("core/other/htmlreport", formato="OTHER"), encoding="utf-8")

    # Una línea por tipo de alerta (ZAP repite la misma alerta por cada URL afectada).
    tipos = {}
    for a in alertas:
        tipos.setdefault((a["risk"], a["alert"]), set()).add(a["url"])
    orden = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    conteo = Counter(riesgo for riesgo, _ in tipos)
    lineas = [f"Objetivo: {objetivo}",
              "Tipos de alerta por riesgo: " + ", ".join(f"{r}={conteo.get(r, 0)}" for r in orden), ""]
    for (riesgo, nombre), afectadas in sorted(tipos.items(), key=lambda x: (orden.get(x[0][0], 9), x[0][1])):
        lineas.append(f"[{riesgo}] {nombre}  ({len(afectadas)} URL)  ej.: {sorted(afectadas)[0]}")
    resumen = "\n".join(lineas)
    (REPORTES / "zap-resumen.txt").write_text(resumen + "\n", encoding="utf-8")
    print("\n" + resumen, flush=True)

    graves = sum(conteo.get(r, 0) for r in FALLA_EN)
    if graves:
        print(f"\nZAP encontró {graves} tipo(s) de alerta High/Medium. Revisa reports/zap-report.html", flush=True)
        sys.exit(2)
    print("\nZAP no encontró alertas High ni Medium.", flush=True)


if __name__ == "__main__":
    main()
