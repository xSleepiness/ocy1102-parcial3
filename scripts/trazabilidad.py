"""Registro de trazabilidad del pipeline (lo ejecuta Jenkins al final de cada build).

Une en una fila: build <-> versión <-> commit <-> pruebas <-> hallazgos de seguridad <-> despliegue.
- reports/trazabilidad-build.md : el detalle de ESTE build.
- REGISTRO (fuera del workspace) : el historial de TODOS los builds; se copia a reports/TRAZABILIDAD.md.
Si un reporte no existe (la etapa aún no está en el pipeline), la columna muestra "n/a".
"""
import json
import os
import subprocess  # nosec B404 - solo se ejecuta git con argumentos fijos
import xml.etree.ElementTree as ET  # nosec B405 - lee el XML que genera pytest en este mismo build
from datetime import datetime, timezone
from pathlib import Path

R = Path("reports")
REGISTRO = Path(os.environ.get("REGISTRO_TRAZABILIDAD",
                               Path.home() / "registro-trazabilidad" / "TRAZABILIDAD.md"))
ENCABEZADO = (
    "# Registro de trazabilidad - Sistema Alumnos\n\n"
    "Cada fila la agrega Jenkins al terminar un build (`scripts/trazabilidad.py`).\n\n"
    "| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L "
    "| pip-audit | ZAP H/M/L | Resultado | Producción |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|\n"
)


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()  # nosec B603 B607


def pruebas():
    try:
        raiz = ET.parse(R / "junit.xml").getroot()  # nosec B314
    except (OSError, ET.ParseError):
        return "n/a"
    suite = raiz if raiz.tag == "testsuite" else raiz.find("testsuite")
    total = int(suite.get("tests"))
    malas = int(suite.get("failures")) + int(suite.get("errors"))
    return f"{total - malas}/{total} OK"


def bandit():
    try:
        datos = json.loads((R / "bandit.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "n/a"
    n = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in datos.get("results", []):
        n[r["issue_severity"]] = n.get(r["issue_severity"], 0) + 1
    return f"{n['HIGH']}/{n['MEDIUM']}/{n['LOW']}"


def pip_audit():
    try:
        datos = json.loads((R / "pip-audit.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "n/a"
    ids = {v["id"] for dep in datos.get("dependencies", []) for v in dep.get("vulns", [])}
    return f"{len(ids)} vuln."


def zap():
    try:
        alertas = json.loads((R / "zap-alertas.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "n/a"
    tipos = {(a["risk"], a["alert"]) for a in alertas}
    return "/".join(str(sum(1 for r, _ in tipos if r == riesgo)) for riesgo in ("High", "Medium", "Low"))


def main():
    R.mkdir(exist_ok=True)
    mensaje = git("log", "-1", "--format=%s").replace("|", "/")[:70]
    fila = {
        "Build": os.environ.get("BUILD_NUMBER", "local"),
        "Fecha (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "Versión": os.environ.get("APP_VERSION", "dev"),
        "Commit": f"`{git('rev-parse', '--short', 'HEAD')}`",
        "Mensaje del commit": mensaje,
        "Pruebas": pruebas(),
        "Bandit H/M/L": bandit(),
        "pip-audit": pip_audit(),
        "ZAP H/M/L": zap(),
        "Resultado": os.environ.get("RESULTADO", "?"),
        "Producción": os.environ.get("PRODUCCION", "no desplegado"),
    }
    linea = "| " + " | ".join(fila.values()) + " |\n"

    detalle = [f"# Trazabilidad del build {fila['Build']}", ""]
    detalle += [f"- **{k}:** {v}" for k, v in fila.items()]
    detalle += ["", f"- **Autor del commit:** {git('log', '-1', '--format=%an')}",
                f"- **Enlace al build:** {os.environ.get('BUILD_URL', 'n/a')}",
                "- **Reportes de este build:** junit.xml, bandit.txt, pip-audit.txt, zap-report.html", ""]
    (R / "trazabilidad-build.md").write_text("\n".join(detalle), encoding="utf-8")

    REGISTRO.parent.mkdir(parents=True, exist_ok=True)
    if not REGISTRO.exists():
        REGISTRO.write_text(ENCABEZADO, encoding="utf-8")
    with REGISTRO.open("a", encoding="utf-8") as archivo:
        archivo.write(linea)
    (R / "TRAZABILIDAD.md").write_text(REGISTRO.read_text(encoding="utf-8"), encoding="utf-8")
    print(linea.strip())


if __name__ == "__main__":
    main()
