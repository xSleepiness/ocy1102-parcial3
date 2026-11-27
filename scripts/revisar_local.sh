#!/usr/bin/env bash
# Revisión ANTES de hacer push (shift-left): pruebas, Bandit y pip-audit sobre tu carpeta proyecto/.
# Uso (desde la carpeta laboratorio/):  docker compose exec taller bash scripts/revisar_local.sh
# El entorno virtual vive en /tmp del contenedor taller, no en tu carpeta.
set -u
VENV=/tmp/venv-revision
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r requirements.txt -r requirements-dev.txt

echo "== 1/3 Pruebas (pytest)";              "$VENV/bin/python" -m pytest -p no:cacheprovider; p=$?
echo "== 2/3 Código (Bandit, Medium+)";       bandit -q -ll app.py; b=$?
echo "== 3/3 Dependencias (pip-audit)";       pip-audit -r requirements.txt; a=$?

echo
[ $p -eq 0 ] && echo "Pruebas:      OK" || echo "Pruebas:      FALLAN"
[ $b -eq 0 ] && echo "Bandit:       sin hallazgos Medium/High" || echo "Bandit:       hay hallazgos"
[ $a -eq 0 ] && echo "pip-audit:    sin vulnerabilidades" || echo "pip-audit:    hay vulnerabilidades"
echo "(OWASP ZAP corre en el pipeline, sobre staging.)"
