#!/usr/bin/env bash
# Despliega la aplicación en un entorno (staging o produccion) y hace una prueba de humo.
#
# Uso: bash scripts/deploy.sh <entorno> <puerto>
#   staging    -> puerto 5001 (lo escanea OWASP ZAP)
#   produccion -> puerto 5000 (lo vigilan Prometheus y Grafana; en tu equipo: http://localhost:5000)
#
# Cada entorno vive en su propia carpeta dentro del contenedor de Jenkins, con su propio
# entorno virtual y su propia base de datos. Solo se instalan las dependencias de EJECUCIÓN.
set -euo pipefail

ENTORNO="${1:?Indica el entorno: staging o produccion}"
PUERTO="${2:?Indica el puerto}"
APP_VERSION="${APP_VERSION:-dev}"
DESTINO="${DEPLOY_ROOT:-$HOME/despliegues}/$ENTORNO"
PIDFILE="$DESTINO/app.pid"

echo ">> [$ENTORNO] 1/4 Deteniendo la versión anterior (si existe)"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  kill "$(cat "$PIDFILE")" || true
  for _ in $(seq 1 10); do kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break; sleep 1; done
fi
rm -f "$PIDFILE"

echo ">> [$ENTORNO] 2/4 Copiando artefactos a $DESTINO"
mkdir -p "$DESTINO"
rm -f "$DESTINO/alumnos.db"
cp app.py requirements.txt "$DESTINO/"

echo ">> [$ENTORNO] 3/4 Instalando dependencias de ejecución"
cd "$DESTINO"
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/pip install --quiet --disable-pip-version-check -r requirements.txt

echo ">> [$ENTORNO] 4/4 Iniciando la aplicación (versión $APP_VERSION)"
# JENKINS_NODE_COOKIE=dontKillMe evita que Jenkins detenga la app al terminar el build.
# Escucha en 0.0.0.0 DENTRO del contenedor; Docker la publica solo en 127.0.0.1 de tu equipo.
APP_VERSION="$APP_VERSION" DB_PATH="$DESTINO/alumnos.db" JENKINS_NODE_COOKIE=dontKillMe \
  setsid nohup .venv/bin/gunicorn --bind "0.0.0.0:$PUERTO" --workers 1 --threads 4 \
  --access-logfile access.log app:app < /dev/null > app.log 2>&1 &
echo $! > "$PIDFILE"

echo ">> [$ENTORNO] Prueba de humo"
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PUERTO/health" > /dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:$PUERTO/health" > /dev/null || { echo "ERROR: /health no responde"; cat app.log; exit 1; }
DESPLEGADA="$(curl -fsS "http://127.0.0.1:$PUERTO/version")"
echo "/version -> $DESPLEGADA"
echo "$DESPLEGADA" | grep -qF "\"$APP_VERSION\"" || { echo "ERROR: la versión desplegada no es $APP_VERSION"; exit 1; }
echo "OK: $ENTORNO responde en el puerto $PUERTO con la versión $APP_VERSION"
