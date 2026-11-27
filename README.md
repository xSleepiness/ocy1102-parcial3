# Sistema Alumnos · SecureDev

API y portal web (Flask) de la **Evaluación Parcial 3 de OCY1102 – Ciberseguridad en desarrollo**.
Sobre este código, **que es vulnerable a propósito**, construyes un pipeline seguro en Jenkins:
pruebas, análisis estático, dependencias, OWASP ZAP, despliegue protegido, monitoreo en Grafana y trazabilidad.

> Este repositorio es solo el punto de partida. Las capturas van en **Desarrollo EV3.docx** (sección con el mismo número de evidencia).

## Rutas

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` | Portada con enlaces y formularios |
| GET | `/hello?name=Ana` | Saludo |
| GET | `/alumnos` · `/alumnos/<id>` | Listado y detalle de alumnos |
| GET | `/alumnos/buscar?nombre=Ana` | Búsqueda por nombre |
| POST | `/login` | Acceso del administrador (formulario) |
| GET | `/health` · `/version` | Estado y versión desplegada |
| GET | `/metrics` | Métricas para Prometheus (no cambies sus nombres) |

## Contenido

| Archivo | Para qué sirve |
|---|---|
| `app.py` | Aplicación (contiene vulnerabilidades que debes encontrar y corregir) |
| `tests/` | Pruebas funcionales (pytest). Deben seguir pasando después de corregir |
| `requirements.txt` | Dependencias de ejecución (antiguas a propósito) |
| `requirements-dev.txt` | Dependencias solo de pruebas |
| `Jenkinsfile` | Pipeline base: Build → Test → Deploy Producción. Los marcadores `>>> [ETIQUETA]` indican dónde agregar etapas |
| `scripts/deploy.sh` | Despliega en `staging` (5001) o `produccion` (5000) y hace prueba de humo |
| `scripts/zap_scan.py` | Escaneo DAST con OWASP ZAP (spider, pasivo y activo) |
| `scripts/trazabilidad.py` | Registro build ↔ versión ↔ commit ↔ hallazgos ↔ despliegue |
| `scripts/revisar_local.sh` | Pruebas + Bandit + pip-audit en el contenedor taller, antes del push |
| `scripts/simular_ataque.py` | Ataque de prueba para ver incidentes en Grafana (solo en este laboratorio) |
| `docs/REGISTRO_SEGURIDAD.md` | Tu registro de revisiones, vulnerabilidades, incidentes y dependencias |

## Convención de commits (trazabilidad)

Cada corrección va en su propio commit y empieza con el identificador del hallazgo:
`VULN-02: consulta parametrizada en /alumnos/buscar`. Así cada build del registro de
trazabilidad se puede seguir hasta el hallazgo que corrigió.

## Evidencias que debes subir

Pega cada captura en **Desarrollo EV3.docx**, en la sección con el mismo número. Al inicio del documento escribe tu nombre
y la URL de tu repositorio en GitHub. Ninguna captura ni archivo puede mostrar claves (Jenkins, Grafana, API de ZAP).

**Implementación de pipeline e identificación y corrección de vulnerabilidades**

1. Pipeline de CI/CD en Jenkins con etapas de construcción, pruebas y despliegue: configuración del job y build en verde.
2. Revisiones de seguridad continuas en el pipeline (análisis del código y de dependencias) y sus reportes.
3. Corrección de cada vulnerabilidad: commits `VULN-xx` (diff) y build que verifica la corrección.
4. Documentación de las revisiones, las vulnerabilidades identificadas y cómo se mitigó cada una (`docs/REGISTRO_SEGURIDAD.md`, secciones 1 y 2).

**Pruebas automatizadas de seguridad**

5. OWASP ZAP integrado en el pipeline de Jenkins: etapa en el `Jenkinsfile` y en la vista de etapas.
6. Resultados de ZAP sobre el código vulnerable: alertas encontradas y cómo se mitiga cada una (sección 3).

**Monitorización del entorno de producción**

7. Grafana configurado: fuente de datos Prometheus, dashboard de producción y regla de alerta.
8. Monitoreo en tiempo real: dashboard y alerta mostrando un incidente de seguridad.
9. Documentación del monitoreo y del incidente: detección, análisis, clasificación, respuesta y verificación (sección 4).

**Gestión de dependencias**

10. Dependabot implementado: `.github/dependabot.yml` y alertas activas en GitHub.
11. Dependencias actualizadas (PR de Dependabot) y build que verifica que no hay nuevas vulnerabilidades.
12. Documentación del proceso de gestión de dependencias (sección 5).

**Documentación y trazabilidad en el SDLC**

13. Trazabilidad de las actividades del pipeline (revisiones de seguridad, pruebas automatizadas y gestión de dependencias): `TRAZABILIDAD.md` del último build y sección 6.
14. Documentación que refleje las prácticas de seguridad en todo el ciclo de vida: registro completo en GitHub y pipeline final en verde.

## Referencia del laboratorio

| Servicio | Dirección |
|---|---|
| Jenkins | `http://localhost:8080` |
| Producción (puerto 5000) / Staging (puerto 5001) | `http://localhost:5000` · `http://localhost:5001` (dentro de Docker: `http://jenkins:5000` · `http://jenkins:5001`) |
| Prometheus | `http://localhost:9090` (dentro de Docker: `http://prometheus:9090`) |
| Grafana | `http://localhost:3000` (usuario `admin`) |
| OWASP ZAP | solo red interna: `http://zap:8080`; la clave de su API está en `/run/secrets/zap_api_key` del contenedor de Jenkins |

Métricas de la app: `http_requests_total`, `login_fallidos_total`, `peticiones_sospechosas_total{tipo}`, `app_info{version}`.
