# Registro de seguridad · Sistema Alumnos

Estudiante: Emilio Herrera   Repositorio: https://github.com/xSleepiness/ocy1102-parcial3   Fecha: 27-11-2026

Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #1 | 2 hallazgos High / 2 Medium / 1 Low (B324 MD5, B201 debug=True, B608 SQL con strings, B104 0.0.0.0, B105 clave en el código). Desde el build #4: 0 / 0 / 0 |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #1 | 19 vulnerabilidades en 4 paquetes (Flask, Werkzeug, Jinja2, gunicorn). Desde el build #7: 0 |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #1 | 3 High / 3 Medium / 1 Low (SQL Injection, XSS reflejado y DOM, sin anti-CSRF, sin CSP, sin anti-clickjacking, sin nosniff). Desde el build #5: 0 / 0 / 0 |
| R4 | Revisión manual | Lectura de `app.py` | — | Confirmó los hallazgos de las herramientas y agregó: clave de administrador trivial (MD5 de "admin"), consulta SQL expuesta en el mensaje de error (CWE-209), login sin límite de intentos (CWE-307) y usuario sin escapar en el log (CWE-117) |
| R5 | Producción | Grafana + Prometheus | — | 2 ataques simulados contra producción detectados en el dashboard y por las alertas; el primero reveló una brecha de detección (MON-01), corregida en el build #9 |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) y consulta expuesta en el error (CWE-209) | Bandit B608, ZAP "SQL Injection" (High), revisión manual | `app.py:205` | Alto | Consulta parametrizada `LIKE ? ESCAPE '\'` con escape de `%` y `_`; el error se registra en el log y el cliente recibe un mensaje genérico | `9d38662` | #2 |
| VULN-02 | XSS reflejado y DOM (CWE-79) | ZAP "Cross Site Scripting (Reflected)" y "(DOM Based)" (High) | `app.py:154` | Alto | Salida con plantilla Jinja2 (`render_template_string`), que escapa el HTML automáticamente | `731b7da` | #3 |
| VULN-03 | Hash MD5 sin sal (CWE-328) y clave trivial "admin" en el código (CWE-521, CWE-798) | Bandit B324 (High), revisión manual | `app.py:221` | Alto | Hash PBKDF2-SHA256 con sal (`werkzeug.security`) leído de la variable de entorno `ADMIN_CLAVE_HASH`; usuario comparado en tiempo constante; sin la variable, el acceso de administrador queda deshabilitado | `bbb14ff` | #4 |
| VULN-04 | `SECRET_KEY` escrita en el código (CWE-798) | Bandit B105 (Low) | `app.py:20` | Medio | Se lee de la variable de entorno `SECRET_KEY`; si no existe, se genera una aleatoria de 256 bits | `aabe867` | #4 |
| VULN-05 | Depurador de Werkzeug activo (CWE-489 / CWE-94) y escucha en todas las interfaces (CWE-605) | Bandit B201 (High), B104 (Medium) | `app.py:241` | Alto | `debug=False` y `host=127.0.0.1` por defecto al ejecutar `app.py` directamente | `f93b82c` | #4 |
| VULN-06 | Falta de token anti-CSRF en el login (CWE-352) | ZAP "Absence of Anti-CSRF Tokens" (Medium) | `app.py:69` | Medio | Token aleatorio de 256 bits en la sesión y en un campo oculto; `/login` responde 400 si falta o no coincide; cookie `HttpOnly` y `SameSite=Strict` | `9e728b7` | #5 |
| VULN-07 | Faltan cabeceras de seguridad CSP, anti-clickjacking y nosniff (CWE-693, CWE-1021) | ZAP "CSP Header Not Set", "Missing Anti-clickjacking Header" (Medium), "X-Content-Type-Options Header Missing" (Low) | `app.py` (todas las respuestas) | Medio | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP y `Cache-Control: no-store` en todas las respuestas | `c761b7e` | #5 |
| VULN-08 | Login sin límite de intentos (CWE-307) y usuario sin escapar en el log (CWE-117) | Revisión manual, `simular_ataque.py` | `app.py:214` | Medio | Máximo 5 fallos por IP en 5 minutos → HTTP 429 con `Retry-After`; los bloqueos se cuentan en las métricas de Grafana; el usuario se registra con `%r` | `fa67f34` | #5 |
| MON-01 | Monitoreo incompleto: el primer ataque de cada tipo tras un despliegue no se detectaba (CWE-778) | Grafana (ataque simulado 1) | `app.py` (métricas) | Medio | Las series `peticiones_sospechosas_total{tipo}` y `http_requests_total` de `/login` se crean en 0 al iniciar | `f56a27e` | #9 |

(Agrega las filas que necesites.)

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| SQL Injection | High | `http://jenkins:5001/alumnos/buscar?nombre='` | VULN-01 | Consulta parametrizada y mensaje de error genérico | Sí · #2 |
| Cross Site Scripting (Reflected) | High | `http://jenkins:5001/hello?name=</h1><scrIpt>alert(1);</scRipt><h1>` | VULN-02 | Escapado automático con Jinja2 | Sí · #3 |
| Cross Site Scripting (DOM Based) | High | `http://jenkins:5001/hello?name=<script>alert(5397)</script>` | VULN-02 | Escapado automático con Jinja2 | Sí · #3 |
| Absence of Anti-CSRF Tokens | Medium | `http://jenkins:5001/` | VULN-06 | Token anti-CSRF en la sesión y en el formulario | Sí · #5 |
| Content Security Policy (CSP) Header Not Set | Medium | `http://jenkins:5001/` | VULN-07 | Cabecera `Content-Security-Policy` en todas las respuestas | Sí · #5 |
| Missing Anti-clickjacking Header | Medium | `http://jenkins:5001/` | VULN-07 | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Sí · #5 |
| X-Content-Type-Options Header Missing | Low | `http://jenkins:5001/` | VULN-07 | `X-Content-Type-Options: nosniff` | Sí · #5 |
| Session Management Response Identified | Informational | `http://jenkins:5001/` | — | Informativa: ZAP reconoce la cookie de sesión (`HttpOnly`, `SameSite=Strict`) | No requiere acción · #5 |
| User Agent Fuzzer | Informational | `http://jenkins:5001/` | — | Informativa: sin respuestas anómalas con otros User-Agent | No requiere acción · #5 |

## 4. Monitoreo e incidentes

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 17:34 | Todos los paneles y las 3 reglas de alerta | Línea base: producción `up=1`, versión `1.0.8+79a9220`, 0 logins fallidos, 0 ataques | Producción | Normal | — | Las 3 reglas en estado Normal |
| 17:35 | Logins fallidos (últimos 5 min) = 31; alerta "Fuerza bruta en /login" en Firing | Ataque simulado 1: 31 intentos de login, 1 inyección SQL y 1 XSS desde 172.18.0.6 | Producción | Incidente de seguridad, severidad alta (fuerza bruta + SQLi + XSS) | Contención automática: tras 5 fallos la IP quedó bloqueada (26 respuestas HTTP 429). Análisis del log de producción: 33 advertencias de seguridad | Ninguna clave funcionó, la SQLi no devolvió datos y el XSS se escapó |
| 17:36 | Peticiones sospechosas (últimos 5 min) = 0 | El log registró sqli, xss y fuerza_bruta, pero el panel y la alerta "Peticiones con patrones de ataque" no los vieron | Producción | Brecha de detección (MON-01) | Se inicializaron en 0 las métricas al arrancar la app (`f56a27e`), desplegado por el build #9 | `/metrics` muestra todas las series en 0 desde el inicio |
| 17:40 | Logins fallidos = 62; Peticiones sospechosas = 28; alertas "Fuerza bruta en /login" y "Peticiones con patrones de ataque" en Firing | Ataque simulado 2 sobre `1.0.9+f56a27e`: fuerza_bruta 27, sqli 1, xss 1; en `/login` 5 respuestas 401 y 27 respuestas 429 | Producción | Incidente de seguridad, severidad alta | Misma contención automática (bloqueo HTTP 429); detectado por las dos alertas | Las dos alertas en Firing; "Produccion no responde" siguió en Normal (`up=1`) |
| 17:53 | Logins fallidos y peticiones sospechosas (2 min) | Ambas métricas volvieron a 0 | Producción | Cierre del incidente | — | Consulta en Prometheus = 0 |

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861, CVE-2026-27205 | 3.1.3 | PR #12 de Dependabot | Sí · #7 |
| Werkzeug | 2.2.2 | CVE-2023-25577, CVE-2023-23934, CVE-2023-46136, CVE-2024-34069, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.9 | PR #12 de Dependabot | Sí · #7 |
| Jinja2 | 3.1.2 | CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | PR #12 de Dependabot | Sí · #7 |
| gunicorn | 21.2.0 | CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR #12 de Dependabot | Sí · #7 |
| prometheus-client | 0.17.1 | — | 0.26.0 | PR #12 de Dependabot | Sí · #7 |

## 6. Trazabilidad

Pega aquí (o adjunta) el `TRAZABILIDAD.md` del último build y completa un recorrido por cada actividad del pipeline:

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:53 | 1.0.1+e7d6321 | `e7d6321` | Pipeline seguro: etapas SAST (Bandit), SCA (pip-audit), staging, DAST  | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 2 | 2026-11-27 20:00 | 1.0.2+9d38662 | `9d38662` | VULN-01: consulta parametrizada en /alumnos/buscar | 9/9 OK | 2/1/1 | 19 vuln. | 2/3/1 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 20:06 | 1.0.3+731b7da | `731b7da` | VULN-02: escapar salida HTML en /hello | 9/9 OK | 2/1/1 | 19 vuln. | 0/3/1 | UNSTABLE | no desplegado |
| 4 | 2026-11-27 20:12 | 1.0.4+f93b82c | `f93b82c` | VULN-05: desactivar modo debug y escuchar solo en localhost | 9/9 OK | 0/0/0 | 19 vuln. | 0/3/1 | UNSTABLE | no desplegado |
| 5 | 2026-11-27 20:15 | 1.0.5+fa67f34 | `fa67f34` | VULN-08: límite de intentos de login por IP | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 6 | 2026-11-27 20:21 | 1.0.6+6aeb7f2 | `6aeb7f2` | Dependabot: agrupar actualizaciones de pip | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 7 | 2026-11-27 20:24 | 1.0.7+24c07ef | `24c07ef` | Merge pull request #12 from xSleepiness/dependabot/pip/main/dependenci | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.7+24c07ef |
| 8 | 2026-11-27 20:30 | 1.0.8+79a9220 | `79a9220` | Monitoreo: Grafana como código (Prometheus, dashboard y alertas) | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.8+79a9220 |
| 9 | 2026-11-27 20:39 | 1.0.9+f56a27e | `f56a27e` | Monitoreo: inicializar en 0 las métricas de ataques | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.9+f56a27e |

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B608 SQL con strings, B324 MD5, B105 clave en el código, B201 debug=True, B104 0.0.0.0 (VULN-01, 03, 04, 05) | #1 | `9d38662`, `bbb14ff`, `aabe867`, `f93b82c` | #4 | 1.0.7+24c07ef |
| Prueba automatizada (OWASP ZAP) | SQL Injection, XSS, sin anti-CSRF, sin CSP, sin anti-clickjacking, sin nosniff (VULN-01, 02, 06, 07) | #1 | `9d38662`, `731b7da`, `9e728b7`, `c761b7e` | #5 | 1.0.7+24c07ef |
| Gestión de dependencias (Dependabot) | 19 vulnerabilidades en Flask, Werkzeug, Jinja2 y gunicorn (20 alertas de Dependabot) | #1 | PR #12 | #7 | 1.0.7+24c07ef |
