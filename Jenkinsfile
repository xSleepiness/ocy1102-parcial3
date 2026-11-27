// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Etapas: Build -> Test -> Security Review (SAST, Bandit) -> Dependency Management (SCA, pip-audit)
//         -> Deploy Staging -> DAST (OWASP ZAP) -> Deploy Producción (solo si todo quedó en verde).
// Al final de cada build se registra la trazabilidad (build <-> commit <-> hallazgos <-> despliegue).
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // ---------------------------------------------------------------- Revisión de seguridad del código
        // SAST con Bandit sobre app.py (el código de la aplicación): busca patrones inseguros (SQL armado con strings,
        // MD5, secretos escritos en el código, debug=True, etc.). Hallazgos Medium/High -> UNSTABLE.
        stage('Security Review (SAST)') {
            steps {
                sh 'bandit --version | head -1'
                // Reportes completos (todas las severidades) para la documentación y la trazabilidad
                sh 'bandit app.py -f json -o reports/bandit.json || true'
                sh 'bandit app.py -f txt  -o reports/bandit.txt  || true'
                sh 'cat reports/bandit.txt || true'
                script {
                    // Compuerta: solo Medium y High (-ll) hacen fallar la revisión
                    def rc = sh(returnStatus: true, script: 'bandit -q -ll app.py')
                    if (rc != 0) {
                        unstable('Bandit encontró hallazgos Medium/High: revisa reports/bandit.txt')
                    }
                }
            }
        }

        // ---------------------------------------------------------------- Gestión de dependencias (SCA)
        // pip-audit compara requirements.txt con la base de vulnerabilidades de PyPI/OSV.
        // Dependabot (.github/dependabot.yml) abre las PR de actualización; este paso verifica
        // en cada build que ninguna dependencia tenga CVE conocidos.
        stage('Dependency Management') {
            steps {
                sh 'pip-audit --version'
                sh 'pip-audit -r requirements.txt -f json    -o reports/pip-audit.json || true'
                sh 'pip-audit -r requirements.txt -f columns -o reports/pip-audit.txt  || true'
                sh 'cat reports/pip-audit.txt || true'
                script {
                    def vulns = sh(returnStdout: true, script: '''python3 -c "
import json
d = json.load(open('reports/pip-audit.json'))
print(sum(len(p.get('vulns', [])) for p in d.get('dependencies', [])))
"''').trim()
                    echo "pip-audit: ${vulns} vulnerabilidades conocidas en dependencias"
                    if (vulns != '0') {
                        unstable("pip-audit encontró ${vulns} vulnerabilidades en dependencias: revisa reports/pip-audit.txt")
                    }
                }
            }
        }

        // ---------------------------------------------------------------- Despliegue a staging
        // Staging (puerto 5001) es una copia de producción solo para atacarla con ZAP.
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        // ---------------------------------------------------------------- Pruebas dinámicas (DAST)
        // OWASP ZAP (contenedor "zap") ataca staging por la red interna de Docker:
        // spider + escaneo pasivo + escaneo activo. Alertas High/Medium -> UNSTABLE.
        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (rc == 2) {
                        unstable('OWASP ZAP encontró alertas High/Medium: revisa reports/zap-report.html')
                    } else if (rc != 0) {
                        error("El escaneo de OWASP ZAP no pudo ejecutarse (código ${rc})")
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // Compuerta de seguridad: solo se despliega a producción si TODAS las etapas anteriores
            // quedaron en verde (sin hallazgos Medium/High de Bandit, sin CVE de pip-audit y sin
            // alertas High/Medium de ZAP). Si el build está UNSTABLE, producción no se toca.
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
