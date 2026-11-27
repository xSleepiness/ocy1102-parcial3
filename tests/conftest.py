"""Prepara una base de datos temporal antes de importar la app en las pruebas."""
import os
import tempfile

os.environ.setdefault("DB_PATH", os.path.join(tempfile.mkdtemp(prefix="alumnos-test-"), "alumnos.db"))
