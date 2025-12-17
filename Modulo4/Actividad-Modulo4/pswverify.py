# app.py - Microservicio de validación de contraseñas seguras
from flask import Flask, request, jsonify
import re
import pytest

app = Flask(__name__)

# --- Función principal con programación defensiva ---
def is_secure_password(password: str) -> bool:
    assert isinstance(password, str), "Entrada inválida: debe ser texto"
    if len(password) < 8:
        return False
    if " " in password:
        return False
    # Reglas de complejidad: mayúsculas, minúsculas, números y símbolos
    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"[0-9]", password)
    has_symbol = re.search(r"[@$!%*?&]", password)
    return all([has_upper, has_lower, has_digit, has_symbol])

# --- Ruta principal ---
@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json()
    password = data.get("password", "")
    result = is_secure_password(password)
    return jsonify({"secure": result})

# --- Pruebas unitarias ---
@pytest.mark.parametrize("password,expected", [
    ("Admin123!", True),
    ("weakpass", False),
    ("PASSWORD", False),
    ("P@ss", False),
    ("Strong@123", True)
])
def test_is_secure_password(password, expected):
    assert is_secure_password(password) == expected

# --- Arranque del servidor ---
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
