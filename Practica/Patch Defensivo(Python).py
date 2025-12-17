import re, html
def safe_comment(user_input: str) -> str:
 assert len(user_input) < 500, "Comentario muy largo"
 sane = html.escape(user_input) # evita XSS
 if re.search(r"(https?://|<script)", sane, re.I):
   raise ValueError("Contenido prohibido")
 return sane

try:
  entrada = '<script>alert("hackeado!")</script>'
  print("Entrada maliciosa:", entrada)
  salida = safe_comment(entrada)
  print("Salida:", salida)
except Exception as e:
  print("Bloqueado:", e)

print("-" * 50)

try:
  entrada = "¡Hola, excelente artículo! Gracias por compartir."
  print("Entrada segura:", entrada)
  salida = safe_comment(entrada)
  print("Salida segura:", salida)
except Exception as e:
  print("Bloqueado:", e)