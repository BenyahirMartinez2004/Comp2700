import html

comment = input("Escribe un comentario: ")

safe_comment = html.escape(comment)

print("Comentario seguro:", safe_comment)
