from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
API = (ROOT / "supabase" / "functions" / "awards-api" / "index.ts").read_text(encoding="utf-8")

match = re.search(r"const categories = \[(.*?)\n    \];", HTML, re.S)
if not match:
    print("Não encontrei a lista de categorias em docs/index.html")
    sys.exit(1)
ui_ids = re.findall(r"\{id:'([^']+)'", match.group(1))
api_source = API.split("const categoryIds", 1)[0]
api_ids = re.findall(r'\{ id: "([^"]+)"', api_source)

if ui_ids != api_ids:
    print("ERRO: as categorias da página e do servidor estão diferentes.")
    print("Só na página:", [x for x in ui_ids if x not in api_ids])
    print("Só no servidor:", [x for x in api_ids if x not in ui_ids])
    sys.exit(1)

print(f"OK: {len(ui_ids)} categorias sincronizadas entre página e servidor.")
if "mais_entrosa" not in ui_ids:
    print("AVISO: a categoria mais_entrosa não está listada.")
    sys.exit(1)
print("OK: Mais Entrosa está presente na página e no servidor.")
