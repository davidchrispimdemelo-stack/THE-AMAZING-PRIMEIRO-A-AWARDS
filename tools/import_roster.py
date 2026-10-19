#!/usr/bin/env python3
"""Importa o roster privado para a Edge Function sem imprimir os RAs na tela."""
import json
import sys
from pathlib import Path
from getpass import getpass
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
ROSTER_PATH = ROOT / "private" / "roster.json"


def main() -> int:
    if not ROSTER_PATH.exists():
        print("Não encontrei private/roster.json. O arquivo privado precisa estar na pasta private/.")
        return 1
    try:
        roster = json.loads(ROSTER_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Não consegui ler a lista privada: {exc}")
        return 1
    if not isinstance(roster, list) or not roster:
        print("A lista privada está vazia ou inválida.")
        return 1

    print("Importação inicial do 1ºA Awards — os RAs não serão exibidos nem gravados no site público.")
    project_url = input("URL do projeto Supabase (https://....supabase.co): ").strip().rstrip("/")
    anon_key = getpass("Chave pública anon do Supabase: ").strip()
    setup_key = getpass("Valor de ROSTER_SETUP_KEY configurado no servidor: ").strip()
    if not project_url.startswith("https://") or not anon_key or not setup_key:
        print("URL, chave anon e chave de configuração são obrigatórias.")
        return 1

    endpoint = project_url + "/functions/v1/awards-api"
    payload = json.dumps({"action": "setup_roster", "setupKey": setup_key, "roster": roster}).encode("utf-8")
    request = Request(endpoint, data=payload, method="POST", headers={
        "Content-Type": "application/json",
        "apikey": anon_key,
        "Authorization": "Bearer " + anon_key,
    })
    try:
        with urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
            print(f"Importação concluída. Participantes importados: {body.get('imported', '?')}.")
            print("Os RAs foram transformados em HMAC no servidor e não são armazenados em texto puro.")
            return 0
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            message = body.get("error", "Erro HTTP sem detalhes.")
        except Exception:
            message = "Erro HTTP sem detalhes."
        print(f"A importação falhou ({exc.code}): {message}")
        print("Se o servidor disser que a lista já foi importada, não tente repetir nem apagar os dados sem backup.")
        return 1
    except URLError as exc:
        print(f"Não consegui conectar ao Supabase: {exc.reason}")
        return 1
    except Exception as exc:
        print(f"Falha na importação: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
