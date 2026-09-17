#!/usr/bin/env python3
"""Confirma a mitigacao e preserva o login normal na versao corrigida."""
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
    parser.add_argument("--target", default="http://localhost:8081")
    args = parser.parse_args()
    base = args.target.rstrip("/")
    ok = True

    response = requests.post(
        f"{base}/login",
        json={"username": "wiener", "password": "peter"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("login legitimo (wiener/peter) autentica", response.status_code == 302)

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": {"$ne": "invalid"}},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check(
        "$ne recusado (nao autentica, nao 'Account locked')",
        TRUE_MARKER not in response.text and response.status_code != 302,
    )

    response = requests.post(
        f"{base}/login",
        json={"username": "carlos", "password": {"$ne": "invalid"}, "$where": "1"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("$where recusado pela allowlist", FALSE_MARKER in response.text)

    response = requests.post(
        f"{base}/login",
        json={"username": "wiener", "password": "errada"},
        allow_redirects=False,
        timeout=20,
    )
    ok &= check("senha errada -> mensagem generica", FALSE_MARKER in response.text)

    if ok:
        print("\n[+] Versao corrigida confirmada: bloqueia injecao, login normal ok.")
        return 0
    print("\n[-] Algum teste falhou (endpoint pode estar vulneravel ou fora do ar).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
