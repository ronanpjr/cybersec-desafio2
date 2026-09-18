#!/usr/bin/env bash
set -euo pipefail

# Verifica links relativos em arquivos Markdown. Links externos e âncoras são
# resolvidos pelo hospedeiro do repositório e não são consultados por este script.
repository_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_dir"

failed=0
while IFS= read -r document; do
  while IFS= read -r target; do
    target="${target%%#*}"
    case "$target" in
      "" | http://* | https://* | mailto:* ) continue ;;
    esac

    if [[ ! -e "$(dirname "$document")/$target" ]]; then
      printf 'Link relativo inexistente em %s: %s\n' "$document" "$target" >&2
      failed=1
    fi
  done < <(grep -oE '\]\([^)]+\)' "$document" | sed -E 's/^\]\((.*)\)$/\1/')
done < <(rg --files -g '*.md')

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Links relativos em Markdown: OK\n'
