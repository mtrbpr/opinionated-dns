#!/bin/sh
# Refresh a persisted SenPaiScanner result. A failed run keeps the previous file.
set -eu
DATA="${DATA_DIR:-/data}"
BIN="$DATA/senpaiscanner"
OUT="$DATA/cloudflare-ips.txt"
mkdir -p "$DATA"

if [ ! -x "$BIN" ]; then
  url=$(curl -fsSL https://api.github.com/repos/MatinSenPai/SenPaiScanner/releases/latest \
    | jq -r '.assets[].browser_download_url' \
    | grep -E 'cli-linux-amd64$|linux-amd64$' \
    | head -n 1)
  if [ -z "$url" ]; then
    echo "senpai: no linux amd64 asset found" >&2
    exit 1
  fi
  tmp=$(mktemp)
  curl -fsSL "$url" -o "$tmp"
  case "$url" in
    *.tar.gz|*.tgz)
      tar -xzf "$tmp" -C "$DATA"
      found=$(find "$DATA" -type f -name 'senpaiscanner*' -perm -111 | head -n 1)
      if [ -n "$found" ]; then
        mv "$found" "$BIN"
      fi
      ;;
    *)
      mv "$tmp" "$BIN"
      ;;
  esac
  chmod +x "$BIN"
  rm -f "$tmp"
fi

while true; do
  need=0
  if [ ! -s "$OUT" ]; then
    need=1
  elif [ -n "$(find "$OUT" -mmin +1440 -print -quit)" ]; then
    need=1
  fi
  if [ "$need" -eq 1 ]; then
    tmp=$(mktemp)
    if "$BIN" scan -count 200 -gentle -output "$tmp" && [ -s "$tmp" ]; then
      mv "$tmp" "$OUT"
    else
      rm -f "$tmp"
      echo "senpai: scan failed, keeping the previous list" >&2
    fi
  fi
  sleep 3600
done
