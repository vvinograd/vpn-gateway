#!/usr/bin/env bash
# Собирает install.sh: встраивает vpnbot.py, vpngw.py и server/install-vless.sh, проставляет версию и контрольную сумму.
# Порядок выпуска: поменяй номер в VERSION.in, допиши CHANGELOG.md, запусти ./build.sh, загрузи всё на GitHub.
set -euo pipefail
cd "$(dirname "$0")"
V=$(head -1 VERSION.in | tr -d '[:space:]')
[[ "$V" =~ ^[0-9]+(\.[0-9]+)+$ ]] || { echo "Неверная версия в VERSION.in: $V"; exit 1; }
sed -i -E "s/^BOT_VERSION = '[^']*'/BOT_VERSION = '$V'/" vpnbot.py
python3 -m py_compile vpnbot.py src/vpngw.py
bash -n server/install-vless.sh
b64() { gzip -9c "$1" | base64 -w0; }
{
  sed -n '1,/^#@PAYLOADS@$/p' src/install.sh | sed '$d' | sed "s/^GW_VERSION=\"__VERSION__\"/GW_VERSION=\"$V\"/"
  echo "P_VPNBOT='$(b64 vpnbot.py)'"
  echo "P_VPNGW='$(b64 src/vpngw.py)'"
  echo "P_VLESS='$(b64 server/install-vless.sh)'"
  sed -n '/^#@PAYLOADS@$/,$p' src/install.sh | sed '1d'
} > install.sh
chmod +x install.sh
bash -n install.sh
grep -q "^GW_VERSION=\"$V\"" install.sh || { echo "Версия не подставилась"; exit 1; }
echo "$V $(sha256sum install.sh | cut -d' ' -f1)" > VERSION
echo "Собрано: install.sh v$V ($(du -h install.sh | cut -f1)), VERSION обновлён"
