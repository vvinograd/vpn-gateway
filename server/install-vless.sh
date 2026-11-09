#!/usr/bin/env bash
# ============================================================================
#  Свой сервер VLESS Reality за границей — для подключения к VPN-шлюзу
#  второй подпиской. Ставится рядом с другими VPN (SSTP, AmneziaWG и т.п.).
#
#  Запуск на зарубежном сервере:   sudo bash install-vless.sh
#  Повторный запуск покажет ссылку подключения. Другие команды:
#     sudo bash install-vless.sh show        ссылка и QR-код
#     sudo bash install-vless.sh rotate      новые ключи (старая ссылка перестанет работать)
#     sudo bash install-vless.sh update      обновить Xray (при неудаче вернётся прежняя версия)
#     sudo bash install-vless.sh status      состояние
#     sudo bash install-vless.sh os-upgrade  обновить Ubuntu/Debian в фоне (ход: os-job)
#     sudo bash install-vless.sh reboot      перезагрузить сервер через 5 секунд
#     sudo bash install-vless.sh postmortem  что было: перезагрузки, нехватка памяти, падения Xray, нагрузка
#     sudo bash install-vless.sh sni-scan    найти сайты для маскировки: соседи по сети и запасной список
#     sudo bash install-vless.sh uninstall   удалить VLESS с сервера
#  Настройки через переменные: PORT=8443 SNI=www.nvidia.com NAME=latvia sudo -E bash install-vless.sh
#
#  Скрипт также запускает бот шлюза (🛰 Свои серверы): строки, начинающиеся с «@@»,
#  предназначены для него.
# ============================================================================
set -o pipefail
CONF=/usr/local/etc/xray/config.json
INFO=/root/vless-server.txt
LOG=/var/log/vless-server-install.log
XRAY_INSTALLER=https://github.com/XTLS/Xray-install/raw/main/install-release.sh
# сайты для маскировки: поддерживают TLS 1.3 и HTTP/2 и проходят рукопожатие Reality
# (www.microsoft.com не подходит — Reality с ним не устанавливает соединение)
SNI_LIST="www.samsung.com www.nvidia.com www.amd.com dl.google.com addons.mozilla.org www.apple.com"
# запасной список: сайты средней известности (соседи по сети предпочтительнее — см. sni_scan)
SNI_MORE="www.ikea.com www.philips.com www.siemens.com www.bosch.com www.dw.com www.zalando.de www.bol.com
www.lidl.de www.otto.de www.ing.nl www.airbaltic.com www.delfi.lv www.lsm.lv www.rimi.lv www.err.ee www.delfi.lt
www.yle.fi www.finnair.com www.nrk.no www.dr.dk www.svt.se www.postnord.se www.orange.fr www.rtve.es
www.corriere.it www.heise.de www.tagesschau.de www.booking.com www.skyscanner.net www.ricardo.ch"
PORT_LIST="443 8443 2053 2083 2087 2096 9443"
SNI_REVERT=vpngw-sni-revert
PASS_CONF=/etc/ssh/sshd_config.d/00-vpngw.conf
MPTCP_CONF=/etc/sysctl.d/99-vpngw-mptcp.conf
JOB_DIR=/var/lib/vpngw-vless
JOB_UNIT=vpngw-osupgrade
JOB_LOG=/var/log/vpngw-os-upgrade.log
MODE=${1:-install}

if [ -t 1 ]; then C1=$'\033[1;36m'; C2=$'\033[1;31m'; C0=$'\033[0m'; else C1=; C2=; C0=; fi
say()  { printf '\n%s%s%s\n' "$C1" "$*" "$C0"; echo "@@STEP $*"; }
out()  { echo "@@$*"; }
die()  { printf '\n%sОшибка: %s%s\nЖурнал: %s\n' "$C2" "$*" "$C0" "$LOG"; out "ERROR $*"; exit 1; }
run()  { echo "+ $*" >>"$LOG"; "$@" >>"$LOG" 2>&1; }

[ "$(id -u)" -eq 0 ] || { echo "Запустите через sudo: sudo bash $0"; out "ERROR нужны права root"; exit 1; }
touch "$LOG"; chmod 600 "$LOG"
echo "===== $(date '+%F %T') $MODE" >>"$LOG"

xray_bin() { command -v xray 2>/dev/null || echo /usr/local/bin/xray; }

# В конфиге приватный ключ REALITY: читать его должны только root и служба xray (обычно User=nobody),
# а не все пользователи сервера. То же для копий конфига (.bak-*, .sni-*) — в них тот же ключ.
conf_perms() {
    local u g f
    if systemctl cat xray >/dev/null 2>&1; then u=$(systemctl show -p User --value xray 2>/dev/null); u=${u:-root}
    else u=nobody; fi                                   # служба ещё не поставлена: официальная — от nobody
    for f in "$CONF" "$CONF".*; do
        [ -f "$f" ] || continue
        if [ "$u" = root ] || ! g=$(id -gn "$u" 2>/dev/null); then chown root:root "$f"; chmod 600 "$f"
        else chown "root:$g" "$f"; chmod 640 "$f"; fi
    done
}
[ -f "$CONF" ] && conf_perms     # серверы, установленные до 2.6.1, — сразу при любом обращении бота
xver()     { "$(xray_bin)" version 2>/dev/null | awk 'NR==1{print $2}'; }
busy()     { ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }
conf_str() { grep -oP "\"$1\": *\\[?\"\\K[^\"]+" "$CONF" 2>/dev/null | head -1; }
conf_port(){ grep -oP '"port": *\K[0-9]+' "$CONF" 2>/dev/null | head -1; }
pub_of()   { "$(xray_bin)" x25519 -i "$1" 2>/dev/null | awk -F': *' 'tolower($1) ~ /public|password/ {print $2; exit}'; }

new_keys() {
    local x keys
    x=$(xray_bin)
    UUID=$("$x" uuid)
    keys=$("$x" x25519)
    PRIV=$(awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}' <<<"$keys")
    PUB=$(awk -F': *' 'tolower($1) ~ /public|password/ {print $2; exit}' <<<"$keys")
    SID=$(openssl rand -hex 8)
    [ -n "$UUID" ] && [ -n "$PRIV" ] && [ -n "$PUB" ] && [ -n "$SID" ] || die "не удалось сгенерировать ключи: $keys"
}

# текущие параметры из конфига (для rotate/update/status)
load_conf() {
    [ -f "$CONF" ] || die "VLESS не установлен (нет $CONF)"
    PORT=$(conf_port); SNI=$(conf_str serverNames); UUID=$(conf_str id)
    PRIV=$(conf_str privateKey); SID=$(conf_str shortIds); PUB=$(pub_of "$PRIV")
    DEST=$(grep -oP '"dest": *"\K[^"]+' "$CONF" 2>/dev/null | head -1); DEST=${DEST%:443}
    [ -n "$PORT" ] && [ -n "$SNI" ] && [ -n "$UUID" ] && [ -n "$PUB" ] || die "не смог прочитать настройки из $CONF"
}

write_conf() {   # порт маска [dest — по умолчанию сам домен маски]
    mkdir -p "$(dirname "$CONF")"
    cat >"$CONF" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": $1,
    "protocol": "vless",
    "settings": { "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "${3:-$2}:443",
        "serverNames": ["$2"],
        "minClientVer": "1.8.2",
        "privateKey": "$PRIV",
        "shortIds": ["$SID"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "rules": [ { "type": "field", "outboundTag": "block", "ip": ["10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128"] } ] }
}
EOF
    conf_perms
    run "$(xray_bin)" run -test -c "$CONF"
}

restart_xray() {   # порт
    run systemctl restart xray || return 1
    local _
    for _ in $(seq 1 20); do busy "$1" && return 0; sleep 0.5; done
    return 1
}

# подключаемся к себе же как клиент: проверяет ключи, маску и сам Xray
selftest() {   # порт маска
    local lp tp code=000 _ t=/tmp/vless-selftest.$$.json
    for lp in 10808 10818 10828 10838 10848; do busy "$lp" || break; done
    cat >"$t" <<EOF
{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":$lp,"protocol":"socks"}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":$1,
 "users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
 "serverName":"$2","fingerprint":"chrome","publicKey":"$PUB","shortId":"$SID"}}}]}
EOF
    "$(xray_bin)" run -c "$t" >/dev/null 2>&1 &
    tp=$!
    for _ in 1 2 3; do
        sleep 1.5
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 --socks5-hostname "127.0.0.1:$lp" https://www.gstatic.com/generate_204)
        [ "$code" = 204 ] && break
    done
    kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null; rm -f "$t"
    echo "selftest $1 $2 → $code" >>"$LOG"
    [ "$code" = 204 ]
}

fetch_installer() {
    local _
    for _ in 1 2 3; do
        curl -fsSL -m 60 -o /tmp/xray-install.sh "$XRAY_INSTALLER" >>"$LOG" 2>&1 && return 0
        sleep 3
    done
    return 1
}

pub_ip() {
    local ip=${ADDR:-}
    if [ -z "$ip" ] && [ -f "$INFO" ]; then ip=$(grep -oP '^LINK=.*@\K[^:]+' "$INFO" | tr -d "'\\\\"); fi
    [ -n "$ip" ] || ip=$(curl -4 -s -m 10 https://ifconfig.me/ip || curl -4 -s -m 10 https://api.ipify.org)
    [ -n "$ip" ] || ip=$(hostname -I | awk '{print $1}')
    echo "$ip"
}

save_info() {
    local ip name
    ip=$(pub_ip)
    name=${NAME:-}
    if [ -z "$name" ] && [ -f "$INFO" ]; then name=$(grep -oP '^LINK=.*#\K.*' "$INFO" | tr -d "'\\\\"); fi
    name=$(printf '%s' "${name:-$(hostname)}" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-40)
    LINK="vless://$UUID@$ip:$PORT?type=tcp&security=reality&pbk=$PUB&fp=chrome&sni=$SNI&sid=$SID&flow=xtls-rprx-vision#$name"
    (umask 077; printf 'LINK=%q\nPORT=%q\nSNI=%q\n' "$LINK" "$PORT" "$SNI" >"$INFO")
}

show_link() {
    # shellcheck disable=SC1090
    . "$INFO" 2>/dev/null || die "нет файла $INFO — VLESS установлен не этим скриптом"
    out "LINK $LINK"
    out "PORT $PORT"
    out "SNI $SNI"
    [ -t 1 ] || return 0
    say "Ссылка подключения (вставьте её в боте шлюза: 📦 Подписки → ➕ Добавить подписку):"
    echo; echo "$LINK"; echo
    command -v qrencode >/dev/null && qrencode -t ansiutf8 -m 2 "$LINK"
    echo "Ссылка сохранена в $INFO (доступна только root)."
}

open_firewall() {
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then run ufw allow "$1/tcp"; fi
}

# MPTCP не нужен, а через него атакуют ядро (CVE-2026-98432: Go 1.24+ открывает порты с MPTCP);
# обновления безопасности ставятся сами (перезагрузку делает бот шлюза ночью)
# История нагрузки: раз в 30 с — процессор, память, нагрузка (последние 2 часа, переживает перезагрузку).
# Нужна боту шлюза, чтобы после сбоя сказать, что было с сервером перед ним (см. postmortem).
HIST_BIN=/usr/local/sbin/vpngw-hist
hist_setup() {
    mkdir -p "$JOB_DIR"
    cat >"$HIST_BIN" <<'EOS'
#!/bin/bash
D=/var/lib/vpngw-vless; F=$D/hist; mkdir -p "$D"
read -r _ u n s i w x y z _ </proc/stat
tot=$((u+n+s+i+w+x+y+z)); idl=$((i+w)); cpu=-
if read -r pt pi 2>/dev/null <"$D/cpu.prev" && [ "$tot" -gt "$pt" ]; then cpu=$((100 - 100*(idl-pi)/(tot-pt))); fi
echo "$tot $idl" >"$D/cpu.prev"
mem=$(awk '/^MemTotal/{t=$2}/^MemAvailable/{a=$2}END{if(t) printf "%d", 100-100*a/t}' /proc/meminfo)
echo "$(date +%s),$cpu,${mem:-0},$(cut -d' ' -f1 /proc/loadavg)" >>"$F"
if [ "$(wc -l <"$F")" -gt 300 ]; then tail -n 240 "$F" >"$F.tmp" && mv -f "$F.tmp" "$F"; fi
EOS
    chmod 755 "$HIST_BIN"
    printf '[Unit]\nDescription=vpn-gateway: история нагрузки\n[Service]\nType=oneshot\nExecStart=%s\n' "$HIST_BIN" \
        >/etc/systemd/system/vpngw-hist.service
    printf '[Unit]\nDescription=vpn-gateway: история нагрузки раз в 30 с\n[Timer]\nOnBootSec=20\nOnUnitActiveSec=30\nAccuracySec=1\n[Install]\nWantedBy=timers.target\n' \
        >/etc/systemd/system/vpngw-hist.timer
    run systemctl daemon-reload
    run systemctl enable --now vpngw-hist.timer
}

# Что было с сервером: перезагрузка (штатная или нет), нехватка памяти, падения Xray, нагрузка перед сбоем.
# SINCE — с какого момента смотреть (время Unix).
do_postmortem() {
    local since=${SINCE:-$(( $(date +%s) - 3600 ))} boot clean=unknown oom xerr hist
    boot=$(( $(date +%s) - $(cut -d. -f1 /proc/uptime) ))
    out "BOOT $boot"
    if [ "$boot" -gt "$since" ] && [ "$(journalctl --list-boots -q 2>/dev/null | wc -l)" -ge 2 ]; then
        if journalctl -b -1 -q -o cat 2>/dev/null | tail -n 400 \
            | grep -Eq 'systemd-shutdown|Journal stopped|Reached target .*(Power-Off|Reboot|Shutdown|Final Step)'; then
            clean=yes; else clean=no; fi
    fi
    out "CLEAN $clean"
    oom=$( { journalctl -k -b 0 --since "@$since" -o cat 2>/dev/null
             [ "$boot" -gt "$since" ] && journalctl -k -b -1 --since "@$since" -o cat 2>/dev/null; } \
           | grep -oP 'Killed process \d+ \(\K[^)]+' | sort | uniq -c | awk '{printf "%s%s×%s", (NR>1?", ":""), $2, $1}')
    [ -n "$oom" ] && out "OOM $oom"
    out "XRESTARTS $(systemctl show xray -p NRestarts --value 2>/dev/null || echo 0)"
    xerr=$(journalctl -u xray --since "@$since" -p err -o cat 2>/dev/null | tail -1 | cut -c1-160)
    [ -n "$xerr" ] && out "XERR $xerr"
    if [ -f "$JOB_DIR/hist" ]; then
        hist=$(awk -F, -v a="$since" -v b="$((since + 1200))" '$1>=a && $1<=b' "$JOB_DIR/hist" | tail -n 40 | paste -sd';')
        [ -n "$hist" ] && out "HIST $hist"
    fi
    out "OK"
}

harden() {
    compat_conf
    [ -f /etc/systemd/system/vpngw-hist.timer ] || hist_setup
    if [ -e /proc/sys/net/mptcp/enabled ]; then
        printf '# vpn-gateway: MPTCP выключен (CVE-2026-98432)\nnet.mptcp.enabled = 0\n' >"$MPTCP_CONF"
        run sysctl -q -w net.mptcp.enabled=0
        # порт, открытый до выключения, остаётся MPTCP — перезапускаем Xray
        if ss -HMltnp 2>/dev/null | grep -q '"xray"'; then run systemctl restart xray; fi
    fi
    command -v apt-get >/dev/null || return 0
    export DEBIAN_FRONTEND=noninteractive
    dpkg -s unattended-upgrades >/dev/null 2>&1 \
        || run apt-get -o DPkg::Lock::Timeout=120 install -y -qq unattended-upgrades || return 0
    if ! apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
            >/etc/apt/apt.conf.d/20auto-upgrades
    fi
    return 0
}

# защита и совместимость на месте: MPTCP выключен, в конфиге есть minClientVer (автообновления — строка UU)
hard_ok() {
    [ -f /etc/systemd/system/vpngw-hist.timer ] || return 1
    { [ ! -e /proc/sys/net/mptcp/enabled ] || [ "$(cat /proc/sys/net/mptcp/enabled)" = 0 ]; } || return 1
    [ ! -f "$CONF" ] || [ ! -f "$INFO" ] || grep -q '"minClientVer"' "$CONF"
}

# Xray с версии 26.7.11 по умолчанию пускает только клиентов от 26.3.27, а mihomo (клиент шлюза) называет
# себя версией 1.8.2 — без minClientVer проверка REALITY у него не проходит («REALITY authentication failed»)
compat_conf() {
    [ -f "$CONF" ] && [ -f "$INFO" ] || return 0
    grep -q '"minClientVer"' "$CONF" && return 0
    cp -a "$CONF" "$CONF.bak-compat"
    if ( load_conf; write_conf "$PORT" "$SNI" "$DEST" && restart_xray "$PORT" ); then
        echo "minClientVer добавлен в конфиг" >>"$LOG"
    else
        cp -a "$CONF.bak-compat" "$CONF"; systemctl restart xray >/dev/null 2>&1
    fi
}

# вернуть сохранённый бинарник Xray. Не через cp поверх: запущенный файл так не перезаписать
# («Text file busy»), поэтому копия рядом и атомарная замена
put_prev() {   # путь к xray
    cp -a "$1.prev" "$1.new" && mv -f "$1.new" "$1"
}

# обновления системы и перезагрузка: строки @@ для бота
os_info() {
    local newk sim
    out "KERNEL $(uname -r)"
    newk=$(find /boot -maxdepth 1 -name 'vmlinuz-*' 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -1)
    out "KNEW ${newk:-?}"
    if [ -f /var/run/reboot-required ]; then
        out "REBOOT yes $(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    else
        out "REBOOT no"
    fi
    out "MPTCP $(cat /proc/sys/net/mptcp/enabled 2>/dev/null || echo -)"
    if hard_ok; then out "HARD yes"; else out "HARD no"; fi
    command -v apt-get >/dev/null || return 0
    [ -n "${APTUPDATE:-}" ] && run apt-get -o DPkg::Lock::Timeout=120 update -qq
    sim=$(apt-get -s -o Debug::NoLocking=1 upgrade --with-new-pkgs 2>/dev/null | grep '^Inst ')
    out "OSUPD $(grep -c . <<<"$sim") $(grep -ci -- '-security' <<<"$sim")"
    if apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then out "UU yes"; else out "UU no"; fi
}

do_os_upgrade() {
    command -v apt-get >/dev/null || die "обновление системы поддерживается только в Ubuntu и Debian"
    if systemctl is-active --quiet "$JOB_UNIT"; then out "JOB running"; out "OK"; return; fi
    mkdir -p "$JOB_DIR"
    if [ -f "$JOB_DIR/rc" ]; then mv -f "$JOB_DIR/rc" "$JOB_DIR/rc.old"; fi
    cat >"$JOB_DIR/upgrade.sh" <<EOF
#!/bin/sh
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
O='-o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'
{ echo "===== \$(date '+%F %T') обновление системы"
  apt-get \$O update -q && apt-get \$O -y -q upgrade --with-new-pkgs && apt-get \$O -y -q autoremove --purge
} >>$JOB_LOG 2>&1
echo \$? >$JOB_DIR/rc
EOF
    systemctl reset-failed "$JOB_UNIT" >/dev/null 2>&1
    run systemd-run --quiet --collect --unit "$JOB_UNIT" /bin/sh "$JOB_DIR/upgrade.sh" \
        || die "не удалось запустить обновление системы"
    harden
    out "JOB started"
    out "OK"
}

do_os_job() {
    if systemctl is-active --quiet "$JOB_UNIT"; then out "JOB running"
    elif [ -s "$JOB_DIR/rc" ]; then out "JOB done $(cat "$JOB_DIR/rc")"
    else out "JOB none"; fi
    out "TAIL $(grep -Ev '^(Get|Hit|Ign|Reading|Building|Preparing|Unpacking|Selecting|\(Reading)' "$JOB_LOG" 2>/dev/null \
        | tail -n 3 | tr '\n' ' ' | cut -c1-300)"
    os_info
    out "OK"
}

do_reboot() {
    if pgrep -x 'dpkg|apt-get|apt|unattended-upgr' >/dev/null 2>&1; then
        die "сейчас устанавливаются пакеты — перезагрузка их сломает, попробуйте через несколько минут"
    fi
    run systemd-run --quiet --collect --unit "vpngw-reboot-$(date +%s)" --on-active=5 /bin/systemctl reboot \
        || die "не удалось запланировать перезагрузку"
    out "OK"
}

# ---- подбор маскировки ----
# Сосед по сети: на 443 TLS 1.3 + HTTP/2 + X25519 и настоящий сертификат на домен. SNI такого домена рядом с IP
# сервера выглядит правдоподобно (тот же дата-центр), в отличие от «www.nvidia.com» на маленьком хостинге.
# Строка вывода: домен dest задержка_мс тот_же_адресный_блок(1/0) вид(n — сосед, l — из списка)
probe_ip() {
    local ip=$1 out dom r v code t same=0 dest
    out=$(timeout 4 openssl s_client -connect "$ip:443" -tls1_3 -alpn h2 -groups X25519 </dev/null 2>/dev/null) || return 0
    grep -q 'ALPN protocol: h2' <<<"$out" || return 0
    dom=$(openssl x509 -noout -subject -ext subjectAltName 2>/dev/null <<<"$out" \
        | grep -oE '(CN ?= ?|DNS:)[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | sed -E 's/^(CN ?= ?|DNS:)//' | grep -v '^\*' | head -1)
    [ -n "$dom" ] || return 0
    # с правильным SNI сертификат должен быть настоящим, а ответ — по HTTP/2
    r=$(curl -s -o /dev/null --max-time 6 --tlsv1.3 --http2 --resolve "$dom:443:$ip" \
        -w '%{http_version} %{http_code} %{time_appconnect}' "https://$dom/") || return 0
    read -r v code t <<<"$r"
    [ "$v" = 2 ] && [ "$code" != 000 ] || return 0
    if getent ahostsv4 "$dom" 2>/dev/null | awk '{print $1}' | grep -q "^$NET\."; then same=1; dest=$dom; else dest=$ip; fi
    echo "$dom $dest $(awk -v t="$t" 'BEGIN{printf "%d", t*1000}') $same n"
}

probe_name() {
    local dom=$1 r v code t
    r=$(curl -s -o /dev/null --max-time 6 --tlsv1.3 --http2 -w '%{http_version} %{http_code} %{time_appconnect}' \
        "https://$dom/") || return 0
    read -r v code t <<<"$r"
    [ "$v" = 2 ] && [ "$code" != 000 ] || return 0
    timeout 6 openssl s_client -connect "$dom:443" -servername "$dom" -tls1_3 -groups X25519 -alpn h2 </dev/null 2>/dev/null \
        | grep -q 'ALPN protocol: h2' || return 0
    echo "$dom $dom $(awk -v t="$t" 'BEGIN{printf "%d", t*1000}') 0 l"
}

sni_scan() {   # → строки кандидатов, лучшие первыми
    local ip
    ip=$(pub_ip)
    export -f probe_ip probe_name
    {
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            export NET="${ip%.*}"
            seq 1 254 | grep -vx "${ip##*.}" | sed "s/^/$NET./" | xargs -P 48 -I{} bash -c 'probe_ip {}' 2>/dev/null
        fi
        # shellcheck disable=SC2086
        printf '%s\n' $SNI_MORE $SNI_LIST | xargs -P 16 -I{} bash -c 'probe_name {}' 2>/dev/null
    } | awk '!seen[$1]++ { r = ($5 == "n") ? ($4 == 1 ? 0 : 1) : 2; print r, $0 }' | sort -k1,1n -k4,4n | cut -d' ' -f2-
}

do_sni_scan() {
    local c n=0 who
    say "Ищу сайты для маскировки: соседи по сети и запасной список (до минуты)…"
    while read -r c; do
        [ -n "$c" ] || continue
        out "CAND $c"; n=$((n + 1))
        [ "$n" -ge 15 ] && break
    done < <(sni_scan)
    who=$(ss -Hltnp 'sport = :443' 2>/dev/null | grep -oP 'users:\(\("\K[^"]+' | head -1)
    [ -n "$who" ] && out "P443 $who"
    [ -f "$CONF" ] && { load_conf; out "SNI $SNI"; out "PORT $PORT"; }
    local p free=""
    for p in $PORT_LIST; do [ "$p" = "${PORT:-}" ] || busy "$p" || free="$free $p"; done
    out "PORTS${free}"
    out "OK"
}

# Проба маски: ключи прежние, меняются только маска и dest. Если бот не подтвердит за 10 минут,
# вернётся исходная маска (на случай, если проба оборвала связь).
sni_restore() {
    [ -f "$CONF.sni-orig" ] || return 0
    cp -a "$CONF.sni-orig" "$CONF"
    [ -f "$INFO.sni-orig" ] && cp -a "$INFO.sni-orig" "$INFO"
    systemctl restart xray >/dev/null 2>&1
    mv -f "$CONF.sni-orig" "$CONF.sni-old"; [ -f "$INFO.sni-orig" ] && mv -f "$INFO.sni-orig" "$INFO.sni-old"
    return 0
}

# DOMAIN — маска, DEST — адрес сайта (по умолчанию домен), NEWPORT — другой порт (по умолчанию прежний),
# NEWKEYS=1 — заодно новые UUID, ключи x25519 и shortId (если старые не принимаются или попали в фильтры)
do_sni_try() {
    [ -n "${DOMAIN:-}" ] || [ -n "${NEWKEYS:-}" ] || die "не задан DOMAIN"
    local want_dest=${DEST:-} want_port=${NEWPORT:-}   # load_conf перепишет DEST и PORT из конфига
    load_conf
    if [ -z "${DOMAIN:-}" ]; then DOMAIN=$SNI; want_dest=${want_dest:-${DEST:-$SNI}}; fi   # только ключи: маска та же
    want_dest=${want_dest:-$DOMAIN}
    want_port=${want_port:-$PORT}
    if [ -n "${NEWKEYS:-}" ]; then new_keys; fi
    if [ "$want_port" != "$PORT" ] && busy "$want_port" && ! [ -f "$CONF.sni-orig" ]; then
        die "порт $want_port занят другой программой"
    fi
    if ! systemctl is-active --quiet "$SNI_REVERT.timer"; then     # первая проба — запоминаем исходное
        cp -a "$CONF" "$CONF.sni-orig"; cp -a "$INFO" "$INFO.sni-orig"
    fi
    systemctl stop "$SNI_REVERT.timer" >/dev/null 2>&1
    [ "$want_port" != "$PORT" ] && open_firewall "$want_port"
    write_conf "$want_port" "$DOMAIN" "$want_dest" || { sni_restore; die "Xray отклонил конфиг с маской $DOMAIN"; }
    if ! { restart_xray "$want_port" && selftest "$want_port" "$DOMAIN"; }; then
        sni_restore; die "маска $DOMAIN на порту $want_port не прошла самопроверку на сервере"
    fi
    SNI=$DOMAIN; PORT=$want_port
    save_info
    systemctl reset-failed "$SNI_REVERT.timer" "$SNI_REVERT.service" >/dev/null 2>&1
    run systemd-run --quiet --collect --unit "$SNI_REVERT" --on-active=600 /bin/bash "$(readlink -f "$0")" sni-revert \
        || { sni_restore; die "не удалось включить страховочный откат"; }
    out "SNI $SNI"
    out "PORT $PORT"
    out "OK"
    show_link
}

do_sni_confirm() {
    systemctl stop "$SNI_REVERT.timer" >/dev/null 2>&1
    [ -f "$CONF.sni-orig" ] && mv -f "$CONF.sni-orig" "$CONF.sni-old"
    [ -f "$INFO.sni-orig" ] && mv -f "$INFO.sni-orig" "$INFO.sni-old"
    out "OK"
}

do_sni_revert() {
    systemctl stop "$SNI_REVERT.timer" >/dev/null 2>&1
    sni_restore
    [ -f "$CONF" ] && { load_conf; out "SNI $SNI"; }
    out "OK"
}

do_install() {
    if [ -f "$INFO" ] && [ -f "$CONF" ] && [ -z "${FORCE:-}" ]; then
        if systemctl is-active --quiet xray || { load_conf; restart_xray "$PORT"; }; then
            say "VLESS-сервер уже установлен и работает."
            out "EXISTING"
            out "VER $("$(xray_bin)" version 2>/dev/null | awk 'NR==1{print $2}')"
            show_link
            exit 0
        fi
    fi
    if [ -z "${FORCE:-}" ] && [ ! -f "$INFO" ]; then
        if systemctl is-active --quiet x-ui 2>/dev/null || systemctl is-active --quiet 3x-ui 2>/dev/null \
            || { [ -f "$CONF" ] && [ "$(tr -d ' \n\r\t' <"$CONF")" != "{}" ]; }; then
            out "FOREIGN"
            die "на сервере уже есть Xray с другими настройками (например, панель 3x-ui). Чтобы их не сломать, установка остановлена. Перезаписать: FORCE=1"
        fi
    fi

    say "1/5 Проверяю систему и пакеты…"
    command -v systemctl >/dev/null || die "нужна система с systemd (Ubuntu или Debian)"
    local need="" c
    for c in curl:curl openssl:openssl ss:iproute2 unzip:unzip; do
        command -v "${c%%:*}" >/dev/null || need="$need ${c#*:}"
    done
    export DEBIAN_FRONTEND=noninteractive
    if [ -n "$need" ]; then
        command -v apt-get >/dev/null || die "не хватает программ:$need — установите их вручную (поддерживаются Ubuntu и Debian)"
        run apt-get -o DPkg::Lock::Timeout=300 update -qq || die "apt-get update не удался"
        # shellcheck disable=SC2086
        run apt-get -o DPkg::Lock::Timeout=300 install -y -qq $need ca-certificates || die "не удалось установить:$need"
    fi
    command -v qrencode >/dev/null || run apt-get -o DPkg::Lock::Timeout=300 install -y -qq qrencode || true

    say "2/5 Устанавливаю Xray (официальный установщик XTLS)…"
    if [ ! -x "$(xray_bin)" ]; then
        fetch_installer || die "не удалось скачать установщик Xray с GitHub"
        run bash /tmp/xray-install.sh install || die "установка Xray не удалась"
    fi
    [ -x "$(xray_bin)" ] || die "xray не найден после установки"
    out "VER $("$(xray_bin)" version 2>/dev/null | awk 'NR==1{print $2}')"

    say "3/5 Выбираю порт…"
    local bak=""
    [ -f "$CONF" ] && { bak="$CONF.bak-$(date +%s)"; cp -a "$CONF" "$bak"; }
    systemctl stop xray >/dev/null 2>&1
    if [ -n "${PORT:-}" ]; then
        busy "$PORT" && die "порт $PORT занят другой программой"
    else
        PORT=""
        for c in $PORT_LIST; do busy "$c" || { PORT=$c; break; }; done
        [ -n "$PORT" ] || die "все порты ($PORT_LIST) заняты, задайте свой: PORT=12345"
        [ "$PORT" = 443 ] || echo "Порт 443 занят (например, SSTP) — использую $PORT."
    fi
    out "PORT $PORT"

    say "4/5 Генерирую ключи и подбираю маскировку…"
    new_keys
    local s good=""
    local list=${SNI:-}
    if [ -z "$list" ]; then
        echo "  ищу сайты-соседи по сети для маскировки…"
        list="$(sni_scan | awk '$4 == 1 && $5 == "n" {print $1}' | head -3 | tr '\n' ' ')$SNI_LIST"
    fi
    for s in $list; do
        if ! curl -s -m 8 -o /dev/null --tlsv1.3 "https://$s"; then
            echo "  $s — сайт недоступен по TLS 1.3, пропускаю"; out "SNI_SKIP $s"; continue
        fi
        write_conf "$PORT" "$s" || { echo "  $s — Xray отклонил конфиг"; continue; }
        if restart_xray "$PORT" && selftest "$PORT" "$s"; then good=$s; break; fi
        echo "  $s — не прошёл самопроверку"; out "SNI_FAIL $s"
    done
    if [ -z "$good" ]; then
        if [ -n "$bak" ]; then cp -a "$bak" "$CONF"; systemctl restart xray >/dev/null 2>&1; fi
        die "ни один сайт для маскировки не прошёл самопроверку ($list). Подробности в журнале"
    fi
    SNI=$good
    echo "Маскировка: $SNI, самопроверка пройдена."
    out "SNI $SNI"

    say "5/5 Запускаю…"
    open_firewall "$PORT"
    run systemctl enable xray
    harden
    save_info
    say "Готово! VLESS Reality работает на порту $PORT."
    out "OK"
    show_link
    echo
    echo "Если у хостинга есть внешний файрвол (панель провайдера), откройте в нём TCP-порт $PORT."
}

do_rotate() {
    load_conf
    say "Генерирую новые ключи…"
    cp -a "$CONF" "$CONF.bak-rotate"
    new_keys
    write_conf "$PORT" "$SNI" "$DEST" || { cp -a "$CONF.bak-rotate" "$CONF"; die "Xray отклонил конфиг"; }
    if ! { restart_xray "$PORT" && selftest "$PORT" "$SNI"; }; then
        cp -a "$CONF.bak-rotate" "$CONF"; systemctl restart xray >/dev/null 2>&1
        die "новые ключи не прошли самопроверку, оставлены старые"
    fi
    save_info
    rm -f "$CONF.bak-rotate"
    say "Ключи заменены. Старая ссылка больше не работает."
    out "OK"
    show_link
}

# XRAY_VERSION=v26.10.31 — поставить именно эту версию (бот передаёт проверенную стабильную)
do_update() {
    load_conf
    local old new x
    x=$(xray_bin)
    old=$(xver)
    if [ -n "${XRAY_VERSION:-}" ] && [ "v${old#v}" = "v${XRAY_VERSION#v}" ]; then
        out "VER $old"; out "OLDVER $old"; say "Уже стоит Xray $old"; out "OK"; return
    fi
    say "Обновляю Xray (сейчас $old)…"
    # копия до установки; прежней версией (.prev) она станет, только если версия действительно сменилась —
    # иначе повторное обновление затёрло бы сохранённую старую версию новой
    cp -a "$x" "$x.before" 2>/dev/null
    fetch_installer || die "не удалось скачать установщик Xray с GitHub"
    if [ -n "${XRAY_VERSION:-}" ]; then
        run bash /tmp/xray-install.sh install --version "$XRAY_VERSION" || die "не удалось установить Xray $XRAY_VERSION"
    else
        run bash /tmp/xray-install.sh install || die "обновление Xray не удалось"
    fi
    harden
    new=$(xver)
    if [ "$new" != "$old" ] && [ -f "$x.before" ]; then mv -f "$x.before" "$x.prev"; fi
    if ! { restart_xray "$PORT" && selftest "$PORT" "$SNI"; }; then
        if [ -f "$x.prev" ]; then
            put_prev "$x" || die "Xray $new не прошёл самопроверку, а вернуть прежнюю версию не удалось"
            restart_xray "$PORT"
            die "Xray $new не прошёл самопроверку — возвращена прежняя версия $(xver)"
        fi
        die "после обновления Xray самопроверка не прошла"
    fi
    out "VER $new"
    out "OLDVER $old"
    say "Xray: $old → $new"
    out "OK"
}

# вернуть версию Xray, которая стояла до последнего обновления
do_xray_rollback() {
    load_conf
    local x cur
    x=$(xray_bin)
    [ -f "$x.prev" ] || die "нет сохранённой прежней версии Xray"
    cur=$(xver)
    put_prev "$x" || die "не удалось заменить файл Xray"
    [ "$(xver)" != "$cur" ] || die "сохранённая версия совпадает с текущей ($cur) — возвращать нечего"
    restart_xray "$PORT" && selftest "$PORT" "$SNI" || die "прежняя версия Xray тоже не прошла самопроверку"
    out "VER $(xver)"
    out "OLDVER $cur"
    out "OK"
}

do_status() {
    local x
    x=$(xray_bin)
    out "XRAY $(systemctl is-active xray 2>/dev/null | head -1)"
    [ -x "$x" ] && out "VER $(xver)"
    if [ -f "$CONF" ] && [ -f "$INFO" ]; then
        load_conf
        out "PORT $PORT"; out "SNI $SNI"
        if [ -n "${SELFTEST:-}" ]; then selftest "$PORT" "$SNI" && out "SELFTEST ok" || out "SELFTEST fail"; fi
    elif [ -f "$CONF" ]; then out "FOREIGN"
    fi
    out "OS $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}")"
    out "UPTIME $(cut -d. -f1 /proc/uptime)"
    out "LOAD $(cut -d' ' -f1-3 /proc/loadavg) $(nproc)"
    out "MEM $(free -b | awk '/^Mem:/{print $2, $3}')"
    out "DISK $(df -PB1 / | awk 'NR==2{print $2, $4}')"
    out "PASSAUTH $(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
    os_info
    out "OK"
}

do_uninstall() {
    local port
    port=$(conf_port)
    say "Удаляю VLESS…"
    systemctl disable --now xray >/dev/null 2>&1
    if fetch_installer; then run bash /tmp/xray-install.sh remove --purge; fi
    systemctl disable --now vpngw-hist.timer >/dev/null 2>&1
    rm -rf /usr/local/etc/xray /usr/local/bin/xray /usr/local/share/xray /etc/systemd/system/xray*.service \
        /etc/systemd/system/xray*.service.d /etc/systemd/system/vpngw-hist.* "$HIST_BIN"
    systemctl daemon-reload >/dev/null 2>&1
    rm -f "$INFO"
    if [ -n "$port" ] && command -v ufw >/dev/null; then run ufw delete allow "$port/tcp"; fi
    say "VLESS удалён."
    out "OK"
}

# вход по паролю для SSH: off — выключить (с автоматическим откатом через 3 минуты,
# если бот не подтвердит, что вход по ключу работает), confirm — подтвердить, on — включить обратно
do_passauth() {
    local reload='systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true'
    case "${2:-}" in
        off)
            grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
                || die "в /etc/ssh/sshd_config нет строки Include sshd_config.d — настройте вручную"
            printf '# vpn-gateway: вход только по ключу\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' >"$PASS_CONF"
            sshd -t >>"$LOG" 2>&1 || { rm -f "$PASS_CONF"; die "sshd отклонил настройку"; }
            systemctl stop vpngw-passauth-revert.timer >/dev/null 2>&1
            systemd-run --quiet --unit vpngw-passauth-revert --on-active=180 /bin/sh -c "rm -f $PASS_CONF; $reload" \
                >>"$LOG" 2>&1 || die "не удалось включить страховочный откат"
            sh -c "$reload"
            if [ "$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')" != no ]; then
                rm -f "$PASS_CONF"; sh -c "$reload"
                systemctl stop vpngw-passauth-revert.timer >/dev/null 2>&1
                die "настройка не подействовала: в конфигурации SSH вход по паролю включён раньше (настройте вручную)"
            fi
            ;;
        confirm)
            systemctl stop vpngw-passauth-revert.timer >/dev/null 2>&1
            ;;
        on)
            systemctl stop vpngw-passauth-revert.timer >/dev/null 2>&1
            rm -f "$PASS_CONF"
            sh -c "$reload"
            ;;
        *) die "использование: passauth off|confirm|on" ;;
    esac
    out "PASSAUTH $(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
    out "OK"
}

case "$MODE" in
    install) do_install ;;
    show)    show_link; out "OK" ;;
    rotate)  do_rotate ;;
    update)  do_update ;;
    status)  do_status ;;
    uninstall) do_uninstall ;;
    passauth) do_passauth "$@" ;;
    harden)  harden; if hard_ok; then out "HARD yes"; else out "HARD no"; fi; out "OK" ;;
    xray-rollback) do_xray_rollback ;;
    os-upgrade) do_os_upgrade ;;
    os-job)  do_os_job ;;
    reboot)  do_reboot ;;
    postmortem) do_postmortem ;;
    sni-scan) do_sni_scan ;;
    sni-try) do_sni_try ;;
    sni-confirm) do_sni_confirm ;;
    sni-revert) do_sni_revert ;;
    *) echo "Команды: install | show | rotate | update | status | uninstall | os-upgrade | os-job | reboot"; exit 1 ;;
esac
