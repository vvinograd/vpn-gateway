#!/usr/bin/env bash
# ============================================================================
#  Свой сервер VLESS Reality за границей — для подключения к VPN-шлюзу
#  второй подпиской. Ставится рядом с другими VPN (SSTP, AmneziaWG и т.п.).
#
#  Запуск на зарубежном сервере:   sudo bash install-vless.sh
#  Повторный запуск покажет ссылку подключения. Другие команды:
#     sudo bash install-vless.sh show        ссылка и QR-код
#     sudo bash install-vless.sh rotate      новые ключи (старая ссылка перестанет работать)
#     sudo bash install-vless.sh update      обновить Xray
#     sudo bash install-vless.sh status      состояние
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
PORT_LIST="443 8443 2053 2083 2087 2096 9443"
PASS_CONF=/etc/ssh/sshd_config.d/00-vpngw.conf
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
    [ -n "$PORT" ] && [ -n "$SNI" ] && [ -n "$UUID" ] && [ -n "$PUB" ] || die "не смог прочитать настройки из $CONF"
}

write_conf() {   # порт маска
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
        "dest": "$2:443",
        "serverNames": ["$2"],
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
    chmod 644 "$CONF"
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

save_info() {
    local ip name
    ip=${ADDR:-}
    if [ -z "$ip" ] && [ -f "$INFO" ]; then ip=$(grep -oP '^LINK=.*@\K[^:]+' "$INFO" | tr -d "'\\\\"); fi
    [ -n "$ip" ] || ip=$(curl -4 -s -m 10 https://ifconfig.me/ip || curl -4 -s -m 10 https://api.ipify.org)
    [ -n "$ip" ] || ip=$(hostname -I | awk '{print $1}')
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
    for s in ${SNI:-$SNI_LIST}; do
        if ! curl -s -m 8 -o /dev/null --tlsv1.3 "https://$s"; then
            echo "  $s — сайт недоступен по TLS 1.3, пропускаю"; out "SNI_SKIP $s"; continue
        fi
        write_conf "$PORT" "$s" || { echo "  $s — Xray отклонил конфиг"; continue; }
        if restart_xray "$PORT" && selftest "$PORT" "$s"; then good=$s; break; fi
        echo "  $s — не прошёл самопроверку"; out "SNI_FAIL $s"
    done
    if [ -z "$good" ]; then
        if [ -n "$bak" ]; then cp -a "$bak" "$CONF"; systemctl restart xray >/dev/null 2>&1; fi
        die "ни один сайт для маскировки не прошёл самопроверку (${SNI:-$SNI_LIST}). Подробности в журнале"
    fi
    SNI=$good
    echo "Маскировка: $SNI, самопроверка пройдена."
    out "SNI $SNI"

    say "5/5 Запускаю…"
    open_firewall "$PORT"
    run systemctl enable xray
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
    write_conf "$PORT" "$SNI" || { cp -a "$CONF.bak-rotate" "$CONF"; die "Xray отклонил конфиг"; }
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

do_update() {
    load_conf
    local old new
    old=$("$(xray_bin)" version 2>/dev/null | awk 'NR==1{print $2}')
    say "Обновляю Xray (сейчас $old)…"
    fetch_installer || die "не удалось скачать установщик Xray с GitHub"
    run bash /tmp/xray-install.sh install || die "обновление Xray не удалось"
    new=$("$(xray_bin)" version 2>/dev/null | awk 'NR==1{print $2}')
    restart_xray "$PORT" && selftest "$PORT" "$SNI" || die "после обновления Xray самопроверка не прошла"
    out "VER $new"
    out "OLDVER $old"
    say "Xray: $old → $new"
    out "OK"
}

do_status() {
    local x
    x=$(xray_bin)
    out "XRAY $(systemctl is-active xray 2>/dev/null | head -1)"
    [ -x "$x" ] && out "VER $("$x" version 2>/dev/null | awk 'NR==1{print $2}')"
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
    out "OK"
}

do_uninstall() {
    local port
    port=$(conf_port)
    say "Удаляю VLESS…"
    systemctl disable --now xray >/dev/null 2>&1
    if fetch_installer; then run bash /tmp/xray-install.sh remove --purge; fi
    rm -rf /usr/local/etc/xray /usr/local/bin/xray /usr/local/share/xray /etc/systemd/system/xray*.service \
        /etc/systemd/system/xray*.service.d
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
    *) echo "Команды: install | show | rotate | update | status | uninstall"; exit 1 ;;
esac
