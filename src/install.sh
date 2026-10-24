#!/usr/bin/env bash
# ============================================================================
#  Установщик VPN-шлюза: VLESS (mihomo) → WireGuard → телефоны, ПК, MikroTik
#  + Telegram-бот управления.  Запуск:  sudo bash install.sh
# ============================================================================
GW_VERSION="__VERSION__"            # подставляет build.sh
REPO="vvinograd/vpn-gateway"     # откуда брать обновления
BRANCH="main"
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"
UPD_DIR=/var/lib/vpngw/update
UPD_RESULT=/var/lib/vpngw/update-result
MIHOMO_FALLBACK="v1.19.32"
LOG=/var/log/vpngw-install.log
CONF_DIR=/etc/vpngw
CONF=$CONF_DIR/install.conf
SUMMARY=/root/vpngw-summary.txt
BT="VPN-шлюз · установщик v$GW_VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- оформление
log()  { echo "[$(date '+%F %T')] $*" >>"$LOG"; }
run()  { log "+ $*"; "$@" >>"$LOG" 2>&1; }
W()    { whiptail --backtitle "$BT" "$@"; }
msg()  { W --title "$1" --scrolltext --msgbox "$2" "${3:-18}" 76; }
ask()  { W --title "$1" --yes-button "Да" --no-button "Нет" ${4:+--defaultno} --yesno "$2" "${3:-14}" 76; }
info() { log "== $1"; W --title "Подождите" --infobox "\n  $1" 8 76; }
inp()  { W --title "$1" --ok-button "Далее" --cancel-button "Отмена" --inputbox "$2" "${4:-14}" 76 "$3" 3>&1 1>&2 2>&3; }
pwd_() { W --title "$1" --ok-button "Далее" --cancel-button "Отмена" --passwordbox "$2" 12 76 3>&1 1>&2 2>&3; }
menu() { local t=$1 x=$2 h=$3; shift 3
         W --title "$t" --ok-button "Выбрать" --cancel-button "Отмена" ${MENU_DEFAULT:+--default-item "$MENU_DEFAULT"} \
           --menu "$x" "$h" 76 $(( h - 8 )) "$@" 3>&1 1>&2 2>&3; }
onoff() { [ "$1" = "$2" ] && echo ON || echo OFF; }
radio() { local t=$1 x=$2 h=$3; shift 3
         W --title "$t" --ok-button "Выбрать" --cancel-button "Отмена" --radiolist "$x" "$h" 76 $(( h - 9 )) "$@" 3>&1 1>&2 2>&3; }

MAINPID=$$
trap 'clear; echo "Установка прервана. Журнал: $LOG"; exit 1' TERM
# работает и из подоболочки $(...): завершает весь установщик
cancel() { ask "Отмена" "Прервать установку?\n\nУже сделанные шаги останутся, установщик можно запустить снова." 10 \
           && { kill -TERM "$MAINPID"; exit 1; }; }
die() {
    log "ОШИБКА: $1"
    W --title "Ошибка" --msgbox "$1\n\nПоследние строки журнала ($LOG):\n\n$(tail -n 8 "$LOG" | cut -c1-70)" 24 76
    clear; echo "Установка остановлена: $1"; echo "Полный журнал: $LOG"
    trap - TERM; kill -TERM "$MAINPID" 2>/dev/null; exit 1
}
# повторяет вопрос, пока пользователь не ответит или не прервёт установку
need() { local v; while :; do v=$("$@") && { echo "$v"; return; }; cancel; done; }

save_conf() {   # KEY VALUE
    mkdir -p "$CONF_DIR"; touch "$CONF"; chmod 600 "$CONF"
    grep -v "^$1=" "$CONF" >"$TMP/c" 2>/dev/null; printf '%s=%q\n' "$1" "$2" >>"$TMP/c"; cat "$TMP/c" >"$CONF"
}
load_conf() { [ -f "$CONF" ] && . "$CONF"; true; }

# ---------------------------------------------------------------- встроенные файлы
#@PAYLOADS@
unpack() { echo "$1" | base64 -d | gunzip >"$2"; }

# ================================================================ гроздь винограда
# Небольшая заставка в терминале при установке (в Telegram не показывается).
grapes() {
    local P1='' P2='' P3='' G='' B='' T='' D='' R=''
    if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
        P1=$'\033[38;5;91m'; P2=$'\033[38;5;129m'; P3=$'\033[38;5;135m'
        G=$'\033[38;5;70m'; B=$'\033[38;5;94m'; T=$'\033[1;38;5;141m'; D=$'\033[38;5;245m'; R=$'\033[0m'
    fi
    local row cols=("$P1" "$P2" "$P3" "$P2")
    local -a rows=(5 6 5 4 3 2 1)
    local -a right=("" "${T}VPN-шлюз${R} ${D}v$GW_VERSION${R}" "${D}VLESS · WireGuard · Telegram${R}" ""
                    "${D}by${R} ${T}Виноградов${R}" "${D}github.com/$REPO${R}" "")
    echo
    printf '           %s┃%s%s❦%s\n' "$B" "$R" "$G" "$R"
    local i j line pad
    for i in "${!rows[@]}"; do
        row=${rows[$i]}
        pad=$(( 6 + (6 - row) ))
        line=$(printf '%*s' "$pad" '')
        for ((j = 0; j < row; j++)); do
            line+="${cols[$(( (i + j) % 4 ))]}●${R} "
        done
        printf '%s%*s   %s\n' "$line" $(( (6 - row) )) '' "${right[$i]}"
    done
    echo
}

# ================================================================ проверки
preflight() {
    [ "$(id -u)" -eq 0 ] || { echo "Запустите через sudo:  sudo bash $0"; exit 1; }
    [ -t 0 ] || { echo "Нужен интерактивный терминал. Скачайте файл и запустите: sudo bash install.sh"; exit 1; }
    touch "$LOG"; chmod 600 "$LOG"; log "===== запуск установщика v$GW_VERSION"
    # os-release читаем в подоболочке: иначе его переменные (VERSION, NAME…) затрут наши
    OS_VER=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-?}")
    OS_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
    OS_NAME=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-неизвестная система}")
    if ! command -v whiptail >/dev/null; then
        echo "Устанавливаю whiptail…"; apt-get -o DPkg::Lock::Timeout=900 update -qq >>"$LOG" 2>&1; apt-get -o DPkg::Lock::Timeout=900 install -y -qq whiptail >>"$LOG" 2>&1 \
            || { echo "Не удалось установить whiptail, см. $LOG"; exit 1; }
    fi
    if [ "$OS_ID" != "ubuntu" ] && [ "$OS_ID" != "debian" ]; then
        ask "Внимание" "Установщик рассчитан на Ubuntu 22.04/24.04, а здесь: $OS_NAME.\n\nПродолжить на свой риск?" 12 1 || exit 1
    fi
    case "$(uname -m)" in
        x86_64)  ARCH_ASSET="amd64-v1" ;;
        aarch64) ARCH_ASSET="arm64" ;;
        *) die "Неподдерживаемая архитектура: $(uname -m)" ;;
    esac
}

# ================================================================ главное меню
main_menu() {
    load_conf
    local c
    c=$(menu "VPN-шлюз уже установлен" "Что сделать?" 21 \
        1 "Добавить клиента WireGuard (телефон / ПК)" \
        2 "Показать QR-код и файл клиента" \
        3 "Список клиентов" \
        4 "Проверить состояние" \
        5 "Проверить обновления (GitHub)" \
        6 "Обновить mihomo" \
        7 "Переустановить / изменить настройки" \
        r "Восстановить из резервной копии" \
        8 "Удалить VPN-шлюз" \
        9 "Выход") || exit 0
    case $c in
        1) add_clients_loop; show_new_clients ;;
        2) pick_and_show_qr ;;
        3) clear; vpngw peers; read -rp $'\nEnter — назад ' _ ;;
        4) clear; vpngw status; echo; vpngw peers; read -rp $'\nEnter — назад ' _ ;;
        5) check_updates_interactive ;;
        6) install_mihomo && run systemctl restart mihomo && msg "Готово" "mihomo обновлён: $(mihomo -v 2>/dev/null | head -1)" 9 ;;
        7) full_install ;;
        r) restore_install; clear; grapes; cat "$SUMMARY" 2>/dev/null; exit 0 ;;
        8) uninstall ;;
        *) exit 0 ;;
    esac
    main_menu
}

# ================================================================ шаги установки
step_welcome() {
    msg "Добро пожаловать" "Этот мастер развернёт VPN-шлюз:\n
  1. mihomo — клиент VLESS с автопереключением серверов
  2. WireGuard — к шлюзу подключаются телефоны, компьютеры, MikroTik
  3. Telegram-бот — управление, клиенты с QR-кодом и файлом .conf
\nВам нужно будет только отвечать на вопросы.\n
Понадобятся:
  • ссылка на подписку VPN
  • токен Telegram-бота от @BotFather (если нужен бот)
\nЖурнал установки: $LOG" 22
}

step_packages() {
    wait_apt
    info "Устанавливаю пакеты (curl, wireguard, qrencode, python3)…"
    export DEBIAN_FRONTEND=noninteractive
    run apt-get -o DPkg::Lock::Timeout=900 update -qq || die "apt-get update не удался — проверьте интернет."
    run apt-get -o DPkg::Lock::Timeout=900 install -y -qq curl ca-certificates wireguard wireguard-tools qrencode jq python3 openssl iproute2 openssh-client iputils-ping \
        || die "Не удалось установить пакеты."
    mkdir -p /usr/local/lib/vpngw
    install_tools
    install_bot_files
}

# утилита vpngw и копия установщика (команда vpngw-setup открывает это меню)
install_tools() {
    mkdir -p /usr/local/lib/vpngw "$CONF_DIR"
    unpack "$P_VPNGW" /usr/local/lib/vpngw/vpngw.py
    chmod 755 /usr/local/lib/vpngw/vpngw.py
    # скрипт для своих серверов VLESS: бот загружает его на сервер по SSH
    unpack "$P_VLESS" /usr/local/lib/vpngw/install-vless.sh && chmod 644 /usr/local/lib/vpngw/install-vless.sh
    command -v ssh >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 install -y -qq openssh-client >>"$LOG" 2>&1 || true
    ln -sf /usr/local/lib/vpngw/vpngw.py /usr/local/bin/vpngw
    if [ -f "$0" ] && head -c 200 "$0" | grep -q 'Установщик VPN-шлюза'; then
        [ "$(readlink -f "$0")" = /usr/local/lib/vpngw/install.sh ] || install -m 700 "$0" /usr/local/lib/vpngw/install.sh
        printf '#!/bin/sh\nexec bash /usr/local/lib/vpngw/install.sh "$@"\n' >/usr/local/bin/vpngw-setup
        chmod 755 /usr/local/bin/vpngw-setup
    fi
}

step_network() {
    IFACE=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    GW=$(ip route show default | awk '{print $3; exit}')
    LAN_IP=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$LAN_IP" ] || die "Не удалось определить IP-адрес сервера."
    local dhcp="статический"
    ip -4 addr show dev "$IFACE" | grep -q dynamic && dhcp="получен по DHCP"
    log "сеть: $IFACE $LAN_IP gw $GW ($dhcp)"
    msg "Сеть сервера" "Интерфейс:        $IFACE\nIP-адрес:         $LAN_IP ($dhcp)\nШлюз по умолчанию: $GW\n
$( [ "$dhcp" != "статический" ] && echo "Важно: закрепите адрес $LAN_IP за этим сервером в настройках DHCP
вашего роутера (статическая аренда). Иначе после перезагрузки адрес
может смениться, и клиенты потеряют подключение.
На MikroTik:  /ip dhcp-server lease make-static [find address=$LAN_IP]")" 18
    save_conf LAN_IP "$LAN_IP"; save_conf IFACE "$IFACE"; save_conf GW "$GW"
}

# HWID для подписки: после переезда можно оставить старый (файл $CONF_DIR/hwid), чтобы не занимать новое место
read_hwid() {
    HWID=$(cat /etc/machine-id); MODEL="Ubuntu-Gateway-$(hostname)"
    if [ -f "$CONF_DIR/hwid" ]; then
        local h m; h=$(grep -oP '^HWID=\K.*' "$CONF_DIR/hwid"); m=$(grep -oP '^MODEL=\K.*' "$CONF_DIR/hwid")
        [ -n "$h" ] && HWID=$h; [ -n "$m" ] && MODEL=$m
    fi
}

fetch_sub() {   # $1 = User-Agent → код ответа HTTP
    curl -sS -m 30 -A "$1" -H "x-hwid: $HWID" -H "x-device-os: Linux" -H "x-ver-os: $OS_VER" \
         -H "x-device-model: $MODEL" -o "$TMP/sub.raw" -w '%{http_code}' "$SUB_URL" 2>>"$LOG"
}

# что уже настроено на этом сервере (переустановка или сервер, настроенный вручную)
detect_current() {
    CUR_SUBS="[]"; CUR_VPN="{}"; MAIN_ID=sub
    [ -f /etc/mihomo/config.yaml ] || return 0
    CUR_SUBS=$(python3 /usr/local/bin/vpnbot.py --subs 2>>"$LOG") || CUR_SUBS="[]"
    CUR_VPN=$(python3 /usr/local/bin/vpnbot.py --vpn 2>>"$LOG") || CUR_VPN="{}"
    MAIN_ID=$(jq -r '.[0].id // "sub"' <<<"$CUR_SUBS")
    log "текущие подписки: $(jq -c '[.[]|{id,name,type}]' <<<"$CUR_SUBS")"
}

step_subscription() {
    load_conf
    read_hwid
    PROVIDER=http
    detect_current
    local cur_url cur_type cur_ua extra c res
    cur_url=$(jq -r '.[0].url // empty' <<<"$CUR_SUBS"); cur_type=$(jq -r '.[0].type // empty' <<<"$CUR_SUBS")
    cur_ua=$(jq -r '.[0].ua // empty' <<<"$CUR_SUBS")
    if [ -n "$cur_url" ] || { [ "$cur_type" = file ] && [ -s "/etc/mihomo/providers/$MAIN_ID.yaml" ]; }; then
        extra=$(jq -r '.[1:]|map(.name)|join(", ")' <<<"$CUR_SUBS")
        c=$(need menu "Подписка VPN" "На сервере уже есть подписка:\n  $( [ -n "$cur_url" ] && echo "${cur_url:0:28}…${cur_url: -3}" || echo "ссылки vless:// (вручную)")$( [ -n "$extra" ] && printf '\n\nДополнительные подписки (сохранятся): %s' "$extra")" 16 \
            keep "Использовать текущую" new "Ввести новую ссылку")
        if [ "$c" = keep ]; then
            res=$(python3 /usr/local/lib/vpngw/vpngw.py analyze "/etc/mihomo/providers/$MAIN_ID.yaml" 2>>"$LOG")
            if [ "$(head -1 <<<"$res")" = OK ]; then
                SERVERS=$(tail -n +2 <<<"$res"); SUB_URL=$cur_url; SUB_UA=${cur_ua:-FlClashX/0.8.80}; PROVIDER=${cur_type:-http}
                save_conf SUB_URL "$SUB_URL"; save_conf PROVIDER "$PROVIDER"
                return
            fi
            [ -n "$cur_url" ] && SUB_URL=$cur_url   # кэша нет — скачаем заново по текущей ссылке
        else
            SUB_URL=""
        fi
    fi
    while :; do
        SUB_URL=$(need inp "Подписка VPN" "Вставьте ссылку на подписку (https://…).\n\nСсылка — это ключ доступа к VPN, никому её не показывайте.\nВставка в терминале: правая кнопка мыши или Shift+Insert.\n\nЕсли подписки нет, оставьте поле пустым — можно будет вставить ссылки vless:// вручную." "${SUB_URL:-}" 17)
        if [ -z "$SUB_URL" ]; then manual_links && return; continue; fi
        local ua code result tries
        for ua in "FlClashX/0.8.80" "clash-verge/v2.2.3" "mihomo/1.19.12"; do
            for tries in 1 2 3; do
                info "Запрашиваю подписку (клиент $ua)…"
                code=$(fetch_sub "$ua"); log "подписка: UA=$ua HTTP $code"
                [ "$code" = "429" ] || break
                info "Сервер подписки просит подождать (слишком много запросов). Жду 40 секунд… ($tries/3)"; sleep 40
            done
            [ "$code" = "200" ] || continue
            result=$(python3 /usr/local/lib/vpngw/vpngw.py analyze "$TMP/sub.raw")
            [ "$(head -1 <<<"$result")" = "STUB_APP" ] && continue
            break
        done
        case "$(head -1 <<<"$result")" in
            OK) SUB_UA=$ua; SERVERS=$(tail -n +2 <<<"$result")
                save_conf SUB_URL "$SUB_URL"; save_conf SUB_UA "$SUB_UA"; save_conf PROVIDER http
                mkdir -p /etc/mihomo/providers; install -m 600 "$TMP/sub.raw" "/etc/mihomo/providers/$MAIN_ID.yaml"
                return ;;
            LIMIT) ask "Лимит устройств" "Подписка ответила: «Превышено количество устройств».\n\nЭтот сервер регистрируется как отдельное устройство. Удалите старое устройство в боте или личном кабинете провайдера, затем нажмите «Да», чтобы повторить.\n\n«Нет» — ввести ссылки vless:// вручную." 16 || { manual_links && return; } ;;
            STUB_APP) ask "Подписка не отдала серверы" "Провайдер отвечает «приложение не поддерживается» даже для Clash-клиентов.\n\nВвести ссылки vless:// вручную (их можно скопировать из Happ или v2rayNG)?" 13 && manual_links && return ;;
            *) ask "Подписка не ответила" "Не удалось получить серверы (HTTP ${code:-нет ответа}).\n\nПроверьте ссылку. Ввести ссылки vless:// вручную вместо подписки?" 12 1 && manual_links && return ;;
        esac
    done
}

manual_links() {
    local links
    links=$(inp "Ссылки vless://" "Вставьте одну или несколько ссылок vless:// через пробел.\n\nМинус ручного режима: серверы не будут обновляться сами — при смене серверов у провайдера запустите установщик снова." "" 14) || return 1
    printf '%s\n' "$links" >"$TMP/links.txt"
    mkdir -p /etc/mihomo/providers
    SERVERS=$(python3 /usr/local/lib/vpngw/vpngw.py links2yaml "$TMP/links.txt" "/etc/mihomo/providers/$MAIN_ID.yaml" 2>>"$LOG") \
        || { msg "Ошибка" "Не нашёл ни одной корректной ссылки vless://." 8; return 1; }
    PROVIDER="file"; SUB_URL=""; SUB_UA=""
    save_conf PROVIDER file; save_conf SUB_URL ""
}

step_servers() {
    local args=() i=0 n sel had
    jq -r '.excluded // [] | .[]' <<<"${CUR_VPN:-{\}}" >"$TMP/cur_excl.txt" 2>/dev/null
    had=$(jq -r 'has("excluded")' <<<"${CUR_VPN:-{\}}" 2>/dev/null)
    while IFS= read -r n; do
        [ -n "$n" ] || continue; i=$((i+1))
        if [ "$had" = true ]; then
            if grep -qxF -- "$n" "$TMP/cur_excl.txt"; then args+=("$i" "$n" OFF); else args+=("$i" "$n" ON); fi
        elif grep -qiE 'Россия|Russia|Мобильный|mobile' <<<"$n"; then args+=("$i" "$n" OFF); else args+=("$i" "$n" ON); fi
    done <<<"$SERVERS"
    [ $i -gt 0 ] || die "В подписке нет серверов."
    while :; do
        sel=$(W --title "Серверы ($i)" --ok-button "Далее" --cancel-button "Отмена" --separate-output --checklist \
            "Отметьте серверы для автовыбора (пробел — отметить).\nСерверы с выходом в России и «мобильные» каскады отключены по умолчанию.\nНовые серверы из подписки будут добавляться сами." \
            22 76 12 "${args[@]}" 3>&1 1>&2 2>&3) || { cancel; continue; }
        [ -n "$sel" ] && break
        msg "Серверы" "Нужно выбрать хотя бы один сервер." 8
    done
    EXCLUDED=()
    i=0
    while IFS= read -r n; do
        [ -n "$n" ] || continue; i=$((i+1))
        grep -qx "$i" <<<"$sel" || EXCLUDED+=("$n")
    done <<<"$SERVERS"
}

step_mode() {
    local cm cr
    cm=$(jq -r '.mode // "stable"' <<<"${CUR_VPN:-{\}}" 2>/dev/null); [[ "$cm" =~ ^(fast|stable|priority)$ ]] || cm=stable
    cr=$(jq -r '.routing // "smart"' <<<"${CUR_VPN:-{\}}" 2>/dev/null); [[ "$cr" =~ ^(smart|blocked|all)$ ]] || cr=smart
    MODE=$(need radio "Переключение серверов" "Как выбирать VPN-сервер?" 16 \
        stable "Стабильный — меняет сервер, только если он упал (рекомендуется)" "$(onoff "$cm" stable)" \
        fast "Быстрый — всегда самый быстрый, переключается часто" "$(onoff "$cm" fast)" \
        priority "По приоритету — по порядку списка, порядок меняется в боте" "$(onoff "$cm" priority)")
    case $MODE in fast) INTERVAL=120; TOL=50 ;; *) INTERVAL=300; TOL=300 ;; esac
    ROUTING=$(need radio "Маршрутизация" "Какой трафик отправлять через VPN?\n(Можно поменять позже в боте: Настройки → Маршрутизация.)" 17 \
        smart "Умная: заблокированное и зарубежное — VPN, российское — напрямую" "$(onoff "$cr" smart)" \
        blocked "Только заблокированное в РФ через VPN, остальное напрямую" "$(onoff "$cr" blocked)" \
        all "Весь трафик через VPN" "$(onoff "$cr" all)")
    save_conf MODE "$MODE"; save_conf ROUTING "$ROUTING"
}

# на свежей Ubuntu первые минуты работают автообновления и держат менеджер пакетов — ждём, а не падаем
# свободен ли менеджер пакетов: пробуем взять те же блокировки, что берут apt и dpkg (и сразу отпускаем)
apt_free() {
    python3 - <<'PY' 2>/dev/null
import fcntl, sys
for p in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/lib/apt/lists/lock'):
    try:
        f = open(p, 'a')
    except OSError:
        continue
    try:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit(1)
PY
}

wait_apt() {
    local i
    for i in $(seq 1 180); do
        apt_free && return 0
        info "Ubuntu ставит свои обновления, жду окончания (до 15 минут)… $((i * 5)) с"
        sleep 5
    done
}

install_mihomo() {
    wait_apt
    info "Скачиваю mihomo…"
    local url
    url=$(curl -s -m 20 https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
          | grep -oE "https://[^\"]+mihomo-linux-${ARCH_ASSET}-v[0-9.]+\.deb" | head -1)
    [ -n "$url" ] || url="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_FALLBACK}/mihomo-linux-${ARCH_ASSET}-${MIHOMO_FALLBACK}.deb"
    log "mihomo: $url"
    curl -fsSL -m 300 -o "$TMP/mihomo.deb" "$url" >>"$LOG" 2>&1 || { die "Не удалось скачать mihomo с GitHub."; return 1; }
    run apt-get -o DPkg::Lock::Timeout=900 install -y -qq -o Dpkg::Options::=--force-confold "$TMP/mihomo.deb" || { die "Не удалось установить mihomo."; return 1; }
    command -v mihomo >/dev/null || { die "mihomo не найден после установки."; return 1; }
    return 0
}

write_mihomo_config() {
    local secret; secret=$(grep -oP '^secret: \K.*' /etc/mihomo/config.yaml 2>/dev/null || openssl rand -hex 16)
    SECRET=$secret SUB_URL=$SUB_URL SUB_UA=${SUB_UA:-FlClashX/0.8.80} HWID=$HWID OS_VER=$OS_VER MODEL=$MODEL \
    PROVIDER=$PROVIDER ROUTING=$ROUTING MODE=$MODE INTERVAL=$INTERVAL TOL=$TOL EXCL=$TMP/excluded.txt \
    CUR_SUBS=${CUR_SUBS:-[]} MAIN_ID=${MAIN_ID:-sub} \
    python3 - "$TMP/params.json" <<'PY'
import json, os, sys
e = os.environ
cur = json.loads(e["CUR_SUBS"] or "[]")
main = {"id": e["MAIN_ID"], "name": cur[0]["name"] if cur else "Основная", "type": e["PROVIDER"],
        "url": e["SUB_URL"], "ua": e["SUB_UA"], "prefix": cur[0].get("prefix", "") if cur else ""}
subs = [main] + cur[1:]
json.dump({"secret": e["SECRET"], "url": e["SUB_URL"], "ua": e["SUB_UA"], "hwid": e["HWID"],
           "os_ver": e["OS_VER"], "model": e["MODEL"], "provider": e["PROVIDER"], "routing": e["ROUTING"],
           "mode": e["MODE"], "interval": int(e["INTERVAL"]), "tolerance": int(e["TOL"]),
           "excluded": [l for l in open(e["EXCL"], encoding="utf-8").read().split("\n") if l], "subs": subs},
          open(sys.argv[1], "w"), ensure_ascii=False)
PY
    python3 /usr/local/lib/vpngw/vpngw.py gen-base "$TMP/params.json" "$TMP/base.yaml" \
        && python3 /usr/local/bin/vpnbot.py --render "$TMP/base.yaml" "$TMP/params.json" "$TMP/config.yaml" \
        || die "Не удалось собрать конфигурацию mihomo."
}

geo_download() {   # базы runetfreedom: заблокированное в РФ, российские сайты и IP
    [ "$(cat /etc/mihomo/.geo-source 2>/dev/null)" = runetfreedom ] && [ -s /etc/mihomo/GeoSite.dat ] && return 0
    local g n
    for g in geoip geosite; do
        n=$([ $g = geoip ] && echo GeoIP.dat || echo GeoSite.dat)
        curl -fsSL -m 600 -o "/etc/mihomo/$n.tmp" \
            "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/$g.dat" >>"$LOG" 2>&1 \
            && [ "$(stat -c %s "/etc/mihomo/$n.tmp")" -gt 1000000 ] && mv "/etc/mihomo/$n.tmp" "/etc/mihomo/$n" \
            || { rm -f "/etc/mihomo/$n.tmp"; return 1; }
    done
    echo runetfreedom >/etc/mihomo/.geo-source
}

step_mihomo() {
    systemctl disable --now sing-box >>"$LOG" 2>&1
    install_mihomo
    printf '%s\n' "${EXCLUDED[@]}" >"$TMP/excluded.txt"
    write_mihomo_config
    local geo_ok=1
    if [ "$ROUTING" != all ]; then
        info "Скачиваю базы заблокированных и российских ресурсов (~90 МБ, до пары минут)…"
        geo_download || geo_ok=0
    fi
    info "Проверяю конфигурацию mihomo…"
    if [ $geo_ok = 0 ] || ! run mihomo -d /etc/mihomo -f "$TMP/config.yaml" -t; then
        if [ "$ROUTING" != "all" ]; then
            msg "Выборочная маршрутизация недоступна" "Не удалось скачать базы адресов (geoip/geosite) с GitHub.\n\nСейчас включу режим «весь трафик через VPN». Умную маршрутизацию можно включить позже в боте: Настройки → Маршрутизация (бот скачает базы через VPN)." 14
            ROUTING=all; save_conf ROUTING all; write_mihomo_config
            run mihomo -d /etc/mihomo -f "$TMP/config.yaml" -t || die "mihomo отклонил конфигурацию."
        else
            die "mihomo отклонил конфигурацию."
        fi
    fi
    [ -f /etc/mihomo/config.yaml ] && cp /etc/mihomo/config.yaml "/etc/mihomo/config.yaml.bak-$(date +%s)"
    install -m 600 "$TMP/config.yaml" /etc/mihomo/config.yaml
    cat >/etc/systemd/system/mihomo.service <<EOF
[Unit]
Description=mihomo proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$(command -v mihomo) -d /etc/mihomo
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p /etc/systemd/system/mihomo.service.d
    cat >/etc/systemd/system/mihomo.service.d/route.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c 'for i in $$(seq 1 30); do ip link show mihomo >/dev/null 2>&1 && break; sleep 0.5; done; ip route replace default dev mihomo table 100'
EOF
    printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=2\n' >/etc/sysctl.d/99-vpngw.conf
    run sysctl --system
    run systemctl daemon-reload
    run systemctl enable mihomo
    run systemctl restart mihomo || die "mihomo не запустился."
    info "Жду, пока mihomo проверит серверы…"
    local ip="" i
    for i in $(seq 1 12); do
        sleep 5
        ip=$(curl -4 -s -m 8 -x http://127.0.0.1:7890 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]') && [ -n "$ip" ] && break
    done
    [ -n "$ip" ] || die "VPN не заработал: через mihomo нет выхода в интернет. Проверьте подписку."
    VPN_IP=$ip
    DIRECT_IP=$(curl -4 -s -m 8 https://ifconfig.me/ip 2>/dev/null)
    log "VPN IP $VPN_IP, прямой $DIRECT_IP"
}

# Проверка по MikroTik: вывод команды вставляется в терминал, ключей и паролей в нём нет
MT_CMD='/ip address print terse proplist=address,interface; /interface wireguard print terse proplist=name,listen-port'
mt_check_paste() {
    clear
    echo "  Проверка по MikroTik"
    echo
    echo "  Выполните в терминале MikroTik (Winbox → New Terminal):"
    echo
    echo "    $MT_CMD"
    echo
    echo "  Команда ничего не меняет, только показывает адреса и порты WireGuard."
    echo "  Скопируйте весь вывод, вставьте сюда (правая кнопка мыши или Shift+Insert),"
    echo "  затем нажмите Enter два раза."
    echo
    : >"$TMP/mt.txt"
    local line empty=0
    while IFS= read -r line; do
        if [ -z "${line//[[:space:]]/}" ]; then
            empty=$((empty + 1)); [ -s "$TMP/mt.txt" ] && [ $empty -ge 2 ] && break; continue
        fi
        empty=0; printf '%s\n' "$line" >>"$TMP/mt.txt"
    done
    log "вывод MikroTik: $(wc -l <"$TMP/mt.txt") строк"
}
mt_check() {   # $1 подсеть, $2 порт → JSON
    python3 /usr/local/bin/vpnbot.py --mt-check "$TMP/mt.txt" "$1" "$2" "${LAN_IP:-}" 2>>"$LOG" || echo '{}'
}

step_wireguard() {
    load_conf
    local keep=0
    # WireGuard уже настроен — подсеть не меняем (иначе сломаются клиенты и MikroTik)
    [ -f /etc/wireguard/wg0.conf ] && keep=1
    # сервер, настроенный раньше вручную: берём порт и подсеть из существующего wg0.conf
    if [ -f /etc/wireguard/wg0.conf ]; then
        [ -n "${WG_PORT:-}" ] || WG_PORT=$(grep -oP '^ListenPort\s*=\s*\K\d+' /etc/wireguard/wg0.conf)
        [ -n "${WG_NET:-}" ] || WG_NET=$(grep -oP '^Address\s*=\s*\K\d+\.\d+\.\d+' /etc/wireguard/wg0.conf)
    fi
    [ $keep -eq 1 ] && [ -z "${WG_NET:-}" ] && keep=0
    local mt=0 r used
    rm -f "$TMP/mt.txt"
    if [ "$RESTORE" != 1 ] && ask "Проверка по MikroTik" "Шлюз стоит за MikroTik или к нему будут подключаться MikroTik?\n\nМожно проверить, что порт и подсеть туннеля не заняты на роутере: понадобится выполнить одну команду в терминале MikroTik и вставить сюда её вывод.\n\nПроверить?" 14; then
        mt_check_paste; mt=1
        r=$(mt_check "${WG_NET:-10.10.10}" "${WG_PORT:-51820}")
        if [ "$(jq -r '.addrs // 0' <<<"$r")" = 0 ]; then
            msg "Проверка по MikroTik" "В выводе не нашлось ни одного адреса — проверка пропущена." 8; mt=0
        else
            used=$(jq -r '.port_used_by // empty' <<<"$r")
            local old_port=${WG_PORT:-51820}
            # на уже работающем шлюзе порт сами не меняем: у клиентов он вписан в конфиги
            [ -n "$used" ] && [ $keep -eq 0 ] && WG_PORT=$(jq -r .free_port <<<"$r")
            msg "Проверка по MikroTik" "На роутере: адресов $(jq -r .addrs <<<"$r"), интерфейсов WireGuard $(jq -r .wg <<<"$r").
$( [ "$(jq -r .local <<<"$r")" = true ] && echo "Роутер в одной сети с этим сервером ($LAN_IP).")
$( [ -n "$used" ] && echo "
Порт $old_port на роутере занят интерфейсом «$used»$( [ $keep -eq 0 ] && echo " — предлагаю свободный: $WG_PORT" || echo ". Шлюз уже работает на этом порту: если смените его, клиентам понадобятся новые конфиги").")
$( [ "$(jq -r '.net_conflict|length' <<<"$r")" != 0 ] && echo "
Подсеть туннеля ${WG_NET:-10.10.10}.0/24 пересекается с адресом роутера: $(jq -r '.net_conflict|join(", ")' <<<"$r").$( [ $keep -eq 0 ] && echo " Предлагаю свободную: $(jq -r .free_net <<<"$r").0/24." || echo "
WireGuard на этом сервере уже настроен — подсеть менять нельзя (отвалятся клиенты). Смените эту сеть на роутере.")")" 18
            [ $keep -eq 0 ] && [ "$(jq -r '.net_conflict|length' <<<"$r")" != 0 ] && [ "$(jq -r '.free_net // empty' <<<"$r")" != "" ] \
                && WG_NET=$(jq -r .free_net <<<"$r")
        fi
    fi
    while :; do
        [ "$RESTORE" = 1 ] && [ -n "${WG_PORT:-}" ] \
            || WG_PORT=$(need inp "WireGuard: порт" "UDP-порт, на котором шлюз принимает подключения клиентов:" "${WG_PORT:-51820}" 10)
        [[ "$WG_PORT" =~ ^[0-9]{2,5}$ ]] || WG_PORT=51820
        [ $mt = 1 ] || break
        used=$(mt_check "${WG_NET:-10.10.10}" "$WG_PORT" | jq -r '.port_used_by // empty')
        [ -z "$used" ] && break
        ask "Порт занят на MikroTik" "На роутере порт $WG_PORT уже слушает WireGuard «$used».\n\nЕсли роутер пробрасывает этот порт на шлюз, его собственный WireGuard перестанет работать. Всё равно оставить $WG_PORT?" 12 1 && break
    done
    if [ $keep -eq 0 ]; then
        while :; do
            local subnet
            subnet=$(need inp "WireGuard: подсеть" "Внутренняя подсеть туннеля (/24). Не должна совпадать с вашей локальной сетью ($LAN_IP)$( [ $mt = 1 ] && echo " и сетями MikroTik")." "${WG_NET:-10.10.10}.0/24" 11)
            WG_NET=$(sed -E 's#^([0-9]+\.[0-9]+\.[0-9]+)\.0(/24)?$#\1#' <<<"$subnet")
            if ! [[ "$WG_NET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then msg "Подсеть" "Формат: 10.10.10.0/24" 8; continue; fi
            if [ "${LAN_IP%.*}" = "$WG_NET" ] || ip route | grep -q "^$WG_NET\.0/"; then
                msg "Подсеть" "Подсеть $WG_NET.0/24 уже используется в вашей сети. Выберите другую." 8; continue; fi
            if [ $mt = 1 ]; then
                r=$(mt_check "$WG_NET" "$WG_PORT")
                if [ "$(jq -r '.net_conflict|length' <<<"$r")" != 0 ]; then
                    msg "Подсеть" "Подсеть $WG_NET.0/24 пересекается с адресом на MikroTik: $(jq -r '.net_conflict|join(", ")' <<<"$r").\n\nСвободная, например: $(jq -r '.free_net // "10.10.20"' <<<"$r").0/24" 10; continue
                fi
            fi
            break
        done
    fi
    local how pub_ip
    if [ "$RESTORE" = 1 ]; then
        # адрес уже выбран в restore_questions; способ подключения и роутер — как были
        WG_EP_MODE=${WG_EP_MODE:-router}
        ROUTER_IP=${ROUTER_IP:-}
    else
    pub_ip=$(curl -4 -s -m 8 https://ifconfig.me/ip 2>/dev/null)
    how=$(MENU_DEFAULT=${WG_EP_MODE:-} need menu "Как клиенты будут подключаться" "Откуда будут подключаться телефоны и компьютеры?" 16 \
        router "Через роутер: у роутера белый IP, на нём проброс порта" \
        direct "У этого сервера свой белый IP (VPS, выделенный адрес)" \
        lan "Только из этой локальной сети")
    WG_EP_MODE=$how; ROUTER_IP=""
    case $how in
        direct) WG_HOST=$(need inp "Адрес сервера" "Внешний IP или доменное имя этого сервера:" "${pub_ip:-}" 10) ;;
        lan)    WG_HOST=$LAN_IP ;;
        router)
            WG_HOST=$(need inp "Внешний адрес" "Внешний IP или DDNS-имя вашего роутера.\n\nОпределён автоматически: ${pub_ip:-не удалось}.\nЕсли IP у провайдера меняется, лучше указать DDNS-имя (на MikroTik: IP → Cloud)." "${pub_ip:-}" 13)
            ROUTER_IP=$(need inp "Роутер" "Локальный IP роутера, на котором будет проброс порта:" "$GW" 10)
            msg "Проброс порта" "На роутере ($ROUTER_IP) пробросьте UDP-порт $WG_PORT на $LAN_IP:$WG_PORT.\n
MikroTik:
/ip firewall nat add chain=dstnat in-interface-list=WAN protocol=udp dst-port=$WG_PORT action=dst-nat to-addresses=$LAN_IP to-ports=$WG_PORT comment=\"vpn-gateway\"
\nKeenetic / TP-Link / другие: раздел «Переадресация портов» / «Port forwarding», протокол UDP.
$( [ "$ROUTER_IP" != "$GW" ] && echo "
Роутер не является шлюзом по умолчанию ($GW) — установщик добавит правило,
чтобы ответы клиентам уходили через $ROUTER_IP.")" 22 ;;
    esac
    fi
    WG_ENDPOINT="$WG_HOST:${RST_EXT_PORT:-$WG_PORT}"
    save_conf WG_PORT "$WG_PORT"; save_conf WG_NET "$WG_NET"; save_conf WG_ENDPOINT "$WG_ENDPOINT"
    save_conf WG_EP_MODE "$WG_EP_MODE"; save_conf ROUTER_IP "$ROUTER_IP"

    info "Настраиваю WireGuard…"
    local priv peers=""
    priv=$(grep -oP '^PrivateKey\s*=\s*\K\S+' /etc/wireguard/wg0.conf 2>/dev/null || wg genkey)
    [ -f /etc/wireguard/wg0.conf ] && peers=$(awk '/^\[Peer\]/{p=1} p' /etc/wireguard/wg0.conf)
    # трафик клиентов — только через mihomo; если он перезапускается, правило 101 не даёт уйти напрямую
    local up="ip rule add iif wg0 lookup 100 priority 100; ip rule add iif wg0 prohibit priority 101"
    local down="ip rule del iif wg0 lookup 100 priority 100; ip rule del iif wg0 prohibit priority 101"
    if [ -n "$ROUTER_IP" ] && [ "$ROUTER_IP" != "$GW" ]; then
        local lan_net; lan_net=$(ip -4 route show dev "$IFACE" proto kernel scope link | awk '{print $1; exit}')
        up="$up; ip route replace default via $ROUTER_IP dev $IFACE table 200; ip route replace $lan_net dev $IFACE table 200; ip rule add ipproto udp sport $WG_PORT lookup 200 priority 90"
        down="$down; ip rule del ipproto udp sport $WG_PORT lookup 200 priority 90; ip route flush table 200"
    fi
    umask 077; mkdir -p /etc/wireguard
    cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $WG_NET.1/24
ListenPort = $WG_PORT
PrivateKey = $priv
MTU = 1420
PostUp = $up
PostDown = $down
EOF
    [ -n "$peers" ] && printf '\n%s\n' "$peers" >>/etc/wireguard/wg0.conf
    umask 022
    mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
    printf '[Unit]\nAfter=mihomo.service\nWants=mihomo.service\n' >/etc/systemd/system/wg-quick@wg0.service.d/after.conf
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        run ufw allow "$WG_PORT/udp"; run ufw route allow in on wg0
    fi
    run systemctl daemon-reload
    run systemctl enable wg-quick@wg0
    run systemctl restart wg-quick@wg0 || die "WireGuard не запустился."
    # адрес подключения — в состояние, чтобы его видели и бот, и vpngw
    python3 - >>"$LOG" 2>&1 <<PY || die "Не удалось сохранить настройки WireGuard."
import json, os
p = "/var/lib/vpnbot/state.json"
os.makedirs(os.path.dirname(p), exist_ok=True)
st = json.load(open(p)) if os.path.exists(p) else {}
st["wg"] = st.get("wg") or {"peers": {}}
st["wg"].setdefault("peers", {})
st["wg"]["endpoint"] = "$WG_ENDPOINT"
ep = st["wg"].get("ep") or {}
host = "$WG_HOST"
if "${RESTORE}" == "1":
    ep.update(domain="${RST_DOM:-}", ip="${RST_IP:-}")   # внешний порт (ep.port) — как в копии
    ep.setdefault("port", "$WG_PORT")
else:
    if all(x.isdigit() for x in host.split(".")) and host.count(".") == 3:
        ep["ip"] = host
    else:
        ep["domain"] = host
    ep["port"] = "$WG_PORT"
st["wg"]["ep"] = ep
json.dump(st, open(p + ".tmp", "w"), ensure_ascii=False); os.chmod(p + ".tmp", 0o600); os.replace(p + ".tmp", p)
PY
}

install_bot_files() {
    unpack "$P_VPNBOT" "$TMP/vpnbot.py"
    python3 -m py_compile "$TMP/vpnbot.py" || { die "Встроенный бот повреждён."; return 1; }
    install -m 700 -o root -g root "$TMP/vpnbot.py" /usr/local/bin/vpnbot.py
}

# из старого vpnbot.env берём только бота и владельца: адрес и подсеть WireGuard уже посчитаны заново
env_get_bot() {
    local k
    for k in BOT_TOKEN ADMIN_ID GW_NAME MIKROTIK; do
        printf -v "$k" '%s' "$(grep -oP "^$k=\K.*" /etc/vpnbot.env 2>/dev/null)"
    done
}

tg_api() { curl -s -m 20 -x http://127.0.0.1:7890 "https://api.telegram.org/bot$BOT_TOKEN/$1" 2>/dev/null \
           || curl -s -m 20 "https://api.telegram.org/bot$BOT_TOKEN/$1"; }

step_bot() {
    load_conf
    if [ -f /etc/vpnbot.env ] && { { [ "$RESTORE" = 1 ] && [ "${RST_BOT:-same}" = same ]; } \
                                    || { [ "$RESTORE" != 1 ] && ask "Telegram-бот" "Бот уже настроен. Оставить текущий токен и владельца?" 9; }; }; then
        env_get_bot; WITH_BOT=1
        BOT_USER=$(tg_api getMe | jq -r '.result.username // empty' 2>/dev/null)
    else
        [ "$RESTORE" = 1 ] || ask "Telegram-бот" "Установить Telegram-бота для управления шлюзом?\n\nВ нём: статус, выбор сервера, трафик, тест скорости, добавление клиентов WireGuard с QR-кодом и файлом .conf, уведомления." 13 \
            || { WITH_BOT=0; return; }
        WITH_BOT=1
        local me
        while :; do
            BOT_TOKEN=$(need pwd_ "Токен бота" "Создайте бота у @BotFather (/newbot) и вставьте токен:$( [ "$RESTORE" = 1 ] && printf '\n\nАдмины и настройки из копии сохранятся.')")
            info "Проверяю токен…"
            me=$(tg_api getMe)
            [ "$(jq -r .ok <<<"$me" 2>/dev/null)" = "true" ] && break
            msg "Токен" "Telegram не принял токен. Проверьте, что скопировали его целиком." 8
        done
        BOT_USER=$(jq -r .result.username <<<"$me")
        systemctl stop vpnbot >>"$LOG" 2>&1
        tg_api "deleteWebhook" >/dev/null
        ADMIN_ID=""
        while [ -z "$ADMIN_ID" ]; do
            msg "Владелец бота" "Откройте в Telegram бота @$BOT_USER и нажмите «Старт» (или отправьте /start).\n\nЗатем нажмите здесь «OK» — я определю ваш Telegram ID." 11
            local up id name
            up=$(tg_api "getUpdates?timeout=5")
            id=$(jq -r '[.result[]|.message|select(.!=null)]|last|.from.id // empty' <<<"$up" 2>/dev/null)
            name=$(jq -r '[.result[]|.message|select(.!=null)]|last|.from|((.first_name//"")+" "+(.last_name//"")+(if .username then " (@"+.username+")" else "" end))' <<<"$up" 2>/dev/null)
            if [ -n "$id" ] && ask "Владелец бота" "Вам написал:\n\n  $name\n  ID: $id\n\nЭто вы? Этот человек станет владельцем бота." 12; then
                ADMIN_ID=$id
            elif ! ask "Владелец бота" "Сообщение не найдено. Попробовать ещё раз?\n\n«Нет» — ввести ID вручную (его можно узнать у @userinfobot)." 11; then
                ADMIN_ID=$(need inp "Владелец бота" "Ваш Telegram ID (число):" "" 9)
                [[ "$ADMIN_ID" =~ ^[0-9]+$ ]] || ADMIN_ID=""
            fi
        done
        local last; last=$(jq -r '[.result[].update_id]|max // empty' <<<"$up" 2>/dev/null)
        [ -n "$last" ] && tg_api "getUpdates?offset=$((last+1))&timeout=1" >/dev/null
    fi
    local mt=0
    if [ "$RESTORE" = 1 ]; then
        mt=${MIKROTIK:-1}
    else
    GW_NAME=$(need inp "Название шлюза" "Как назвать этот шлюз в боте (видно в заголовке меню):" "${GW_NAME:-VPN $(hostname)}" 10)
    ask "MikroTik" "Будут ли к шлюзу подключаться роутеры MikroTik?\n\n«Да» — в боте появится кнопка добавления MikroTik с готовыми командами." 11 \
        "$( [ "${MIKROTIK:-0}" = 1 ] || echo 1 )" && mt=1
    fi
    umask 077
    cat >/etc/vpnbot.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ADMIN_ID=$ADMIN_ID
GW_NAME=$GW_NAME
WG_NET=$WG_NET
WG_ENDPOINT=$WG_ENDPOINT
MIKROTIK=$mt
UPDATE_REPO=$REPO
UPDATE_BRANCH=$BRANCH
EOF
    umask 022
    install_bot_files
    cat >/etc/systemd/system/vpnbot.service <<'EOF'
[Unit]
Description=VPN gateway Telegram bot
After=mihomo.service wg-quick@wg0.service network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/vpnbot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    run systemctl daemon-reload; run systemctl enable vpnbot
    save_conf WITH_BOT 1
}

step_email() {
    [ "${WITH_BOT:-0}" = 1 ] || return
    [ -f /etc/vpnnotify.env ] && return
    [ "${EMAIL_ASKED:-0}" = 1 ] && return          # уже спрашивали при прошлой установке
    jq -e '.email.smtp.host // empty' /var/lib/vpnbot/state.json >/dev/null 2>&1 && return   # настроена в боте
    save_conf EMAIL_ASKED 1
    ask "Почта" "Присылать уведомления ещё и на почту?\n\n(Можно настроить позже в боте: Настройки → Почта.)" 10 1 || return
    local hp host port user pass to
    hp=$(need inp "Почта: сервер" "SMTP-сервер и порт:" "smtp.yandex.ru:465" 9)
    host=${hp%%:*}; port=${hp##*:}; [ "$port" = "$hp" ] && port=465
    user=$(need inp "Почта: отправитель" "Адрес ящика, с которого отправлять:" "" 9)
    pass=$(need pwd_ "Почта: пароль" "Пароль приложения для $user\n(Яндекс: id.yandex.ru → Безопасность → Пароли приложений):")
    to=$(need inp "Почта: получатель" "Куда присылать уведомления:" "$user" 9)
    info "Отправляю тестовое письмо…"
    if SMTP_HOST=$host SMTP_PORT=$port SMTP_USER=$user SMTP_PASS=$pass MAIL_TO=$to python3 - >>"$LOG" 2>&1 <<'PY'
import os, smtplib, ssl
from email.message import EmailMessage
e = os.environ; m = EmailMessage()
m['Subject'] = 'VPN-шлюз: тестовое письмо'; m['From'] = e['SMTP_USER']; m['To'] = e['MAIL_TO']
m.set_content('Почтовые уведомления VPN-шлюза работают.')
p = int(e['SMTP_PORT']); c = ssl.create_default_context()
s = smtplib.SMTP_SSL(e['SMTP_HOST'], p, context=c, timeout=20) if p == 465 else smtplib.SMTP(e['SMTP_HOST'], p, timeout=20)
if p != 465: s.starttls(context=c)
s.login(e['SMTP_USER'], e['SMTP_PASS']); s.send_message(m); s.quit()
PY
    then
        umask 077
        printf 'SMTP_HOST=%s\nSMTP_PORT=%s\nSMTP_USER=%s\nSMTP_PASS=%s\nMAIL_TO=%s\n' "$host" "$port" "$user" "$pass" "$to" >/etc/vpnnotify.env
        umask 022
        msg "Почта" "Тестовое письмо отправлено на $to." 8
    else
        msg "Почта" "Не удалось отправить письмо (подробности в журнале). Почту можно настроить позже в боте." 9
    fi
}

step_timezone() {
    local tz; tz=$(need inp "Часовой пояс" "Часовой пояс для времени в уведомлениях:" "$(timedatectl show -p Timezone --value 2>/dev/null | sed 's#^Etc/UTC$#Europe/Moscow#')" 9)
    run timedatectl set-timezone "$tz" || msg "Часовой пояс" "Неизвестный часовой пояс «$tz», оставлен прежний." 8
}

NEW_CLIENTS=()
add_clients_loop() {
    local first=${1:-}
    ask "Клиенты WireGuard" "${first:+Создать клиентов сейчас? }Добавить телефон или компьютер?\n\nДля каждого будут созданы файл .conf и QR-код.${WITH_BOT:+\nКлиентов можно добавлять и позже в боте: 🔐 WireGuard.}" 12 || return
    while :; do
        local name kind out
        name=$(inp "Новый клиент" "Имя клиента (например: Телефон Ивана, Ноутбук офис):" "" 9) || break
        [ -n "$name" ] || continue
        kind=$(menu "Новый клиент" "Что это за устройство?" 12 phone "Телефон или планшет (QR-код)" pc "Компьютер (файл .conf)") || continue
        if out=$(vpngw add "$name" "$kind" 2>&1); then NEW_CLIENTS+=("$name"); log "клиент $name → $out"
        else msg "Ошибка" "$out" 9; fi
        ask "Клиенты WireGuard" "Клиент «$name» создан.\n\nДобавить ещё одного?" 9 1 || break
    done
}

show_new_clients() {
    local n
    for n in "${NEW_CLIENTS[@]}"; do
        clear; vpngw qr "$n"
        echo; echo "  Телефон: WireGuard → «+» → «Сканировать QR-код»."
        echo "  Компьютер: скачайте файл через вкладку SFTP в MobaXterm (/root/wg-clients) и импортируйте."
        read -rp $'\n  Enter — дальше ' _
    done
    NEW_CLIENTS=()
}

pick_and_show_qr() {
    local args=() i=0 line
    while IFS= read -r line; do
        [[ "$line" =~ ^\ *([0-9]+)\.\ (.*)$ ]] || continue
        args+=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]:0:60}")
    done < <(vpngw peers)
    [ ${#args[@]} -gt 0 ] || { msg "Клиенты" "Клиентов пока нет." 8; return; }
    i=$(menu "Клиенты" "Чей QR-код показать?" 20 "${args[@]}") || return
    clear; vpngw qr "$i"; read -rp $'\n  Enter — назад ' _
}

step_finish() {
    info "Финальная проверка и тест скорости…"
    local s speed st
    [ "${WITH_BOT:-0}" = 1 ] && run systemctl restart vpnbot
    sleep 3
    speed=$(curl -s -o /dev/null -m 30 -r 0-24999999 -x http://127.0.0.1:7890 -w '%{speed_download}' \
            https://fsn1-speed.hetzner.com/1GB.bin 2>/dev/null | awk '{printf "%.0f", $1*8/1000000}')
    st=""
    for s in mihomo wg-quick@wg0 $( [ "${WITH_BOT:-0}" = 1 ] && echo vpnbot ); do
        if systemctl is-active --quiet "$s"; then st+="  ✓ $s\n"; else st+="  ✗ $s — НЕ РАБОТАЕТ\n"; fi
    done
    touch "$CONF_DIR/installed"; echo "$GW_VERSION" >"$CONF_DIR/version"
    {
        echo "VPN-шлюз установлен $(date '+%F %T')"
        echo "IP через VPN:        $VPN_IP (напрямую: ${DIRECT_IP:-?})"
        echo "Скорость через VPN:  ${speed:-?} Мбит/с"
        echo "Режим:               $MODE, маршрутизация: $ROUTING"
        echo "WireGuard:           $WG_NET.1/24, подключение: $WG_ENDPOINT"
        [ "${WITH_BOT:-0}" = 1 ] && echo "Бот:                 @${BOT_USER:-?}"
        echo "Файлы клиентов:      /root/wg-clients/"
        echo "Команды: vpngw status | vpngw peers | vpngw add \"Имя\" phone|pc | vpngw qr \"Имя\""
        echo "Меню установщика:    sudo vpngw-setup"
    } >"$SUMMARY"; chmod 600 "$SUMMARY"
    msg "Готово!" "$(printf "$st")
IP через VPN:   $VPN_IP
Скорость:       ${speed:-?} Мбит/с (Hetzner, Германия)
Подключение WireGuard: $WG_ENDPOINT
$( [ "${WITH_BOT:-0}" = 1 ] && echo "
Бот @${BOT_USER:-} прислал вам сообщение «Бот запущен».
Клиенты добавляются в боте: 🔐 WireGuard → ➕ Телефон / Компьютер.")
\nКраткая сводка сохранена в $SUMMARY.
Меню управления на сервере: sudo vpngw-setup" 22
}

full_install() {
    systemctl stop vpnbot >/dev/null 2>&1   # бот держит состояние в памяти — на время установки останавливаем
    clear; grapes; sleep 2
    step_welcome
    step_packages
    step_network
    step_subscription
    step_servers
    step_mode
    step_mihomo
    step_wireguard
    step_bot
    step_email
    step_timezone
    # настройки переключения сразу видны в боте
    [ -f "$TMP/params.json" ] && python3 /usr/local/bin/vpnbot.py --seed-vpn "$TMP/params.json" >>"$LOG" 2>&1
    add_clients_loop first
    step_finish
    show_new_clients
}

# ================================================================ восстановление из резервной копии
# Копию делает бот (⚙️ Настройки → 💾 Резервные копии): tar.gz, зашифрованный openssl AES-256 + PBKDF2.
BK_FORMAT=1
RESTORE=0
RST=""            # распакованная копия

bk_decrypt() {    # $1 файл, $2 пароль, $3 куда
    VPNGW_BK_PW=$2 openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -pass env:VPNGW_BK_PW \
        -in "$1" -out "$3" 2>>"$LOG"
}

ver_newer() {     # $1 новее $2 (по major.minor)?
    local a b; a=$(cut -d. -f1,2 <<<"$1"); b=$(cut -d. -f1,2 <<<"$2")
    [ "$a" != "$b" ] && [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -1)" = "$a" ]
}

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

bk_is_file() { [ -s "$1" ] && [ "$(head -c 8 "$1")" = "Salted__" ]; }

# Скачать копию по ссылке: прямая, публичная Яндекс.Диска, Google Диска
fetch_url() {     # $1 ссылка → $TMP/backup.vpngw
    local url=$1 id key meta name href out=$TMP/backup.vpngw
    rm -f "$out"
    if [[ "$url" =~ ^https?://(disk\.yandex\.[a-z]+|yadi\.sk)/ ]]; then
        key=$(urlenc "$url")
        meta=$(curl -sS -m 30 "https://cloud-api.yandex.net/v1/disk/public/resources?public_key=$key&sort=-created&limit=50" 2>>"$LOG")
        local path=""
        if [ "$(jq -r '.type // empty' <<<"$meta")" = dir ]; then
            name=$(jq -r '[._embedded.items[]? | select(.name|endswith(".vpngw"))] | sort_by(.created) | last | .name // empty' <<<"$meta")
            [ -n "$name" ] || { msg "Яндекс.Диск" "В этой папке нет файлов .vpngw." 8; return 1; }
            path="&path=$(urlenc "/$name")"
            log "Яндекс.Диск: папка, берём последний файл $name"
        fi
        href=$(curl -sS -m 30 "https://cloud-api.yandex.net/v1/disk/public/resources/download?public_key=$key$path" 2>>"$LOG" | jq -r '.href // empty')
        [ -n "$href" ] || { msg "Яндекс.Диск" "Не удалось получить файл по ссылке. Проверьте, что доступ открыт «для всех, у кого есть ссылка»." 9; return 1; }
        url=$href
    elif [[ "$url" =~ drive\.google\.com ]] || [[ "$url" =~ docs\.google\.com ]]; then
        id=$(grep -oP '(/d/|[?&]id=)\K[A-Za-z0-9_-]{10,}' <<<"$url" | head -1)
        [ -n "$id" ] || { msg "Google Диск" "Не нашёл в ссылке идентификатор файла." 8; return 1; }
        url="https://drive.usercontent.google.com/download?id=$id&export=download&confirm=t"
    fi
    info "Скачиваю резервную копию…"
    curl -fsSL -m 300 -o "$out" "$url" 2>>"$LOG" \
        || curl -fsSL -m 300 -x http://127.0.0.1:7890 -o "$out" "$url" 2>>"$LOG" \
        || { msg "Загрузка" "Не удалось скачать файл по ссылке." 8; return 1; }
    bk_is_file "$out" || { msg "Загрузка" "По ссылке скачался не файл резервной копии (возможно, страница входа или ошибка доступа).\n\nДля Google Диска откройте доступ «Все, у кого есть ссылка»." 11; return 1; }
}

# SFTP: пароль спрашивает сам ssh прямо в терминале
fetch_sftp() {
    local t user host port path out=$TMP/backup.vpngw
    t=$(inp "SFTP" "Где лежит копия? Формат:\n  пользователь@сервер:порт/путь/к/файлу.vpngw\nили папка (возьму самую свежую копию):\n  backup@192.168.1.20:22/backups/vpngw/" "${RST_SFTP:-}" 13) || return 1
    RST_SFTP=$t
    [[ "$t" =~ ^([A-Za-z0-9_.-]+)@([A-Za-z0-9.-]+)(:([0-9]+))?(/.*)$ ]] || { msg "SFTP" "Не понял адрес. Пример: root@192.168.1.20:22/root/backup.vpngw" 8; return 1; }
    user=${BASH_REMATCH[1]}; host=${BASH_REMATCH[2]}; port=${BASH_REMATCH[4]:-22}; path=${BASH_REMATCH[5]}
    local opts=(-P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
    clear
    if [[ "$path" == */ ]]; then
        echo "Подключаюсь к $host, ищу копии в $path (введите пароль, если спросит)…"
        local list
        list=$(printf 'ls -1t %s*.vpngw\n' "$path" | sftp "${opts[@]}" -o BatchMode=no -b - "$user@$host" 2>>"$LOG" | grep '\.vpngw$' | head -1)
        [ -n "$list" ] || { msg "SFTP" "В папке $path нет файлов .vpngw (или не удалось войти)." 8; return 1; }
        path=$(sed 's/^ *//' <<<"$list"); [[ "$path" == /* ]] || path="${BASH_REMATCH[5]}$path"
    fi
    echo "Скачиваю $path (введите пароль, если спросит)…"
    sftp "${opts[@]}" "$user@$host:$path" "$out" || { msg "SFTP" "Не удалось скачать файл. Подробности были на экране." 8; return 1; }
    bk_is_file "$out" || { msg "SFTP" "Скачанный файл — не резервная копия шлюза." 8; return 1; }
}

fetch_local() {
    local f cand
    cand=$(ls -1t /root/*.vpngw /home/*/*.vpngw /home/*/Downloads/*.vpngw /tmp/*.vpngw 2>/dev/null | head -1)
    f=$(inp "Файл копии" "Путь к файлу .vpngw на этом сервере.\n\nЗагрузить файл можно через вкладку SFTP в MobaXterm/WinSCP, например в /root." "${cand:-/root/}" 12) || return 1
    bk_is_file "$f" || { msg "Файл копии" "Это не файл резервной копии шлюза (или его нет): $f" 8; return 1; }
    cp "$f" "$TMP/backup.vpngw"
}

restore_get() {
    local c pw i
    while :; do
        c=$(need menu "Восстановление" "Откуда взять резервную копию (.vpngw)?" 15 \
            file "Файл на этом сервере" \
            url "Ссылка: прямая, Яндекс.Диск или Google Диск (публичная)" \
            sftp "С сервера по SFTP (NAS, другой сервер)")
        case $c in
            file) fetch_local || continue ;;
            url)  local u; u=$(inp "Ссылка на копию" "Вставьте ссылку на файл .vpngw:\n• публичная ссылка Яндекс.Диска (на файл или папку)\n• ссылка «Поделиться» Google Диска (доступ: все, у кого есть ссылка;\n  из России без VPN может не открыться — надёжнее Яндекс.Диск)\n• прямая ссылка https://…" "" 16) || continue
                  [ -n "$u" ] || continue; fetch_url "$u" || continue ;;
            sftp) fetch_sftp || continue ;;
        esac
        for i in 1 2 3; do
            pw=$(pwd_ "Пароль копии" "Пароль, с которым создавалась копия:") || break
            info "Расшифровываю…"
            if bk_decrypt "$TMP/backup.vpngw" "$pw" "$TMP/restore.tgz" && tar -tzf "$TMP/restore.tgz" manifest.json >/dev/null 2>&1; then
                RST=$TMP/restore; rm -rf "$RST"; mkdir -p "$RST"
                tar -xzf "$TMP/restore.tgz" -C "$RST" || die "Архив копии повреждён."
                rm -f "$TMP/restore.tgz"
                return 0
            fi
            msg "Пароль копии" "Не подошёл пароль (или файл повреждён). Попытка $i из 3." 8
        done
    done
}

mf() { jq -r "$1 // empty" "$RST/manifest.json" 2>/dev/null; }

restore_summary() {
    local fmt ver; fmt=$(mf .format); ver=$(mf .version)
    [ "${fmt:-0}" -le "$BK_FORMAT" ] 2>/dev/null || die "Копия сделана в новом формате ($fmt). Скачайте свежий установщик с GitHub."
    if ver_newer "$ver" "$GW_VERSION"; then
        ask "Версия копии" "Копия сделана ботом версии $ver, а этот установщик — версии $GW_VERSION.\n\nЛучше скачать свежий установщик с GitHub. Продолжить с этим на свой риск?" 12 1 || { clear; exit 1; }
    fi
    msg "Что в копии" "Копия от:            $(mf .created_text)  ($( [ "$(mf .why)" = автоматически ] && echo автобэкап || echo вручную))
Сервер:              $(mf .host), $(mf .lan_ip)
Название шлюза:      $(mf .gw_name)
Версия бота:         $ver
Клиентов WireGuard:  $(mf .peers)   (подсеть $(mf .wg_net).0/24, порт $(mf .wg_port))
Подписок VPN:        $(mf .subs)
Своих серверов VLESS: $(mf .vps)
Администраторов:     $(mf .admins)
Почта:               $( [ "$(mf .email)" = true ] && echo настроена || echo нет)
Адрес для клиентов:  $(mf .ep_domain) $(mf .ep_ip)
\nКлючи сервера WireGuard, порт и подсеть останутся прежними — клиентам ничего менять не нужно, если адрес подключения тот же." 21
}

state_py() {   # $1 — код Python, работающий со словарём st
    python3 - "$1" >>"$LOG" 2>&1 <<'PY'
import json, os, sys
p = "/var/lib/vpnbot/state.json"
st = json.load(open(p)) if os.path.exists(p) else {}
exec(sys.argv[1])
json.dump(st, open(p + ".tmp", "w"), ensure_ascii=False); os.chmod(p + ".tmp", 0o600); os.replace(p + ".tmp", p)
PY
}

restore_place() {
    if [ -f "$CONF_DIR/installed" ] || [ -f /etc/wireguard/wg0.conf ]; then
        ask "На сервере уже есть шлюз" "Текущие настройки этого сервера будут заменены настройками из копии.\n\nПеред этим они сохранятся в архив в /root. Продолжить?" 11 1 || { clear; exit 1; }
        local bak="/root/vpngw-before-restore-$(date +%Y%m%d-%H%M).tar.gz"
        tar czf "$bak" /etc/mihomo/config.yaml /etc/mihomo/providers /etc/wireguard /etc/vpngw /etc/vpnbot.env \
            /etc/vpnnotify.env /var/lib/vpnbot /root/wg-clients 2>/dev/null; chmod 600 "$bak"
        log "текущие настройки сохранены: $bak"
    fi
    info "Восстанавливаю файлы…"
    systemctl stop vpnbot >>"$LOG" 2>&1
    rm -f "$RST/files$CONF_DIR/installed" "$RST/files$CONF_DIR/version"
    cp -a "$RST/files/." / || die "Не удалось разложить файлы из копии."
    chmod 700 /var/lib/vpnbot /var/lib/vpnbot/ssh 2>/dev/null
    chmod 600 /var/lib/vpnbot/state.json /etc/vpnbot.env /etc/wireguard/*.conf 2>/dev/null
    RESTORE=1
    load_conf
}

restore_questions() {
    local c
    # --- Telegram-бот (токен нового бота спросим позже, когда заработает VPN: Telegram в РФ без него недоступен)
    RST_BOT=same
    if [ -f /etc/vpnbot.env ]; then
        env_get_bot
        c=$(need menu "Telegram-бот" "В копии настроен бот «$GW_NAME», владелец — Telegram ID $ADMIN_ID.\nАдмины, уведомления и настройки бота сохранятся в любом случае." 15 \
            same "Тот же бот (тот же токен)" new "Новый бот (другой токен от @BotFather)")
        RST_BOT=$c
        if [ "$c" = same ]; then
            msg "Важно: старый сервер" "Один бот не может работать на двух серверах сразу — они будут перехватывать друг у друга сообщения.\n
Если старый сервер ещё включён, остановите на нём бота:
  sudo systemctl disable --now vpnbot
\nЗатем нажмите OK." 13
        fi
        WITH_BOT=1
    fi
    # --- почта
    if [ "$(mf .email)" = true ]; then
        c=$(need menu "Почта" "В копии настроены почтовые уведомления." 14 \
            same "Оставить как было" new "Настроить заново (другой ящик)" off "Выключить уведомления на почту")
        case $c in
            new) state_py 'st.pop("email", None)'; rm -f /etc/vpnnotify.env; EMAIL_ASKED=0; save_conf EMAIL_ASKED 0; RST_EMAIL=new ;;
            off) state_py 'e = st.get("email") or {}; e["enabled"] = False; st["email"] = e' ;;
        esac
    fi
    # --- подписка: тот же HWID — провайдер не увидит «нового устройства»
    local hw; hw=$(mf .hwid)
    if [ -n "$hw" ] && [ "$hw" != "$(cat /etc/machine-id)" ]; then
        c=$(need menu "Подписка VPN" "Провайдер подписки различает устройства по HWID.\n\nСтарый: $hw\nЭтот сервер: $(cat /etc/machine-id)" 16 \
            keep "Оставить старый HWID — провайдер увидит то же устройство (рекомендуется)" \
            new "HWID этого сервера — займёт ещё одно место в лимите устройств")
        if [ "$c" = keep ]; then
            printf 'HWID=%s\nMODEL=%s\n' "$hw" "$(mf .model)" >"$CONF_DIR/hwid"; chmod 600 "$CONF_DIR/hwid"
        else
            rm -f "$CONF_DIR/hwid"; RST_NEWLINK=1
        fi
    fi
    # --- адрес для клиентов
    local dom ip pub; dom=$(mf .ep_domain); ip=$(mf .ep_ip)
    pub=$(curl -4 -s -m 8 https://ifconfig.me/ip 2>/dev/null)
    c=$(need menu "Адрес для подключения клиентов" "В копии: домен ${dom:-—}, IP ${ip:-—}.\nВнешний IP этого сервера сейчас: ${pub:-не удалось узнать}.\n\nДомен удобнее: при переезде достаточно поменять запись DNS." 17 \
        keep "Оставить как в копии" \
        domain "Указать домен (основной адрес)" \
        ip "Указать IP")
    case $c in
        domain) dom=$(need inp "Домен" "Доменное имя, которое указывает на внешний IP (DDNS MikroTik или запись у регистратора):" "${dom:-}" 10) ;;
        ip)     ip=$(need inp "IP-адрес" "Внешний (или локальный, если клиенты только в сети) IP:" "${pub:-$ip}" 10) ;;
    esac
    if [ -n "$dom" ] && [ "$c" != keep ]; then
        local r; r=$(getent ahostsv4 "$dom" | awk '{print $1}' | sort -u | tr '\n' ' ')
        if [ -z "$r" ]; then msg "Проверка домена" "Домен $dom пока не находится в DNS. Клиенты с ним не подключатся, пока запись не появится." 9
        elif [ -n "$pub" ] && ! grep -qw "$pub" <<<"$r"; then msg "Проверка домена" "Домен $dom указывает на $r,\nа внешний IP сервера — $pub.\n\nЕсли сервер за роутером с другим IP или DNS ещё обновляется — это может быть нормально." 11
        fi
    fi
    RST_DOM=$dom; RST_IP=$ip; RST_EXT_PORT=$(mf .wg_port)
    WG_HOST=${dom:-${ip:-$LAN_IP}}
}

restore_install() {
    clear; grapes; sleep 1
    msg "Восстановление из копии" "Мастер перенесёт шлюз на этот сервер из резервной копии бота (.vpngw):
подписки, серверы и режим, ключи и клиенты WireGuard, свои серверы VLESS, бот, админы, почта.\n
Понадобятся:
  • файл копии (на сервере, по ссылке или по SFTP)
  • пароль этой копии\n
Журнал: $LOG" 17
    step_packages
    restore_get
    restore_summary
    restore_place
    step_network          # после копии: в install.conf из копии адрес и интерфейс старого сервера
    restore_questions
    step_subscription
    detect_current
    # серверы и режим — из копии, без вопросов
    MODE=$(jq -r '.mode // "stable"' <<<"$CUR_VPN"); ROUTING=$(jq -r '.routing // "smart"' <<<"$CUR_VPN")
    INTERVAL=$(jq -r '.interval // 300' <<<"$CUR_VPN"); TOL=$(jq -r '.tolerance // 300' <<<"$CUR_VPN")
    mapfile -t EXCLUDED < <(jq -r '.excluded // [] | .[]' <<<"$CUR_VPN")
    step_mihomo
    python3 /usr/local/bin/vpnbot.py --mark-applied >>"$LOG" 2>&1
    step_wireguard
    step_bot              # новый токен спрашиваем здесь: Telegram из России доступен только через mihomo
    [ "${RST_EMAIL:-}" = new ] && step_email
    step_timezone
    mkdir -p /var/lib/vpngw
    M=$RST/manifest.json NEWLINK=${RST_NEWLINK:-0} python3 - <<'PY' >>"$LOG" 2>&1
import json, os
m = json.load(open(os.environ["M"]))
json.dump({"created": m.get("created_text"), "from_host": m.get("host"), "version": m.get("version"),
           "new_link": os.environ["NEWLINK"] == "1"}, open("/var/lib/vpngw/restored.json", "w"), ensure_ascii=False)
PY
    rm -rf "$RST"
    step_finish
    msg "Не забудьте" "1. На роутере проброс UDP-порта ${RST_EXT_PORT:-$WG_PORT} должен вести на НОВЫЙ адрес: $LAN_IP:$WG_PORT.
   MikroTik: /ip firewall nat set [find chain=dstnat comment~\"vpn-gateway\"] to-addresses=$LAN_IP
2. Домен для клиентов (${RST_DOM:-не задан}) должен указывать на внешний IP.
3. Старый сервер выключите или остановите на нём mihomo, WireGuard и бота.
4. Если MikroTik подключён к шлюзу по локальному адресу — поменяйте endpoint-address на $LAN_IP.\n
Бот пришлёт сообщение «♻️ Шлюз восстановлен»." 17
}

uninstall() {
    ask "Удаление" "Удалить VPN-шлюз с этого сервера?\n\nБудут остановлены и удалены mihomo, WireGuard (wg0) и бот.\nПеред удалением настройки и ключи клиентов сохранятся в архив в /root." 13 1 || return
    local bak="/root/vpngw-backup-$(date +%Y%m%d-%H%M).tar.gz"
    tar czf "$bak" /etc/mihomo /etc/wireguard /etc/vpngw /etc/vpnbot.env /etc/vpnnotify.env /var/lib/vpnbot \
        /root/wg-clients 2>/dev/null; chmod 600 "$bak"
    for s in vpnbot wg-quick@wg0 mihomo; do run systemctl disable --now "$s"; done
    rm -rf /etc/systemd/system/vpnbot.service /etc/systemd/system/mihomo.service /etc/systemd/system/mihomo.service.d \
        /etc/systemd/system/wg-quick@wg0.service.d /etc/wireguard/wg0.conf /etc/vpnbot.env /etc/vpnnotify.env \
        /var/lib/vpnbot /usr/local/bin/vpnbot.py /usr/local/bin/vpngw /usr/local/bin/vpngw-setup \
        /usr/local/lib/vpngw /var/lib/vpngw "$CONF_DIR" /etc/sysctl.d/99-vpngw.conf
    run systemctl daemon-reload
    ask "Удаление" "Удалить и сам пакет mihomo с его папкой /etc/mihomo?" 8 && { run apt-get -o DPkg::Lock::Timeout=900 remove -y mihomo; rm -rf /etc/mihomo; }
    msg "Удалено" "VPN-шлюз удалён.\nРезервная копия: $bak" 9
    clear; exit 0
}

# ================================================================ обновление
# Защита от утечки: пока mihomo перезапускается, трафик из туннеля блокируется, а не идёт напрямую.
ensure_killswitch() {
    local f=/etc/wireguard/wg0.conf
    [ -f "$f" ] || return 0
    if ! grep -q 'prohibit priority 101' "$f"; then
        cp -a "$f" "$f.bak-killswitch"
        sed -i -E 's#^(PostUp = .*)$#\1; ip rule add iif wg0 prohibit priority 101#; s#^(PostDown = .*)$#\1; ip rule del iif wg0 prohibit priority 101#' "$f"
        log "wg0.conf: добавлена защита от утечки"
    fi
    if ip link show wg0 >/dev/null 2>&1 && ! ip rule show | grep -q 'iif wg0 prohibit'; then
        ip rule add iif wg0 prohibit priority 101 && log "правило защиты от утечки применено"
    fi
}

# Без вопросов: обновляет бота и vpngw, проверяет запуск, при неудаче откатывает.
self_update() {
    mkdir -p /var/lib/vpngw/backup "$CONF_DIR"; touch "$LOG"
    log "===== самообновление до $GW_VERSION"
    local B=/var/lib/vpngw/backup
    unpack "$P_VPNBOT" "$TMP/vpnbot.py" && unpack "$P_VPNGW" "$TMP/vpngw.py" \
        && python3 -m py_compile "$TMP/vpnbot.py" "$TMP/vpngw.py" \
        || { echo "fail встроенные файлы новой версии повреждены" >"$UPD_RESULT"; return 1; }
    rm -f "$B"/*
    cp -a /usr/local/bin/vpnbot.py "$B/vpnbot.py" 2>/dev/null
    cp -a /usr/local/lib/vpngw/vpngw.py "$B/vpngw.py" 2>/dev/null
    cp -a /usr/local/lib/vpngw/install.sh "$B/install.sh" 2>/dev/null
    cp -a "$CONF_DIR/version" "$B/version" 2>/dev/null
    install -m 700 -o root -g root "$TMP/vpnbot.py" /usr/local/bin/vpnbot.py
    install_tools
    ensure_killswitch
    grep -q '^UPDATE_REPO=' /etc/vpnbot.env 2>/dev/null || printf 'UPDATE_REPO=%s\nUPDATE_BRANCH=%s\n' "$REPO" "$BRANCH" >>/etc/vpnbot.env
    if ! systemctl is-enabled --quiet vpnbot 2>/dev/null; then
        echo "$GW_VERSION" >"$CONF_DIR/version"
        echo "ok $GW_VERSION" >"$UPD_RESULT"; log "бот не установлен — обновлены только файлы"; return 0
    fi
    rm -f /var/lib/vpnbot/alive
    systemctl restart vpnbot
    local i
    for i in $(seq 1 60); do
        sleep 1
        if [ -f /var/lib/vpnbot/alive ] && systemctl is-active --quiet vpnbot; then
            echo "$GW_VERSION" >"$CONF_DIR/version"; echo "ok $GW_VERSION" >"$UPD_RESULT"; log "обновление успешно"; return 0
        fi
    done
    log "новая версия не запустилась — откат"
    [ -f "$B/vpnbot.py" ] && install -m 700 "$B/vpnbot.py" /usr/local/bin/vpnbot.py
    [ -f "$B/vpngw.py" ] && install -m 755 "$B/vpngw.py" /usr/local/lib/vpngw/vpngw.py
    [ -f "$B/install.sh" ] && install -m 700 "$B/install.sh" /usr/local/lib/vpngw/install.sh
    [ -f "$B/version" ] && cp "$B/version" "$CONF_DIR/version"
    echo "fail версия $GW_VERSION не запустилась за минуту: $(journalctl -u vpnbot -n 3 --no-pager 2>/dev/null | tail -1 | cut -c1-200)" >"$UPD_RESULT"
    systemctl restart vpnbot
    return 1
}

check_updates_interactive() {
    info "Проверяю обновления на GitHub…"
    local ver latest sha
    ver=$(curl -fsSL -m 20 "$RAW/VERSION?t=$(date +%s)" 2>>"$LOG" || curl -fsSL -m 20 -x http://127.0.0.1:7890 "$RAW/VERSION" 2>>"$LOG")
    latest=$(awk 'NR==1{print $1}' <<<"$ver"); sha=$(awk 'NR==1{print $2}' <<<"$ver")
    [ -n "$latest" ] || { msg "Обновления" "Не удалось связаться с GitHub ($RAW)." 9; return; }
    if [ "$(printf '%s\n%s\n' "$GW_VERSION" "$latest" | sort -V | tail -1)" = "$GW_VERSION" ]; then
        msg "Обновления" "У вас последняя версия: $GW_VERSION." 8; return
    fi
    ask "Обновления" "Доступна версия $latest (у вас $GW_VERSION).\n\nОбновить бота и утилиты? Настройки и клиенты сохранятся, VPN не прервётся." 11 || return
    mkdir -p "$UPD_DIR"
    curl -fsSL -m 120 -o "$UPD_DIR/install.sh" "$RAW/install.sh?t=$(date +%s)" 2>>"$LOG" \
        || curl -fsSL -m 120 -x http://127.0.0.1:7890 -o "$UPD_DIR/install.sh" "$RAW/install.sh" 2>>"$LOG" \
        || { msg "Обновления" "Не удалось скачать install.sh." 8; return; }
    if [ -n "$sha" ] && [ "$(sha256sum "$UPD_DIR/install.sh" | cut -d' ' -f1)" != "$sha" ]; then
        msg "Обновления" "Контрольная сумма не совпала — файл на GitHub ещё обновляется. Попробуйте через пару минут." 9; return
    fi
    info "Обновляю…"
    bash "$UPD_DIR/install.sh" --self-update
    msg "Обновления" "Результат: $(cat "$UPD_RESULT" 2>/dev/null || echo неизвестно)\n\nМеню установщика тоже обновлено — откройте его заново: sudo vpngw-setup" 11
    clear; exit 0
}

# ================================================================ запуск
if [ "${1:-}" = "--self-update" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "нужен root"; exit 1; }
    self_update; exit $?
fi
preflight
if [ -f "$CONF_DIR/installed" ]; then
    command -v vpngw >/dev/null && [ -x /usr/local/bin/vpngw-setup ] || install_tools
    main_menu
else
    c=$(menu "VPN-шлюз v$GW_VERSION" "Что сделать?" 13 \
        new "Новая установка" \
        restore "Восстановить из резервной копии (переезд на этот сервер)") || exit 0
    if [ "$c" = restore ]; then restore_install; else full_install; fi
fi
clear
grapes
cat "$SUMMARY" 2>/dev/null
