#!/usr/bin/env python3
# Telegram-бот для VPN-шлюза: mihomo + WireGuard + MikroTik.
# Только стандартная библиотека Python, внешних зависимостей нет.
BOT_VERSION = '1.7.1'   # подставляется build.sh из файла VERSION
import base64
import calendar
import hashlib
import html
import ipaddress
import platform
import sys
import json
import os
import re
import shlex
import shutil
import smtplib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import traceback
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

# ---------------- настройки ----------------
ENV_FILE = '/etc/vpnbot.env'
STATE_FILE = '/var/lib/vpnbot/state.json'
MIHOMO_CFG = '/etc/mihomo/config.yaml'
MIHOMO_TEST_CFG = '/etc/mihomo/config.test.yaml'
MIHOMO_BAK_CFG = '/etc/mihomo/config.yaml.bak-bot'
NOTIFY_ENV = '/etc/vpnnotify.env'
VERSION_FILE = '/etc/vpngw/version'
UPDATE_DIR = '/var/lib/vpngw/update'
UPDATE_RESULT = '/var/lib/vpngw/update-result'
ALIVE_FILE = '/var/lib/vpnbot/alive'
GEO_DIR = '/etc/mihomo'
GEO_MARK = '/etc/mihomo/.geo-source'
GEO_SRC = 'runetfreedom'
GEO_URL = 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/'
RU_DNS = ['77.88.8.8', '77.88.8.1']
GB = 1 << 30
SUB_REMIND = (1, 2, 3)            # за сколько дней напоминать об окончании подписки
SRV_DEFAULTS = {'disk': 90, 'ram': 90, 'load': 2.0}
# сервисы, которые можно отправить через выбранную подписку (категории баз runetfreedom/v2fly)
SERVICES = {
    'google': ('Google: поиск, аккаунт, Gemini, Gmail', ['GEOSITE,google', 'GEOSITE,google-gemini',
                                                         'GEOSITE,google-deepmind']),
    'youtube': ('YouTube', ['GEOSITE,youtube']),
    'openai': ('ChatGPT', ['GEOSITE,openai']),
    'ai': ('Другие зарубежные ИИ (Claude, Copilot…)', ['GEOSITE,category-ai-!cn']),
    'telegram': ('Telegram', ['GEOSITE,telegram', 'GEOIP,telegram,no-resolve']),
    'meta': ('Instagram, Facebook, WhatsApp', ['GEOSITE,meta', 'GEOSITE,facebook', 'GEOIP,facebook,no-resolve']),
    'netflix': ('Netflix', ['GEOSITE,netflix', 'GEOIP,netflix,no-resolve']),
    'spotify': ('Spotify', ['GEOSITE,spotify']),
}
# Режим «Только выбранные сервисы» (как маршруты на MikroTik): через VPN — только отмеченное, остальное напрямую.
# Домены сервисов шлюз видит сам (DNS клиентов идёт через него), а для приложений, которые ходят прямо на IP
# (Telegram, Meta, X, Netflix), добавлены их подсети.
LIST_CATALOG = {
    'youtube': ('YouTube', ['GEOSITE,youtube'], True),
    'telegram': ('Telegram', ['GEOSITE,telegram', 'GEOIP,telegram,no-resolve'], True),
    'whatsapp': ('WhatsApp', ['GEOSITE,whatsapp'], True),
    'meta': ('Instagram, Facebook, Threads', ['GEOSITE,instagram', 'GEOSITE,facebook', 'GEOSITE,meta',
                                              'GEOIP,facebook,no-resolve'], True),
    'twitter': ('X (Twitter)', ['GEOSITE,twitter', 'GEOSITE,x', 'GEOIP,twitter,no-resolve'], True),
    'discord': ('Discord', ['GEOSITE,discord'], True),
    'ai': ('ChatGPT, Claude, Grok, Perplexity и другие ИИ', ['GEOSITE,openai', 'GEOSITE,anthropic', 'GEOSITE,xai',
                                                            'GEOSITE,perplexity', 'GEOSITE,category-ai-!cn'], True),
    'gemini': ('Gemini и Google AI Studio', ['GEOSITE,google-gemini', 'GEOSITE,google-deepmind'], True),
    'dev': ('Cursor, GitHub, Docker, JetBrains', ['GEOSITE,cursor', 'GEOSITE,github', 'GEOSITE,docker',
                                                  'GEOSITE,jetbrains'], True),
    'work': ('Notion, Figma, Canva, Slack, Zoom', ['GEOSITE,notion', 'GEOSITE,figma', 'GEOSITE,canva',
                                                   'GEOSITE,slack', 'GEOSITE,zoom'], True),
    'linkedin': ('LinkedIn', ['GEOSITE,linkedin'], True),
    'media': ('Reddit, Medium, Pinterest, Quora, Patreon, SoundCloud, Tumblr',
              ['GEOSITE,reddit', 'GEOSITE,medium', 'GEOSITE,pinterest', 'GEOSITE,quora', 'GEOSITE,patreon',
               'GEOSITE,soundcloud', 'GEOSITE,tumblr'], True),
    'tiktok': ('TikTok', ['GEOSITE,tiktok'], True),
    'signal': ('Signal, Viber', ['GEOSITE,signal', 'GEOSITE,viber'], True),
    'netflix': ('Netflix', ['GEOSITE,netflix', 'GEOIP,netflix,no-resolve'], True),
    'spotify': ('Spotify', ['GEOSITE,spotify'], True),
    'twitch': ('Twitch', ['GEOSITE,twitch'], False),
    'google': ('Google целиком (поиск, Gmail, Диск)', ['GEOSITE,google', 'GEOIP,google,no-resolve'], False),
    'microsoft': ('Microsoft (Copilot, OneDrive, обновления — много трафика)', ['GEOSITE,microsoft'], False),
    'hw': ('Драйверы Intel и NVIDIA', ['GEOSITE,intel', 'GEOSITE,nvidia'], False),
    'blocked': ('Всё остальное заблокированное в РФ (список РКН)', ['GEOSITE,ru-blocked',
                                                                   'GEOIP,ru-blocked,no-resolve'], False),
}
LIST_DEFAULT = [k for k, x in LIST_CATALOG.items() if x[2]]


def via_rule(x, target):
    """'GEOIP,telegram,no-resolve' → 'GEOIP,telegram,PROXY,no-resolve'"""
    a = x.split(',')
    return f'{a[0]},{a[1]},{target}' + (',no-resolve' if x.endswith('no-resolve') else '')


API = 'http://127.0.0.1:9090'
PROXY_URL = 'http://127.0.0.1:7890'
PROVIDER = 'sub'
SELECT_GROUP = 'PROXY'
AUTO_GROUP = 'AUTO'
WG_IF = 'wg0'
WG_CONF = f'/etc/wireguard/{WG_IF}.conf'
PEERS_PAGE = 8
WATCH_EVERY = 30          # как часто проверять состояние, сек
TRAFFIC_EVERY = 60        # как часто учитывать трафик, сек
WG_STALE = 210            # туннель считается упавшим, если рукопожатия не было дольше, сек
SPEED_URL = 'https://fsn1-speed.hetzner.com/1GB.bin'
SPEED_BYTES = 25_000_000
HIDE_RE = re.compile(r'поддерживается|Превышено', re.I)
MODES = {
    'fast': '⚡ Самый быстрый',
    'stable': '🛡 Стабильный',
    'priority': '📋 По приоритету',
    'custom': '🎛 Свои настройки',
}
MODE_HELP = {
    'fast': 'Всегда самый быстрый сервер. Переключается часто, из-за этого могут рваться звонки и загрузки.',
    'stable': 'Держится за текущий сервер и меняет его, только если он упал или другой заметно быстрее. Рекомендуется.',
    'priority': 'Работает через первый живой сервер из вашего списка. Упал — берёт следующий, вернулся — возвращается к нему.',
    'custom': 'Ваши значения интервала проверки и порога переключения.',
}
PRESETS = {'fast': (120, 50), 'stable': (300, 300)}
INTERVALS = [30, 60, 120, 300, 600, 1800]
TOLERANCES = [30, 50, 100, 200, 300, 500, 1000]
CFG_FORMAT = 5            # 4: замеры пинга и скорости всегда через выбранный сервер; 5: MAX и проверки IP — напрямую
# Российские приложения (MAX и т.п.) узнают внешний IP через несколько сервисов и сравнивают ответы.
# Если часть проверок уходит через VPN, адреса расходятся, и приложение жалуется на VPN.
# Поэтому сами приложения и эти сервисы всегда идут напрямую, в любом режиме маршрутизации.
RU_APPS_DIRECT = ['DOMAIN-SUFFIX,max.ru', 'DOMAIN-SUFFIX,oneme.ru', 'DOMAIN-SUFFIX,okcdn.ru',
                  'DOMAIN-SUFFIX,gosuslugi.ru', 'DOMAIN-SUFFIX,trace-flow.ru',
                  'DOMAIN-SUFFIX,ifconfig.me', 'DOMAIN,api.ipify.org', 'DOMAIN,checkip.amazonaws.com',
                  'DOMAIN,ipv4-internet.yandex.net', 'DOMAIN,ipv6-internet.yandex.net', 'DOMAIN,ip.mail.ru',
                  'IP-CIDR,155.212.204.0/24']
# свой адрес выхода бот узнаёт через сервис, которого нет в списке выше
EXIT_IP_URLS = ('https://ipv4.icanhazip.com', 'https://ipinfo.io/ip')
WG_IOS = 'https://apps.apple.com/app/wireguard/id1441195209'
WG_ANDROID = 'https://play.google.com/store/apps/details?id=com.wireguard.android'
AMNEZIA_NOTE = 'Если у вас уже стоит AmneziaWG (или AmneziaVPN), можно сканировать QR-код ею — WireGuard ставить не нужно.'
NOTIFY_KINDS = [
    ('switch', '🔁 Смена сервера'),
    ('dead', '🔴 Недоступность VPN'),
    ('tunnel', '🔌 Связь с MikroTik и пирами'),
    ('billing', '📅 Подписка, сроки и лимиты клиентов'),
    ('server', '🖥 Состояние сервера (диск, память, нагрузка)'),
    ('actions', '👤 Действия админов, запуск, обновления'),
    ('backup', '💾 Резервные копии'),
]
UI_FILE = '/var/lib/vpnbot/ui.json'      # чистый чат: живое меню, отправленные сообщения, таймеры удаления
CLEAN_DEFAULTS = {'files': 3600, 'backup': 86400, 'notif': 86400}
CLEAN_TTLS = [(600, '10 мин'), (3600, '1 час'), (86400, '24 часа'), (0, 'не удалять')]
TG_DEL_MAX = 47 * 3600                   # Telegram даёт удалять сообщения только в первые 48 часов


def log(*a):
    print(time.strftime('%d.%m %H:%M:%S'), *a, flush=True)


def load_env():
    env = {}
    if not os.path.exists(ENV_FILE):
        return env
    with open(ENV_FILE, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env


CLI_MODE = len(sys.argv) > 1 and sys.argv[1].startswith('--')
ENV = load_env()
if not CLI_MODE and not ENV.get('BOT_TOKEN'):
    sys.exit(f'Нет BOT_TOKEN в {ENV_FILE}')
TOKEN = ENV.get('BOT_TOKEN', '')
OWNER = int(ENV.get('ADMIN_ID') or 0)
UPDATE_REPO = ENV.get('UPDATE_REPO', 'vvinograd/vpn-gateway')
UPDATE_BRANCH = ENV.get('UPDATE_BRANCH', 'main')
WG_NET = ENV.get('WG_NET', '10.10.10')            # первые три октета подсети туннеля
WG_ENDPOINT_DEFAULT = ENV.get('WG_ENDPOINT', '')  # адрес для подключения клиентов
SHOW_MIKROTIK = ENV.get('MIKROTIK', '1') != '0'
GW_NAME = ENV.get('GW_NAME', 'VPN-шлюз')
try:
    with open(MIHOMO_CFG, encoding='utf-8') as _f:
        SECRET = re.search(r'^secret:\s*(\S+)', _f.read(), re.M).group(1)
except Exception:
    if not CLI_MODE:
        raise
    SECRET = ''

h = html.escape
proxy_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({'http': PROXY_URL, 'https': PROXY_URL}))
direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# ---------------- состояние ----------------
lock = threading.RLock()
state = {'admins': {}, 'events': [], 'traffic': {}, 'pending': {}, 'rejected': {}, 'last_raw': None,
         'vpn': None, 'email': None, 'wg': None}
awaiting = {}
last_manual = [0.0]       # когда админ последний раз менял сервер вручную
prio_streak = {}
speed_lock = threading.Lock()


def default_notify():
    return {k: True for k, _ in NOTIFY_KINDS}


def save_state():
    with lock:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)


def load_state():
    try:
        with open(STATE_FILE, encoding='utf-8') as f:
            state.update(json.load(f))
    except FileNotFoundError:
        pass
    except Exception as e:
        log('ошибка чтения состояния:', e)
    state.setdefault('rejected', {})
    adm = state['admins']
    if OWNER and str(OWNER) not in adm:
        adm[str(OWNER)] = {'name': str(OWNER), 'notify': default_notify()}
    for a in adm.values():
        a.setdefault('notify', default_notify())
        for k, _ in NOTIFY_KINDS:
            a['notify'].setdefault(k, True)
    save_state()


def is_admin(uid):
    return str(uid) in state['admins']


def is_owner(uid):
    return uid == OWNER


def admin_name(uid):
    a = state['admins'].get(str(uid))
    return a['name'] if a else str(uid)


def user_label(u):
    name = ' '.join(x for x in (u.get('first_name'), u.get('last_name')) if x) or str(u.get('id'))
    if u.get('username'):
        name += f' (@{u["username"]})'
    return name


def touch_admin(u):
    a = state['admins'].get(str(u['id']))
    if a is not None:
        name = user_label(u)
        if a.get('name') != name:
            with lock:
                a['name'] = name
                save_state()


def add_event(text):
    with lock:
        state['events'].append([time.time(), text])
        state['events'] = state['events'][-100:]
        save_state()


# ---------------- Telegram ----------------
def tg(method, _timeout=20, **params):
    if LINK_MODE:                         # ведомый шлюз: в Telegram ходит главный бот
        if method in ('getUpdates', 'setMyCommands', 'getMe'):
            return None
        return link_call({'t': 'call', 'm': method, 'p': params}, _timeout + 15)
    data = json.dumps(params).encode()
    url = f'https://api.telegram.org/bot{TOKEN}/{method}'
    last = None
    # сначала через VPN, если mihomo лежит — напрямую
    for opener in (proxy_opener, direct_opener):
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=_timeout) as r:
                return json.load(r).get('result')
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='ignore')
            if not re.search(r'message is not modified|message to (delete|edit) not found|'
                             r"message can't be (deleted|edited)", body):
                log('Telegram', method, e.code, body[:200])
            return None
        except Exception as e:
            last = e
    log('Telegram недоступен:', method, last)
    return None


def tg_file(method, chat, field, filename, content, caption=None, kb=None, ttl_kind='files'):
    if LINK_MODE:
        res = link_call({'t': 'file', 'm': method, 'chat': chat, 'field': field, 'filename': filename,
                         'b64': base64.b64encode(content).decode(), 'caption': caption, 'kb': kb}, 150)
        if res and ttl_kind:
            track(chat, res['message_id'], clean_ttl(chat, ttl_kind))
        return res
    boundary = uuid.uuid4().hex
    parts = []

    def add(name, value):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    add('chat_id', chat)
    if caption:
        add('caption', caption)
        add('parse_mode', 'HTML')
    if kb:
        add('reply_markup', json.dumps({'inline_keyboard': kb}))
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n'.encode() + content + b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    data = b''.join(parts)
    url = f'https://api.telegram.org/bot{TOKEN}/{method}'
    for opener in (proxy_opener, direct_opener):
        req = urllib.request.Request(url, data=data, headers={
            'Content-Type': f'multipart/form-data; boundary={boundary}'})
        try:
            with opener.open(req, timeout=120) as r:
                res = json.load(r).get('result')
            if res and ttl_kind:
                track(chat, res['message_id'], clean_ttl(chat, ttl_kind))
            return res
        except urllib.error.HTTPError as e:
            log('Telegram', method, e.code, e.read().decode(errors='ignore')[:200])
            return None
        except Exception as e:
            log('Telegram недоступен:', method, e)
    return None


def btn(text, data):
    return {'text': text, 'callback_data': data}


# ---------------- чистый чат ----------------
# В чате всегда одно «живое» меню. Ответы на ввод и новые экраны заменяют его (старое удаляется),
# сообщения админа удаляются после обработки, файлы и уведомления — по таймеру.
CTX = threading.local()          # чат, для которого сейчас обрабатывается нажатие или сообщение
ui = {'menu': {}, 'msgs': {}, 'del': []}
ui_lock = threading.Lock()


def ui_load():
    try:
        with open(UI_FILE, encoding='utf-8') as f:
            d = json.load(f)
        for k in ui:
            if isinstance(d.get(k), type(ui[k])):
                ui[k] = d[k]
    except FileNotFoundError:
        pass
    except Exception as e:
        log('ошибка чтения ui.json:', e)


def ui_save():
    with ui_lock:
        try:
            os.makedirs(os.path.dirname(UI_FILE), exist_ok=True)
            tmp = UI_FILE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(ui, f)
            os.replace(tmp, UI_FILE)
        except Exception as e:
            log('ui.json:', e)


def clean_cfg(uid):
    a = state['admins'].get(str(uid))
    if a is None:
        return dict(CLEAN_DEFAULTS)
    c = a.setdefault('clean', {})
    for k, v in CLEAN_DEFAULTS.items():
        c.setdefault(k, v)
    return c


def clean_ttl(chat, kind):
    if kind in ('keep', None):
        return None
    try:
        return clean_cfg(chat).get(kind) or None
    except Exception:
        return None


def track(chat, mid, ttl=None):
    """Запомнить сообщение бота (для «Очистить чат») и, если нужно, когда его удалить."""
    now = time.time()
    with ui_lock:
        msgs = ui['msgs'].setdefault(str(chat), {})
        msgs[str(mid)] = now
        for k in [k for k, t in msgs.items() if now - t > 48 * 3600]:
            msgs.pop(k, None)
        if ttl:
            ui['del'].append([now + min(ttl, TG_DEL_MAX), chat, mid])
    ui_save()


def tg_del(chat, mid):
    """Удалить сообщение; если Telegram не даёт (старше 48 часов) — хотя бы убрать кнопки."""
    with ui_lock:
        ui['msgs'].get(str(chat), {}).pop(str(mid), None)
    if tg('deleteMessage', chat_id=chat, message_id=mid):
        return True
    tg('editMessageReplyMarkup', chat_id=chat, message_id=mid, reply_markup={'inline_keyboard': []})
    return False


def del_tick():
    now = time.time()
    with ui_lock:
        due = [d for d in ui['del'] if d[0] <= now]
        ui['del'] = [d for d in ui['del'] if d[0] > now]
    for _, chat, mid in due:
        if ui['menu'].get(str(chat)) != mid:
            tg_del(chat, mid)
    if due:
        ui_save()


def set_menu(chat, mid):
    """Сделать сообщение живым меню чата; прежнее меню удаляется."""
    with ui_lock:
        old = ui['menu'].get(str(chat))
        ui['menu'][str(chat)] = mid
        ui['del'] = [d for d in ui['del'] if not (d[1] == chat and d[2] == mid)]
    if old and old != mid:
        tg_del(chat, old)
    ui_save()


def raw_send(chat, text, kb=None, ttl_kind=None):
    p = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
    if kb:
        p['reply_markup'] = {'inline_keyboard': kb}
    r = tg('sendMessage', **p)
    if r:
        track(chat, r['message_id'], clean_ttl(chat, ttl_kind))
    return r


def send(chat, text, kb=None):
    # В ответ на действие админа в его чате — это новый экран: он заменяет живое меню.
    if getattr(CTX, 'chat', None) != chat:
        return raw_send(chat, text, kb)
    if kb is None and '/cancel' in text:
        kb = [[btn('✖️ Отмена', 'menu')]]
    r = raw_send(chat, text, kb)
    if r:
        set_menu(chat, r['message_id'])
    return r


def edit(chat, mid, text, kb=None):
    p = {'chat_id': chat, 'message_id': mid, 'text': text, 'parse_mode': 'HTML',
         'disable_web_page_preview': True}
    if kb:
        p['reply_markup'] = {'inline_keyboard': kb}
    return tg('editMessageText', **p)


IMPORTANT = ('dead', 'tunnel', 'server', 'billing')


def notify(kind, text, exclude=None, keep=None):
    """keep=True — важное: висит, пока не нажмут «✔️ Понятно». Иначе удаляется по таймеру админа."""
    if keep is None:
        keep = kind in IMPORTANT and not text.startswith('🟢')
    text = gw_prefix(text)
    with lock:
        targets = [int(uid) for uid, a in state['admins'].items()
                   if a['notify'].get(kind, True) and int(uid) != exclude
                   and (LINK_MODE or 'm' in gw_allowed(int(uid)))]
    for uid in targets:
        raw_send(uid, text, [[btn('✔️ Понятно', 'ok'), btn('🏠 Меню', 'nmenu')]],
                 ttl_kind='keep' if keep else 'notif')
    mail_async(kind, text)


def clean_chat(chat):
    """Удалить всё, что можно, кроме живого меню: известные сообщения бота и последние 500 по номерам."""
    live = ui['menu'].get(str(chat))
    with ui_lock:
        known = [int(m) for m in ui['msgs'].get(str(chat), {}) if int(m) != live]
    n = 0
    for i in range(0, len(known), 100):
        part = known[i:i + 100]
        if tg('deleteMessages', chat_id=chat, message_ids=part):
            n += len(part)
        else:
            n += sum(1 for m in part if tg('deleteMessage', chat_id=chat, message_id=m))
    if live:
        rest = [m for m in range(max(live - 500, 1), live) if m not in known]
        for i in range(0, len(rest), 100):
            tg('deleteMessages', chat_id=chat, message_ids=rest[i:i + 100])
    with ui_lock:
        ui['msgs'][str(chat)] = {str(live): time.time()} if live else {}
        ui['del'] = [d for d in ui['del'] if d[1] != chat]
    ui_save()
    return n


# ---------------- почта ----------------
def read_env_file(path):
    env = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env


def email_cfg():
    e = state.get('email')
    if e is None:
        e = {'enabled': False, 'to': [], 'smtp': {}, 'last_error': '',
             'kinds': {k: k != 'actions' for k, _ in NOTIFY_KINDS}}
        try:
            env = read_env_file(NOTIFY_ENV)
            e['smtp'] = {'host': env['SMTP_HOST'], 'port': int(env.get('SMTP_PORT', '465')),
                         'user': env['SMTP_USER'], 'pass': env['SMTP_PASS']}
            e['to'] = [x.strip() for x in env.get('MAIL_TO', '').split(',') if x.strip()]
            e['enabled'] = bool(e['to'])
        except Exception:
            pass
        with lock:
            state['email'] = e
            save_state()
    e['kinds'].setdefault('billing', True)
    return e


def plain(text):
    return html.unescape(re.sub(r'<[^>]+>', '', text))


def smtp_connect(cfg):
    ctx = ssl.create_default_context()
    port = int(cfg.get('port', 465))
    if port == 465:
        s = smtplib.SMTP_SSL(cfg['host'], port, context=ctx, timeout=20)
    else:
        s = smtplib.SMTP(cfg['host'], port, timeout=20)
        s.starttls(context=ctx)
    s.login(cfg['user'], cfg['pass'])
    return s


def send_mail(subject, body, to=None, html_body=None, attachments=(), inline=()):
    """attachments/inline: [(имя или cid, bytes, maintype, subtype)]."""
    e = email_cfg()
    cfg = e['smtp']
    to = to or e['to']
    if not cfg.get('host') or not to:
        raise RuntimeError('почта не настроена: нет отправителя или получателей')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = formataddr((e.get('from_name') or GW_NAME, cfg['user']))
    msg['To'] = ', '.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype='html')
        part = msg.get_payload()[-1]
        for cid, data, maintype, subtype in inline:
            part.add_related(data, maintype=maintype, subtype=subtype, cid=f'<{cid}>')
    for fname, data, maintype, subtype in attachments:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    with smtp_connect(cfg) as s:
        s.send_message(msg)


def mail_async(kind, text):
    e = email_cfg()
    if not (e['enabled'] and e['kinds'].get(kind) and e['to'] and e['smtp'].get('host')):
        return
    body = plain(text).strip()
    subject = f'{GW_NAME}: ' + body.split('\n')[0].strip()
    body += f'\n\nВремя: {time.strftime("%d.%m.%Y %H:%M:%S")}'

    def worker():
        try:
            send_mail(subject, body)
        except Exception as ex:
            log('ошибка почты:', ex)
            with lock:
                e['last_error'] = f'{time.strftime("%d.%m %H:%M")} {ex}'
                save_state()
    threading.Thread(target=worker, daemon=True).start()


# ---------------- mihomo и система ----------------
def api(path, method='GET', body=None, timeout=8):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        'Authorization': 'Bearer ' + SECRET, 'Content-Type': 'application/json'})
    with direct_opener.open(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw.strip() else None


def tag(name):
    return format(zlib.crc32(name.encode()), '08x')


def q(s):
    return urllib.parse.quote(s, safe='')


# ---------------- подписки (одна или несколько) ----------------
SUB_UAS = ['FlClashX/0.8.80', 'clash-verge/v2.2.3', 'mihomo/1.19.12']
SRV_PROV = {}            # имя сервера → id подписки
PROV_DIR = '/etc/mihomo/providers'


def parse_providers(txt):
    """Читает блок proxy-providers из существующего конфига (для перехода со старых версий)."""
    out, cur, in_block, in_hdr = [], None, False, False
    for line in txt.split('\n'):
        if re.match(r'^[A-Za-z]', line):
            in_block = line.startswith('proxy-providers:')
            continue
        if not in_block:
            continue
        m = re.match(r'^  ([\w-]+):\s*$', line)
        if m:
            cur = {'id': m.group(1), 'name': 'Основная' if not out else m.group(1), 'type': 'http',
                   'url': '', 'ua': SUB_UAS[0], 'prefix': ''}
            out.append(cur)
            in_hdr = False
            continue
        if cur is None:
            continue
        m = re.match(r'^    ([\w-]+):\s*(.*)$', line)
        if m:
            k, val = m.group(1), m.group(2).strip().strip('"\'')
            in_hdr = k == 'header'
            if k in ('type', 'url'):
                cur[k] = val
            continue
        m = re.match(r'^      User-Agent:\s*\[(.*)\]', line)
        if m and in_hdr:
            cur['ua'] = m.group(1).strip().strip('"\'')
        m = re.match(r'^      additional-prefix:\s*(.*)$', line)
        if m:
            cur['prefix'] = m.group(1).strip().strip('"\'')
    return out


def subs():
    sl = state.get('subs')
    if sl is None:
        try:
            sl = parse_providers(open(MIHOMO_CFG, encoding='utf-8').read())
        except Exception:
            sl = []
        if not sl:
            sl = [{'id': PROVIDER, 'name': 'Основная', 'type': 'file', 'url': '', 'ua': SUB_UAS[0], 'prefix': ''}]
        with lock:
            state['subs'] = sl
            save_state()
    return sl


def sub_by_id(pid):
    return next((x for x in subs() if x['id'] == pid), None)


def device_headers():
    hwid, model = hwid_info()
    try:
        osv = re.search(r'^VERSION_ID="?([^"\n]*)', open('/etc/os-release').read(), re.M).group(1)
    except Exception:
        osv = ''
    return {'x-hwid': hwid, 'x-device-os': 'Linux', 'x-ver-os': osv,
            'x-device-model': model}


def build_providers():
    q = lambda x: json.dumps(x, ensure_ascii=False)
    out = ['proxy-providers:']
    for sb in subs():
        out.append(f'  {sb["id"]}:')
        if sb.get('type') == 'file':
            out += ['    type: file', f'    path: ./providers/{sb["id"]}.yaml']
        else:
            out += ['    type: http', f'    url: {q(sb["url"])}', f'    path: ./providers/{sb["id"]}.yaml',
                    '    interval: 43200', '    header:', f'      User-Agent: [{q(sb.get("ua") or SUB_UAS[0])}]']
            out += [f'      {k}: [{q(val)}]' for k, val in device_headers().items()]
        if sb.get('prefix'):
            out += ['    override:', f'      additional-prefix: {q(sb["prefix"])}']
    return '\n'.join(out) + '\n\n'


def provider(pid=None):
    return api(f'/providers/proxies/{pid or subs()[0]["id"]}')


def servers():
    res = []
    for sb in subs():
        try:
            for p in provider(sb['id']).get('proxies') or []:
                if not HIDE_RE.search(p['name']):
                    p['_prov'] = sb['id']
                    SRV_PROV[p['name']] = sb['id']
                    res.append(p)
        except Exception as e:
            log('provider', sb['id'], e)
    return res


def delay_of(p):
    hist = p.get('history') or []
    return hist[-1].get('delay', 0) if hist else 0


def fmt_delay(p):
    if not p.get('history'):
        return 'не проверялся'
    d = delay_of(p)
    return f'{d} мс' if d else 'нет ответа'


def server_info(name):
    if name not in SRV_PROV:
        try:
            servers()
        except Exception:
            pass
    try:
        return api(f'/providers/proxies/{SRV_PROV.get(name, subs()[0]["id"])}/{q(name)}') or {}
    except Exception:
        return {}


def mode_and_current():
    sel = api(f'/proxies/{SELECT_GROUP}')['now']
    if sel == AUTO_GROUP:
        return 'auto', api(f'/proxies/{AUTO_GROUP}')['now']
    v = state.get('vpn') or {}
    if v.get('mode') == 'priority' and not v.get('manual'):
        return 'priority', sel
    return 'manual', sel


TEST_URL = 'https://www.gstatic.com/generate_204'


def probe(name, tries=3):
    """Живой замер сервера через mihomo: задержка в мс или 0, если не отвечает ни с одной попытки."""
    if name not in SRV_PROV:
        try:
            servers()
        except Exception:
            pass
    prov = SRV_PROV.get(name)
    path = (f'/providers/proxies/{prov}/{q(name)}/healthcheck' if prov else f'/proxies/{q(name)}/delay')
    for i in range(tries):
        try:
            d = (api(f'{path}?url={q(TEST_URL)}&timeout=5000', timeout=8) or {}).get('delay')
            if d:
                return d
        except Exception:
            pass
        if i < tries - 1:
            time.sleep(3)
    return 0


def fallback_to_auto(dead):
    """Выбранный вручную сервер не отвечает — возвращаемся на автовыбор (и остаёмся на нём)."""
    v = vpn()
    with lock:
        v['manual'] = False
        save_state()
    last_manual[0] = time.time()
    if v['mode'] == 'priority':
        prio_tick(force=True)
    else:
        api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': AUTO_GROUP})
    time.sleep(2)
    try:
        _, now = mode_and_current()
    except Exception:
        now = '?'
    how = 'по приоритету' if v['mode'] == 'priority' else 'автовыбор'
    add_event(f'Сервер {dead} не отвечает — включён {how} ({now})')
    notify('switch', f'⚠️ <b>Выбранный сервер не отвечает</b>\n\n{h(dead)} → <b>{h(now)}</b>\n'
                     f'Включён {how}. Вернуть сервер можно в «🌍 Серверы».')


MODE_RU = {'auto': 'авто', 'priority': 'по приоритету', 'manual': 'вручную'}


def snapshot(v):
    return {'interval': v['interval'], 'tolerance': v['tolerance'], 'excluded': sorted(v['excluded']),
            'routing': v.get('routing', 'all'), 'rules_direct': list(v.get('rules_direct', [])),
            'rules_proxy': list(v.get('rules_proxy', [])), 'svc': dict(sorted((v.get('svc') or {}).items())),
            'list_svc': sorted(v.get('list_svc', LIST_DEFAULT)), 'fmt': CFG_FORMAT}


ROUTING = {
    'smart': ('🧠 Умная', 'Заблокированное в РФ и зарубежные ИИ-сервисы — через VPN. Российские сайты '
                         '(.ru, .рф, .su, сервисы РФ, российские IP, сайты «только для России») — напрямую. '
                         'Всё остальное — через VPN. Рекомендуется.'),
    'list': ('📋 Только выбранные сервисы', 'Как маршруты на MikroTik: через VPN идут только сервисы из вашего '
                                         'списка (YouTube, Telegram, Instagram, ИИ и др.) и исключения «через VPN». '
                                         'Всё остальное, включая все российские сайты и приложения, — напрямую.'),
    'blocked': ('🎯 Только заблокированное', 'Через VPN идут только заблокированные в РФ ресурсы и зарубежные '
                                            'ИИ-сервисы, всё остальное — напрямую. Экономит трафик VPN, но '
                                            'сайты, которые сами не пускают из России, придётся добавлять в исключения.'),
    'all': ('🌐 Всё через VPN', 'Весь трафик идёт через VPN-сервер (кроме ваших исключений «напрямую»). '
                              'MAX и сервисы, по которым приложения проверяют IP, в любом режиме идут напрямую.'),
}


def detect_routing(txt):
    if re.search(r'^\s*-\s*MATCH,DIRECT', txt, re.M):
        return 'blocked' if re.search(r'^\s*-\s*GEOSITE,category-ai-ru,DIRECT', txt, re.M) else 'list'
    if re.search(r'^\s*-\s*GEOIP,RU,DIRECT', txt, re.M):
        return 'smart'
    return 'all'


def vpn_dirty(v):
    a = {k: x for k, x in (v.get('applied') or {}).items() if k != 'mode'}
    return snapshot(v) != a


def detect_mode(v):
    if v['mode'] == 'priority':
        return 'priority'
    for k, (iv, tol) in PRESETS.items():
        if (v['interval'], v['tolerance']) == (iv, tol):
            return k
    return 'custom'


def vpn():
    v = state.get('vpn')
    if v:
        return vpn_migrate(v)
    txt = open(MIHOMO_CFG, encoding='utf-8').read()
    sec = txt[txt.find('proxy-groups:'):]
    iv = re.search(r'^\s+interval:\s*(\d+)', sec, re.M)
    tol = re.search(r'^\s+tolerance:\s*(\d+)', sec, re.M)
    v = {'mode': 'custom', 'interval': int(iv.group(1)) if iv else 120,
         'tolerance': int(tol.group(1)) if tol else 50,
         'excluded': [p['name'] for p in servers() if re.search('Россия|Мобильный', p['name'])],
         'priority': [], 'manual': False, 'rules_direct': [], 'rules_proxy': []}
    v['routing'] = detect_routing(txt)
    v['mode'] = detect_mode(v)
    v['applied'] = dict(snapshot(v), fmt=1)
    with lock:
        state['vpn'] = v
        save_state()
    return v


def vpn_migrate(v):
    if 'svc' not in v:
        with lock:
            v['svc'] = {}
            if v.get('applied') is not None:
                v['applied'].setdefault('svc', {})
            save_state()
    if 'list_svc' not in v:
        with lock:
            v['list_svc'] = list(LIST_DEFAULT)
            if v.get('applied') is not None:
                v['applied'].setdefault('list_svc', sorted(LIST_DEFAULT))
            save_state()
    if 'routing' not in v or 'rules_direct' not in v:
        try:
            r = detect_routing(open(MIHOMO_CFG, encoding='utf-8').read())
        except Exception:
            r = 'all'
        with lock:
            v.setdefault('routing', r)
            v.setdefault('rules_direct', [])
            v.setdefault('rules_proxy', [])
            a = v.get('applied')
            if a is not None:
                a.setdefault('routing', v['routing'])
                a.setdefault('rules_direct', [])
                a.setdefault('rules_proxy', [])
            save_state()
    return v


def rx_escape(name):
    return re.sub(r'([\\^$.|?*+()\[\]{}])', r'\\\1', name)


def norm_target(text):
    """Домен или IP/подсеть из того, что ввёл пользователь. None — если не распознано."""
    t = text.strip().lower()
    t = re.sub(r'^[a-z]+://', '', t).split('/')[0] if not re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', t) else t
    t = t.split('?')[0].rstrip('.')
    for pre in ('*.', 'www.'):
        if t.startswith(pre):
            t = t[len(pre):]
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$', t)
    if m:
        if all(int(x) <= 255 for x in m.group(1).split('.')) and int(m.group(2) or 32) <= 32:
            return f'{m.group(1)}/{m.group(2) or 32}'
        return None
    t = t.split(':')[0]
    try:
        t = t.encode('idna').decode()
    except Exception:
        return None
    return t if re.match(r'^(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$', t) else None


def target_rule(t, out):
    return f'IP-CIDR,{t},{out},no-resolve' if re.match(r'^\d', t) else f'DOMAIN-SUFFIX,{t},{out}'


def build_managed(v):
    """Блоки конфига mihomo, которыми управляет бот: базы geo, DNS, группы, правила."""
    r = v.get('routing', 'all')
    svc = {k: x for k, x in (v.get('svc') or {}).items() if k in SERVICES and sub_by_id(x)}
    out = []
    if r != 'all' or svc:
        out += ['geodata-mode: true', 'geodata-loader: memconservative', 'geo-auto-update: true',
                'geo-update-interval: 24', 'geox-url:',
                f'  geoip: {GEO_URL}geoip.dat', f'  geosite: {GEO_URL}geosite.dat', '']
    out += ['dns:', '  enable: true', '  enhanced-mode: redir-host', '  respect-rules: true',
            '  proxy-server-nameserver:', '    - 1.1.1.1', '    - 8.8.8.8',
            '  nameserver:', '    - https://1.1.1.1/dns-query', '    - https://8.8.8.8/dns-query']
    if r != 'all':
        ru = '[' + ', '.join(RU_DNS) + ']'
        out += ['  nameserver-policy:', f"    '+.ru': {ru}", f"    '+.xn--p1ai': {ru}", f"    '+.su': {ru}",
                f"    'geosite:category-ru': {ru}", f"    'geosite:ru-available-only-inside': {ru}"]
    out.append('')
    # Сниффер: имя сайта берётся из самого соединения (TLS/QUIC/HTTP), даже если клиент спросил адрес не у шлюза.
    # override-destination — mihomo сам находит адрес по имени: российские сайты получают российский IP.
    out += ['sniffer:', '  enable: true', '  force-dns-mapping: true', '  parse-pure-ip: true',
            '  override-destination: true', '  sniff:', '    HTTP: { ports: [80, 8080] }',
            '    TLS: { ports: [443, 8443] }', '    QUIC: { ports: [443] }',
            "  skip-domain: ['Mijia Cloud', '+.push.apple.com']", '']
    pat = 'поддерживается|Превышено'
    if v['excluded']:
        pat += '|^(?:' + '|'.join(rx_escape(n) for n in v['excluded']) + ')$'
    use = '[' + ', '.join(x['id'] for x in subs()) + ']'
    out.append(build_providers().rstrip('\n'))
    out.append('')
    out += ['proxy-groups:', f'  - name: {AUTO_GROUP}', '    type: url-test', f'    use: {use}',
            "    exclude-filter: '" + pat.replace("'", "''") + "'",
            '    url: https://www.gstatic.com/generate_204', f'    interval: {v["interval"]}',
            f'    tolerance: {v["tolerance"]}', '    lazy: false',
            f'  - name: {SELECT_GROUP}', '    type: select', f'    proxies: [{AUTO_GROUP}]', f'    use: {use}']
    for pid in sorted(set(svc.values())):
        # серверы одной подписки (самый быстрый), а если они все упали — общий выбор
        out += [f'  - name: SUB-{pid}', '    type: url-test', f'    use: [{pid}]',
                "    exclude-filter: 'поддерживается|Превышено'", '    url: https://www.gstatic.com/generate_204',
                f'    interval: {v["interval"]}', f'    tolerance: {v["tolerance"]}', '    lazy: false',
                f'  - name: VIA-{pid}', '    type: fallback', f'    proxies: [SUB-{pid}, {SELECT_GROUP}]',
                '    url: https://www.gstatic.com/generate_204', '    interval: 120', '    lazy: false']
    out += ['', 'rules:']
    rules = ['IP-CIDR,10.0.0.0/8,DIRECT,no-resolve', 'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
             'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve', 'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
             # замеры пинга и скорости в боте всегда идут через выбранный сервер
             f'DOMAIN,{PING_HOST},{SELECT_GROUP}', f'DOMAIN,{urllib.parse.urlsplit(SPEED_URL).hostname},{SELECT_GROUP}']
    rules += [f'DOMAIN,{urllib.parse.urlsplit(u).hostname},{SELECT_GROUP}' for u in EXIT_IP_URLS]
    rules += [target_rule(t, SELECT_GROUP) for t in v.get('rules_proxy', [])]
    rules += [target_rule(t, 'DIRECT') for t in v.get('rules_direct', [])]
    rules += [x + ',DIRECT' + (',no-resolve' if x.startswith('IP-') else '') for x in RU_APPS_DIRECT]
    for key, pid in svc.items():
        rules += [f'{x.split(",")[0]},{x.split(",")[1]},VIA-{pid}' + (',no-resolve' if x.endswith('no-resolve') else '')
                  for x in SERVICES[key][1]]
    if r == 'list':
        for key in LIST_CATALOG:
            if key in v.get('list_svc', LIST_DEFAULT):
                rules += [via_rule(x, SELECT_GROUP) for x in LIST_CATALOG[key][1]]
        rules.append('MATCH,DIRECT')
        out += [f'  - {x}' for x in rules]
        return '\n'.join(out) + '\n'
    if r != 'all':
        rules += [f'GEOSITE,ru-blocked,{SELECT_GROUP}', f'GEOIP,ru-blocked,{SELECT_GROUP},no-resolve',
                  'GEOSITE,category-ai-ru,DIRECT', f'GEOSITE,category-ai-!cn,{SELECT_GROUP}']
    if r == 'smart':
        rules += ['GEOSITE,ru-available-only-inside,DIRECT', 'DOMAIN-SUFFIX,ru,DIRECT',
                  'DOMAIN-SUFFIX,xn--p1ai,DIRECT', 'DOMAIN-SUFFIX,su,DIRECT',
                  'GEOSITE,category-ru,DIRECT', 'GEOIP,RU,DIRECT', f'MATCH,{SELECT_GROUP}']
    elif r == 'blocked':
        rules.append('MATCH,DIRECT')
    else:
        rules.append(f'MATCH,{SELECT_GROUP}')
    out += [f'  - {x}' for x in rules]
    return '\n'.join(out) + '\n'


MANAGED_KEYS = {'geodata-mode', 'geodata-loader', 'geox-url', 'geo-auto-update', 'geo-update-interval',
                'dns', 'sniffer', 'proxy-providers', 'proxy-groups', 'rules', 'rule-providers'}


def render_config(txt, v):
    kept, skip = [], False
    for line in txt.split('\n'):
        m = re.match(r'^([A-Za-z][\w-]*):', line)
        if m:
            skip = m.group(1) in MANAGED_KEYS
        if not skip:
            kept.append(line)
    head = '\n'.join(kept).rstrip('\n')
    return head + '\n\n' + build_managed(v)


def geo_ready():
    try:
        return (open(GEO_MARK).read().strip() == GEO_SRC and
                all(os.path.getsize(os.path.join(GEO_DIR, n)) > 1_000_000 for n in ('GeoIP.dat', 'GeoSite.dat')))
    except Exception:
        return False


def geo_download():
    # базы для умной маршрутизации (runetfreedom: ru-blocked, category-ru и др.), сначала через VPN
    if geo_ready():
        return
    for name, url in (('GeoIP.dat', 'geoip.dat'), ('GeoSite.dat', 'geosite.dat')):
        dst = os.path.join(GEO_DIR, name)
        ok = False
        for opener in (proxy_opener, direct_opener):
            try:
                with opener.open(urllib.request.Request(GEO_URL + url, headers={'User-Agent': 'curl/8.5'}),
                                 timeout=300) as r:
                    data = r.read()
                if len(data) > 1_000_000:
                    with open(dst + '.tmp', 'wb') as f:
                        f.write(data)
                    os.replace(dst + '.tmp', dst)
                    ok = True
                    break
            except Exception as e:
                log('geo download', name, e)
        if not ok:
            raise RuntimeError(f'не удалось скачать базу {name} с GitHub')
    with open(GEO_MARK, 'w') as f:
        f.write(GEO_SRC)


def apply_vpn_config(v):
    txt = open(MIHOMO_CFG, encoding='utf-8').read()
    if v.get('routing', 'all') != 'all' or v.get('svc'):
        geo_download()
    new = render_config(txt, v)
    with open(MIHOMO_TEST_CFG, 'w', encoding='utf-8') as f:
        f.write(new)
    os.chmod(MIHOMO_TEST_CFG, 0o600)
    binary = shutil.which('mihomo') or '/usr/bin/mihomo'
    r = run([binary, '-d', GEO_DIR, '-f', MIHOMO_TEST_CFG, '-t'], 180)
    if r.returncode != 0:
        os.remove(MIHOMO_TEST_CFG)
        raise RuntimeError('mihomo отклонил конфиг: ' + (r.stdout + r.stderr)[-300:])
    shutil.copy2(MIHOMO_CFG, MIHOMO_BAK_CFG)
    os.replace(MIHOMO_TEST_CFG, MIHOMO_CFG)
    r = run(['systemctl', 'restart', 'mihomo'], 60)
    if r.returncode != 0:
        raise RuntimeError('mihomo не перезапустился: ' + r.stderr[-300:])
    with lock:
        v['applied'] = dict(snapshot(v), mode=v['mode'])
        save_state()


def prio_order(v, lst):
    names = [p['name'] for p in lst if p['name'] not in v['excluded']]
    return [n for n in v['priority'] if n in names] + [n for n in names if n not in v['priority']]


def prio_tick(force=False):
    v = state.get('vpn')
    if not v or v['mode'] != 'priority' or v['manual']:
        return
    lst = servers()
    order = prio_order(v, lst)
    ok = {p['name']: bool(p.get('alive', True) and p.get('history') and delay_of(p)) for p in lst}
    for n in order:
        prio_streak[n] = prio_streak.get(n, 0) + 1 if ok.get(n) else 0
    target = next((n for n in order if ok.get(n)), None)
    sel = api(f'/proxies/{SELECT_GROUP}')['now']
    if target is None or sel == target:
        return
    cur_ok = sel in order and ok.get(sel, False)
    if (cur_ok and not force and order.index(target) < order.index(sel)
            and prio_streak.get(target, 0) < 2):
        return      # сервер выше по списку вернулся — ждём, пока он стабильно поработает
    api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': target})


def auto_members():
    try:
        return set(api(f'/proxies/{AUTO_GROUP}').get('all') or [])
    except Exception:
        return set()


def current_speed():
    req = urllib.request.Request(API + '/traffic', headers={'Authorization': 'Bearer ' + SECRET})
    r = direct_opener.open(req, timeout=5)
    try:
        r.readline()
        line = r.readline()
    finally:
        r.close()
    d = json.loads(line)
    return d.get('down', 0), d.get('up', 0)


def exit_ip():
    for url in EXIT_IP_URLS:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.5'})
            ip = proxy_opener.open(req, timeout=8).read().decode().strip()
            if IP_RE.match(ip):
                return ip
        except Exception:
            pass
    return 'не удалось определить'


def fmt_autoapply():
    """После обновления бота: если отличается только формат конфига, применить его самому."""
    v = state.get('vpn')
    a = dict((v or {}).get('applied') or {})
    if not v or a.get('fmt') == CFG_FORMAT:
        return
    cur = dict(snapshot(v))
    cur.pop('fmt'); a.pop('fmt', None); a.pop('mode', None)
    if cur != a:
        return                      # есть неприменённые правки пользователя — пусть применит сам
    for _ in range(30):
        try:
            api('/version')
            break
        except Exception:
            time.sleep(10)
    try:
        apply_vpn_config(v)
        time.sleep(5)
        if v['mode'] == 'priority' and not v['manual']:
            prio_tick(force=True)
        add_event('Конфиг VPN обновлён до нового формата: MAX и сервисы проверки IP идут напрямую')
        log('конфиг mihomo переведён на формат', CFG_FORMAT)
    except Exception as e:
        log('не удалось обновить формат конфига mihomo:', e)


def run(cmd, timeout=30, inp=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=inp)


# ---------------- сторож маршрута: wg0 → таблица 100 → mihomo ----------------
route_miss = {'n': 0}


def route_tick():
    """Трафик клиентов WireGuard идёт в VPN через правило «iif wg0 lookup 100» и маршрут
    «default dev mihomo» в таблице 100. Если что-то пропало (сбой при перезапуске mihomo) —
    возвращаем на место. Чиним со второй проверки подряд, чтобы не мешать обычному запуску mihomo."""
    if run(['ip', 'link', 'show', 'mihomo'], 5).returncode != 0 or \
            run(['ip', 'link', 'show', WG_IF], 5).returncode != 0:
        route_miss['n'] = 0          # mihomo или WireGuard не запущены — об этом предупреждают другие проверки
        return
    rules = run(['ip', 'rule', 'show'], 5).stdout
    table = run(['ip', 'route', 'show', 'table', '100'], 5).stdout
    missing = []
    if not re.search(r'^default dev mihomo\b', table, re.M):
        missing.append('route')
    if not re.search(rf'iif {re.escape(WG_IF)} lookup 100', rules):
        missing.append('rule')
    if not re.search(rf'iif {re.escape(WG_IF)} prohibit', rules):
        missing.append('kill')
    if not missing:
        route_miss['n'] = 0
        if route_miss.get('alert'):
            route_miss['alert'] = False
            notify('dead', '🟢 <b>Маршрутизация VPN снова в порядке</b>')
        return
    route_miss['n'] += 1
    if route_miss['n'] < 2:
        return
    route_miss['n'] = 0
    fixed, errs = [], []
    cmds = {'route': (['ip', 'route', 'replace', 'default', 'dev', 'mihomo', 'table', '100'],
                      'маршрут в таблице 100'),
            'rule': (['ip', 'rule', 'add', 'iif', WG_IF, 'lookup', '100', 'priority', '100'],
                     f'правило {WG_IF} → таблица 100'),
            'kill': (['ip', 'rule', 'add', 'iif', WG_IF, 'prohibit', 'priority', '101'], 'защита от утечек')}
    for k in missing:
        cmd, what = cmds[k]
        r = run(cmd, 5)
        (fixed if r.returncode == 0 else errs).append(what if r.returncode == 0 else f'{what}: {r.stderr.strip()}')
    if fixed:
        add_event('Сторож маршрута восстановил: ' + ', '.join(fixed))
    if errs:
        log('route_tick:', errs)
        if route_miss.get('alert'):
            return                    # уже предупредили, не повторяем каждую минуту
        route_miss['alert'] = True
        text = ('⚠️ <b>Сбой маршрутизации VPN</b>\n\nПропало: ' + ', '.join(cmds[k][1] for k in missing) +
                '.\nКлиенты WireGuard сейчас без VPN.\n\nНе удалось починить: ' + h('; '.join(errs)) +
                '\nПомогает «🔧 Управление → ♻️ Перезапуск mihomo».')
    else:
        route_miss['alert'] = False
        text = ('🛠 <b>Восстановлена маршрутизация VPN</b>\n\nПропало: ' + ', '.join(cmds[k][1] for k in missing) +
                '.\nНа время сбоя клиенты WireGuard были без VPN (утечки IP не было — сработала защита).'
                if 'kill' not in missing else
                '🛠 <b>Восстановлена маршрутизация VPN</b>\n\nПропало: ' + ', '.join(cmds[k][1] for k in missing) + '.')
    notify('dead', text)


# ---------------- WireGuard ----------------
def wg_live():
    r = run(['wg', 'show', WG_IF, 'dump'], 5)
    lines = r.stdout.strip().split('\n')
    if r.returncode != 0 or not lines or not lines[0]:
        raise RuntimeError('WireGuard не запущен')
    head = lines[0].split('\t')
    info = {'pub': head[1], 'port': int(head[2]), 'peers': {}}
    for ln in lines[1:]:
        f = ln.split('\t')
        if len(f) >= 7:
            ts = int(f[4])
            info['peers'][f[0]] = {'endpoint': '' if f[2] == '(none)' else f[2],
                                   'age': time.time() - ts if ts else None,
                                   'rx': int(f[5]), 'tx': int(f[6])}
    return info


def wg_import():
    peers, txt = {}, open(WG_CONF, encoding='utf-8').read()
    for i, block in enumerate(txt.split('[Peer]')[1:], 1):
        kv, name = {}, None
        for ln in block.strip().split('\n'):
            ln = ln.strip()
            if ln.startswith('#') and name is None:
                name = ln.lstrip('# ').strip()
            elif '=' in ln:
                k, v = ln.split('=', 1)
                kv[k.strip()] = v.strip()
        if 'PublicKey' not in kv:
            continue
        name = name or f'Пир {i}'
        mt = 'mikrotik' in name.lower()
        peers[kv['PublicKey']] = {
            'name': name, 'kind': 'mikrotik' if mt else 'device', 'ip': kv.get('AllowedIPs', '').split('/')[0],
            'psk': kv.get('PresharedKey'), 'priv': None, 'enabled': True, 'monitor': mt, 'created': time.time()}
    return peers


def wg_state():
    w = state.get('wg')
    if w is None:
        try:
            host = run(['hostname', '-I'], 5).stdout.split()[0]
        except Exception:
            host = ''
        w = {'endpoint': WG_ENDPOINT_DEFAULT or host, 'peers': wg_import()}
        with lock:
            state['wg'] = w
            save_state()
    return w


def wg_write():
    txt = open(WG_CONF, encoding='utf-8').read()
    head = txt.split('[Peer]')[0].rstrip() + '\n'
    blocks = []
    for pub, p in wg_state()['peers'].items():
        if not p['enabled']:
            continue
        b = f'\n[Peer]\n# {p["name"]}\nPublicKey = {pub}\n'
        if p.get('psk'):
            b += f'PresharedKey = {p["psk"]}\n'
        b += f'AllowedIPs = {p["ip"]}/32\n'
        blocks.append(b)
    shutil.copy2(WG_CONF, WG_CONF + '.bak-bot')
    tmp = WG_CONF + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(head + ''.join(blocks))
    os.chmod(tmp, 0o600)
    os.replace(tmp, WG_CONF)
    r = run(['bash', '-c', f'wg syncconf {WG_IF} <(wg-quick strip {WG_IF})'], 20)
    if r.returncode != 0:
        raise RuntimeError('wg syncconf: ' + r.stderr[-300:])


DNS_HOST = 53          # WG_NET.53 — DNS для клиентов: такого узла нет, запросы перехватывает mihomo


def wg_dns():
    return f'{WG_NET}.{DNS_HOST}'


def wg_free_ip():
    used = {p['ip'] for p in wg_state()['peers'].values()}
    for n in range(2, 255):
        if n != DNS_HOST and f'{WG_NET}.{n}' not in used:
            return f'{WG_NET}.{n}'
    raise RuntimeError('закончились свободные адреса')


def wg_new_peer(name, kind):
    priv = run(['wg', 'genkey'], 5).stdout.strip()
    pub = run(['wg', 'pubkey'], 5, inp=priv + '\n').stdout.strip()
    psk = run(['wg', 'genpsk'], 5).stdout.strip()
    if not (priv and pub and psk):
        raise RuntimeError('не удалось сгенерировать ключи WireGuard')
    with lock:
        w = wg_state()
        w['peers'][pub] = {'name': name, 'kind': kind, 'ip': wg_free_ip(), 'psk': psk, 'priv': priv,
                           'enabled': True, 'monitor': kind == 'mikrotik', 'created': time.time()}
        save_state()
    wg_write()
    return pub


IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def split_hostport(text):
    m = re.match(r'^(.*?)(?::(\d{1,5}))?$', text.strip())
    return m.group(1), m.group(2)


def wg_eps():
    """Адреса для подключения клиентов: домен (основной) и IP (запасной), плюс внешний порт."""
    w = wg_state()
    host, port = split_hostport(w.get('endpoint') or lan_ip() or '127.0.0.1')
    e = w.get('ep')
    if not isinstance(e, dict):
        e = w['ep'] = {'domain': '', 'ip': '', 'port': port or ''}
    if host and host not in (e.get('domain'), e.get('ip')):   # адрес поменял установщик или старая версия
        e['ip' if IP_RE.match(host) else 'domain'] = host
        if port:
            e['port'] = port
    return e


def wg_port():
    e = wg_eps()
    if e.get('port'):
        return str(e['port'])
    try:
        return str(wg_live()['port'])
    except Exception:
        return '51820'


def wg_endpoint(via=None):
    """via: 'd' — по домену, 'i' — по IP, None — основной (домен, если задан)."""
    e = wg_eps()
    if via == 'i' and e.get('ip'):
        host = e['ip']
    elif via == 'd' and e.get('domain'):
        host = e['domain']
    else:
        host = e.get('domain') or e.get('ip') or lan_ip() or '127.0.0.1'
    return f'{host}:{wg_port()}'


def wg_set_ep(which, host, port=None):
    with lock:
        w = wg_state()
        e = wg_eps()
        e['domain' if which == 'd' else 'ip'] = host
        if port:
            e['port'] = port
        prim = e.get('domain') or e.get('ip') or lan_ip() or '127.0.0.1'
        w['endpoint'] = f'{prim}:{e["port"]}' if e.get('port') else prim
        save_state()


def both_eps():
    e = wg_eps()
    return bool(e.get('domain') and e.get('ip'))


def public_ip():
    for url in ('https://ipv4-internet.yandex.net/api/v0/ip', 'https://api.ipify.org'):
        try:
            with direct_opener.open(urllib.request.Request(url, headers={'User-Agent': 'curl/8.5'}), timeout=8) as r:
                ip = r.read().decode().strip().strip('"')
            if IP_RE.match(ip):
                return ip
        except Exception:
            pass
    return ''


def check_domain(domain):
    """Куда указывает домен и совпадает ли это с внешним IP шлюза. → (ок?, текст)"""
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception as ex:
        return False, f'🔴 Домен <code>{h(domain)}</code> не находится в DNS ({h(str(ex))[:80]}).'
    pub = public_ip()
    e = wg_eps()
    mine = {x for x in (pub, e.get('ip')) if x}
    got = ', '.join(ips)
    if mine & set(ips):
        return True, f'✅ <code>{h(domain)}</code> → <code>{got}</code>, это адрес шлюза.'
    if not pub:
        return False, f'⚠️ <code>{h(domain)}</code> → <code>{got}</code>. Внешний IP шлюза узнать не удалось, сверьте сами.'
    return False, (f'⚠️ <code>{h(domain)}</code> → <code>{got}</code>, а внешний IP шлюза <code>{pub}</code>. '
                   'Если DNS меняли недавно, подождите до часа. Иначе проверьте запись у регистратора.')


def wg_server_pub():
    return run(['wg', 'show', WG_IF, 'public-key'], 5).stdout.strip()


def wg_client_conf(pub, via=None):
    p = wg_state()['peers'][pub]
    host, port = wg_endpoint(via).rsplit(':', 1)
    if p['kind'] == 'mikrotik':
        return mt_conf(p, via)
    return '\n'.join([
        # DNS — адрес внутри туннеля, а не 1.1.1.1: к 1.1.1.1 Android и Chrome сами переходят на зашифрованный
        # DNS мимо шлюза и получают IPv6-адреса; ::/0 у телефонов не даёт IPv6 уйти мимо VPN
        '[Interface]', f'PrivateKey = {p["priv"]}', f'Address = {p["ip"]}/32', f'DNS = {wg_dns()}',
        f'MTU = {1280 if p["kind"] in ("phone", "device") else 1380}', '',
        '[Peer]', f'PublicKey = {wg_server_pub()}', f'PresharedKey = {p["psk"]}', f'Endpoint = {host}:{port}',
        'AllowedIPs = ' + ('0.0.0.0/0, ::/0' if p['kind'] in ('phone', 'device') else '0.0.0.0/0'),
        'PersistentKeepalive = 25', ''])


def wg_qr(conf):
    try:
        r = subprocess.run(['qrencode', '-t', 'PNG', '-s', '8', '-m', '2', '-o', '-'],
                           input=conf.encode(), capture_output=True, timeout=10)
        return r.stdout if r.returncode == 0 and r.stdout else None
    except Exception:
        return None


def peer_file_name(p):
    tr = dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
                  ['a', 'b', 'v', 'g', 'd', 'e', 'e', 'zh', 'z', 'i', 'y', 'k', 'l', 'm', 'n', 'o', 'p', 'r', 's',
                   't', 'u', 'f', 'h', 'ts', 'ch', 'sh', 'sch', '', 'y', '', 'e', 'yu', 'ya']))
    lat = ''.join(tr.get(c.lower(), c) for c in p['name'])
    return (re.sub(r'[^A-Za-z0-9_-]+', '_', lat).strip('_') or 'peer')[:15]


def wg_mail(pub, to, via=None):
    """Письмо клиенту: файл .conf (или .rsc для MikroTik), QR-код и инструкция."""
    p = wg_state()['peers'][pub]
    conf = wg_client_conf(pub, via)
    safe = peer_file_name(p)
    name = p['name']
    extra = []
    if p.get('expires'):
        extra.append(f'Доступ действует до {fmt_date(p["expires"])}.')
    if p.get('limit'):
        extra.append(f'Лимит трафика: {fmt_bytes(p["limit"])} в месяц.')
    warn = 'В файле и QR-коде — личный ключ доступа. Не пересылайте это письмо другим людям.'
    subject = f'{GW_NAME}: доступ к VPN для «{name}»'
    att, inline = [], []
    if p['kind'] == 'mikrotik':
        att.append((f'{safe}.rsc', conf.encode(), 'application', 'octet-stream'))
        text = '\n'.join([f'Здравствуйте!', '', f'Это настройки подключения MikroTik «{name}» к VPN «{GW_NAME}».', '',
                          f'Откройте вложенный файл {safe}.rsc, скопируйте его содержимое и вставьте в терминал '
                          'MikroTik (Winbox → New Terminal). Проверка после этого: /ping ' + f'{WG_NET}.1', '',
                          *extra, '', warn])
        html_body = None
    else:
        png = wg_qr(conf)
        att.append((f'{safe}.conf', conf.encode(), 'application', 'octet-stream'))
        if png:
            att.append((f'{safe}-qr.png', png, 'image', 'png'))
            inline.append(('qr', png, 'image', 'png'))
        text = '\n'.join([
            'Здравствуйте!', '', f'Это доступ к VPN «{GW_NAME}» для «{name}».', '',
            'Телефон или планшет:',
            '  1. Установите приложение WireGuard:',
            f'     iPhone/iPad: {WG_IOS}',
            f'     Android: {WG_ANDROID}',
            f'     {AMNEZIA_NOTE}',
            '  2. Нажмите «+» → «Сканировать QR-код» и наведите камеру на QR-код из этого письма '
            '(откройте письмо на другом экране).',
            '     Или откройте вложенный файл .conf прямо на телефоне и выберите WireGuard.',
            '  3. Включите туннель.', '',
            'Компьютер (Windows, macOS):',
            '  1. Установите WireGuard: https://www.wireguard.com/install/',
            f'  2. «Импорт туннелей из файла» → выберите вложенный файл {safe}.conf → «Подключить».', '',
            *extra, *([''] if extra else []), warn])
        e = html.escape
        html_body = (
            '<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.5;color:#222">'
            f'<p>Здравствуйте!</p><p>Это доступ к VPN <b>{e(GW_NAME)}</b> для <b>«{e(name)}»</b>.</p>'
            '<h3 style="margin:18px 0 6px">📱 Телефон или планшет</h3><ol style="margin-top:0">'
            f'<li>Установите приложение <b>WireGuard</b>: <a href="{WG_IOS}">App Store</a> (iPhone, iPad) или '
            f'<a href="{WG_ANDROID}">Google Play</a> (Android).<br>'
            f'<span style="color:#555">{html.escape(AMNEZIA_NOTE)}</span></li>'
            '<li>Нажмите <b>«+»</b> → <b>«Сканировать QR-код»</b> и наведите камеру на код ниже '
            '(откройте письмо на другом экране).<br>Или откройте вложенный файл <b>.conf</b> прямо на телефоне.</li>'
            '<li>Включите туннель.</li></ol>'
            + ('<p><img src="cid:qr" alt="QR-код WireGuard" width="300" height="300" '
               'style="border:1px solid #ddd;border-radius:8px"></p>' if png else '')
            + '<h3 style="margin:18px 0 6px">💻 Компьютер</h3><ol style="margin-top:0">'
            '<li>Установите WireGuard: <a href="https://www.wireguard.com/install/">wireguard.com/install</a></li>'
            f'<li><b>«Импорт туннелей из файла»</b> → выберите вложенный файл <b>{e(safe)}.conf</b> → '
            '<b>«Подключить»</b>.</li></ol>'
            + ''.join(f'<p>{e(x)}</p>' for x in extra)
            + f'<p style="color:#a33">⚠️ {e(warn)}</p></div>')
    send_mail(subject, text, to=[to], html_body=html_body, attachments=att, inline=inline)


def wg_send_conf(chat, pub, only=None, via=None):
    p = wg_state()['peers'][pub]
    conf = wg_client_conf(pub, via)
    safe = peer_file_name(p)
    if p['kind'] == 'mikrotik':
        tg_file('sendDocument', chat, 'document', f'{safe}.rsc', conf.encode(),
                f'📡 Команды для MikroTik «{h(p["name"])}». Откройте файл и вставьте его содержимое '
                f'в терминал MikroTik.\n\n⚠️ Внутри приватный ключ, не пересылайте файл посторонним.')
        return
    phone = p['kind'] in ('phone', 'device')
    want_qr = only == 'qr' or (only is None and phone)
    want_file = only == 'file' or (only is None)
    if want_qr:
        png = wg_qr(conf)
        if png:
            tg_file('sendPhoto', chat, 'photo', 'qr.png', png,
                    f'🔳 <b>{h(p["name"])}</b>: QR-код для приложения WireGuard\n\n'
                    f'1. Установите WireGuard: <a href="{WG_IOS}">App Store</a> · <a href="{WG_ANDROID}">Google Play</a>\n'
                    '2. «+» → «Сканировать QR-код»\n3. Включите туннель\n\n'
                    f'💡 {AMNEZIA_NOTE}\n\n'
                    '⚠️ QR — это ключ доступа, не показывайте его посторонним.')
        else:
            raw_send(chat, 'ℹ️ QR-код не создан: на сервере нет программы qrencode '
                           '(<code>sudo apt install -y qrencode</code>).', ttl_kind='files')
    if want_file:
        how = (f'Импорт: WireGuard (<a href="{WG_IOS}">App Store</a> · <a href="{WG_ANDROID}">Google Play</a>) → '
               '«+» → «Импорт из файла». Подойдёт и AmneziaWG.' if phone else
               'Windows/macOS: установите WireGuard с <a href="https://www.wireguard.com/install/">wireguard.com</a> → «Импорт туннелей из файла» → «Подключить».\n'
               'Linux: <code>sudo cp файл.conf /etc/wireguard/ &amp;&amp; sudo wg-quick up имя</code>.')
        tg_file('sendDocument', chat, 'document', f'{safe}.conf', conf.encode(),
                f'{KIND_ICON.get(p["kind"], "📱")} Конфиг «{h(p["name"])}»\n\n{how}\n\n'
                f'⚠️ Внутри приватный ключ, не пересылайте посторонним.')


def mihomo_uptime():
    try:
        pid = run(['systemctl', 'show', '-p', 'MainPID', '--value', 'mihomo'], 5).stdout.strip()
        if pid and pid != '0':
            return int(run(['ps', '-o', 'etimes=', '-p', pid], 5).stdout.strip())
    except Exception:
        pass
    return None


# ---------------- форматирование ----------------
def fmt_bytes(n):
    n = float(n)
    for unit, size in (('ТБ', 1 << 40), ('ГБ', 1 << 30), ('МБ', 1 << 20), ('КБ', 1 << 10)):
        if n >= size:
            return f'{n / size:.2f} {unit}' if size >= 1 << 30 else f'{n / size:.1f} {unit}'
    return f'{int(n)} Б'


def fmt_mbit(bps):
    return f'{bps * 8 / 1e6:.1f} Мбит/с'


def fmt_dur(s):
    s = int(s)
    d, s = divmod(s, 86400)
    hh, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f'{d} д {hh} ч'
    if hh:
        return f'{hh} ч {m} мин'
    if m:
        return f'{m} мин {s} с'
    return f'{s} с'


# ---------------- учёт трафика ----------------
def _traffic_delta():
    c = api('/connections')
    down, up = c.get('downloadTotal', 0), c.get('uploadTotal', 0)
    last = state.get('last_raw')
    if last and down >= last[0] and up >= last[1]:
        dd, du = down - last[0], up - last[1]
    elif last:          # mihomo перезапускался, счётчики начались заново
        dd, du = down, up
    else:
        dd, du = 0, 0
    return down, up, dd, du, len(c.get('connections') or [])


def sample_traffic():
    with lock:
        down, up, dd, du, _ = _traffic_delta()
        t = state['traffic'].setdefault(date.today().isoformat(), [0, 0])
        t[0] += dd
        t[1] += du
        state['last_raw'] = [down, up]
        cutoff = (date.today() - timedelta(days=60)).isoformat()
        for k in [k for k in state['traffic'] if k < cutoff]:
            del state['traffic'][k]
        save_state()


def traffic_view():
    with lock:
        days = {k: list(v) for k, v in state['traffic'].items()}
        try:
            _, _, dd, du, conns = _traffic_delta()
        except Exception:
            dd = du = 0
            conns = None
    t = days.setdefault(date.today().isoformat(), [0, 0])
    t[0] += dd
    t[1] += du
    return days, conns


def period(days, n):
    start = (date.today() - timedelta(days=n - 1)).isoformat()
    d = u = 0
    for k, v in days.items():
        if k >= start:
            d += v[0]
            u += v[1]
    return d, u


# ---------------- экраны ----------------
def kb_back(refresh=None):
    row = []
    if refresh:
        row.append(btn('🔄 Обновить', refresh))
    row.append(btn('🏠 Меню', 'menu'))
    return [row]


def scr_menu(uid):
    try:
        mode, cur = mode_and_current()
        alive = server_info(cur).get('alive', True)
        days, _ = traffic_view()
        td = days.get(date.today().isoformat(), [0, 0])
        head = (f'{"🟢" if alive else "🔴"} Сервер: <b>{h(cur)}</b> ({MODE_RU[mode]})\n'
                f'📈 Сегодня: ↓ {fmt_bytes(td[0])}  ↑ {fmt_bytes(td[1])}')
    except Exception:
        head = '🔴 <b>mihomo не отвечает</b>'
    text = f'🛡 <b>{h(GW_NAME)}</b>\n\n{head}\n\nВыберите раздел:'
    kb = [[btn('📊 Статус', 'status'), btn('🌍 Серверы', 'servers')],
          [btn('🔐 WireGuard', 'wg'), btn('📈 Трафик', 'traffic')],
          [btn('🖥 Сервер' + (' ⚠️' if srv_problems() else ''), 'srv'), btn('⚡ Скорость', 'speed')],
          [btn('⚙️ Настройки', 'set'), btn('🔧 Управление', 'manage')],
          [btn('📜 Журнал', 'log'), btn('🧹 Очистить чат', 'clean')]]
    last = [btn('🔔 Уведомления', 'notif')]
    if is_owner(uid):
        last.append(btn('👥 Админы', 'admins'))
    kb.append(last)
    row = gw_row(uid)
    if row:
        kb.insert(0, row)
    return text, kb


def scr_status(uid):
    lines = ['📊 <b>Статус шлюза</b>', '']
    try:
        mode, cur = mode_and_current()
        info = server_info(cur)
        alive = info.get('alive', True)
        lines += [
            '🟢 VPN работает' if alive else '🔴 Текущий сервер не отвечает',
            f'🌍 Сервер: <b>{h(cur)}</b>',
            f'⚙️ Режим: {MODE_RU[mode]}',
            f'📶 Пинг: {fmt_delay(info)}',
            f'🌐 Внешний IP: <code>{h(exit_ip())}</code>',
        ]
        try:
            down, up = current_speed()
            lines.append(f'⚡ Сейчас: ↓ {fmt_mbit(down)}  ↑ {fmt_mbit(up)}')
        except Exception:
            pass
        days, conns = traffic_view()
        td = days.get(date.today().isoformat(), [0, 0])
        lines.append(f'📈 Сегодня: ↓ {fmt_bytes(td[0])}  ↑ {fmt_bytes(td[1])}')
        if conns is not None:
            lines.append(f'🔗 Активных соединений: {conns}')
        up_s = mihomo_uptime()
        if up_s is not None:
            lines.append(f'⏱ mihomo работает: {fmt_dur(up_s)}')
    except Exception as e:
        lines.append(f'🔴 <b>mihomo не отвечает</b>\n<code>{h(str(e))[:200]}</code>')
    lines.append('')
    try:
        live = wg_live()['peers']
        peers = wg_state()['peers']
        online = 0
        for pub, p in peers.items():
            lv = live.get(pub)
            up = bool(lv and lv['age'] is not None and lv['age'] < WG_STALE)
            online += up
            if p.get('monitor') and p['enabled']:
                lines.append(f'{"📡" if p["kind"] == "mikrotik" else "📱"} {h(p["name"])}: '
                             + (f'🟢 на связи ({fmt_dur(lv["age"])} назад)' if up else '🔴 нет связи'))
        lines.append(f'🔐 WireGuard: на связи {online} из {len([p for p in peers.values() if p["enabled"]])}')
    except Exception:
        lines.append('🔐 WireGuard: ⚠️ не запущен')
    lines += ['', f'<i>Обновлено {time.strftime("%H:%M:%S")}</i>']
    return '\n'.join(lines), kb_back('status')


def scr_servers(uid, note=''):
    mode, cur = mode_and_current()
    lst = servers()
    members = auto_members()
    lines = ['🌍 <b>Серверы</b>', '']
    if mode == 'auto':
        lines.append(f'Режим: 🤖 <b>Авто</b>, сейчас {h(cur)}')
    elif mode == 'priority':
        lines.append(f'Режим: 📋 <b>По приоритету</b>, сейчас {h(cur)}')
    else:
        lines.append(f'Режим: ✋ <b>Вручную</b>: {h(cur)}')
        lines.append('<i>Если сервер перестанет отвечать, шлюз сам включит автовыбор.</i>')
    lines.append('')
    kb, row = [], []
    for i, p in enumerate(lst):
        name = p['name']
        if name == cur:
            icon = '✅'
        elif not p.get('history'):
            icon = '⚪'
        elif p.get('alive', True) and delay_of(p):
            icon = '🟢'
        else:
            icon = '🔴'
        extra = '' if name in members else ' · вне авто'
        lines.append(f'{icon} {h(name)} — {fmt_delay(p)}{extra}')
        label = ('📍 ' if name == cur and mode == 'manual' else '') + name
        row.append(btn(label[:40], f'srv:{i}:{tag(name)}'))
        if len(row) == 2:
            kb.append(row)
            row = []
    if row:
        kb.append(row)
    lines += ['', 'Нажмите на сервер, чтобы выбрать его вручную.']
    if note:
        lines += ['', note]
    prio = (state.get('vpn') or {}).get('mode') == 'priority'
    kb.append([btn(('✅ ' if mode != 'manual' else '') + ('📋 По приоритету' if prio else '🤖 Авто'), 'auto'),
               btn('📶 Замерить пинг', 'ping')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_traffic(uid):
    days, _ = traffic_view()
    today = date.today()

    def row(label, d, u):
        return f'{label:<8} ↓ {fmt_bytes(d):>10}  ↑ {fmt_bytes(u):>9}'

    t = days.get(today.isoformat(), [0, 0])
    y = days.get((today - timedelta(days=1)).isoformat(), [0, 0])
    lines = ['📈 <b>Трафик через VPN</b>', '', '<pre>' + '\n'.join([
        row('Сегодня', *t), row('Вчера', *y),
        row('7 дней', *period(days, 7)), row('30 дней', *period(days, 30))]) + '</pre>']
    daily = []
    week = [(today - timedelta(days=i), days.get((today - timedelta(days=i)).isoformat())) for i in range(7)]
    top = max([v[0] + v[1] for _, v in week if v] or [1]) or 1
    for d, v in week:
        if v:
            n = round((v[0] + v[1]) / top * 12)
            daily.append(f'{d.strftime("%d.%m")} {"█" * n}{"▏" if n == 0 else ""} {fmt_bytes(v[0] + v[1])}')
    if daily:
        lines += ['<b>По дням</b> (всего)', '<pre>' + '\n'.join(daily) + '</pre>']
    lines.append('<i>↓ получено, ↑ отправлено. Учёт ведётся с момента запуска бота.</i>')
    return '\n'.join(lines), kb_back('traffic')


def scr_manage(uid, note=''):
    lines = ['🔧 <b>Управление</b>', '']
    try:
        for sb in subs():
            lines.append(sub_summary(sb))
    except Exception:
        lines.append('🔴 mihomo не отвечает')
    if note:
        lines += ['', note]
    lines.append(f'🧩 Версия шлюза: {BOT_VERSION}' + (
        f' · доступна <b>{h(state["upd"]["latest"])}</b>' if update_available() else ''))
    kb = [[btn('🔄 Обновить подписки', 'do:update'), btn('📦 Подписки', 'subs')],
          [btn('♻️ Перезапуск mihomo', 'ask:mihomo'), btn('🔌 Перезапуск WireGuard', 'ask:wg')]]
    if is_owner(uid):
        kb.append([btn('🛰 Свои серверы', 'vs')])
        kb.append([btn('🆕 Обновления' + (' •' if update_available() else ''), 'upd')])
        kb.append([btn('🖥 Перезагрузить сервер', 'ask:reboot')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_notif(uid):
    n = state['admins'][str(uid)]['notify']
    text = ('🔔 <b>Уведомления</b>\n\nЧто присылать вам в Telegram. '
            'Нажмите, чтобы включить или выключить:')
    kb = [[btn(('✅ ' if n.get(k, True) else '⬜ ') + label, f'nt:{k}')] for k, label in NOTIFY_KINDS]
    kb.append([btn('🏠 Меню', 'menu')])
    return text, kb


def scr_admins(uid, note=''):
    lines = ['👥 <b>Администраторы</b>', '']
    kb = []
    for aid, a in state['admins'].items():
        if int(aid) == OWNER:
            lines.append(f'👑 {h(a["name"])} — владелец')
        else:
            lines.append(f'👤 {h(a["name"])} · <code>{aid}</code>')
            if gw_nodes() or LINK_MODE:
                have = [gw_name(x) for x in a.get('gw', ['m']) if x == 'm' or x in gw_nodes()]
                lines.append('      шлюзы: ' + (h(', '.join(have)) if have else 'нет'))
                kb.append([btn(f'🏢 {a["name"]}'[:30] + ': шлюзы', f'adm:gws:{aid}'),
                           btn('🗑', f'adm:del:{aid}')])
            else:
                kb.append([btn(f'🗑 {a["name"]}'[:40], f'adm:del:{aid}')])
    lines += ['', 'Чтобы добавить администратора, попросите его написать боту /start: '
                  'вам придёт запрос с кнопкой «Дать доступ». Или добавьте по Telegram ID.']
    if note:
        lines += ['', note]
    kb.append([btn('➕ Добавить по ID', 'adm:add')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_log(uid):
    ev = state['events'][-20:][::-1]
    lines = ['📜 <b>Журнал событий</b>', '']
    if not ev:
        lines.append('Пока пусто.')
    for ts, text in ev:
        lines.append(f'<code>{time.strftime("%d.%m %H:%M", time.localtime(ts))}</code> {h(text)}')
    return '\n'.join(lines), kb_back('log')


def fmt_int(s):
    return f'{s // 60} мин' if s % 60 == 0 else f'{s} с'


def scr_settings(uid, note=''):
    lines = ['⚙️ <b>Настройки</b>', '']
    try:
        v = vpn()
        lines.append(f'🔀 Переключение VPN: <b>{MODES[v["mode"]]}</b>')
        lines.append(f'🧭 Маршрутизация: <b>{ROUTING[v.get("routing", "all")][0]}</b>')
        if vpn_dirty(v):
            lines.append('    ⚠️ есть неприменённые изменения')
    except Exception:
        lines.append('🔀 Переключение VPN: 🔴 mihomo не отвечает')
    if is_owner(uid):
        e = email_cfg()
        lines.append('📧 Почта: ' + (('✅ ' + h(', '.join(e['to']))) if e['enabled'] and e['to'] else '⛔ выключена'))
        b = bk_cfg()
        lines.append('💾 Автобэкап: ' + (f'✅ раз в {b["every"]} дн.' if b['auto'] else '⛔ выключен')
                     + ('' if not b['auto'] or b.get('last_ok', True) else ' · ⚠️ последний с ошибкой'))
    if note:
        lines += ['', note]
    kb = [[btn('🔀 Переключение VPN', 'sw')], [btn('🧭 Маршрутизация', 'swr')]]
    if is_owner(uid):
        kb.append([btn('📦 Подписки VPN', 'subs')])
        kb.append([btn('📧 Почтовые уведомления', 'em')])
        kb.append([btn('💾 Резервные копии', 'bk')])
        kb.append([btn('🏢 Шлюзы: несколько серверов в одном боте', 'gw:set')])
    kb.append([btn('🧹 Чистый чат', 'cl')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_sw(uid, note=''):
    v = vpn()
    lines = ['🔀 <b>Переключение VPN</b>', '', f'Режим: <b>{MODES[v["mode"]]}</b>',
             f'<i>{MODE_HELP[v["mode"]]}</i>', '',
             f'⏱ Проверка серверов: каждые {fmt_int(v["interval"])}']
    if v['mode'] != 'priority':
        lines.append(f'📏 Порог переключения: {v["tolerance"]} мс')
    try:
        lst = servers()
        n_in = len([p for p in lst if p['name'] not in v['excluded']])
        lines.append(f'🌍 В автовыборе: {n_in} из {len(lst)} серверов')
    except Exception:
        pass
    if v['manual']:
        lines += ['', '✋ Сейчас сервер выбран вручную. Если он перестанет отвечать, шлюз сам включит '
                      'автовыбор. Вернуть вручную: «🌍 Серверы → Авто».']
    dirty = vpn_dirty(v)
    if dirty:
        lines += ['', '⚠️ <b>Есть неприменённые изменения.</b> При применении VPN прервётся на 5–10 секунд.']
    if note:
        lines += ['', note]

    def mk(m, label):
        return btn(('✅ ' if v['mode'] == m else '') + label, f'swm:{m}')
    kb = [[mk('fast', '⚡ Быстрый'), mk('stable', '🛡 Стабильный')], [mk('priority', '📋 По приоритету')]]
    row = [btn(f'⏱ Интервал: {fmt_int(v["interval"])}', 'swi')]
    if v['mode'] != 'priority':
        row.append(btn(f'📏 Порог: {v["tolerance"]} мс', 'swt'))
    kb.append(row)
    row = [btn('🌍 Серверы в авто', 'sws')]
    if v['mode'] == 'priority':
        row.append(btn('🔢 Порядок', 'swp'))
    kb.append(row)
    if dirty:
        kb.append([btn('✅ Применить', 'swapply'), btn('↩️ Отменить', 'swreset')])
    kb.append([btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_sw_route(uid, note=''):
    v = vpn()
    cur = v.get('routing', 'all')
    lines = ['🧭 <b>Маршрутизация</b>', '', 'Какой трафик отправлять через VPN:', '']
    for k, (label, help_) in ROUTING.items():
        lines.append(f'{"✅" if k == cur else "▫️"} <b>{label}</b>\n<i>{help_}</i>\n')
    nd, np_ = len(v.get('rules_direct', [])), len(v.get('rules_proxy', []))
    lines.append(f'✏️ Исключения: напрямую — {nd}, через VPN — {np_}')
    for key, pid in (v.get('svc') or {}).items():
        if key in SERVICES and sub_by_id(pid):
            lines.append(f'🎯 {h(SERVICES[key][0].split(":")[0])} → подписка «{h(sub_by_id(pid)["name"])}»')
    lines.append('Касается всех: и MikroTik, и устройств WireGuard. Базы адресов обновляются раз в сутки.')
    if vpn_dirty(v):
        lines += ['', '⚠️ <b>Есть неприменённые изменения.</b> При применении VPN прервётся на 5–10 секунд '
                      '(в первый раз для умного режима — до пары минут, пока скачиваются базы адресов).']
    if note:
        lines += ['', note]
    kb = [[btn(('✅ ' if k == cur else '') + label, f'swr:{k}')] for k, (label, _) in ROUTING.items()]
    if cur == 'list':
        kb.append([btn(f'📋 Сервисы через VPN ({len(v.get("list_svc", LIST_DEFAULT))})', 'swl')])
    kb.append([btn('✏️ Исключения', 'swe'), btn('🎯 Сервисы через подписку', 'svs')])
    kb.append([btn('🔎 Куда идёт сайт', 'site')])
    if vpn_dirty(v):
        kb.append([btn('✅ Применить', 'swapply:r'), btn('↩️ Отменить', 'swreset:r')])
    kb.append([btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_sw_exc(uid, note=''):
    v = vpn()
    lines = ['✏️ <b>Исключения маршрутизации</b>', '',
             'Работают в любом режиме и проверяются первыми. Домен действует вместе с поддоменами '
             '(<code>example.com</code> = и <code>www.example.com</code>). Можно указать IP или подсеть.', '']
    kb = []
    for title, key, out in (('🏠 Всегда напрямую', 'rules_direct', 'd'), ('🔒 Всегда через VPN', 'rules_proxy', 'p')):
        items = v.get(key, [])
        lines.append(f'<b>{title}</b>: ' + (', '.join(f'<code>{h(x)}</code>' for x in items) if items else 'пусто'))
        for x in items:
            kb.append([btn(f'🗑 {"🏠" if out == "d" else "🔒"} {x}'[:40], f'swed:{out}:{tag(x)}')])
    if vpn_dirty(v):
        lines += ['', '⚠️ Чтобы изменения заработали, нажмите «Применить».']
    if note:
        lines += ['', note]
    kb.append([btn('➕ Напрямую', 'swea:d'), btn('➕ Через VPN', 'swea:p')])
    if vpn_dirty(v):
        kb.append([btn('✅ Применить', 'swapply:e'), btn('↩️ Отменить', 'swreset:e')])
    kb.append([btn('⬅️ Маршрутизация', 'swr')])
    return '\n'.join(lines), kb


def scr_sw_list(uid, note=''):
    v = vpn()
    sel = v.get('list_svc', LIST_DEFAULT)
    lines = ['📋 <b>Сервисы через VPN</b>', '',
             'В режиме «Только выбранные сервисы» через VPN идёт только отмеченное здесь и ваши исключения '
             '«через VPN». Остальное — напрямую. Сайт, которого нет в списке, добавьте в ✏️ Исключения.', '']
    if v.get('routing') != 'list':
        lines += ['ℹ️ Сейчас выбран другой режим — список начнёт работать, когда включите '
                  '«📋 Только выбранные сервисы».', '']
    if not sel:
        lines += ['⚠️ Ничего не отмечено — весь трафик пойдёт напрямую.', '']
    kb = [[btn((('✅ ' if k in sel else '▫️ ') + title)[:40], f'swl:{k}')] for k, (title, _, _) in LIST_CATALOG.items()]
    if vpn_dirty(v):
        lines += ['⚠️ <b>Есть неприменённые изменения.</b> При применении VPN прервётся на 5–10 секунд.']
        kb.append([btn('✅ Применить', 'swapply:l'), btn('↩️ Отменить', 'swreset:l')])
    if note:
        lines += ['', note]
    kb.append([btn('✔️ Все', 'swl:+all'), btn('▫️ Только основные', 'swl:+def')])
    kb.append([btn('⬅️ Маршрутизация', 'swr')])
    return '\n'.join(lines), kb


def scr_svc(uid, note=''):
    v = vpn()
    svc = v.get('svc') or {}
    lines = ['🎯 <b>Сервисы через подписку</b>', '',
             'Можно отправить отдельные сервисы через серверы конкретной подписки — например, Google и Gemini '
             'через свой сервер, который Google не считает российским. Если все её серверы недоступны, '
             'сервис временно пойдёт через общий автовыбор.', '']
    if len(subs()) < 2:
        lines.append('ℹ️ Сейчас подписка одна. Добавьте вторую: 🔧 Управление → 📦 Подписки → ➕.')
    kb = []
    for key, (title, _) in SERVICES.items():
        sb = sub_by_id(svc.get(key, ''))
        lines.append(f'{"🎯" if sb else "▫️"} {h(title)} — ' + (f'<b>{h(sb["name"])}</b>' if sb else 'как всё остальное'))
        kb.append([btn(f'{"🎯 " if sb else ""}{title}'[:40], f'svc:{key}')])
    if vpn_dirty(v):
        lines += ['', '⚠️ <b>Есть неприменённые изменения.</b> При применении VPN прервётся на 5–10 секунд.']
        kb.append([btn('✅ Применить', 'swapply:s'), btn('↩️ Отменить', 'swreset:s')])
    if note:
        lines += ['', note]
    kb.append([btn('⬅️ Маршрутизация', 'swr')])
    return '\n'.join(lines), kb


def scr_svc_pick(uid, key):
    v = vpn()
    cur = (v.get('svc') or {}).get(key)
    text = f'🎯 <b>{h(SERVICES[key][0])}</b>\n\nЧерез какую подписку отправлять?'
    kb = [[btn(('✅ ' if not cur else '') + '↩️ Как всё остальное', f'svcs:{key}:-')]]
    for sb in subs():
        kb.append([btn(('✅ ' if cur == sb['id'] else '') + f'📦 {sb["name"]}', f'svcs:{key}:{sb["id"]}')])
    kb.append([btn('⬅️ Назад', 'svs')])
    return text, kb


def scr_sw_choice(uid, what):
    v = vpn()
    if what == 'i':
        text = ('⏱ <b>Интервал проверки серверов</b>\n\nКак часто mihomo проверяет все серверы. '
                'Реже — меньше лишних переключений, но дольше реакция на падение сервера '
                '(при активном трафике сбой обычно замечается быстрее).')
        opts, cur, fmt = INTERVALS, v['interval'], fmt_int
    else:
        text = ('📏 <b>Порог переключения</b>\n\nmihomo сменит сервер, только если другой быстрее '
                'текущего на это значение или больше. Маленький порог — частые переключения, '
                'большой — держится за текущий сервер, пока тот работает.')
        opts, cur, fmt = TOLERANCES, v['tolerance'], (lambda x: f'{x} мс')
    kb, row = [], []
    for o in opts:
        row.append(btn(('✅ ' if o == cur else '') + fmt(o), f'sw{what}:{o}'))
        if len(row) == 3:
            kb.append(row)
            row = []
    if row:
        kb.append(row)
    kb.append([btn('⬅️ Назад', 'sw')])
    return text, kb


def scr_sw_srv(uid, note=''):
    v = vpn()
    lst = servers()
    text = ('🌍 <b>Серверы в автовыборе</b>\n\nОтмеченные ✅ участвуют в автоматическом выборе. '
            'Новые серверы из подписки добавляются сами.')
    if note:
        text += '\n\n' + note
    kb, row = [], []
    for p in lst:
        n = p['name']
        row.append(btn(('⬜ ' if n in v['excluded'] else '✅ ') + n, f'swx:{tag(n)}'))
        if len(row) == 2:
            kb.append(row)
            row = []
    if row:
        kb.append(row)
    kb.append([btn('⬅️ Назад', 'sw')])
    return text, kb


def scr_sw_prio(uid):
    v = vpn()
    order = prio_order(v, servers())
    lines = ['🔢 <b>Порядок приоритета</b>', '',
             'Работа идёт через первый живой сервер сверху. ⬆️ — поднять на одну позицию, ⏫ — в начало.', '']
    lines += [f'{i + 1}. {h(n)}' for i, n in enumerate(order)]
    kb = [[btn(f'⬆️ {i + 1}. {n}'[:40], f'swu:{tag(n)}'), btn('⏫', f'swtop:{tag(n)}')]
          for i, n in enumerate(order) if i > 0]
    kb.append([btn('⬅️ Назад', 'sw')])
    return '\n'.join(lines), kb


MAIL_PRESETS = {
    'yandex': ('Яндекс', 'smtp.yandex.ru', 465,
               'Пароль приложения: id.yandex.ru → Безопасность → Пароли приложений → Почта.'),
    'mailru': ('Mail.ru', 'smtp.mail.ru', 465,
               'Пароль приложения: Настройки → Безопасность → Пароли для внешних приложений.'),
    'gmail': ('Gmail', 'smtp.gmail.com', 465,
              'Нужна двухэтапная аутентификация, затем пароль приложения: myaccount.google.com/apppasswords. '
              'Из России Gmail иногда работает нестабильно.'),
}


def scr_email(uid, note=''):
    e = email_cfg()
    cfg = e['smtp']
    sender = (f'{h(e.get("from_name") or GW_NAME)} &lt;{h(cfg.get("user", ""))}&gt; · '
              f'{h(cfg.get("host", ""))}:{cfg.get("port", "")}') if cfg.get('host') else 'не настроен'
    lines = ['📧 <b>Почтовые уведомления</b>', '',
             '✅ Включены' if e['enabled'] else '⛔ Выключены',
             f'📤 Отправитель: {sender}',
             '📨 Получатели: ' + (h(', '.join(e['to'])) if e['to'] else 'не заданы')]
    if e['enabled'] and (not cfg.get('host') or not e['to']):
        lines.append('⚠️ Письма не уходят: ' + ('настройте отправителя' if not cfg.get('host') else 'добавьте получателя'))
    if e.get('last_error'):
        lines.append(f'⚠️ Последняя ошибка: <code>{h(e["last_error"][:200])}</code>')
    lines += ['', 'Ниже — какие события отправлять на почту.']
    if note:
        lines += ['', note]
    kb = [[btn('⛔ Выключить почту' if e['enabled'] else '✅ Включить почту', 'em:on')],
          [btn('🔧 Отправитель', 'em:smtp'), btn('✏️ Имя отправителя', 'em:name')],
          [btn('➕ Получатель', 'em:add'), btn('✉️ Тестовое письмо', 'em:test')]]
    for a in e['to']:
        kb.append([btn(f'🗑 {a}'[:40], f'em:del:{tag(a)}')])
    for k, label in NOTIFY_KINDS:
        kb.append([btn(('✅ ' if e['kinds'].get(k) else '⬜ ') + label, f'em:k:{k}')])
    kb.append([btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


# ---------------- мониторинг сервера ----------------
_srv_prev = {}


def srv_cfg():
    c = state.setdefault('srvmon', {})
    for k, val in SRV_DEFAULTS.items():
        c.setdefault(k, val)
    c.setdefault('alerts', {})
    return c


def cpu_times():
    f = open('/proc/stat').readline().split()[1:]
    v = [int(x) for x in f]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


def cpu_percent(interval=0.5):
    t1, i1 = cpu_times()
    time.sleep(interval)
    t2, i2 = cpu_times()
    return 100.0 * (1 - (i2 - i1) / max(t2 - t1, 1))


def mem_info():
    m = {}
    for line in open('/proc/meminfo'):
        k, v = line.split(':', 1)
        m[k] = int(v.split()[0]) * 1024
    total, avail = m.get('MemTotal', 0), m.get('MemAvailable', m.get('MemFree', 0))
    return {'total': total, 'used': total - avail, 'swap_total': m.get('SwapTotal', 0),
            'swap_used': m.get('SwapTotal', 0) - m.get('SwapFree', 0)}


def disks():
    seen, out = set(), []
    for line in open('/proc/mounts'):
        dev, mnt, fs = line.split()[:3]
        if fs not in ('ext4', 'ext3', 'xfs', 'btrfs', 'zfs', 'f2fs') or dev in seen:
            continue
        if mnt.startswith(('/snap', '/boot/efi')):
            continue
        seen.add(dev)
        try:
            u = shutil.disk_usage(mnt)
            if u.total < GB and mnt != '/':          # мелкие служебные разделы не показываем
                continue
            out.append({'mount': mnt, 'total': u.total, 'used': u.used, 'free': u.free})
        except Exception:
            pass
    return out


def temperature():
    vals = []
    import glob
    for f in glob.glob('/sys/class/thermal/thermal_zone*/temp') + glob.glob('/sys/class/hwmon/hwmon*/temp*_input'):
        try:
            t = int(open(f).read().strip()) / 1000
            if 0 < t < 150:
                vals.append(t)
        except Exception:
            pass
    return max(vals) if vals else None


def net_bytes():
    out = {}
    for line in open('/proc/net/dev').readlines()[2:]:
        name, data = line.split(':', 1)
        f = data.split()
        out[name.strip()] = (int(f[0]), int(f[8]))
    return out


def unit_info(unit):
    r = run(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID', '--value'], 5).stdout.split()
    active = r[1] if len(r) > 1 else (r[0] if r else 'unknown')
    pid = r[0] if len(r) > 1 else '0'
    rss = 0
    try:
        for line in open(f'/proc/{pid}/status'):
            if line.startswith('VmRSS:'):
                rss = int(line.split()[1]) * 1024
    except Exception:
        pass
    return active, rss


def apt_updates():
    try:
        txt = open('/var/lib/update-notifier/updates-available', encoding='utf-8', errors='ignore').read()
    except Exception:
        return None, None
    total = sec = 0
    for line in txt.splitlines():
        m = re.match(r'\s*(\d+)\s', line)
        if not m:
            continue
        if re.search(r'security|безопасност', line, re.I):
            sec = int(m.group(1))
        elif re.search(r'update|обновлен', line, re.I) and not total:
            total = int(m.group(1))
    return total, sec


def srv_snapshot(sample=True):
    n1 = net_bytes()
    cpu = cpu_percent(1.0 if sample else 0.2)
    n2 = net_bytes()
    la = [float(x) for x in open('/proc/loadavg').read().split()[:3]]
    up = float(open('/proc/uptime').read().split()[0])
    iface = None
    try:
        iface = run(['ip', 'route', 'show', 'default'], 5).stdout.split('dev ')[1].split()[0]
    except Exception:
        pass
    rate = None
    if iface and iface in n1 and iface in n2:
        rate = (n2[iface][0] - n1[iface][0], n2[iface][1] - n1[iface][1])
    return {'cpu': cpu, 'load': la, 'cores': os.cpu_count() or 1, 'mem': mem_info(), 'disks': disks(),
            'temp': temperature(), 'uptime': up, 'iface': iface, 'rate': rate,
            'reboot': os.path.exists('/var/run/reboot-required')}


def srv_problems():
    return [k for k, v in srv_cfg().get('alerts', {}).items() if v]


def scr_srv(uid, note=''):
    c = srv_cfg()
    sn = srv_snapshot()
    m = sn['mem']
    lines = [f'🖥 <b>Сервер {h(platform.node())}</b>', '']
    try:
        osname = re.search(r'^PRETTY_NAME="?([^"\n]*)', open('/etc/os-release').read(), re.M).group(1)
    except Exception:
        osname = 'Linux'
    lines.append(f'{h(osname)} · ядро {h(platform.release())}')
    lines.append(f'⏱ Работает без перезагрузки: {fmt_dur(sn["uptime"])}')
    lines.append('')
    lp = sn['load'][1] / sn['cores']
    lines.append(f'🧠 Процессор: <code>{bar(sn["cpu"] / 100)}</code> {sn["cpu"]:.0f}%')
    lines.append(f'      нагрузка {sn["load"][0]:.2f} / {sn["load"][1]:.2f} / {sn["load"][2]:.2f} '
                 f'(ядер {sn["cores"]})' + (' ⚠️' if lp >= c['load'] else ''))
    mp = 100 * m['used'] / max(m['total'], 1)
    lines.append(f'💾 Память: <code>{bar(mp / 100)}</code> {fmt_bytes(m["used"])} из {fmt_bytes(m["total"])} '
                 f'({mp:.0f}%)' + (' ⚠️' if mp >= c['ram'] else ''))
    if m['swap_total']:
        lines.append(f'      подкачка: {fmt_bytes(m["swap_used"])} из {fmt_bytes(m["swap_total"])}')
    for d in sn['disks']:
        dp = 100 * d['used'] / max(d['total'], 1)
        lines.append(f'💿 Диск {h(d["mount"])}: <code>{bar(dp / 100)}</code> {fmt_bytes(d["used"])} из '
                     f'{fmt_bytes(d["total"])} ({dp:.0f}%), свободно {fmt_bytes(d["free"])}' + (' ⚠️' if dp >= c['disk'] else ''))
    if sn['temp'] is not None:
        lines.append(f'🌡 Температура: {sn["temp"]:.0f}°C' + (' ⚠️' if sn['temp'] >= 85 else ''))
    if sn['rate']:
        lines.append(f'🌐 Сеть {h(sn["iface"])}: ↓ {fmt_mbit(sn["rate"][0])}  ↑ {fmt_mbit(sn["rate"][1])}')
    lines.append('')
    svc = []
    for unit, title in (('mihomo', 'mihomo'), (f'wg-quick@{WG_IF}', 'WireGuard'), ('vpnbot', 'бот')):
        act, rss = unit_info(unit)
        svc.append(f'{"🟢" if act == "active" else "🔴"} {title}' + (f' ({fmt_bytes(rss)})' if rss else ''))
    lines.append('⚙️ Службы: ' + ' · '.join(svc))
    upd, sec = apt_updates()
    if upd:
        lines.append(f'📦 Обновлений Ubuntu: {upd}' + (f', из них безопасности: {sec}' if sec else '') +
                     ' — <code>sudo apt upgrade</code>')
    if sn['reboot']:
        lines.append('🔁 После обновлений Ubuntu нужна перезагрузка (🔧 Управление → 🖥 Перезагрузить).')
    lines += ['', f'🚨 Уведомлю, если: диск ≥ {c["disk"]}%, память ≥ {c["ram"]}%, '
                  f'нагрузка ≥ {c["load"]:g} на ядро, упадёт служба.']
    if note:
        lines += ['', note]
    lines.append(f'<i>Обновлено {time.strftime("%H:%M:%S")}</i>')
    kb = [[btn('🔄 Обновить', 'srv'), btn('🧹 Освободить место', 'srvclean')]]
    if is_owner(uid):
        kb.append([btn('🚨 Пороги уведомлений', 'srvthr')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_srv_thr(uid, note=''):
    c = srv_cfg()
    text = ('🚨 <b>Пороги уведомлений</b>\n\nКогда присылать предупреждение. Нагрузка — среднее за 5 минут '
            'в расчёте на одно ядро (1 = ядра заняты полностью).')
    if note:
        text += '\n\n' + note

    def row(key, vals, fmt):
        return [btn(('✅ ' if c[key] == x else '') + fmt(x), f'srvt:{key}:{x}') for x in vals]
    kb = [[btn('💿 Диск заполнен на:', 'noop')], row('disk', (80, 85, 90, 95), lambda x: f'{x}%'),
          [btn('💾 Память занята на:', 'noop')], row('ram', (85, 90, 95), lambda x: f'{x}%'),
          [btn('🧠 Нагрузка на ядро:', 'noop')], row('load', (1.5, 2.0, 3.0), lambda x: f'×{x:g}'),
          [btn('⬅️ Сервер', 'srv')]]
    return text, kb


def srv_cleanup():
    before = sum(d['free'] for d in disks())
    steps = []
    r = run(['journalctl', '--vacuum-size=200M'], 60)
    steps.append('журналы systemd сжаты до 200 МБ' if r.returncode == 0 else 'журналы: ошибка')
    run(['apt-get', 'clean'], 120)
    steps.append('кэш пакетов apt очищен')
    import glob
    old = sorted(glob.glob('/etc/mihomo/config.yaml.bak-*'))[:-3]
    for f in old + glob.glob(os.path.join(UPDATE_DIR, '*.deb')):
        try:
            os.remove(f)
        except OSError:
            pass
    steps.append(f'старые копии конфига и пакеты обновлений удалены ({len(old)})')
    freed = sum(d['free'] for d in disks()) - before
    return freed, steps


def srv_tick():
    c = srv_cfg()
    al = c['alerts']
    sn = srv_snapshot(sample=False)
    msgs = []

    def flag(key, bad, good, text_bad, text_good):
        cnt_key = '_n_' + key
        if bad:
            al[cnt_key] = al.get(cnt_key, 0) + 1
        else:
            al[cnt_key] = 0
        need = 1 if key.startswith('disk') else 3          # память и нагрузку подтверждаем 3 проверками
        if bad and al[cnt_key] >= need and not al.get(key):
            al[key] = True
            msgs.append(text_bad)
        elif good and al.get(key):
            al[key] = False
            msgs.append(text_good)
    for d in sn['disks']:
        dp = 100 * d['used'] / max(d['total'], 1)
        flag(f'disk:{d["mount"]}', dp >= c['disk'], dp < c['disk'] - 5,
             f'💿 <b>Диск {h(d["mount"])} заполнен на {dp:.0f}%</b>\nСвободно {fmt_bytes(d["free"])}. '
             'Освободить: 🖥 Сервер → 🧹 Освободить место.',
             f'✅ Диск {h(d["mount"])}: место освободилось ({dp:.0f}%)')
    m = sn['mem']
    mp = 100 * m['used'] / max(m['total'], 1)
    flag('ram', mp >= c['ram'], mp < c['ram'] - 5,
         f'💾 <b>Память занята на {mp:.0f}%</b> ({fmt_bytes(m["used"])} из {fmt_bytes(m["total"])})',
         f'✅ Память в норме ({mp:.0f}%)')
    lp = sn['load'][1] / sn['cores']
    flag('load', lp >= c['load'], lp < c['load'] * 0.7,
         f'🧠 <b>Высокая нагрузка на процессор</b>: {sn["load"][1]:.2f} при {sn["cores"]} ядрах',
         '✅ Нагрузка на процессор в норме')
    if sn['temp'] is not None:
        flag('temp', sn['temp'] >= 85, sn['temp'] < 75, f'🌡 <b>Перегрев: {sn["temp"]:.0f}°C</b>',
             f'✅ Температура в норме ({sn["temp"]:.0f}°C)')
    act, _ = unit_info(f'wg-quick@{WG_IF}')
    flag('wg', act != 'active', act == 'active', '🔴 <b>Служба WireGuard остановлена</b>\nКлиенты не могут подключиться. '
         'Перезапуск: 🔧 Управление → 🔌 Перезапуск WireGuard.', '✅ WireGuard снова работает')
    if sn['reboot']:
        try:
            boot = open('/proc/sys/kernel/random/boot_id').read().strip()
        except Exception:
            boot = ''
        if al.get('reboot_note') != boot:
            al['reboot_note'] = boot
            msgs.append('🔁 Ubuntu установила обновления, которым нужна перезагрузка сервера. '
                        'Сделайте её в удобное время: 🔧 Управление → 🖥 Перезагрузить сервер.')
    save_state()
    for t in msgs:
        add_event(plain(t).split('\n')[0])
        notify('server', t)


# ---------------- экран подписок ----------------
def sub_summary(sb, full=False):
    try:
        p = provider(sb['id'])
    except Exception:
        return f'📦 <b>{h(sb["name"])}</b>: 🔴 нет данных'
    cnt = len([x for x in (p.get('proxies') or []) if not HIDE_RE.search(x['name'])])
    stub = cnt == 0 and bool(p.get('proxies'))
    si = p.get('subscriptionInfo') or {}
    parts = [f'серверов {cnt}' if not stub else '⚠️ провайдер отдал заглушку']
    if si.get('Expire'):
        dl = days_left(si['Expire'])
        parts.append(f'до {fmt_date(si["Expire"])}' + (' ⚠️' if dl <= 7 else ''))
    used = (si.get('Upload') or 0) + (si.get('Download') or 0)
    if si.get('Total'):
        parts.append(f'трафик {fmt_bytes(used)} из {fmt_bytes(si["Total"])}')
    elif used:
        parts.append(f'трафик {fmt_bytes(used)}')
    line = f'📦 <b>{h(sb["name"])}</b>: ' + ', '.join(parts)
    if full:
        upd = (p.get('updatedAt') or '')[:16].replace('T', ' ')
        kind = 'ссылки vless (вручную)' if sb.get('type') == 'file' else 'подписка по ссылке, обновляется раз в 12 ч'
        line += f'\n      {kind}' + (f', обновлена {h(upd)}' if upd and sb.get('type') != 'file' else '')
        if sb.get('prefix'):
            line += f'\n      серверы с приставкой <code>{h(sb["prefix"].strip())}</code>'
    return line


def mask_url(u):
    if not u:
        return '—'
    m = re.match(r'^(https?://[^/]+/)(.*)$', u)
    if not m:
        return u[:12] + '…'
    tail = m.group(2)
    return m.group(1) + (tail[:3] + '…' + tail[-3:] if len(tail) > 8 else '…')


def scr_subs(uid, note=''):
    lines = ['📦 <b>Подписки VPN</b>', '']
    for sb in subs():
        lines.append(sub_summary(sb, full=True))
    lines += ['', 'Серверы всех подписок участвуют в общем автовыборе. Если у одного поставщика всё упадёт, '
                  'mihomo переключится на серверы другого.']
    if note:
        lines += ['', note]
    kb = [[btn(f'📦 {x["name"]}'[:40], f'sub:v:{x["id"]}')] for x in subs()]
    kb.append([btn('➕ Добавить подписку', 'sub:a')])
    kb.append([btn('⬅️ Управление', 'manage'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_sub(uid, pid, note=''):
    sb = sub_by_id(pid)
    if not sb:
        return scr_subs(uid, '⚠️ Подписка не найдена')
    lines = [sub_summary(sb, full=True), '',
             f'Ссылка: <code>{h(mask_url(sb.get("url")))}</code>' if sb.get('type') != 'file' else 'Ссылка: нет']
    if note:
        lines += ['', note]
    kb = [[btn('🔑 Заменить ссылку', f'sub:r:{pid}'), btn('✏️ Переименовать', f'sub:n:{pid}')]]
    if sb.get('type') != 'file':
        kb.append([btn('🔄 Обновить сейчас', f'sub:u:{pid}')])
    if len(subs()) > 1:
        kb.append([btn('🗑 Удалить', f'sub:d:{pid}')])
    kb.append([btn('⬅️ Подписки', 'subs')])
    return '\n'.join(lines), kb


def vless_to_proxy(link):
    u = urllib.parse.urlsplit(link.strip())
    if u.scheme != 'vless' or not u.hostname:
        return None
    qs = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    p = {'name': urllib.parse.unquote(u.fragment) or f'{u.hostname}:{u.port}', 'type': 'vless',
         'server': u.hostname, 'port': int(u.port or 443), 'uuid': urllib.parse.unquote(u.username or ''),
         'udp': True, 'network': qs.get('type', 'tcp')}
    sec = qs.get('security', 'none')
    if sec in ('tls', 'reality'):
        p['tls'] = True
        if qs.get('sni'):
            p['servername'] = qs['sni']
        if qs.get('fp'):
            p['client-fingerprint'] = qs['fp']
    if sec == 'reality':
        p['reality-opts'] = {'public-key': qs.get('pbk', ''), 'short-id': qs.get('sid', '')}
        p.setdefault('client-fingerprint', 'chrome')
    if qs.get('flow'):
        p['flow'] = qs['flow']
    if p['network'] == 'ws':
        p['ws-opts'] = {'path': qs.get('path', '/')}
        if qs.get('host'):
            p['ws-opts']['headers'] = {'Host': qs['host']}
    if p['network'] == 'grpc':
        p['grpc-opts'] = {'grpc-service-name': qs.get('serviceName', '')}
    return p


def sub_names(text):
    t = '\n' + text
    if '\nproxies:' in t:
        body = re.split(r'\n[A-Za-z][\w-]*:', t.split('\nproxies:', 1)[1], maxsplit=1)[0]
        names = []
        for m in re.finditer(r'^\s*-\s*(?:\{\s*)?["\']?name["\']?\s*:\s*(.+?)\s*$', body, re.M):
            n = m.group(1).rstrip(',}').strip()
            if len(n) >= 2 and n[0] == n[-1] and n[0] in '"\'':
                n = n[1:-1]
            names.append(n)
        return names
    raw = text.strip()
    if 'vless://' not in raw:
        try:
            import base64
            raw = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', 'ignore')
        except Exception:
            return []
    return [p['name'] for p in map(vless_to_proxy, re.split(r'\s+', raw)) if p]


def fetch_subscription(url):
    """Скачивает подписку так же, как это делает приложение. → (ua, содержимое, имена) или ошибка."""
    last = 'нет ответа'
    hdr = device_headers()
    for ua in SUB_UAS:
        for attempt in range(3):
            code, data = None, b''
            for opener in (direct_opener, proxy_opener):
                try:
                    req = urllib.request.Request(url, headers=dict(hdr, **{'User-Agent': ua}))
                    with opener.open(req, timeout=30) as r:
                        code, data = r.status, r.read()
                    break
                except urllib.error.HTTPError as e:
                    code = e.code
                    break
                except Exception as e:
                    last = str(e)
            if code == 429:
                time.sleep(20)
                continue
            break
        if code != 200:
            last = f'HTTP {code}' if code else last
            continue
        text = data.decode('utf-8', 'ignore')
        names = sub_names(text)
        real = [n for n in names if not re.search(r'поддерживается|Превышено|устройств', n, re.I)]
        if real:
            return ua, text, real
        if any(re.search(r'Превышено|устройств', n, re.I) for n in names):
            raise RuntimeError('провайдер ответил «Превышено количество устройств». Удалите старое устройство '
                               'в боте или личном кабинете провайдера и попробуйте снова.')
        last = 'провайдер отдал заглушку «приложение не поддерживается»'
    raise RuntimeError(f'не удалось получить серверы: {last}')


def new_sub_id():
    used = {x['id'] for x in subs()}
    return next(f'sub{i}' for i in range(2, 100) if f'sub{i}' not in used)


def save_sub(pid, name, text, chat):
    """Проверяет ссылку (или ссылки vless://) и применяет. pid=None — новая подписка."""
    links = [x for x in re.split(r'\s+', text.strip()) if x.startswith('vless://')]
    if links:
        proxies = [p for p in map(vless_to_proxy, links) if p]
        if not proxies:
            raise RuntimeError('не нашёл корректных ссылок vless://')
        content = 'proxies:\n' + ''.join(f'  - {json.dumps(p, ensure_ascii=False)}\n' for p in proxies)
        entry = {'type': 'file', 'url': '', 'ua': SUB_UAS[0]}
        names = [p['name'] for p in proxies]
    else:
        url = text.strip()
        if not re.match(r'^https?://\S+$', url):
            raise RuntimeError('нужна ссылка вида https://… или ссылки vless://')
        ua, content, names = fetch_subscription(url)
        entry = {'type': 'http', 'url': url, 'ua': ua}
    v = vpn()
    with lock:
        if pid is None:
            pid = new_sub_id()
            entry.update(id=pid, name=name, prefix=f'[{name}] ')
            state['subs'].append(entry)
        else:
            sb = sub_by_id(pid)
            sb.update(entry)
        save_state()
    os.makedirs(PROV_DIR, exist_ok=True)
    path = os.path.join(PROV_DIR, f'{pid}.yaml')
    if not content.lstrip().startswith('proxies:') and '\nproxies:' not in content:
        content = 'proxies:\n' + ''.join(f'  - {json.dumps(p, ensure_ascii=False)}\n'
                                          for p in map(vless_to_proxy, re.split(r'\s+', content)) if p)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    os.chmod(path, 0o600)
    apply_vpn_config(v)
    return pid, len(names)


def rename_sub(pid, new):
    sb = sub_by_id(pid)
    old_pref = sb.get('prefix', '')
    v = vpn()
    with lock:
        sb['name'] = new
        if sb['id'] != subs()[0]['id'] or old_pref:
            sb['prefix'] = f'[{new}] '
            for key in ('excluded', 'priority'):
                v[key] = [sb['prefix'] + n[len(old_pref):] if old_pref and n.startswith(old_pref) else n
                          for n in v.get(key, [])]
        save_state()
    if sb.get('prefix') != old_pref:
        apply_vpn_config(v)


def handle_sub(uid, data, chat, mid):
    parts = data.split(':')
    act, pid = parts[1], (parts[2] if len(parts) > 2 else None)
    who = admin_name(uid)
    if act == 'v':
        return scr_sub(uid, pid)
    if act == 'a':
        awaiting[uid] = ('sub_name', None)
        return ('➕ <b>Новая подписка</b>\n\nКак назвать поставщика? Это имя станет приставкой к его серверам, '
                'например <code>Lumpen</code> → «[Lumpen] 🇳🇱 Нидерланды».\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'subs')]])
    sb = sub_by_id(pid)
    if not sb:
        return scr_subs(uid, '⚠️ Подписка не найдена')
    if act == 'r':
        awaiting[uid] = ('sub_url', {'id': pid, 'name': sb['name']})
        return (f'🔑 <b>Новая ссылка для «{h(sb["name"])}»</b>\n\nОтправьте ссылку на подписку (https://…) или '
                'одну-несколько ссылок vless://. Сообщение со ссылкой я сразу удалю из чата.\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', f'sub:v:{pid}')]])
    if act == 'n':
        awaiting[uid] = ('sub_rename', pid)
        return (f'✏️ Новое имя для «{h(sb["name"])}»?\n\nОтмена: /cancel', [[btn('✖️ Отмена', f'sub:v:{pid}')]])
    if act == 'u':
        edit(chat, mid, '🔄 Обновляю…')
        try:
            api(f'/providers/proxies/{pid}', 'PUT', timeout=40)
            return scr_sub(uid, pid, '✅ Обновлено')
        except Exception as e:
            return scr_sub(uid, pid, f'🔴 {h(str(e))[:200]}')
    if act == 'd':
        return (f'🗑 Удалить подписку <b>{h(sb["name"])}</b>? Её серверы пропадут из списка, VPN на 5–10 секунд прервётся.',
                [[btn('✅ Удалить', f'sub:dd:{pid}'), btn('✖️ Отмена', f'sub:v:{pid}')]])
    if act == 'dd' and len(subs()) > 1:
        edit(chat, mid, '⏳ Удаляю и применяю…')
        try:
            err = delete_sub(pid, who)
        except Exception as e:
            return scr_subs(uid, f'🔴 {h(str(e))[:300]}')
        with lock:
            for x in vps_all().values():
                if x.get('sub') == pid:
                    x['sub'] = None
            save_state()
        return scr_subs(uid, f'🔴 {h(err)}' if err else f'🗑 Подписка «{h(sb["name"])}» удалена')
    return scr_subs(uid)


def handle_sub_input(uid, chat, m, kind, wdata, text):
    if kind == 'sub_name':
        name = re.sub(r'[\[\]\'"]', '', text.strip())[:20]
        if not name:
            send(chat, 'Имя не может быть пустым. Ещё раз или /cancel.')
            return
        if any(x['name'].lower() == name.lower() for x in subs()):
            send(chat, 'Подписка с таким именем уже есть. Другое имя или /cancel.')
            return
        awaiting[uid] = ('sub_url', {'id': None, 'name': name})
        send(chat, f'🔑 <b>Подписка «{h(name)}»</b>\n\nОтправьте ссылку на подписку (https://…) или ссылки vless://. '
                   'Сообщение со ссылкой я сразу удалю из чата.\n\nОтмена: /cancel')
        return
    if kind == 'sub_rename':
        name = re.sub(r'[\[\]\'"]', '', text.strip())[:20]
        if not name:
            send(chat, 'Имя не может быть пустым. Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        try:
            rename_sub(wdata, name)
            t, kb = scr_sub(uid, wdata, '✅ Переименовано')
        except Exception as e:
            t, kb = scr_sub(uid, wdata, f'🔴 {h(str(e))[:300]}')
        send(chat, t, kb)
        return
    # sub_url
    tg('deleteMessage', chat_id=chat, message_id=m['message_id'])
    awaiting.pop(uid, None)
    r = send(chat, '⏳ Проверяю подписку и применяю настройки (до минуты)…')
    try:
        pid, n = save_sub(wdata['id'], wdata['name'], text, chat)
        add_event(f'{admin_name(uid)}: подписка «{wdata["name"]}» ' + ('добавлена' if wdata['id'] is None else 'заменена'))
        t, kb = scr_sub(uid, pid, f'✅ Готово: серверов {n}. Они уже участвуют в автовыборе.')
    except Exception as e:
        back = wdata['id']
        t, kb = (scr_sub(uid, back, f'🔴 {h(str(e))[:400]}') if back else scr_subs(uid, f'🔴 {h(str(e))[:400]}'))
    if r:
        edit(chat, r['message_id'], t, kb)
    else:
        send(chat, t, kb)


# ---------------- свои серверы VLESS: развёртывание и управление по SSH ----------------
SSH_DIR = '/var/lib/vpnbot/ssh'
SSH_KEY = os.path.join(SSH_DIR, 'id_ed25519')
SSH_KNOWN = os.path.join(SSH_DIR, 'known_hosts')
VLESS_SCRIPT = '/usr/local/lib/vpngw/install-vless.sh'
REMOTE_SCRIPT = '/usr/local/sbin/vpngw-vless'
SUDOERS_FILE = '/etc/sudoers.d/zzz-vpngw-bot'   # последним: более поздние правила sudo главнее
SNI_SITES = ['www.samsung.com', 'www.nvidia.com', 'www.amd.com', 'dl.google.com', 'addons.mozilla.org',
             'www.apple.com']
BAD_GL = {'RU': 'Россия', 'BY': 'Беларусь', 'IR': 'Иран', 'CN': 'Китай', 'KP': 'КНДР', 'SY': 'Сирия', 'CU': 'Куба'}
CHROME_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
             'Chrome/131.0.0.0 Safari/537.36')
VS_BUSY = set()
VS_STEPS = [('ssh', 'Подключение по SSH'), ('key', 'Ключ бота на сервере'), ('sudo', 'Права администратора'),
            ('sys', 'Проверка системы'), ('xray', 'Установка Xray и подбор маскировки (1–3 мин)'),
            ('ru', 'Доступность порта из России'), ('vless', 'Проверка VLESS и страны для Google'),
            ('add', 'Добавление в шлюз (VPN прервётся на 5–10 с)')]


class VsError(Exception):
    def __init__(self, msg, data=None):
        super().__init__(msg)
        self.data = data or {}


def vps_all():
    with lock:
        return state.setdefault('vps', {})


def vps_by_host(host, port):
    return next((k for k, x in vps_all().items() if x['host'] == host and int(x['port']) == int(port)), None)


def flag(cc):
    return ''.join(chr(0x1F1E6 + ord(c) - 65) for c in cc) if cc and re.match(r'^[A-Z]{2}$', cc) else ''


def ssh_ensure_key():
    os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
    os.chmod(SSH_DIR, 0o700)
    if not os.path.exists(SSH_KEY + '.pub'):
        try:
            r = run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'vpn-gateway-bot@{platform.node()}',
                     '-f', SSH_KEY], 30)
        except FileNotFoundError:
            raise RuntimeError('на шлюзе нет программ SSH — установите: <code>sudo apt install -y openssh-client</code>')
        if r.returncode != 0 or not os.path.exists(SSH_KEY + '.pub'):
            raise RuntimeError('не удалось создать SSH-ключ бота: ' + (r.stderr or r.stdout)[-200:])
    askpass = os.path.join(SSH_DIR, 'askpass')
    if not os.path.exists(askpass):
        with open(askpass, 'w') as f:
            f.write('#!/bin/sh\nprintf \'%s\\n\' "$VPNGW_SSH_SECRET"\n')
        os.chmod(askpass, 0o700)
    return open(SSH_KEY + '.pub').read().strip()


def ssh_argv(vs, auth=None, known=None, strict='yes'):
    """Команда ssh. auth=None — ключ бота; {'pw': пароль} — вход по паролю; {'key': файл} — ключ владельца."""
    argv = ['ssh', '-F', '/dev/null', '-p', str(vs.get('port') or 22), '-o', 'ConnectTimeout=15',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4', '-o', f'UserKnownHostsFile={known or SSH_KNOWN}',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', f'StrictHostKeyChecking={strict}', '-o', 'LogLevel=ERROR',
            '-o', 'UpdateHostKeys=no']
    env = {k: val for k, val in os.environ.items() if not k.startswith(('SSH_', 'DISPLAY'))}
    if auth and auth.get('pw') is not None:
        argv += ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive',
                 '-o', 'NumberOfPasswordPrompts=1']
        env.update(SSH_ASKPASS=os.path.join(SSH_DIR, 'askpass'), SSH_ASKPASS_REQUIRE='force', DISPLAY=':0',
                   VPNGW_SSH_SECRET=auth['pw'])
    else:
        argv += ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
                 '-o', 'KbdInteractiveAuthentication=no', '-i', (auth or {}).get('key') or SSH_KEY]
    argv.append(f'{vs["user"]}@{vs["host"]}')
    return argv, env


def ssh_exec(vs, command, auth=None, inp=None, timeout=90, on_line=None, **kw):
    """Выполняет команду на сервере → (код, stdout, stderr). on_line — вызывается на каждую строку вывода."""
    argv, env = ssh_argv(vs, auth, **kw)
    try:
        p = subprocess.Popen(argv + [command], stdin=subprocess.PIPE if inp is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                             start_new_session=True)
    except FileNotFoundError:
        raise RuntimeError('на шлюзе нет программы ssh — установите: sudo apt install -y openssh-client')
    err_buf = []
    t_err = threading.Thread(target=lambda: err_buf.append(p.stderr.read()), daemon=True)
    t_err.start()
    if inp is not None:
        try:
            p.stdin.write(inp)
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    out = []
    killed = []
    timer = threading.Timer(timeout, lambda: (killed.append(1), p.kill()))
    timer.start()
    try:
        for line in p.stdout:
            out.append(line)
            if on_line:
                try:
                    on_line(line.rstrip('\n'))
                except Exception:
                    pass
        p.wait()
    finally:
        timer.cancel()
    t_err.join(5)
    if killed:
        return 124, ''.join(out), 'timeout'
    return p.returncode, ''.join(out), ''.join(err_buf)


def ssh_err(err):
    e = (err or '').strip()
    for pat, txt in [
            ('HOST IDENTIFICATION HAS CHANGED', 'ключ сервера изменился (сервер переустановлен?). Если это ожидаемо, '
                                                'удалите сервер из бота и разверните заново'),
            ('Host key verification failed', 'ключ сервера не совпадает с сохранённым'),
            ('Permission denied', 'неверный пароль или ключ (или вход этому пользователю запрещён)'),
            ('Too many authentication failures', 'слишком много попыток входа — подождите и попробуйте снова'),
            ('Connection refused', 'порт SSH закрыт — соединение отклонено'),
            ('timed out', 'сервер не отвечает — проверьте IP-адрес и порт SSH'),
            ('Could not resolve', 'не удалось найти сервер по этому имени'),
            ('No route to host', 'нет маршрута до сервера'),
            ('Connection closed', 'сервер закрыл соединение'),
            ('Connection reset', 'соединение сброшено'),
            ('timeout', 'операция не уложилась по времени')]:
        if pat.lower() in e.lower():
            return txt
    return e.splitlines()[-1][:200] if e else 'неизвестная ошибка SSH'


def kh_pattern(host, port):
    return host if int(port) == 22 else f'[{host}]:{port}'


def kh_lines():
    try:
        return [x for x in open(SSH_KNOWN).read().splitlines() if x.strip()]
    except OSError:
        return []


def kh_set(host, port, lines):
    pat = kh_pattern(host, port)
    keep = [x for x in kh_lines() if x.split(' ', 1)[0] != pat]
    with open(SSH_KNOWN, 'w') as f:
        f.write('\n'.join(keep + list(lines)) + '\n')
    os.chmod(SSH_KNOWN, 0o600)


def kh_known(host, port):
    pat = kh_pattern(host, port)
    return [x for x in kh_lines() if x.split(' ', 1)[0] == pat]


def ssh_fp(line):
    typ, b64 = line.split()[1:3]
    digest = hashlib.sha256(base64.b64decode(b64)).digest()
    return typ, 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')


def ssh_scan(host, port):
    """Получает ключ сервера (без входа) → строки для known_hosts."""
    ssh_ensure_key()
    tmp = os.path.join(SSH_DIR, f'scan-{uuid.uuid4().hex}')
    try:
        _, _, err = ssh_exec({'host': host, 'port': port, 'user': 'vpngw-check'}, 'true', known=tmp,
                             strict='accept-new', timeout=40)
        lines = [x for x in open(tmp).read().splitlines() if x.strip()] if os.path.exists(tmp) else []
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if not lines:
        raise RuntimeError(ssh_err(err))
    return lines


def as_root(vs, cmd):
    return cmd if vs['user'] == 'root' else 'sudo -n sh -c ' + shlex.quote(cmd)


def vs_script_text():
    try:
        return open(VLESS_SCRIPT, encoding='utf-8').read()
    except OSError:
        return fetch(raw_url('server/install-vless.sh'))


def parse_marks(out):
    data = {}
    for line in out.splitlines():
        if line.startswith('@@'):
            k, _, val = line[2:].partition(' ')
            if k in ('STEP', 'SNI_SKIP', 'SNI_FAIL'):
                data.setdefault(k, []).append(val)
            else:
                data[k] = val
    return data


def vs_call(vs, mode, env=None, timeout=900, on_step=None):
    """Загружает на сервер скрипт install-vless.sh и запускает его с правами root."""
    up = (f'mkdir -p /usr/local/sbin && cat > {REMOTE_SCRIPT}.new && chmod 700 {REMOTE_SCRIPT}.new '
          f'&& mv -f {REMOTE_SCRIPT}.new {REMOTE_SCRIPT}')
    rc, _, err = ssh_exec(vs, as_root(vs, up), inp=vs_script_text(), timeout=90)
    if rc != 0:
        raise VsError('не удалось загрузить скрипт на сервер: ' + ssh_err(err))
    envs = ' '.join(f'{k}={shlex.quote(str(val))}' for k, val in (env or {}).items())
    cmd = f'env {envs} bash {REMOTE_SCRIPT} {mode} </dev/null'

    def line_cb(line):
        if on_step and line.startswith('@@STEP '):
            on_step(line[7:])
    rc, out, err = ssh_exec(vs, as_root(vs, cmd), timeout=timeout, on_line=line_cb)
    data = parse_marks(out)
    if rc != 0 or 'ERROR' in data or not ({'OK', 'EXISTING'} & set(data)):
        if data.get('ERROR'):
            msg = data['ERROR']
        elif rc == 255 or err.strip().lower().startswith(('ssh:', 'connection')):
            msg = ssh_err(err)
        elif 'sudo' in err and 'password' in err:
            msg = 'sudo требует пароль. Нажмите «➕ Развернуть сервер» ещё раз и войдите по паролю'
        else:
            msg = (err or out).strip()[-300:] or f'код выхода {rc}'
        raise VsError(msg, data)
    return data


def tcp_open(host, port, timeout=8, tries=3):
    for i in range(tries):
        try:
            socket.create_connection((host, int(port)), timeout).close()
            return True
        except OSError:
            if i < tries - 1:
                time.sleep(2)
    return False


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def vless_check(link, geo=True):
    """Проверяет ссылку vless через отдельный временный mihomo (основной VPN не трогается).
    → {'ok', 'ms', 'ip', 'gl', 'err'}. gl — страна, которую видит Google (по YouTube)."""
    p = vless_to_proxy(link)
    if not p:
        return {'ok': False, 'err': 'некорректная ссылка vless://'}
    p = dict(p, name='T')
    port = free_port()
    base = '/var/lib/vpnbot' if os.path.isdir('/var/lib/vpnbot') else None
    d = tempfile.mkdtemp(prefix='vless-check-', dir=base)
    with open(os.path.join(d, 'config.yaml'), 'w', encoding='utf-8') as f:
        f.write('\n'.join([f'mixed-port: {port}', 'bind-address: 127.0.0.1', 'allow-lan: false', 'mode: rule',
                           'log-level: warning', 'ipv6: false', 'proxies:', '  - ' + json.dumps(p, ensure_ascii=False),
                           'rules:', '  - MATCH,T', '']))
    binary = shutil.which('mihomo') or '/usr/bin/mihomo'
    res = {'ok': False}
    logf = open(os.path.join(d, 'log.txt'), 'w')
    try:
        proc = subprocess.Popen([binary, '-d', d], stdout=logf, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        logf.close()
        shutil.rmtree(d, ignore_errors=True)
        return {'ok': False, 'err': 'не найден mihomo'}
    try:
        for _ in range(40):
            try:
                socket.create_connection(('127.0.0.1', port), 0.5).close()
                break
            except OSError:
                if proc.poll() is not None:
                    break
                time.sleep(0.25)
        purl = f'http://127.0.0.1:{port}'
        op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': purl, 'https': purl}))
        best, err = None, ''
        for _ in range(3):
            t0 = time.time()
            try:
                with op.open(urllib.request.Request(TEST_URL, headers={'User-Agent': CHROME_UA}), timeout=12) as r:
                    r.read()
                    ok = r.status in (200, 204)
                if ok:
                    ms = int((time.time() - t0) * 1000)
                    best = ms if best is None else min(best, ms)
            except Exception as e:
                err = str(e)
        if best is None:
            res['err'] = err or 'нет ответа'
            return res
        res.update(ok=True, ms=best)
        if geo:
            try:
                with op.open(urllib.request.Request('https://api.ipify.org', headers={'User-Agent': CHROME_UA}),
                             timeout=12) as r:
                    res['ip'] = r.read(64).decode().strip()
            except Exception:
                pass
            try:
                req = urllib.request.Request('https://www.youtube.com/?hl=en', headers={
                    'User-Agent': CHROME_UA, 'Cookie': 'SOCS=CAI', 'Accept-Language': 'en-US,en;q=0.9'})
                with op.open(req, timeout=15) as r:
                    page = r.read(1_500_000).decode('utf-8', 'ignore')
                m = (re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"', page)
                     or re.search(r'"GL"\s*:\s*"([A-Z]{2})"', page)
                     or re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', page))
                res['gl'] = m.group(1) if m else None
            except Exception:
                res['gl'] = None
        return res
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()
        logf.close()
        shutil.rmtree(d, ignore_errors=True)


def gl_text(gl):
    if not gl:
        return 'страну для Google определить не удалось'
    if gl in BAD_GL:
        return f'⚠️ Google считает сервер: {flag(gl)} {BAD_GL[gl]} — Gemini и часть сервисов Google могут не работать'
    return f'Google видит страну: {flag(gl)} {gl}'


def vs_link_host(text):
    return {p['server'] for p in map(vless_to_proxy, re.findall(r'vless://\S+', text or '')) if p}


def sub_for_host(host):
    """Подписка из ссылок vless, в которой есть сервер с этим адресом (например, добавленная вручную)."""
    for sb in subs():
        if sb.get('type') != 'file':
            continue
        try:
            txt = open(os.path.join(PROV_DIR, f'{sb["id"]}.yaml'), encoding='utf-8').read()
        except OSError:
            continue
        if re.search(r'"server":\s*"' + re.escape(host) + '"', txt):
            return sb['id']
    return None


def vs_attach(vid, link, gl=None):
    """Добавляет сервер в шлюз отдельной подпиской (или обновляет ссылку в существующей)."""
    x = vps_all()[vid]
    pid = x.get('sub') if sub_by_id(x.get('sub') or '') else sub_for_host(x['host'])
    p = vless_to_proxy(link) or {}
    try:
        cur = open(os.path.join(PROV_DIR, f'{pid}.yaml'), encoding='utf-8').read() if pid else ''
    except OSError:
        cur = ''
    same = bool(p) and p.get('uuid', '-') in cur and (p.get('reality-opts') or {}).get('public-key', '-') in cur
    if pid and same:
        pass                            # ссылка уже стоит в шлюзе — лишний раз VPN не перезапускаем
    elif pid:
        save_sub(pid, sub_by_id(pid)['name'], link, None)
    else:
        base = f'Свой {flag(gl)}'.strip() if gl and gl not in BAD_GL else 'Свой'
        name, i = base, 2
        while any(s['name'].lower() == name.lower() for s in subs()):
            name, i = f'{base} {i}', i + 1
        pid, _ = save_sub(None, name, link, None)
    with lock:
        x['sub'] = pid
        save_state()
    return pid


def delete_sub(pid, who):
    sb = sub_by_id(pid)
    if not sb or len(subs()) < 2:
        return 'нельзя удалить последнюю подписку'
    v = vpn()
    with lock:
        state['subs'] = [x for x in subs() if x['id'] != pid]
        v['svc'] = {k: x for k, x in (v.get('svc') or {}).items() if x != pid}
        pref = sb.get('prefix')
        if pref:
            for key in ('excluded', 'priority'):
                v[key] = [n for n in v.get(key, []) if not n.startswith(pref)]
        save_state()
    apply_vpn_config(v)
    try:
        os.remove(os.path.join(PROV_DIR, f'{pid}.yaml'))
    except OSError:
        pass
    add_event(f'{who} удалил подписку «{sb["name"]}»')
    return None


class Progress:
    def __init__(self, chat, mid, title, steps):
        self.chat, self.mid, self.title = chat, mid, title
        self.order = [k for k, _ in steps]
        self.label = dict(steps)
        self.st = {k: ['▫️', ''] for k in self.order}
        self.last = 0

    def text(self, tail=''):
        lines = [self.title, '']
        for k in self.order:
            icon, note = self.st[k]
            lines.append(f'{icon} {self.label[k]}' + (f' — {note}' if note else ''))
        return '\n'.join(lines) + (f'\n\n{tail}' if tail else '')

    def set(self, key, icon, note='', force=True):
        self.st[key] = [icon, note]
        if force or time.time() - self.last > 3:
            self.last = time.time()
            if self.mid:
                edit(self.chat, self.mid, self.text())


PROBE = ('echo "@@UID $(id -u)"; echo "@@ARCH $(uname -m)"; '
         '( . /etc/os-release 2>/dev/null; echo "@@OS $ID|$ID_LIKE|$PRETTY_NAME" ); '
         'echo "@@DISK $(df -Pk / | awk \'NR==2{print $4}\')"; '
         'command -v systemctl >/dev/null && echo "@@SYSTEMD 1"; command -v sudo >/dev/null && echo "@@SUDO 1"; '
         'echo "@@HOST $(hostname)"; echo "@@OK"')


def vs_deploy(uid, chat, mid, ctx):
    """Мастер: подключение → ключ бота → sudo → проверка системы → установка → проверки → подписка."""
    host, port, user = ctx['host'], int(ctx['port']), ctx['user']
    auth = ctx.pop('auth', None) or {}
    pw = auth.get('pw')
    vs = {'host': host, 'port': port, 'user': user}
    pr = Progress(chat, mid, f'🛰 <b>Развёртывание сервера {h(host)}</b>', VS_STEPS)
    vid = None
    busy_key = (host, port)
    back_kb = [[btn('🛰 Свои серверы', 'vs'), btn('🏠 Меню', 'menu')]]

    def fail(step, msg, extra=''):
        pr.set(step, '🔴', '', force=False)
        text = pr.text(f'🔴 <b>{h(msg)}</b>' + (f'\n\n{extra}' if extra else ''))
        kb = ([[btn('🛰 Открыть сервер', f'vs:v:{vid}')]] if vid else []) + back_kb
        add_event(f'Развёртывание {host}: ошибка — {msg[:120]}')
        return text, kb

    if busy_key in VS_BUSY:
        return '⏳ С этим сервером уже идёт операция, дождитесь её окончания.', back_kb
    VS_BUSY.add(busy_key)
    try:
        if ctx.get('hk'):
            kh_set(host, port, ctx['hk'])
        # 1. вход
        pr.set('ssh', '⏳')
        rc, out, err = ssh_exec(vs, PROBE, auth=auth, timeout=60)
        info = parse_marks(out)
        if rc != 0 or 'OK' not in info:
            return fail('ssh', 'Не удалось войти: ' + ssh_err(err))
        os_id, os_like, os_name = (info.get('OS', '') + '||').split('|')[:3]
        pr.set('ssh', '✅', f'{user}, {os_name or os_id or "?"}')
        # 2. ключ бота
        pr.set('key', '⏳')
        pub = ssh_ensure_key()
        body = pub.split()[1]
        cmd = ('umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && '
               f'(grep -qF {shlex.quote(body)} ~/.ssh/authorized_keys || printf "%s\\n" {shlex.quote(pub)} '
               '>> ~/.ssh/authorized_keys) && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && echo @@OK')
        rc, out, err = ssh_exec(vs, cmd, auth=auth, timeout=60)
        if '@@OK' not in out:
            return fail('key', 'Не удалось добавить ключ: ' + ssh_err(err))
        rc, out, err = ssh_exec(vs, 'echo @@OK', timeout=40)
        if '@@OK' not in out:
            return fail('key', 'Ключ добавлен, но вход по нему не работает: ' + ssh_err(err),
                        'Возможно, на сервере выключен вход по ключам (PubkeyAuthentication no).')
        with lock:
            vid = vps_by_host(host, port)
            if not vid:
                used = set(vps_all())
                vid = next(f'vps{i}' for i in range(1, 1000) if f'vps{i}' not in used)
                vps_all()[vid] = {'host': host, 'port': port, 'created': time.time()}
            x = vps_all()[vid]
            x.update(user=user, name=(info.get('HOST') or host)[:40], os=os_name[:60])
            save_state()
        pr.set('key', '✅', 'дальше бот входит по ключу, пароль не сохраняется')
        add_event(f'{admin_name(uid)}: бот получил доступ к серверу {host}')
        # 3. sudo
        if info.get('UID') == '0':
            pr.set('sudo', '✅', 'root')
        else:
            pr.set('sudo', '⏳')
            if not info.get('SUDO'):
                return fail('sudo', 'На сервере нет sudo, а пользователь не root',
                            'Разверните заново, войдя под root.')
            rc, out, _ = ssh_exec(vs, 'sudo -n true && echo @@OK', timeout=40)
            if '@@OK' not in out:
                if pw is None:
                    return fail('sudo', 'sudo требует пароль',
                                'Нажмите «➕ Развернуть сервер» ещё раз и войдите по паролю — бот один раз '
                                'настроит для себя sudo без пароля.')
                line = f'{user} ALL=(ALL) NOPASSWD:ALL'
                inner = (f"printf '%s\\n' {shlex.quote(line)} > {SUDOERS_FILE}.tmp && chmod 440 {SUDOERS_FILE}.tmp "
                         f"&& visudo -cf {SUDOERS_FILE}.tmp >/dev/null && mv -f {SUDOERS_FILE}.tmp {SUDOERS_FILE} "
                         f"&& echo @@OK")
                ssh_exec(vs, "sudo -S -p '' sh -c " + shlex.quote(inner), inp=pw + '\n', timeout=60)
                rc, out, _ = ssh_exec(vs, 'sudo -n true && echo @@OK', timeout=40)
                if '@@OK' not in out:
                    return fail('sudo', 'Не удалось настроить sudo: пароль не подошёл или у пользователя нет прав')
            pr.set('sudo', '✅', f'sudo для {user}')
        pw = None
        # 4. система
        pr.set('sys', '⏳')
        if os_id not in ('ubuntu', 'debian') and 'debian' not in os_like:
            return fail('sys', f'Система «{os_name or os_id}» не поддерживается',
                        'Скрипт рассчитан на Ubuntu и Debian.')
        if info.get('ARCH') not in ('x86_64', 'aarch64', 'armv7l'):
            return fail('sys', f'Архитектура {info.get("ARCH")} не поддерживается')
        if not info.get('SYSTEMD'):
            return fail('sys', 'На сервере нет systemd')
        try:
            free_mb = int(info.get('DISK', '0')) // 1024
        except ValueError:
            free_mb = 0
        if free_mb and free_mb < 300:
            return fail('sys', f'Мало места на диске: свободно {free_mb} МБ, нужно хотя бы 300 МБ')
        pr.set('sys', '✅', f'{info.get("ARCH")}, свободно {fmt_bytes(free_mb * 1024 * 1024)}')
        # 5. установка
        pr.set('xray', '⏳')
        env = {'ADDR': host, 'NAME': re.sub(r'[^A-Za-z0-9._-]+', '-', x['name'])[:40] or 'vpn'}
        if ctx.get('env'):
            env.update(ctx['env'])
        try:
            data = vs_call(vs, 'install', env, timeout=1500,
                           on_step=lambda s: pr.set('xray', '⏳', h(s), force=False))
        except VsError as e:
            if 'FOREIGN' in e.data:
                return fail('xray', 'На сервере уже есть Xray с другими настройками',
                            'Похоже, там стоит панель (например, 3x-ui) или ручная настройка. Бот не стал её '
                            'перезаписывать. Если она не нужна, удалите её на сервере и запустите установку '
                            'снова кнопкой «🚀 Установить VLESS».')
            return fail('xray', str(e))
        link = data.get('LINK', '')
        with lock:
            x['vless'] = {'port': int(data.get('PORT') or 0), 'sni': data.get('SNI', ''), 'ver': data.get('VER', ''),
                          'ts': time.time()}
            save_state()
        pr.set('xray', '✅', ('уже был установлен — подключаю, ' if 'EXISTING' in data else '')
               + f'порт {data.get("PORT")}, маскировка {h(data.get("SNI", ""))}')
        # 6. доступность из России
        pr.set('ru', '⏳')
        vport = int(data.get('PORT') or 0)
        if not tcp_open(host, vport):
            return fail('ru', f'С шлюза (из России) порт {vport} недоступен',
                        f'На сервере всё работает, значит порт закрыт снаружи. Откройте TCP {vport} во внешнем '
                        'файрволе в панели хостинга и нажмите «🔄 Проверить» на экране сервера. Если порт открыт, '
                        'его может блокировать провайдер — тогда помогут «🎭 Другая маскировка» или другой порт.')
        pr.set('ru', '✅', f'порт {vport} открыт')
        # 7. VLESS через ТСПУ и страна для Google
        pr.set('vless', '⏳')
        chk = vless_check(link)
        if not chk.get('ok'):
            return fail('vless', 'Порт открыт, но VLESS через него не работает: ' + h(chk.get('err', ''))[:150],
                        'Скорее всего, провайдер режет такую маскировку. Попробуйте «🎭 Другая маскировка» '
                        'на экране сервера.')
        with lock:
            x['last'] = dict(chk, ts=time.time(), xray='active')
            save_state()
        pr.set('vless', '✅', f'{chk["ms"]} мс, ' + gl_text(chk.get('gl')))
        # 8. подписка
        pr.set('add', '⏳')
        try:
            pid = vs_attach(vid, link, chk.get('gl'))
        except Exception as e:
            return fail('add', f'Не удалось добавить в шлюз: {e}')
        pr.set('add', '✅', f'подписка «{h(sub_by_id(pid)["name"])}»')
        add_event(f'{admin_name(uid)} развернул VLESS на {host}')
        notify('actions', f'👤 {h(admin_name(uid))} развернул свой сервер VLESS {h(host)}', exclude=uid)
        tail = ('🎉 <b>Готово!</b> Серверы этой подписки уже участвуют в автовыборе.\n'
                'Пароль бот не сохранил — дальше он заходит на сервер по своему ключу.')
        if chk.get('gl') in BAD_GL:
            tail += '\n\n' + gl_text(chk['gl'])
        kb = []
        v = vpn()
        if (v.get('svc') or {}).get('google') != pid and chk.get('gl') not in BAD_GL:
            kb.append([btn('🎯 Google и Gemini через этот сервер', f'vs:goo:{vid}')])
        kb.append([btn('🛰 Открыть сервер', f'vs:v:{vid}'), btn('⚡ Тест скорости', 'speed')])
        kb.append([btn('🏠 Меню', 'menu')])
        return pr.text(tail), kb
    except VsError as e:
        return fail(next((k for k in pr.order if pr.st[k][0] == '⏳'), 'ssh'), str(e))
    except Exception as e:
        log('vs_deploy:', traceback.format_exc())
        return fail(next((k for k in pr.order if pr.st[k][0] == '⏳'), 'ssh'), f'Ошибка: {e}')
    finally:
        VS_BUSY.discard(busy_key)
        if auth.get('key') and os.path.exists(auth['key']):
            os.remove(auth['key'])
        auth.clear()


def fmt_ago(ts):
    if not ts:
        return 'никогда'
    s = time.time() - ts
    if s < 90:
        return 'только что'
    if s < 3600:
        return f'{int(s // 60)} мин назад'
    if s < 86400:
        return f'{int(s // 3600)} ч назад'
    return time.strftime('%d.%m %H:%M', time.localtime(ts))


def scr_vs(uid, note=''):
    lst = vps_all()
    lines = ['🛰 <b>Свои серверы</b>', '',
             'Бот сам развернёт VLESS Reality на вашем зарубежном сервере: подберёт порт и маскировку, '
             'проверит, что сервер работает из России и какой страной его видит Google, и добавит его в шлюз.', '']
    kb = []
    for vid, x in sorted(lst.items()):
        last = x.get('last') or {}
        icon = '⚪' if not last else ('🟢' if last.get('ok') else '🔴')
        if not x.get('vless'):
            icon = '⚪'
        sb = sub_by_id(x.get('sub') or '')
        lines.append(f'{icon} <b>{h(x.get("name") or x["host"])}</b> · <code>{h(x["host"])}</code>'
                     + (f' · {flag(last.get("gl"))}' if last.get('gl') else '')
                     + (f'\n      подписка «{h(sb["name"])}»' if sb else '\n      не добавлен в шлюз'))
        kb.append([btn(f'{icon} {x.get("name") or x["host"]}'[:40], f'vs:v:{vid}')])
    if not lst:
        lines.append('Пока нет ни одного сервера.')
    lines += ['', 'Понадобятся IP сервера и пароль (или SSH-ключ). Пароль бот использует один раз: '
                  'кладёт на сервер свой ключ и дальше входит по нему.']
    if note:
        lines += ['', note]
    kb.append([btn('➕ Развернуть сервер', 'vs:new')])
    kb.append([btn('⬅️ Управление', 'manage'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_vs_one(uid, vid, note=''):
    x = vps_all().get(vid)
    if not x:
        return scr_vs(uid, '⚠️ Сервер не найден')
    last = x.get('last') or {}
    vl = x.get('vless') or {}
    sb = sub_by_id(x.get('sub') or '')
    lines = [f'🛰 <b>{h(x.get("name") or x["host"])}</b>', '',
             f'Адрес: <code>{h(x["host"])}</code>, SSH: {h(x["user"])}@…:{x["port"]}',
             f'Система: {h(x.get("os") or "?")}']
    if vl:
        lines.append(f'VLESS: порт {vl.get("port")}, маскировка {h(vl.get("sni", ""))}, Xray {h(vl.get("ver") or "?")}')
    else:
        lines.append('VLESS: не установлен')
    lines.append(f'В шлюзе: подписка «{h(sb["name"])}»' if sb else 'В шлюзе: не добавлен')
    if last:
        lines.append('')
        lines.append(f'Проверка {fmt_ago(last.get("ts"))}: ' + (
            f'🟢 работает, {last.get("ms")} мс' if last.get('ok') else f'🔴 {h(last.get("err") or "не работает")}'))
        if last.get('ok'):
            lines.append(f'Выход в интернет: <code>{h(last.get("ip") or "?")}</code>; ' + gl_text(last.get('gl')))
        if last.get('xray') and last.get('xray') != 'active':
            lines.append(f'⚠️ Служба Xray: {h(last["xray"])}')
        st = last.get('sys')
        if st:
            lines.append(st)
    if x.get('pass_off'):
        lines.append('🔒 Вход на сервер по паролю выключен (только по ключу)')
    v = vpn()
    if sb and (v.get('svc') or {}).get('google') == sb['id']:
        lines.append('🎯 Google и Gemini идут через этот сервер')
    if note:
        lines += ['', note]
    kb = [[btn('🔄 Проверить', f'vs:chk:{vid}')]]
    if vl:
        kb[0].append(btn('🔑 Новые ключи', f'vs:rot:{vid}'))
        kb.append([btn('🎭 Другая маскировка', f'vs:sni:{vid}'), btn('⬆️ Обновить Xray', f'vs:upd:{vid}')])
        if sb and (v.get('svc') or {}).get('google') != sb['id']:
            kb.append([btn('🎯 Google и Gemini через него', f'vs:goo:{vid}')])
        if not sb:
            kb.append([btn('➕ Добавить в шлюз', f'vs:att:{vid}')])
    else:
        kb.append([btn('🚀 Установить VLESS', f'vs:ins:{vid}')])
    kb.append([btn('🔓 Вернуть вход по паролю' if x.get('pass_off') else '🔒 Вход только по ключу', f'vs:pa:{vid}')])
    row = [btn('🔌 Отключить бота', f'vs:off:{vid}')]
    if vl:
        row.insert(0, btn('🗑 Удалить VLESS', f'vs:del:{vid}'))
    kb.append(row)
    kb.append([btn('⬅️ Свои серверы', 'vs')])
    return '\n'.join(lines), kb


def vs_check(vid):
    """Состояние сервера по SSH + проверка VLESS из России через временный mihomo."""
    x = vps_all()[vid]
    vs = {'host': x['host'], 'port': x['port'], 'user': x['user']}
    try:
        st = vs_call(vs, 'status', {'SELFTEST': 1}, timeout=120)
    except VsError as e:
        with lock:
            x['last'] = {'ok': False, 'err': f'нет доступа по SSH: {e}', 'ts': time.time()}
            save_state()
        return
    sysl = []
    try:
        up = int(st.get('UPTIME', '0'))
        la = st.get('LOAD', '').split()
        mt, mu = (int(z) for z in st.get('MEM', '0 0').split()[:2])
        dt, df = (int(z) for z in st.get('DISK', '0 0').split()[:2])
        sysl.append(f'Сервер: работает {fmt_dur(up)}, нагрузка {la[0] if la else "?"}'
                    + (f' на {la[3]} ядр.' if len(la) > 3 else '')
                    + f', память {fmt_bytes(mu)} из {fmt_bytes(mt)}, диск свободно {fmt_bytes(df)} из {fmt_bytes(dt)}')
    except Exception:
        pass
    with lock:
        if 'PORT' in st:
            x['vless'] = dict(x.get('vless') or {}, port=int(st['PORT']), sni=st.get('SNI', ''), ver=st.get('VER', ''))
        else:
            x['vless'] = None          # Xray не установлен или настроен не этим ботом
        if st.get('PASSAUTH'):
            x['pass_off'] = st['PASSAUTH'] == 'no'
        save_state()
    res = {'ts': time.time(), 'xray': st.get('XRAY'), 'sys': '; '.join(sysl)}
    if not x.get('vless'):
        res.update(ok=False, err='VLESS не установлен' + (' (на сервере Xray с чужими настройками)'
                                                          if 'FOREIGN' in st else ''))
    elif st.get('SELFTEST') == 'fail':
        res.update(ok=False, err='самопроверка на сервере не прошла (Xray не отвечает)')
    elif not tcp_open(x['host'], x['vless']['port']):
        res.update(ok=False, err=f'порт {x["vless"]["port"]} недоступен из России')
    else:
        try:
            link = vs_call(vs, 'show', timeout=60).get('LINK', '')
        except VsError as e:
            link, res['err'] = '', str(e)
        if link:
            res.update(vless_check(link))
            res['link_host'] = list(vs_link_host(link))
    with lock:
        x['last'] = res
        save_state()


def vs_action(uid, vid, act, chat, mid):
    """Долгие действия с сервером: показывают «⏳…» и возвращают экран сервера."""
    x = vps_all().get(vid)
    if not x:
        return scr_vs(uid, '⚠️ Сервер не найден')
    vs = {'host': x['host'], 'port': x['port'], 'user': x['user']}
    who = admin_name(uid)
    key = (x['host'], int(x['port']))
    if key in VS_BUSY:
        return scr_vs_one(uid, vid, '⏳ С сервером уже идёт операция, подождите.')
    msgs = {'chk': '🔄 Проверяю сервер (до минуты)…', 'rot': '🔑 Меняю ключи и обновляю ссылку в шлюзе…',
            'upd': '⬆️ Обновляю Xray (до 2 минут)…', 'sni': '🎭 Подбираю другую маскировку (1–3 минуты)…',
            'ins': '🚀 Устанавливаю VLESS (1–3 минуты)…', 'del': '🗑 Удаляю VLESS с сервера…',
            'att': '➕ Проверяю сервер и добавляю в шлюз…', 'goo': '🎯 Направляю Google через сервер и применяю…',
            'paoff': '🔒 Выключаю вход по паролю…', 'paon': '🔓 Возвращаю вход по паролю…',
            'off': '🔌 Удаляю ключ бота с сервера…'}
    edit(chat, mid, msgs.get(act, '⏳ Выполняю…'))
    VS_BUSY.add(key)
    try:
        if act == 'chk':
            vs_check(vid)
            return scr_vs_one(uid, vid)
        if act in ('rot', 'sni', 'ins', 'att'):
            if act == 'rot':
                data = vs_call(vs, 'rotate', timeout=300)
            elif act == 'att':
                data = vs_call(vs, 'show', timeout=60)
            else:
                env = {'ADDR': x['host'], 'NAME': re.sub(r'[^A-Za-z0-9._-]+', '-', x.get('name') or 'vpn')[:40]}
                if act == 'sni':
                    cur = (x.get('vless') or {}).get('sni')
                    env.update(FORCE=1, PORT=(x.get('vless') or {}).get('port') or '',
                               SNI=' '.join(s for s in SNI_SITES if s != cur))
                    if not env['PORT']:
                        env.pop('PORT')
                data = vs_call(vs, 'install', env, timeout=1500,
                               on_step=lambda s: edit(chat, mid, f'{msgs[act]}\n\n<i>{h(s)}</i>'))
            link = data.get('LINK', '')
            with lock:
                x['vless'] = dict(x.get('vless') or {}, port=int(data.get('PORT') or 0), sni=data.get('SNI', ''),
                                  ts=time.time())
                if data.get('VER'):
                    x['vless']['ver'] = data['VER']
                save_state()
            chk = vless_check(link)
            with lock:
                x['last'] = dict(chk, ts=time.time(), xray='active')
                save_state()
            if not chk.get('ok') and act != 'rot':
                return scr_vs_one(uid, vid, f'⚠️ Установлено, но из России VLESS не отвечает: {h(chk.get("err", ""))}.'
                                            ' В шлюз не добавлял. Проверьте файрвол хостинга или смените маскировку.')
            vs_attach(vid, link, chk.get('gl'))
            what = {'rot': 'Ключи заменены, ссылка в шлюзе обновлена', 'sni': f'Маскировка: {data.get("SNI")}',
                    'ins': 'VLESS установлен и добавлен в шлюз', 'att': 'Сервер добавлен в шлюз'}[act]
            add_event(f'{who}: {x["host"]} — {what}')
            return scr_vs_one(uid, vid, f'✅ {h(what)}.' + ('' if chk.get('ok') else
                                                            f'\n⚠️ Проверка из России не прошла: {h(chk.get("err", ""))}'))
        if act == 'upd':
            data = vs_call(vs, 'update', timeout=600)
            with lock:
                x['vless'] = dict(x.get('vless') or {}, ver=data.get('VER', ''))
                save_state()
            old, new = data.get('OLDVER'), data.get('VER')
            add_event(f'{who}: Xray на {x["host"]} {old} → {new}')
            return scr_vs_one(uid, vid, f'✅ Xray {h(old or "")} → {h(new or "")}' if old != new
                              else f'✅ Уже последняя версия Xray: {h(new or "")}')
        if act == 'del':
            vs_call(vs, 'uninstall', timeout=300)
            note = '🗑 VLESS удалён с сервера.'
            if x.get('sub') and sub_by_id(x['sub']):
                err = delete_sub(x['sub'], who)
                note += ' Подписка удалена из шлюза.' if not err else f' Подписку удалить не удалось: {h(err)}'
            with lock:
                x['vless'], x['sub'], x['last'] = None, None, {}
                save_state()
            add_event(f'{who} удалил VLESS с {x["host"]}')
            return scr_vs_one(uid, vid, note)
        if act == 'goo':
            pid = x.get('sub')
            if not sub_by_id(pid or ''):
                return scr_vs_one(uid, vid, '⚠️ Сервер не добавлен в шлюз')
            v = vpn()
            with lock:
                v.setdefault('svc', {})['google'] = pid
                save_state()
            apply_vpn_config(v)
            add_event(f'{who}: Google через {x["host"]}')
            return scr_vs_one(uid, vid, '✅ Google, Gemini, Gmail и аккаунт Google теперь идут через этот сервер. '
                                        'Если он упадёт, Google временно пойдёт через общий автовыбор.')
        if act == 'paoff':
            vs_call(vs, 'passauth off', timeout=90)
            rc, out, err = ssh_exec(vs, as_root(vs, f'bash {REMOTE_SCRIPT} passauth confirm </dev/null'), timeout=60)
            if '@@OK' not in out:
                return scr_vs_one(uid, vid, '⚠️ После выключения бот не смог войти по ключу, поэтому через 3 минуты '
                                            'вход по паролю включится обратно сам. Ошибка: ' + h(ssh_err(err)))
            with lock:
                x['pass_off'] = True
                save_state()
            add_event(f'{who}: на {x["host"]} выключен вход по паролю')
            return scr_vs_one(uid, vid, '🔒 Вход по паролю выключен. Подобрать пароль к серверу теперь невозможно.')
        if act == 'paon':
            vs_call(vs, 'passauth on', timeout=90)
            with lock:
                x['pass_off'] = False
                save_state()
            add_event(f'{who}: на {x["host"]} включён вход по паролю')
            return scr_vs_one(uid, vid, '🔓 Вход по паролю снова включён.')
        if act == 'off':
            body = ssh_ensure_key().split()[1]
            cmd = (f'{"sudo -n rm -f " + SUDOERS_FILE + "; " if x["user"] != "root" else ""}'
                   f'f=~/.ssh/authorized_keys; grep -vF {shlex.quote(body)} "$f" > "$f.vpngw" ; '
                   f'cat "$f.vpngw" > "$f"; rm -f "$f.vpngw"; echo @@OK')
            rc, out, err = ssh_exec(vs, cmd, timeout=60)
            ok = '@@OK' in out
            with lock:
                vps_all().pop(vid, None)
                save_state()
            if not any(y['host'] == x['host'] and int(y['port']) == int(x['port']) for y in vps_all().values()):
                pat = kh_pattern(x['host'], x['port'])
                keep = [z for z in kh_lines() if z.split(' ', 1)[0] != pat]
                with open(SSH_KNOWN, 'w') as f:
                    f.write('\n'.join(keep) + ('\n' if keep else ''))
            add_event(f'{who} отключил бота от сервера {x["host"]}')
            return scr_vs(uid, '🔌 Бот отключён от сервера: его ключ удалён, сервер убран из списка. VLESS и '
                               'подписка в шлюзе остались.' if ok else
                          '🔌 Сервер убран из списка, но удалить ключ бота с сервера не удалось ('
                          + h(ssh_err(err)) + '). Удалите строку «vpn-gateway-bot» из ~/.ssh/authorized_keys вручную.')
    except VsError as e:
        return scr_vs_one(uid, vid, f'🔴 {h(str(e))[:400]}')
    except Exception as e:
        log('vs_action:', traceback.format_exc())
        return scr_vs_one(uid, vid, f'🔴 Ошибка: {h(str(e))[:300]}')
    finally:
        VS_BUSY.discard(key)
    return scr_vs_one(uid, vid)


VS_CONFIRM = {
    'rot': ('🔑 <b>Новые ключи?</b>\n\nНа сервере будут созданы новые ключи, старая ссылка перестанет работать. '
            'Ссылка в шлюзе обновится сама (VPN прервётся на 5–10 секунд). Если эту ссылку вы давали '
            'кому-то ещё, им понадобится новая.'),
    'sni': ('🎭 <b>Сменить маскировку?</b>\n\nПомогает, если провайдер начал резать подключение. Бот подберёт другой '
            'сайт для маскировки и создаст новые ключи, ссылка в шлюзе обновится сама.'),
    'upd': '⬆️ <b>Обновить Xray на сервере?</b>\n\nVPN через этот сервер прервётся на несколько секунд.',
    'del': ('🗑 <b>Удалить VLESS с сервера?</b>\n\nXray и его настройки будут удалены, подписка этого сервера '
            'пропадёт из шлюза. Доступ бота к серверу останется — VLESS можно будет поставить заново.'),
    'off': ('🔌 <b>Отключить бота от сервера?</b>\n\nБот удалит свой SSH-ключ с сервера и забудет его. VLESS '
            'продолжит работать, подписка в шлюзе останется, но управлять сервером из бота будет нельзя.'),
    'paoff': ('🔒 <b>Вход только по ключу?</b>\n\nНа сервере выключится вход по паролю: подобрать пароль станет '
              'невозможно. ⚠️ Убедитесь, что у вас есть свой SSH-ключ или консоль в панели хостинга — иначе '
              'вы сами не сможете зайти на сервер (бот при этом доступ сохранит).\n\nЕсли что-то пойдёт не так, '
              'через 3 минуты вход по паролю вернётся сам.'),
    'paon': '🔓 <b>Вернуть вход по паролю на сервер?</b>',
}


def handle_vs(uid, data, chat, mid):
    parts = data.split(':')
    act = parts[1] if len(parts) > 1 else ''
    vid = parts[2] if len(parts) > 2 else ''
    if data == 'vs':
        return scr_vs(uid)
    if act == 'new':
        awaiting[uid] = ('vs_host', {})
        return ('🛰 <b>Новый сервер — шаг 1 из 3</b>\n\nОтправьте IP-адрес сервера. Если SSH не на стандартном '
                'порту или нужен другой пользователь, можно так: <code>ubuntu@203.0.113.5:2222</code>\n\n'
                'Подойдёт чистый VPS с Ubuntu или Debian. Уже работающие там SSTP, WireGuard и т.п. бот не тронет.'
                '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'vs')]])
    x = vps_all().get(vid)
    if act == 'v':
        return scr_vs_one(uid, vid)
    if not x:
        return scr_vs(uid, '⚠️ Сервер не найден')
    if act == 'pa':
        act = 'paon' if x.get('pass_off') else 'paoff'
    if act in VS_CONFIRM:
        return VS_CONFIRM[act], [[btn('✅ Да', f'vs:{act}!:{vid}'), btn('✖️ Отмена', f'vs:v:{vid}')]]
    if act.endswith('!'):
        act = act[:-1]
    if act in ('chk', 'rot', 'sni', 'upd', 'ins', 'del', 'att', 'goo', 'paoff', 'paon', 'off'):
        return vs_action(uid, vid, act, chat, mid)
    return scr_vs_one(uid, vid)


def vs_ask_user(ctx):
    return (f'🛰 <b>Новый сервер {h(ctx["host"])}</b>\n\nПод каким пользователем входить по SSH? '
            'Нажмите кнопку или отправьте имя.\n\nОтмена: /cancel',
            [[btn('root', 'vsw:u:root'), btn('ubuntu', 'vsw:u:ubuntu'), btn('debian', 'vsw:u:debian')],
             [btn('✖️ Отмена', 'vs')]])


def vs_scan_screen(uid, ctx):
    """Шаг 2: показывает отпечаток ключа сервера для подтверждения."""
    try:
        lines = ssh_scan(ctx['host'], ctx['port'])
    except Exception as e:
        awaiting.pop(uid, None)
        return (f'🔴 Не удалось подключиться к {h(ctx["host"])}:{ctx["port"]}: {h(str(e))}\n\n'
                'Проверьте адрес и что сервер включён.', [[btn('🔁 Ещё раз', 'vs:new'), btn('⬅️ Назад', 'vs')]])
    ctx['hk'] = lines
    typ, fp = ssh_fp(lines[0])
    old = kh_known(ctx['host'], ctx['port'])
    note = ''
    if old:
        same = {ssh_fp(z)[1] for z in old} & {ssh_fp(z)[1] for z in lines}
        note = ('\n\n✅ Совпадает с сохранённым ранее.' if same else
                '\n\n⚠️ <b>Отличается от сохранённого ранее!</b> Так бывает после переустановки системы. '
                'Если вы её не переустанавливали — не продолжайте.')
    awaiting[uid] = ('vs_fp', ctx)
    return (f'🛰 <b>Новый сервер — шаг 2 из 3</b>\n\nСервер <code>{h(ctx["host"])}:{ctx["port"]}</code> ответил. '
            f'Отпечаток его ключа ({h(typ)}):\n<code>{h(fp)}</code>{note}\n\nЭто защита от подмены сервера. '
            'Сверить можно в консоли сервера командой\n<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>\n'
            'Если не уверены — просто продолжайте, для нового сервера это обычная ситуация.',
            [[btn('✅ Да, это мой сервер', 'vsw:fp')], [btn('✖️ Отмена', 'vs')]])


def vs_ask_auth(ctx):
    return (f'🛰 <b>Новый сервер — шаг 3 из 3</b>\n\nОтправьте <b>пароль</b> пользователя '
            f'<code>{h(ctx["user"])}</code> или <b>приватный SSH-ключ</b> (текстом или файлом).\n\n'
            'Сообщение я сразу удалю из чата. Пароль нужен один раз: бот положит на сервер свой ключ и дальше '
            'будет входить по нему, а пароль нигде не сохранится.\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'vs')]])


def handle_vsw(uid, data, chat, mid):
    kind, ctx = awaiting.get(uid, (None, None))
    if not ctx or not kind or not kind.startswith('vs_'):
        return scr_vs(uid, '⚠️ Мастер устарел, начните заново.')
    if data.startswith('vsw:u:'):
        ctx['user'] = data[6:]
        edit(chat, mid, f'⏳ Подключаюсь к {h(ctx["host"])}…')
        return vs_scan_screen(uid, ctx)
    if data == 'vsw:fp' and kind == 'vs_fp':
        awaiting[uid] = ('vs_auth', ctx)
        return vs_ask_auth(ctx)
    return scr_vs(uid)


VS_HOST_RE = re.compile(r'^(?:([a-z_][a-z0-9_.-]{0,31})@)?([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(?::(\d{1,5}))?$')


def tg_download(file_id, limit=64 * 1024):
    if LINK_MODE:
        r = link_call({'t': 'dl', 'file_id': file_id, 'limit': limit}, 90)
        return base64.b64decode(r) if r else None
    info = tg('getFile', file_id=file_id)
    if not info or not info.get('file_path') or (info.get('file_size') or 0) > limit:
        return None
    url = f'https://api.telegram.org/file/bot{TOKEN}/{info["file_path"]}'
    for opener in (proxy_opener, direct_opener):
        try:
            with opener.open(url, timeout=30) as r:
                return r.read(limit + 1)
        except Exception:
            continue
    return None


def handle_vs_input(uid, chat, m, kind, ctx, text):
    if kind == 'vs_host':
        mm = VS_HOST_RE.match(text.strip())
        if not mm or (mm.group(3) and not 0 < int(mm.group(3)) < 65536):
            send(chat, 'Нужен IP или имя сервера, например <code>203.0.113.5</code> или '
                       '<code>root@203.0.113.5:22</code>. Ещё раз или /cancel.')
            return
        ctx.update(host=mm.group(2), port=int(mm.group(3) or 22))
        if mm.group(1):
            ctx['user'] = mm.group(1)
        else:
            awaiting[uid] = ('vs_user', ctx)
            t, kb = vs_ask_user(ctx)
            send(chat, t, kb)
            return
    elif kind == 'vs_user':
        name = text.strip()
        if not re.match(r'^[a-z_][a-z0-9_.-]{0,31}$', name):
            send(chat, 'Имя пользователя: латиница, цифры, «_», «-», например <code>root</code>. Ещё раз или /cancel.')
            return
        ctx['user'] = name
    elif kind == 'vs_auth':
        raw = m.get('text') or ''
        tg('deleteMessage', chat_id=chat, message_id=m['message_id'])
        if m.get('document'):
            blob = tg_download(m['document']['file_id'])
            raw = blob.decode('utf-8', 'ignore') if blob else ''
            if not raw:
                send(chat, 'Не удалось прочитать файл ключа (он должен быть небольшим текстовым файлом). '
                           'Ещё раз или /cancel.')
                return
        if not raw.strip():
            send(chat, 'Пустое сообщение. Отправьте пароль или ключ, или /cancel.')
            return
        auth = {}
        if '-----BEGIN' in raw and 'PRIVATE KEY-----' in raw:
            body = raw.strip() + '\n'
            enc = 'ENCRYPTED' in body
            try:
                b64 = ''.join(body.split('-----')[2].split())
                enc = enc or b'bcrypt' in base64.b64decode(b64 + '=' * (-len(b64) % 4))[:200]
            except Exception:
                pass
            if enc:
                send(chat, '🔐 Этот ключ защищён паролем (passphrase) — такие бот не принимает. Отправьте пароль '
                           'от сервера или ключ без passphrase. Ещё раз или /cancel.')
                return
            ssh_ensure_key()
            path = os.path.join(SSH_DIR, f'owner-{uuid.uuid4().hex}')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(body)
            auth['key'] = path
        else:
            auth['pw'] = raw.rstrip('\r\n')
        awaiting.pop(uid, None)
        ctx['auth'] = auth
        r = send(chat, f'🛰 <b>Развёртывание сервера {h(ctx["host"])}</b>\n\n⏳ Начинаю…')
        t, kb = vs_deploy(uid, chat, r['message_id'] if r else None, ctx)
        if r:
            edit(chat, r['message_id'], t, kb)
        else:
            send(chat, t, kb)
        return
    # хост и пользователь известны — показываем отпечаток ключа
    r = send(chat, f'⏳ Подключаюсь к {h(ctx["host"])}…')
    t, kb = vs_scan_screen(uid, ctx)
    if r:
        edit(chat, r['message_id'], t, kb)
    else:
        send(chat, t, kb)


# ---------------- резервные копии ----------------
BK_DIR = '/var/lib/vpnbot/backups'
BK_KEY = '/etc/vpngw/backup.key'              # пароль автобэкапа, только root
BK_SECRETS = '/etc/vpngw/backup-secrets.json'  # пароли SFTP и Яндекс.Диска, только root
BK_KEEP = 5
BK_EVERY = [7, 14, 30]
BK_PATHS = ['/etc/vpnbot.env', '/etc/vpnnotify.env', '/etc/vpngw', '/etc/wireguard', '/etc/mihomo/config.yaml',
            '/etc/mihomo/providers', STATE_FILE, '/var/lib/vpnbot/ssh', '/root/wg-clients']
BK_PATHS.append('/var/lib/vpnbot/link')       # главный: ключ для входа на ведомые шлюзы и их ключи серверов
BK_FORMAT = 1
BK_DEST = [('tg', '✈️ Telegram'), ('mail', '📧 Почта'), ('sftp', '📁 SFTP'), ('yd', '☁️ Яндекс.Диск')]
BK_LOCK = threading.Lock()
YD_DAV = 'https://webdav.yandex.ru'


def bk_cfg():
    b = state.get('backup')
    if not isinstance(b, dict):
        b = state['backup'] = {}
    b.setdefault('auto', False)
    b.setdefault('every', 14)
    b.setdefault('hour', 3)
    b.setdefault('dest', ['tg'])
    b.setdefault('sftp', {})
    b.setdefault('yd', {})
    return b


def root_file_write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def bk_secrets():
    try:
        with open(BK_SECRETS, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def bk_secret_set(key, value):
    d = bk_secrets()
    if value is None:
        d.pop(key, None)
    else:
        d[key] = value
    root_file_write(BK_SECRETS, json.dumps(d))


def bk_auto_pw():
    try:
        return open(BK_KEY, encoding='utf-8').read().rstrip('\n') or None
    except Exception:
        return None


def hwid_info():
    """HWID и модель для подписки. /etc/vpngw/hwid — сохранённые при переезде, чтобы подписка не считала
    новый сервер ещё одним устройством."""
    hw, model = '', ''
    try:
        for line in open('/etc/vpngw/hwid', encoding='utf-8'):
            k, _, v = line.strip().partition('=')
            if k == 'HWID':
                hw = v.strip()
            elif k == 'MODEL':
                model = v.strip()
    except Exception:
        pass
    if not hw:
        try:
            hw = open('/etc/machine-id').read().strip()
        except Exception:
            hw = ''
    return hw, model or 'Ubuntu-Gateway-' + platform.node()


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ''


def bk_files():
    out = []
    for base in BK_PATHS:
        if os.path.isfile(base):
            out.append(base)
        elif os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                dirs.sort()
                for fn in sorted(files):
                    p = os.path.join(root, fn)
                    if os.path.isfile(p) and not os.path.islink(p) and not fn.endswith('.tmp'):
                        out.append(p)
    return out


def openssl_enc(data, pw, decrypt=False):
    argv = ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-md', 'sha256', '-pass', 'env:VPNGW_BK_PW']
    argv += ['-d'] if decrypt else ['-salt']
    env = dict(os.environ, VPNGW_BK_PW=pw)
    r = subprocess.run(argv, input=data, capture_output=True, timeout=120, env=env)
    if r.returncode != 0:
        raise RuntimeError('неверный пароль или файл повреждён' if decrypt else
                           'openssl: ' + r.stderr.decode(errors='ignore')[-200:])
    return r.stdout


def bk_manifest():
    w = wg_state()
    hw, model = hwid_info()
    e = wg_eps()
    return {'format': BK_FORMAT, 'version': BOT_VERSION, 'created': time.time(),
            'created_text': time.strftime('%d.%m.%Y %H:%M'), 'host': platform.node(), 'gw_name': GW_NAME,
            'hwid': hw, 'model': model, 'lan_ip': lan_ip(), 'ep_domain': e.get('domain', ''),
            'ep_ip': e.get('ip', ''), 'wg_port': wg_port(), 'wg_net': WG_NET,
            'peers': len(w['peers']), 'subs': len(state.get('subs') or []),
            'vps': len(state.get('vps') or []), 'admins': len(state['admins']),
            'email': bool(email_cfg()['to']), 'owner': OWNER}


def bk_make(pw, why='вручную'):
    """Собрать, зашифровать и проверить копию. → (путь, manifest)"""
    import io
    import tarfile
    if len(pw) < 8:
        raise RuntimeError('пароль короче 8 символов')
    save_state()                       # в копию — актуальное состояние, а не то, что было на диске
    man = bk_manifest()
    man['why'] = why
    buf = io.BytesIO()
    files = bk_files()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        body = json.dumps(man, ensure_ascii=False, indent=1).encode()
        ti = tarfile.TarInfo('manifest.json')
        ti.size, ti.mtime, ti.mode = len(body), int(time.time()), 0o600
        tar.addfile(ti, io.BytesIO(body))
        for p in files:
            tar.add(p, arcname='files' + p, recursive=False)
    enc = openssl_enc(buf.getvalue(), pw)
    # проверка: расшифровываем тем же паролем и читаем архив
    dec = openssl_enc(enc, pw, decrypt=True)
    with tarfile.open(fileobj=io.BytesIO(dec), mode='r:gz') as tar:
        names = tar.getnames()
        m2 = json.load(tar.extractfile('manifest.json'))
    if m2.get('created') != man['created'] or len(names) != len(files) + 1:
        raise RuntimeError('проверка копии не прошла: архив не совпадает')
    os.makedirs(BK_DIR, mode=0o700, exist_ok=True)
    os.chmod(BK_DIR, 0o700)
    host = re.sub(r'[^A-Za-z0-9-]+', '-', platform.node())[:30] or 'gw'
    name = f'vpngw-backup-{host}-{time.strftime("%Y-%m-%d_%H%M%S")}.vpngw'
    path = os.path.join(BK_DIR, name)
    n = 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(BK_DIR, name.replace('.vpngw', f'-{n}.vpngw'))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(enc)
    for old in bk_list()[BK_KEEP:]:
        try:
            os.remove(os.path.join(BK_DIR, old['name']))
        except Exception:
            pass
    man['size'] = len(enc)
    man['files'] = len(files)
    return path, man


def bk_list():
    try:
        names = [n for n in os.listdir(BK_DIR) if n.endswith('.vpngw')]
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        try:
            st = os.stat(os.path.join(BK_DIR, n))
            out.append({'name': n, 'size': st.st_size, 'ts': st.st_mtime})
        except Exception:
            pass
    return sorted(out, key=lambda x: -x['ts'])


def bk_caption(man, name):
    return (f'💾 <b>Резервная копия шлюза</b> · {h(man.get("created_text", ""))}\n'
            f'Версия {h(man.get("version", "?"))}, клиентов WireGuard: {man.get("peers", 0)}, '
            f'подписок: {man.get("subs", 0)}\n<code>{h(name)}</code>\n\n'
            'Восстановление: установщик → «Восстановить из бэкапа». Нужен пароль этой копии.')


def sftp_target():
    s = bk_cfg()['sftp']
    return {'host': s.get('host'), 'port': s.get('port') or 22, 'user': s.get('user')}


def sftp_run(batch, timeout=180):
    s = bk_cfg()['sftp']
    if not s.get('host'):
        raise RuntimeError('SFTP не настроен')
    ssh_ensure_key()
    auth = {'pw': bk_secrets().get('sftp_pw', '')} if s.get('auth') == 'pw' else None
    argv, env = ssh_argv(sftp_target(), auth, strict='accept-new')
    target = argv.pop()
    argv[0] = 'sftp'
    i = argv.index('-p')
    argv[i] = '-P'
    if auth:
        argv += ['-o', 'BatchMode=no']      # sftp -b сам включает BatchMode и не спросит пароль
    argv += ['-b', '-', target]
    try:
        r = subprocess.run(argv, input=batch, capture_output=True, text=True, timeout=timeout, env=env,
                           start_new_session=True)
    except subprocess.TimeoutExpired:
        raise RuntimeError('SFTP: сервер не ответил вовремя')
    except FileNotFoundError:
        raise RuntimeError('нет программы sftp — sudo apt install -y openssh-client')
    if r.returncode != 0:
        raise RuntimeError('SFTP: ' + ssh_err(r.stderr or r.stdout))
    return r.stdout


def sftp_q(p):
    return '"' + p.replace('\\', '\\\\').replace('"', '\\"') + '"'


def sftp_put(path):
    d = (bk_cfg()['sftp'].get('path') or '').rstrip('/')
    cmds = []
    if d:
        acc = ''
        for part in [x for x in d.split('/') if x]:
            acc = (acc + '/' + part) if (acc or d.startswith('/')) else part
            cmds.append(f'-mkdir {sftp_q(acc)}')
    dest = (d + '/' if d else '') + os.path.basename(path)
    cmds.append(f'put {sftp_q(path)} {sftp_q(dest + ".part")}')
    cmds.append(f'rename {sftp_q(dest + ".part")} {sftp_q(dest)}')
    sftp_run('\n'.join(cmds) + '\n')
    return dest


def yd_auth():
    y = bk_cfg()['yd']
    pw = bk_secrets().get('yd_pw', '')
    if not y.get('login') or not pw:
        raise RuntimeError('Яндекс.Диск не настроен')
    return 'Basic ' + base64.b64encode(f'{y["login"]}:{pw}'.encode()).decode()


def yd_req(method, path, data=None, headers=None, timeout=60):
    req = urllib.request.Request(YD_DAV + urllib.parse.quote(path), data=data, method=method,
                                 headers=dict({'Authorization': yd_auth(), 'User-Agent': 'vpn-gateway'}, **(headers or {})))
    try:
        with direct_opener.open(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError('Яндекс.Диск: неверный логин или пароль приложения')
        return e.code


def yd_dir():
    return '/' + (bk_cfg()['yd'].get('path') or 'vpngw-backups').strip('/')


def yd_put(path):
    d = yd_dir()
    acc = ''
    for part in [x for x in d.split('/') if x]:
        acc += '/' + part
        code = yd_req('MKCOL', acc)
        if code not in (201, 405, 409):
            raise RuntimeError(f'Яндекс.Диск: не удалось создать папку {acc} (код {code})')
    data = open(path, 'rb').read()
    dest = f'{d}/{os.path.basename(path)}'
    code = yd_req('PUT', dest, data, {'Content-Type': 'application/octet-stream',
                                      'Sha256': hashlib.sha256(data).hexdigest(),
                                      'Etag': hashlib.md5(data).hexdigest()}, timeout=300)
    if code not in (200, 201, 204):
        raise RuntimeError(f'Яндекс.Диск: загрузка не удалась (код {code})')
    return dest


def bk_send(dest, path, man, chat=None):
    """Отправить копию в одно место. → текст результата"""
    name = os.path.basename(path)
    if dest == 'tg':
        r = tg_file('sendDocument', chat or OWNER, 'document', name, open(path, 'rb').read(),
                    bk_caption(man, name), ttl_kind='backup')
        if not r:
            raise RuntimeError('Telegram не принял файл')
        return 'в этот чат'
    if dest == 'mail':
        e = email_cfg()
        if not (e['smtp'].get('host') and e['to']):
            raise RuntimeError('почта не настроена')
        send_mail(f'{GW_NAME}: резервная копия {man.get("created_text", "")}',
                  plain(bk_caption(man, name)) + '\n\nФайл зашифрован паролем — без пароля его не открыть.',
                  attachments=[(name, open(path, 'rb').read(), 'application', 'octet-stream')])
        return ', '.join(e['to'])
    if dest == 'sftp':
        return sftp_put(path)
    if dest == 'yd':
        return 'Яндекс.Диск ' + yd_put(path)
    raise RuntimeError('неизвестное место')


def bk_dest_ready(dest):
    b = bk_cfg()
    if dest == 'tg':
        return True
    if dest == 'mail':
        e = email_cfg()
        return bool(e['smtp'].get('host') and e['to'])
    if dest == 'sftp':
        return bool(b['sftp'].get('host'))
    if dest == 'yd':
        return bool(b['yd'].get('login') and bk_secrets().get('yd_pw'))
    return False


def bk_next_run(after=None, days=0):
    b = bk_cfg()
    base = datetime.fromtimestamp(after or time.time())
    t = base.replace(hour=int(b.get('hour', 3)), minute=0, second=0, microsecond=0) + timedelta(days=days)
    if t.timestamp() <= (after or time.time()):
        t += timedelta(days=1)
    return t.timestamp()


def bk_run_auto():
    b = bk_cfg()
    pw = bk_auto_pw()
    res, errs = [], []
    try:
        if not pw:
            raise RuntimeError('не задан пароль автобэкапа')
        path, man = bk_make(pw, 'автоматически')
    except Exception as ex:
        log('backup:', ex)
        with lock:
            b.update(last=time.time(), last_ok=False, last_err=str(ex)[:300], next=bk_next_run(days=1))
            save_state()
        notify('backup', f'🔴 <b>Автобэкап не создан</b>\n\n{h(str(ex))[:300]}\nСледующая попытка завтра в '
                         f'{b.get("hour", 3)}:00.', keep=True)
        add_event(f'Автобэкап не создан: {ex}')
        return
    for dest in b['dest']:
        label = dict(BK_DEST).get(dest, dest)
        try:
            res.append(f'{label}: ✅ {h(bk_send(dest, path, man))}')
        except Exception as ex:
            errs.append(f'{label}: 🔴 {h(str(ex))[:200]}')
    with lock:
        b.update(last=time.time(), last_ok=not errs, last_err='; '.join(plain(x).replace('🔴 ', '') for x in errs)[:300],
                 last_name=os.path.basename(path), next=bk_next_run(days=int(b['every'])))
        save_state()
    add_event('Автобэкап создан' + (' (не все места получили копию)' if errs else ''))
    text = ('💾 <b>Автобэкап создан и проверен</b>' if not errs else '⚠️ <b>Автобэкап создан, но не везде отправлен</b>')
    text += f'\n\n<code>{h(os.path.basename(path))}</code>, {fmt_bytes(man["size"])}\n' + '\n'.join(res + errs)
    if not b['dest']:
        text += '\nКопия лежит только на сервере (места отправки не выбраны).'
    text += f'\n\nСледующий: {time.strftime("%d.%m.%Y %H:%M", time.localtime(b["next"]))}'
    notify('backup', text, keep=bool(errs))


def backup_tick():
    b = bk_cfg()
    if not b['auto']:
        return
    if not b.get('next'):
        with lock:
            b['next'] = bk_next_run()
            save_state()
        return
    if time.time() >= b['next'] and BK_LOCK.acquire(blocking=False):
        def job():
            try:
                bk_run_auto()
            except Exception:
                log('backup:', traceback.format_exc())
            finally:
                BK_LOCK.release()
        threading.Thread(target=job, daemon=True).start()


def scr_bk(uid, note=''):
    b = bk_cfg()
    copies = bk_list()
    pw = bool(bk_auto_pw())
    lines = ['💾 <b>Резервные копии</b>', '',
             'В копию входят настройки шлюза, подписки, ключи и клиенты WireGuard, серверы VLESS, '
             'почта, бот и админы. Файл шифруется паролем (AES-256): без пароля его не открыть и не восстановить.', '']
    if b['auto']:
        lines.append(f'🔁 Автобэкап: <b>включён</b>, раз в {b["every"]} дн. в {b.get("hour", 3)}:00')
        if b.get('next'):
            lines.append(f'    следующий: {time.strftime("%d.%m.%Y %H:%M", time.localtime(b["next"]))}')
    else:
        lines.append('🔁 Автобэкап: <b>выключен</b>')
    lines.append('🔑 Пароль автобэкапа: ' + ('задан' if pw else '<i>не задан</i>'))
    dests = [dict(BK_DEST)[d] for d in b['dest'] if d in dict(BK_DEST)]
    lines.append('📤 Куда отправлять: ' + (', '.join(dests) if dests else 'только на сервер'))
    if b.get('last'):
        lines.append(f'🕓 Последний автобэкап: {fmt_date(b["last"])} {time.strftime("%H:%M", time.localtime(b["last"]))} '
                     + ('✅' if b.get('last_ok') else f'🔴 {h(b.get("last_err", ""))[:200]}'))
    lines.append(f'🗂 На сервере: {len(copies)} из {BK_KEEP} последних')
    if note:
        lines += ['', note]
    kb = [[btn('💾 Сделать бэкап сейчас', 'bk:now')],
          [btn('⏸ Выключить автобэкап' if b['auto'] else '▶️ Включить автобэкап', 'bk:auto')],
          [btn(('• ' if b['every'] == d else '') + f'раз в {d} дн.', f'bk:ev:{d}') for d in BK_EVERY],
          [btn('🔑 Пароль автобэкапа', 'bk:pw'), btn('📤 Куда отправлять', 'bk:dst')]]
    if copies:
        kb.append([btn(f'🗂 Копии на сервере ({len(copies)})', 'bk:list')])
    kb.append([btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_bk_dst(uid, note=''):
    b = bk_cfg()
    s, y = b['sftp'], b['yd']
    lines = ['📤 <b>Куда отправлять автобэкап</b>', '',
             'Отметьте места. Копия в любом случае хранится на сервере (последние 5).', '',
             '✈️ Telegram — файл придёт в этот чат и удалится через '
             + dict(CLEAN_TTLS).get(clean_cfg(uid)['backup'], '?').replace('не удалять', '— никогда')
             + ' (🧹 Чистый чат). Сохраните его к себе.',
             '📧 Почта — вложением на адреса уведомлений: ' + (h(', '.join(email_cfg()['to'])) or '<i>не настроена</i>'),
             '📁 SFTP — ' + (f'<code>{h(s["user"])}@{h(s["host"])}:{s.get("port") or 22}{h(s.get("path") or "")}</code>, '
                            + ('пароль' if s.get('auth') == 'pw' else 'ключ бота') if s.get('host') else '<i>не настроен</i>'),
             '☁️ Яндекс.Диск — ' + (f'{h(y["login"])}, папка <code>{h(yd_dir())}</code>' if y.get('login')
                                   else '<i>не настроен</i>')]
    if note:
        lines += ['', note]
    kb = []
    for d, label in BK_DEST:
        on = d in b['dest']
        kb.append([btn(('✅ ' if on else '⬜ ') + label, f'bk:dt:{d}')])
    kb.append([btn('📁 Настроить SFTP', 'bk:sftp'), btn('☁️ Настроить Я.Диск', 'bk:yd')])
    row = []
    if s.get('host'):
        row.append(btn('🔎 Проверить SFTP', 'bk:sftpt'))
    if y.get('login'):
        row.append(btn('🔎 Проверить Я.Диск', 'bk:ydt'))
    if row:
        kb.append(row)
    kb.append([btn('⬅️ Резервные копии', 'bk')])
    return '\n'.join(lines), kb


def scr_bk_list(uid, note=''):
    copies = bk_list()
    lines = ['🗂 <b>Копии на сервере</b>', '', f'Хранятся последние {BK_KEEP} в <code>{BK_DIR}</code>.', '']
    kb = []
    for i, c in enumerate(copies):
        when = time.strftime('%d.%m.%Y %H:%M', time.localtime(c['ts']))
        lines.append(f'{i + 1}. {when} · {fmt_bytes(c["size"])}')
        kb.append([btn(f'📥 {when}', f'bk:get:{c["name"][-30:]}')])
    if note:
        lines += ['', note]
    kb.append([btn('⬅️ Резервные копии', 'bk')])
    return '\n'.join(lines), kb


def bk_by_suffix(sfx):
    for c in bk_list():
        if c['name'].endswith(sfx):
            return os.path.join(BK_DIR, c['name'])
    return None


def bk_result_screen(uid, path, man, sent):
    name = os.path.basename(path)
    note = (f'✅ <b>Копия создана и проверена</b> (расшифрована и прочитана)\n<code>{h(name)}</code>, '
            f'{fmt_bytes(man["size"])}, файлов: {man["files"]}\n' + sent)
    t, kb = scr_bk(uid, note)
    extra = [btn(f'📤 {label}', f'bk:to:{d}:{name[-30:]}') for d, label in BK_DEST[1:] if bk_dest_ready(d)]
    if extra:
        kb[:0] = [extra[i:i + 3] for i in range(0, len(extra), 3)]
    return t, kb


def handle_bk(uid, data, chat, mid):
    b = bk_cfg()
    who = admin_name(uid)
    parts = data.split(':')
    act = parts[1] if len(parts) > 1 else ''
    if act == 'now':
        kb = []
        if bk_auto_pw():
            kb.append([btn('🔑 С паролем автобэкапа', 'bk:nowa')])
        kb.append([btn('✖️ Отмена', 'bk')])
        awaiting[uid] = ('bk_pw1', {'mode': 'now'})
        return ('💾 <b>Новая резервная копия</b>\n\nПридумайте пароль для этой копии и отправьте его сообщением '
                '(не короче 8 символов). Сообщение с паролем сразу удалится из чата, а сам пароль нигде не сохраняется.'
                '\n\n⚠️ Запишите пароль: без него копию не восстановить.\n\nОтмена: /cancel', kb)
    if act == 'nowa':
        pw = bk_auto_pw()
        if not pw:
            return scr_bk(uid, '⚠️ Пароль автобэкапа не задан.')
        return bk_now(uid, chat, mid, pw)
    if act == 'pw':
        awaiting[uid] = ('bk_pw1', {'mode': 'auto'})
        return ('🔑 <b>Пароль автобэкапа</b>\n\nОтправьте пароль (не короче 8 символов). Он хранится на сервере '
                f'в файле, доступном только root (<code>{BK_KEY}</code>), и нужен для восстановления любой '
                'автоматической копии. Сообщение с паролем сразу удалится из чата.\n\n⚠️ Запишите пароль.'
                + ('\n\nℹ️ Пароль уже задан. Новый будет у следующих копий, а уже сделанные останутся с прежним.'
                   if bk_auto_pw() else '')
                + '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'bk')]])
    if act == 'auto':
        if not b['auto'] and not bk_auto_pw():
            awaiting[uid] = ('bk_pw1', {'mode': 'auto', 'enable': True})
            return ('🔑 <b>Сначала пароль</b>\n\nДля автобэкапа нужен постоянный пароль. Отправьте его '
                    '(не короче 8 символов). Сообщение удалится из чата.\n\n⚠️ Запишите пароль.\n\nОтмена: /cancel',
                    [[btn('✖️ Отмена', 'bk')]])
        with lock:
            b['auto'] = not b['auto']
            b['next'] = bk_next_run() if b['auto'] else None
            save_state()
        add_event(f'{who}: автобэкап ' + ('включён' if b['auto'] else 'выключен'))
        return scr_bk(uid, '✅ Автобэкап включён' if b['auto'] else '⏸ Автобэкап выключен')
    if act == 'ev' and len(parts) > 2 and int(parts[2]) in BK_EVERY:
        with lock:
            b['every'] = int(parts[2])
            if b['auto'] and b.get('last'):
                b['next'] = max(bk_next_run(b['last'], days=b['every']), bk_next_run())
            save_state()
        return scr_bk(uid, f'✅ Раз в {b["every"]} дн.')
    if act == 'dst':
        return scr_bk_dst(uid)
    if act == 'dt' and len(parts) > 2:
        d = parts[2]
        if d in b['dest']:
            b['dest'].remove(d)
            note = ''
        elif not bk_dest_ready(d):
            return scr_bk_dst(uid, '⚠️ Сначала настройте это место' + (' (⚙️ Настройки → 📧 Почта)' if d == 'mail' else '') + '.')
        else:
            b['dest'].append(d)
            note = ''
        with lock:
            save_state()
        return scr_bk_dst(uid, note)
    if act == 'sftp':
        awaiting[uid] = ('bk_sftp', None)
        return ('📁 <b>SFTP для резервных копий</b>\n\nОтправьте адрес в виде\n<code>пользователь@сервер:порт/папка</code>\n'
                'Например: <code>backup@nas.example.ru:22/backups/vpngw</code> или <code>root@192.168.1.20/srv/backup</code>.\n'
                'Порт можно не указывать (22). Папка создастся сама.\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'bk:dst')]])
    if act == 'sfa' and len(parts) > 2:      # способ входа SFTP
        if parts[2] == 'key':
            with lock:
                b['sftp']['auth'] = 'key'
                save_state()
            bk_secret_set('sftp_pw', None)
            pub = ssh_ensure_key()
            return (f'🔑 <b>Вход по ключу бота</b>\n\nДобавьте эту строку в файл <code>~/.ssh/authorized_keys</code> '
                    f'пользователя на сервере SFTP:\n\n<code>{h(pub)}</code>\n\nЗатем нажмите «Проверить».',
                    [[btn('🔎 Проверить SFTP', 'bk:sftpt')], [btn('⬅️ Куда отправлять', 'bk:dst')]])
        awaiting[uid] = ('bk_sftp_pw', None)
        return ('🔒 Отправьте пароль пользователя SFTP. Он сохранится на сервере в файле только для root, '
                'сообщение удалится из чата.\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'bk:dst')]])
    if act == 'sftpt':
        edit(chat, mid, '🔎 Проверяю SFTP…')
        try:
            d = b['sftp'].get('path') or '.'
            sftp_run(f'-mkdir {sftp_q(d)}\ncd {sftp_q(d)}\npwd\n', 60)
            note = '✅ SFTP работает, папка доступна.'
        except Exception as ex:
            note = f'🔴 {h(str(ex))[:300]}'
        return scr_bk_dst(uid, note)
    if act == 'yd':
        awaiting[uid] = ('bk_yd_login', None)
        return ('☁️ <b>Яндекс.Диск</b>\n\nКопии загружаются по WebDAV. Нужен <b>пароль приложения</b> '
                '(обычный пароль не подойдёт):\nid.yandex.ru → Безопасность → Пароли приложений → '
                '«Файлы (WebDAV)».\n\nСначала отправьте логин Яндекса, например <code>ivanov@yandex.ru</code>.'
                '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'bk:dst')]])
    if act == 'ydt':
        edit(chat, mid, '🔎 Проверяю Яндекс.Диск…')
        try:
            code = yd_req('PROPFIND', '/', headers={'Depth': '0'}, timeout=30)
            note = '✅ Яндекс.Диск: вход выполнен.' if code in (200, 207) else f'🔴 Яндекс.Диск ответил кодом {code}'
        except Exception as ex:
            note = f'🔴 {h(str(ex))[:300]}'
        return scr_bk_dst(uid, note)
    if act == 'list':
        return scr_bk_list(uid)
    if act == 'get' and len(parts) > 2:
        path = bk_by_suffix(parts[2])
        if not path:
            return scr_bk_list(uid, '⚠️ Копия не найдена')
        man = {'created_text': time.strftime('%d.%m.%Y %H:%M', time.localtime(os.path.getmtime(path))),
               'version': '?'}
        tg_file('sendDocument', chat, 'document', os.path.basename(path), open(path, 'rb').read(),
                f'💾 <b>Резервная копия</b> · {h(man["created_text"])}\n<code>{h(os.path.basename(path))}</code>\n'
                'Пароль — тот, с которым её создавали.', ttl_kind='backup')
        t, kb = scr_bk_list(uid, '📥 Файл отправлен выше.')
        send(chat, t, kb)
        return None
    if act == 'to' and len(parts) > 3:
        path = bk_by_suffix(parts[3])
        if not path:
            return scr_bk(uid, '⚠️ Копия не найдена (могла удалиться как старая)')
        edit(chat, mid, '📤 Отправляю…')
        try:
            where = bk_send(parts[2], path, {'created_text': time.strftime('%d.%m.%Y %H:%M',
                                                                           time.localtime(os.path.getmtime(path)))})
            note = f'✅ Отправлено: {h(where)}'
        except Exception as ex:
            note = f'🔴 {h(str(ex))[:300]}'
        return scr_bk(uid, note)
    return scr_bk(uid)


def bk_now(uid, chat, mid, pw):
    if not BK_LOCK.acquire(blocking=False):
        return scr_bk(uid, '⏳ Копия уже создаётся, подождите.')
    try:
        if mid:
            edit(chat, mid, '💾 Создаю копию и проверяю её…')
        else:
            send(chat, '💾 Создаю копию и проверяю её…')
        try:
            path, man = bk_make(pw)
        except Exception as ex:
            log('backup:', traceback.format_exc())
            return scr_bk(uid, f'🔴 Копия не создана: {h(str(ex))[:300]}')
        add_event(f'{admin_name(uid)} создал резервную копию')
        try:
            bk_send('tg', path, man, chat)
            sent = '📥 Файл — ниже. Сохраните его в надёжное место.'
        except Exception as ex:
            sent = f'🔴 В Telegram не отправилась: {h(str(ex))[:200]}. Копия лежит на сервере.'
    finally:
        BK_LOCK.release()
    t, kb = bk_result_screen(uid, path, man, sent)
    send(chat, t, kb)
    return None


def handle_bk_input(uid, chat, kind, wdata, text):
    b = bk_cfg()
    if kind in ('bk_pw1', 'bk_pw2'):
        pw = text
        if kind == 'bk_pw1':
            if len(pw) < 8:
                send(chat, '⚠️ Пароль короче 8 символов. Придумайте подлиннее и отправьте ещё раз, или /cancel.')
                return
            awaiting[uid] = ('bk_pw2', dict(wdata, pw=pw))
            send(chat, '🔁 Отправьте этот же пароль ещё раз — для проверки.\n\nОтмена: /cancel')
            return
        if pw != wdata['pw']:
            awaiting[uid] = ('bk_pw1', {k: v for k, v in wdata.items() if k != 'pw'})
            send(chat, '⚠️ Пароли не совпали. Отправьте новый пароль ещё раз, или /cancel.')
            return
        awaiting.pop(uid, None)
        if wdata['mode'] == 'now':
            res = bk_now(uid, chat, None, pw)
            if res:
                send(chat, *res)
            return
        root_file_write(BK_KEY, pw + '\n')
        with lock:
            if wdata.get('enable'):
                b['auto'] = True
                b['next'] = bk_next_run()
            save_state()
        add_event(f'{admin_name(uid)} задал пароль автобэкапа')
        t, kb = scr_bk(uid, '✅ Пароль сохранён' + (', автобэкап включён' if wdata.get('enable') else ''))
        send(chat, t, kb)
        return
    if kind == 'bk_sftp':
        m = re.match(r'^([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9.-]+)(?::(\d{1,5}))?(/.*)?$', text.strip())
        if not m:
            send(chat, 'Нужно в виде <code>user@host:22/папка</code>. Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        with lock:
            b['sftp'] = {'user': m.group(1), 'host': m.group(2), 'port': int(m.group(3) or 22),
                         'path': (m.group(4) or '').rstrip('/') or '', 'auth': b['sftp'].get('auth', 'key')}
            save_state()
        send(chat, f'📁 SFTP: <code>{h(text.strip())}</code>\n\nКак входить на сервер?',
             [[btn('🔑 Ключом бота', 'bk:sfa:key'), btn('🔒 Паролем', 'bk:sfa:pw')], [btn('⬅️ Куда отправлять', 'bk:dst')]])
        return
    if kind == 'bk_sftp_pw':
        awaiting.pop(uid, None)
        bk_secret_set('sftp_pw', text)
        with lock:
            b['sftp']['auth'] = 'pw'
            save_state()
        send(chat, '🔎 Проверяю SFTP…')
        try:
            d = b['sftp'].get('path') or '.'
            sftp_run(f'-mkdir {sftp_q(d)}\ncd {sftp_q(d)}\npwd\n', 60)
            note = '✅ Пароль сохранён, SFTP работает.'
        except Exception as ex:
            note = f'⚠️ Пароль сохранён, но проверка не прошла: {h(str(ex))[:300]}'
        t, kb = scr_bk_dst(uid, note)
        send(chat, t, kb)
        return
    if kind == 'bk_yd_login':
        login = text.strip()
        if not re.match(r'^[A-Za-z0-9_.@+-]{2,64}$', login):
            send(chat, 'Это не похоже на логин Яндекса. Ещё раз или /cancel.')
            return
        awaiting[uid] = ('bk_yd_pw', login)
        send(chat, '🔒 Теперь отправьте <b>пароль приложения</b> «Файлы (WebDAV)». Сообщение удалится из чата.'
                   '\n\nОтмена: /cancel')
        return
    if kind == 'bk_yd_pw':
        awaiting.pop(uid, None)
        bk_secret_set('yd_pw', text.strip())
        with lock:
            b['yd'] = {'login': wdata, 'path': b['yd'].get('path') or 'vpngw-backups'}
            save_state()
        send(chat, '🔎 Проверяю Яндекс.Диск…')
        try:
            code = yd_req('PROPFIND', '/', headers={'Depth': '0'}, timeout=30)
            note = ('✅ Яндекс.Диск подключён. Копии будут в папке ' + f'<code>{h(yd_dir())}</code>.'
                    if code in (200, 207) else f'⚠️ Яндекс.Диск ответил кодом {code}')
        except Exception as ex:
            note = f'⚠️ {h(str(ex))[:300]}'
        if note.startswith('✅') and 'yd' not in b['dest']:
            b['dest'].append('yd')
            with lock:
                save_state()
            note += ' Отправка туда включена.'
        t, kb = scr_bk_dst(uid, note)
        send(chat, t, kb)
        return


# ---------------- чистый чат: настройки ----------------
def scr_clean(uid, note=''):
    c = clean_cfg(uid)
    names = dict(CLEAN_TTLS)
    lines = ['🧹 <b>Чистый чат</b>', '',
             'В чате всегда одно меню: новые экраны заменяют старое, ваши сообщения и команды удаляются '
             'после обработки. Ниже — когда удалять остальное.', '',
             f'🔳 QR-коды и конфиги: <b>{names.get(c["files"], "?")}</b>',
             f'💾 Файлы резервных копий: <b>{names.get(c["backup"], "?")}</b>',
             f'🔔 Обычные уведомления: <b>{names.get(c["notif"], "?")}</b>',
             '<i>Важные (VPN упал, нет связи, диск, ошибки бэкапа) висят, пока не нажмёте «✔️ Понятно».</i>', '',
             '<i>Telegram разрешает удалять сообщения только в первые 48 часов.</i>']
    if note:
        lines += ['', note]
    kb = []
    for key, title in (('files', '🔳'), ('backup', '💾'), ('notif', '🔔')):
        opts = CLEAN_TTLS if key != 'notif' else [(86400, '24 часа'), (0, 'не удалять')]
        kb.append([btn(('• ' if c[key] == v else '') + f'{title} {n}', f'cl:{key}:{v}') for v, n in opts])
    kb.append([btn('🧹 Очистить чат сейчас', 'clean')])
    kb.append([btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


# ---------------- MikroTik: проверка роутера, порт, что пускать в VPN ----------------

MT_CHECK_CMD = ('/ip address print terse proplist=address,interface; '
                '/interface wireguard print terse proplist=name,listen-port')
MT_PORT = 13240
MT_IFACE = 'wg-vpn-gw'
PRIVATE = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
MT_ROUTE = {'none': '🔒 Только туннель', 'lan': '🏢 Локальная сеть', 'dst': '🎯 Выбранные адреса'}
NET_CANDIDATES = ['10.10.10', '10.10.20', '10.20.30', '10.66.66', '10.99.10', '172.29.29']


def mt_parse(text):
    """Разбор вывода MT_CHECK_CMD (терс или обычный вид). Ключей и паролей там нет."""
    addrs, ports = [], {}
    for line in (text or '').splitlines():
        m = re.search(r'(?<![\w-])address=(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})', line)
        if m:
            i = re.search(r'(?<![\w-])interface=("([^"]*)"|\S+)', line)
            try:
                addrs.append((ipaddress.ip_interface(m.group(1)), (i.group(2) or i.group(1)) if i else ''))
            except ValueError:
                pass
            continue
        m = re.search(r'listen-port=(\d{1,5})', line)
        if m:
            n = re.search(r'(?<![\w-])name=("([^"]*)"|\S+)', line)
            ports[int(m.group(1))] = (n.group(2) or n.group(1)) if n else '?'
    if not addrs:      # вставили обычную таблицу (print без terse): берём все адреса вида x.x.x.x/nn
        for m in re.finditer(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})(?![\d.])', text or ''):
            try:
                addrs.append((ipaddress.ip_interface(m.group(1)), ''))
            except ValueError:
                pass
    return {'addrs': addrs, 'ports': ports}


def gw_ext_port():
    try:
        return int(wg_port())
    except Exception:
        return 51820


def gw_listen_port():
    try:
        return int(wg_live()['port'])
    except Exception:
        return gw_ext_port()


def mt_analyze(text, wg_net=None, gw_ip=None):
    """→ что нашли на роутере и чем это грозит туннелю"""
    info = mt_parse(text)
    tunnel = ipaddress.ip_network(f'{wg_net or WG_NET}.0/24')
    gw = ipaddress.ip_address(gw_ip) if gw_ip else None
    conflicts = [(str(a), i) for a, i in info['addrs'] if a.network.overlaps(tunnel)]
    local = bool(gw and any(gw in a.network for a, _ in info['addrs']))
    lans = []
    for a, i in info['addrs']:
        n = a.network
        if n.prefixlen < 32 and any(n.subnet_of(pn) for pn in PRIVATE) and not n.overlaps(tunnel) \
                and str(n) not in lans:
            lans.append(str(n))
    names = set(info['ports'].values())
    iface = MT_IFACE
    k = 2
    while iface in names:
        iface = f'{MT_IFACE}{k}'
        k += 1
    return {'addrs': [(str(a), i) for a, i in info['addrs']], 'ports': info['ports'], 'conflicts': conflicts,
            'local': local, 'lans': lans, 'iface': iface, 'had_iface': MT_IFACE in names}


def resolve4(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def mt_free_port(used, avoid=()):
    p = MT_PORT
    while p in used or p in avoid:
        p += 1
    return p


def free_wg_net(nets, avoid_ips=()):
    """Первая подсеть туннеля, не пересекающаяся с сетями роутера и сервера."""
    busy = [ipaddress.ip_network(n, strict=False) for n in nets]
    for c in NET_CANDIDATES:
        t = ipaddress.ip_network(f'{c}.0/24')
        if not any(t.overlaps(b) for b in busy) and not any(ipaddress.ip_address(x) in t for x in avoid_ips if x):
            return c
    return None


def mt_defaults(name, pub=None):
    """Начальные настройки мастера (новый MikroTik или правка существующего)."""
    if pub:
        p = wg_state()['peers'][pub]
        mt = dict(p.get('mt') or {})
        ctx = {'name': p['name'], 'pub': pub, 'port': mt.get('port', MT_PORT), 'route': mt.get('route', 'none'),
               'nets': list(mt.get('nets', [])), 'dst': list(mt.get('dst', [])), 'local': mt.get('local', False),
               'via': mt.get('via'), 'iface': mt.get('iface', MT_IFACE), 'gw_ip': mt.get('gw_ip') or lan_ip()}
    else:
        ctx = {'name': name, 'pub': None, 'port': MT_PORT, 'route': 'none', 'nets': [], 'dst': [], 'local': False,
               'via': None, 'iface': MT_IFACE, 'gw_ip': lan_ip()}
    ctx.update(raw='', info=None, step='paste')
    return ctx


def mt_apply_info(ctx):
    """Применить результаты проверки: порт, имя интерфейса, «в той же сети», подсеть по умолчанию."""
    a = mt_analyze(ctx['raw'], gw_ip=ctx['gw_ip'])
    ctx['info'] = a
    if not ctx.get('pub'):
        ctx['iface'] = a['iface']
    used = {pt for pt, n in a['ports'].items() if n != ctx['iface']}   # свой же интерфейс (при правке) не считаем
    avoid = {gw_ext_port()} if a['local'] else set()
    if int(ctx['port']) in used or int(ctx['port']) in avoid:
        ctx['port'] = mt_free_port(used, avoid)
    if not ctx.get('pub'):
        ctx['local'] = a['local']
        if a['local'] and a['lans'] and not ctx['nets']:
            gwnet = [n for n in a['lans'] if ctx['gw_ip'] and ipaddress.ip_address(ctx['gw_ip']) in ipaddress.ip_network(n)]
            ctx['nets'] = gwnet[:1] or a['lans'][:1]
        elif a['lans'] and not ctx['nets']:
            ctx['nets'] = a['lans'][:1]


def mt_warnings(ctx):
    w = []
    a = ctx.get('info')
    tunnel = ipaddress.ip_network(f'{WG_NET}.0/24')
    if a:
        for addr, i in a['conflicts']:
            w.append(f'🔴 На роутере уже есть адрес <code>{addr}</code>' + (f' ({h(i)})' if i else '')
                     + f' — он пересекается с туннелем <code>{tunnel}</code>. Туннель на этом роутере работать '
                     'не будет: смените ту сеть на роутере (подсеть туннеля шлюза менять нельзя — отвалятся все клиенты).')
        used = a['ports'].get(int(ctx['port']))
        if used and used != ctx['iface']:
            w.append(f'🔴 Порт {ctx["port"]} на роутере уже занят интерфейсом «{h(used)}».')
        if a['had_iface'] and not ctx.get('pub') and ctx['iface'] != MT_IFACE:
            w.append(f'ℹ️ Интерфейс {MT_IFACE} на роутере уже есть — новый будет называться {ctx["iface"]}.')
    else:
        w.append('ℹ️ Роутер не проверялся: порт и адреса не сверены с его настройками.')
    if ctx['local'] and int(ctx['port']) == gw_ext_port():
        w.append(f'🔴 Порт {ctx["port"]} пробрасывается на шлюз — MikroTik не сможет слушать его сам. Выберите другой.')
    for n in ctx['nets'] if ctx['route'] == 'lan' else []:
        if ipaddress.ip_network(n).overlaps(tunnel):
            w.append(f'🔴 Сеть {n} пересекается с туннелем {tunnel}.')
    if ctx['route'] == 'lan' and ctx['local']:
        w.append(f'⚠️ Весь интернет сети {", ".join(ctx["nets"]) or "?"} пойдёт через шлюз Ubuntu. Сам шлюз '
                 f'(<code>{h(ctx["gw_ip"])}</code>) и локальные адреса в правилах исключены — петли не будет. '
                 'Если туннель упадёт, трафик автоматически пойдёт напрямую.')
    if ctx['route'] == 'lan' and not ctx['nets']:
        w.append('🔴 Не выбрана сеть, которую пускать в VPN.')
    if ctx['route'] == 'dst' and not ctx['dst']:
        w.append('🔴 Не заданы адреса, которые пускать в VPN.')
    return w


def mt_blocking(ctx):
    return any(x.startswith('🔴') for x in mt_warnings(ctx))


def mt_gw_ip(mt):
    # текущий адрес Ubuntu: после переезда на другой сервер он новый, а не тот, что был при создании
    return lan_ip() or mt.get('gw_ip') or ''


def mt_endpoint(ctx_or_mt, via=None):
    mt = ctx_or_mt
    if mt.get('local'):
        return mt_gw_ip(mt), gw_listen_port()
    host, port = wg_endpoint(via or mt.get('via')).rsplit(':', 1)
    return host, int(port)


def scr_mt(uid, ctx, note=''):
    if ctx['step'] == 'paste':
        got = ''
        if ctx['raw']:
            a = mt_analyze(ctx['raw'], gw_ip=ctx['gw_ip'])
            got = (f'\n\n📥 Получено: адресов {len(a["addrs"])}, интерфейсов WireGuard {len(a["ports"])}. '
                   'Если вывод длинный и пришёл несколькими сообщениями — дошлите остальное, затем «Дальше».')
        text = (f'📡 <b>MikroTik «{h(ctx["name"])}»: проверка роутера</b>\n\n'
                'Чтобы бот подобрал свободный порт и проверил, что подсеть туннеля не занята, выполните в терминале '
                'MikroTik (Winbox → New Terminal) и пришлите сюда весь вывод:\n\n'
                f'<code>{h(MT_CHECK_CMD)}</code>\n\n'
                'Команда ничего не меняет, только показывает адреса и порты. Ключей и паролей в выводе нет.'
                f'{got}\n\nОтмена: /cancel')
        kb = [[btn('✅ Дальше', 'mtw:next')] if ctx['raw'] else [btn('⏭ Пропустить проверку', 'mtw:next')]]
        if ctx['raw']:
            kb.append([btn('🔁 Вставить заново', 'mtw:reset')])
        kb.append([btn('✖️ Отмена', 'mtw:cancel')])
        return text, kb
    a = ctx.get('info')
    host, port = mt_endpoint(ctx)
    lines = [f'📡 <b>MikroTik «{h(ctx["name"])}»</b>' + (' — изменение' if ctx.get('pub') else ''), '',
             '📍 Где роутер: ' + ('<b>в одной сети со шлюзом</b>' if ctx['local'] else '<b>в другом месте</b> (через интернет)'),
             f'    подключается к <code>{h(host)}:{port}</code>',
             f'🔌 Порт WireGuard на роутере: <b>{ctx["port"]}</b>, интерфейс {h(ctx["iface"])}',
             f'🧭 Через VPN: <b>{MT_ROUTE[ctx["route"]]}</b>'
             + (f' — {h(", ".join(ctx["nets"]))}' if ctx['route'] == 'lan' and ctx['nets'] else '')
             + (f' — {len(ctx["dst"])} шт.: {h(", ".join(ctx["dst"][:6]))}' + ('…' if len(ctx['dst']) > 6 else '')
                if ctx['route'] == 'dst' and ctx['dst'] else '')]
    if a:
        lines.append(f'🔎 Роутер проверен: адресов {len(a["addrs"])}, интерфейсов WireGuard {len(a["ports"])}'
                     + (f' (порты {", ".join(map(str, sorted(a["ports"])))})' if a['ports'] else ''))
    lines += ['', '<i>«Только туннель» — роутер подключится к шлюзу, но сам трафик в VPN не отправит (можно '
              'направить позже). «Локальная сеть» — весь интернет выбранной сети через VPN. «Выбранные адреса» — '
              'только трафик к указанным IP и подсетям.</i>']
    warns = mt_warnings(ctx)
    if warns:
        lines += [''] + warns
    if note:
        lines += ['', note]
    kb = [[btn(('• ' if ctx['local'] else '') + '🏠 В этой сети', 'mtw:loc:1'),
           btn(('• ' if not ctx['local'] else '') + '🌍 Удалённо', 'mtw:loc:0')],
          [btn(f'🔌 Порт: {ctx["port"]}', 'mtw:port')],
          [btn(('• ' if ctx['route'] == k else '') + v, f'mtw:rt:{k}') for k, v in MT_ROUTE.items()]]
    if ctx['route'] == 'lan':
        lans = (a or {}).get('lans') or []
        row = [btn(('✅ ' if n in ctx['nets'] else '⬜ ') + n, f'mtw:net:{i}') for i, n in enumerate(lans[:6])]
        for i in range(0, len(row), 2):
            kb.append(row[i:i + 2])
        kb.append([btn('✏️ Указать сеть вручную', 'mtw:netset')])
    if ctx['route'] == 'dst':
        kb.append([btn('✏️ Адреса для VPN', 'mtw:dstset')])
    if not ctx['local'] and both_eps():
        v = ctx.get('via') or 'd'
        kb.append([btn(('• ' if v == 'd' else '') + '🌐 По домену', 'mtw:via:d'),
                   btn(('• ' if v == 'i' else '') + '🔢 По IP', 'mtw:via:i')])
    if not a:
        kb.append([btn('🔎 Проверить роутер', 'mtw:check')])
    kb.append([btn('✅ Сохранить и выдать команды' if ctx.get('pub') else '✅ Создать', 'mtw:go'),
               btn('✖️ Отмена', 'mtw:cancel')])
    return '\n'.join(lines), kb


def mt_save(uid, ctx):
    """Создать пир MikroTik (или сохранить изменения) → pub"""
    mt = {k: ctx[k] for k in ('port', 'route', 'nets', 'dst', 'local', 'via', 'iface', 'gw_ip')}
    if ctx.get('pub'):
        with lock:
            wg_state()['peers'][ctx['pub']]['mt'] = mt
            save_state()
        add_event(f'{admin_name(uid)} изменил настройки MikroTik «{ctx["name"]}»')
        return ctx['pub']
    pub = wg_new_peer(ctx['name'], 'mikrotik')
    with lock:
        wg_state()['peers'][pub]['mt'] = mt
        save_state()
    add_event(f'{admin_name(uid)} добавил MikroTik «{ctx["name"]}»')
    notify('actions', f'👤 {h(admin_name(uid))} добавил MikroTik «{h(ctx["name"])}»', exclude=uid)
    return pub


def handle_mtw(uid, data, chat, mid):
    kind, ctx = awaiting.get(uid, (None, None))
    if kind != 'mt' or not isinstance(ctx, dict):
        return scr_wg(uid, '⚠️ Мастер MikroTik устарел (бот перезапускался?). Начните заново.')
    act = data.split(':')
    a = act[1] if len(act) > 1 else ''
    arg = act[2] if len(act) > 2 else ''
    if a == 'cancel':
        awaiting.pop(uid, None)
        return scr_wg_peer(uid, ctx['pub']) if ctx.get('pub') and ctx['pub'] in wg_state()['peers'] else scr_wg(uid, '✖️ Отменено')
    if a == 'reset':
        ctx['raw'] = ''
        return scr_mt(uid, ctx)
    if a == 'check':
        ctx['step'] = 'paste'
        return scr_mt(uid, ctx)
    if a == 'next':
        if ctx['raw']:
            mt_apply_info(ctx)
        ctx['step'] = None
        return scr_mt(uid, ctx)
    if a == 'loc':
        ctx['local'] = arg == '1'
        return scr_mt(uid, ctx)
    if a == 'via' and arg in ('d', 'i'):
        ctx['via'] = arg
        return scr_mt(uid, ctx)
    if a == 'rt' and arg in MT_ROUTE:
        ctx['route'] = arg
        return scr_mt(uid, ctx)
    if a == 'net' and arg.isdigit():
        lans = (ctx.get('info') or {}).get('lans') or []
        if int(arg) < len(lans):
            n = lans[int(arg)]
            ctx['nets'] = [x for x in ctx['nets'] if x != n] if n in ctx['nets'] else ctx['nets'] + [n]
        return scr_mt(uid, ctx)
    if a in ('port', 'netset', 'dstset'):
        ctx['step'] = a
        txt = {'port': f'🔌 Отправьте UDP-порт для WireGuard на роутере (1024–65535). Сейчас: {ctx["port"]}.',
               'netset': '🏢 Отправьте сеть роутера, которую пускать в VPN, например <code>192.168.88.0/24</code>. '
                         'Можно несколько через пробел.',
               'dstset': '🎯 Отправьте IP-адреса или подсети через пробел или с новой строки, например '
                         '<code>8.8.8.8 149.154.160.0/20</code>. Доменные имена роутер в маршрутах не понимает — '
                         'только IP.'}[a]
        return txt + '\n\nОтмена: /cancel', [[btn('⬅️ Назад', 'mtw:back')]]
    if a == 'back':
        ctx['step'] = None
        return scr_mt(uid, ctx)
    if a == 'go':
        if mt_blocking(ctx):
            return scr_mt(uid, ctx, '⛔ Сначала исправьте отмеченное 🔴.')
        awaiting.pop(uid, None)
        try:
            pub = mt_save(uid, ctx)
        except Exception as ex:
            return scr_wg(uid, f'🔴 Не удалось создать: <code>{h(str(ex))[:250]}</code>')
        wg_send_conf(chat, pub)
        t, kb = scr_wg_peer(uid, pub, '✅ ' + ('Сохранено. ' if ctx.get('pub') else 'MikroTik добавлен. ')
                            + 'Вставьте команды из файла в терминал MikroTik — лучше в Safe Mode (Ctrl+X), '
                              f'затем проверьте: <code>/ping {WG_NET}.1</code>.')
        send(chat, t, kb)
        return None
    return scr_mt(uid, ctx)


def handle_mt_input(uid, chat, ctx, text, m):
    step = ctx.get('step')
    if step == 'paste':
        if m.get('document'):
            raw = tg_download(m['document']['file_id'], 256 * 1024)
            text = raw.decode('utf-8', 'ignore') if raw else ''
        ctx['raw'] = (ctx['raw'] + '\n' + text)[-200000:]
        t, kb = scr_mt(uid, ctx)
        send(chat, t, kb)
        return
    if step == 'port':
        if not text.strip().isdigit() or not 1024 <= int(text.strip()) <= 65535:
            send(chat, 'Нужен номер порта от 1024 до 65535. Ещё раз или /cancel.')
            return
        ctx['port'] = int(text.strip())
    elif step in ('netset', 'dstset'):
        items, bad = [], []
        for x in re.split(r'[\s,;]+', text.strip()):
            if not x:
                continue
            try:
                n = ipaddress.ip_network(x, strict=False)
                if n.version != 4:
                    raise ValueError
                items.append(str(n))
            except ValueError:
                bad.append(x)
        if bad or not items:
            send(chat, f'Не понял: {h(" ".join(bad[:5]) or text[:50])}. Нужны IP или подсети, например '
                       '<code>192.168.88.0/24</code>. Ещё раз или /cancel.')
            return
        if step == 'netset':
            if not all(any(ipaddress.ip_network(n).subnet_of(p) for p in PRIVATE) for n in items):
                send(chat, 'Локальная сеть должна быть из частных диапазонов (10.x, 172.16–31.x, 192.168.x). '
                           'Для внешних адресов выберите «🎯 Выбранные адреса». Ещё раз или /cancel.')
                return
            ctx['nets'] = list(dict.fromkeys(items))
        else:
            ctx['dst'] = list(dict.fromkeys(items))[:100]
    ctx['step'] = None
    t, kb = scr_mt(uid, ctx)
    send(chat, t, kb)


def mt_conf(p, via=None):
    """Команды RouterOS для MikroTik-клиента: интерфейс, пир, адрес, NAT, MSS и маршрутизация по выбору."""
    mt = p.get('mt') or {}
    iface = mt.get('iface') or MT_IFACE
    table = 'via-vpn-gw' if iface == MT_IFACE else f'via-{iface}'
    lport = int(mt.get('port') or MT_PORT)
    host, port = mt_endpoint(mt, via)
    route = mt.get('route', 'none')
    tagc = f'vpn-gateway:{iface}'          # своя метка у каждого интерфейса: удаление не заденет чужие правила
    c = f'comment="{tagc}"'
    out = ['# Команды для MikroTik (RouterOS 7). Вставьте в New Terminal целиком, лучше в Safe Mode (Ctrl+X).',
           f'# Подключение «{p["name"]}» к VPN-шлюзу, адрес в туннеле {p["ip"]}, шлюз {host}:{port}',
           f'/interface wireguard add name="{iface}" listen-port={lport} mtu=1420 private-key="{p["priv"]}" {c}',
           f'/interface wireguard peers add interface="{iface}" public-key="{wg_server_pub()}" '
           f'preshared-key="{p["psk"]}" endpoint-address={host} endpoint-port={port} '
           f'allowed-address=0.0.0.0/0 persistent-keepalive=25s {c}',
           f'/ip address add address={p["ip"]}/24 interface="{iface}" {c}',
           f'/ip firewall nat add chain=srcnat out-interface="{iface}" action=masquerade {c}',
           f'/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn out-interface="{iface}" '
           f'action=change-mss new-mss=clamp-to-pmtu passthrough=yes {c}',
           f'/routing table add name={table} fib',
           f'/ip route add dst-address=0.0.0.0/0 gateway="{iface}" routing-table={table} {c}']
    if route in ('lan', 'dst'):
        out.append('# Мимо туннеля: сам шлюз, адрес подключения и локальные сети (защита от петли)')
        if mt.get('local') and mt_gw_ip(mt):
            out.append(f'/routing rule add src-address={mt_gw_ip(mt)}/32 action=lookup-only-in-table table=main '
                       f'comment="{tagc} сам шлюз мимо туннеля"')
        for ip in ([host] if IP_RE.match(host) else resolve4(host)):
            if not any(ipaddress.ip_address(ip) in n for n in PRIVATE):
                out.append(f'/routing rule add dst-address={ip}/32 action=lookup-only-in-table table=main {c}')
        for n in PRIVATE:
            out.append(f'/routing rule add dst-address={n} action=lookup-only-in-table table=main {c}')
    if route == 'lan':
        out.append('# Через VPN: весь интернет этих сетей (если туннель упадёт — пойдёт напрямую)')
        out += [f'/routing rule add src-address={n} action=lookup table={table} {c}' for n in mt.get('nets', [])]
    elif route == 'dst':
        out.append('# Через VPN: только эти адреса')
        out += [f'/routing rule add dst-address={n} action=lookup table={table} {c}' for n in mt.get('dst', [])]
    else:
        out += ['# Трафик сам в VPN не идёт. Чтобы направить, например, всю сеть:',
                f'# /routing rule add src-address=192.168.88.0/24 action=lookup table={table} {c}',
                '# (в боте это делается кнопкой «⚙️ Настройки MikroTik» → «Локальная сеть»)']
    out += [f'# Проверка: /ping {WG_NET}.1',
            '# Убрать всё, что добавили эти команды:',
            f'# /routing rule remove [find comment~"{tagc}"]; /ip route remove [find comment="{tagc}"]',
            f'# /routing table remove [find name={table}]; /ip firewall mangle remove [find comment="{tagc}"]',
            f'# /ip firewall nat remove [find comment="{tagc}"]; /ip address remove [find comment="{tagc}"]',
            f'# /interface wireguard remove [find name="{iface}"]',
            '']
    return '\n'.join(out)


KIND_ICON = {'mikrotik': '📡', 'device': '📱', 'phone': '📱', 'pc': '💻'}
KIND_RU = {'mikrotik': 'MikroTik / роутер', 'device': 'устройство', 'phone': 'телефон / планшет', 'pc': 'компьютер'}


def peer_by_tag(t):
    return next((pub for pub in wg_state()['peers'] if tag(pub) == t), None)


def month_key(d=None):
    return (d or date.today()).strftime('%Y-%m')


def peer_usage(p):
    st = p.get('stats') or {}
    today = date.today().isoformat()
    mk = month_key()
    t = st.get(today, [0, 0])
    m = [sum(v[i] for k, v in st.items() if k.startswith(mk)) for i in (0, 1)]
    a = [sum(v[i] for v in st.values()) for i in (0, 1)]
    return {'today': t, 'month': m, 'total': a}


def bar(frac, n=10):
    frac = max(0.0, min(1.0, frac))
    full = round(frac * n)
    return '▓' * full + '░' * (n - full)


def fmt_date(ts):
    return time.strftime('%d.%m.%Y', time.localtime(ts))


def days_word(n):
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return f'{n} день'
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f'{n} дня'
    return f'{n} дней'


def days_left(ts):
    return int((ts - time.time()) // 86400) + (1 if (ts - time.time()) % 86400 else 0)


def end_of_day(d):
    return time.mktime(datetime(d.year, d.month, d.day, 23, 59, 59).timetuple())


def peer_badges(p):
    out = []
    if p.get('expires'):
        out.append(f'⏳ до {time.strftime("%d.%m", time.localtime(p["expires"]))}')
    if p.get('limit'):
        u = peer_usage(p)['month']
        out.append(f'📊 {fmt_bytes(u[0] + u[1])}/{fmt_bytes(p["limit"])}')
    return (' · ' + ' · '.join(out)) if out else ''


def peer_status(p, lv):
    if not p['enabled']:
        if p.get('off_reason') == 'expired':
            return '⌛', 'срок истёк'
        if p.get('off_reason') == 'limit':
            return '🚫', 'лимит трафика исчерпан'
        return '⏸', 'выключен'
    if not lv or lv['age'] is None:
        return '⚪', 'ещё не подключался'
    if lv['age'] < WG_STALE:
        return '🟢', f'на связи, {fmt_dur(lv["age"])} назад'
    return '🔴', f'был {fmt_dur(lv["age"])} назад'


def scr_wg(uid, note='', page=0):
    w = wg_state()
    try:
        live = wg_live()
    except Exception:
        live = {'peers': {}, 'port': '?'}
    peers = list(w['peers'].items())
    pages = max((len(peers) - 1) // PEERS_PAGE + 1, 1)
    page = min(max(page, 0), pages - 1)
    lines = ['🔐 <b>WireGuard</b>', '',
             f'Сервер: <code>{WG_NET}.1</code>, порт {live["port"]}',
             f'Адрес для подключения: <code>{h(wg_endpoint())}</code>', '',
             f'<b>Пиры ({len(peers)}):</b>']
    kb, row = [], []
    for pub, p in peers[page * PEERS_PAGE:(page + 1) * PEERS_PAGE]:
        lv = live['peers'].get(pub)
        icon, st = peer_status(p, lv)
        mu = peer_usage(p)['month']
        traffic = f' · за месяц {fmt_bytes(mu[0] + mu[1])}' if mu[0] + mu[1] else ''
        lines.append(f'{icon} {KIND_ICON[p["kind"]]} <b>{h(p["name"])}</b> · {p["ip"]} · {st}{traffic}{peer_badges(p)}')
        row.append(btn(f'{icon} {p["name"]}'[:40], f'wgp:{tag(pub)}'))
        if len(row) == 2:
            kb.append(row)
            row = []
    if row:
        kb.append(row)
    if pages > 1:
        kb.append([btn('◀️', f'wg:{page - 1}') if page else btn('·', 'noop'),
                   btn(f'{page + 1}/{pages}', 'noop'),
                   btn('▶️', f'wg:{page + 1}') if page < pages - 1 else btn('·', 'noop')])
    if note:
        lines += ['', note]
    kb.append([btn('➕ 📱 Телефон', 'wgadd:phone'), btn('➕ 💻 Компьютер', 'wgadd:pc')])
    if SHOW_MIKROTIK:
        kb.append([btn('➕ 📡 MikroTik', 'wgadd:mikrotik')])
    if is_owner(uid):
        kb.append([btn('🌐 Адрес для подключения', 'wgep')])
    kb.append([btn('📊 Статистика клиентов', 'wgstat')])
    kb.append([btn('🔄 Обновить', 'wg'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_wg_peer(uid, pub, note=''):
    p = wg_state()['peers'][pub]
    try:
        lv = wg_live()['peers'].get(pub)
    except Exception:
        lv = None
    icon, st = peer_status(p, lv)
    lines = [f'{KIND_ICON[p["kind"]]} <b>{h(p["name"])}</b>', '',
             f'Тип: {KIND_RU.get(p["kind"], p["kind"])}',
             f'Адрес в туннеле: <code>{p["ip"]}</code>',
             f'Состояние: {icon} {st}']
    if lv and lv['endpoint']:
        lines.append(f'Подключён с: <code>{h(lv["endpoint"])}</code>')
    u = peer_usage(p)
    lines.append('')
    lines.append(f'📊 Трафик: сегодня {fmt_bytes(sum(u["today"]))}, за месяц {fmt_bytes(sum(u["month"]))}, '
                 f'всего {fmt_bytes(sum(u["total"]))}')
    lines.append(f'      (скачал ↓ {fmt_bytes(u["month"][0])}, отправил ↑ {fmt_bytes(u["month"][1])} за месяц)')
    if p.get('limit'):
        used = sum(u['month'])
        lines.append(f'🚦 Лимит: {bar(used / p["limit"])} {fmt_bytes(used)} из {fmt_bytes(p["limit"])} в месяц')
    else:
        lines.append('🚦 Лимит трафика: нет')
    if p.get('expires'):
        dl = days_left(p['expires'])
        lines.append(f'⏳ Доступ до {fmt_date(p["expires"])} ' + (f'(осталось {days_word(dl)})' if dl > 0 else '(истёк)'))
    else:
        lines.append('⏳ Срок доступа: бессрочно')
    lines.append('')
    lines.append(f'Следить за связью: {"✅ да" if p.get("monitor") else "⬜ нет"}')
    lines.append(f'Создан: {time.strftime("%d.%m.%Y", time.localtime(p.get("created", 0)))}')
    if not p.get('priv'):
        lines.append('<i>Пир добавлен вручную, его конфиг бот выдать не может.</i>')
    if note:
        lines += ['', note]
    t = tag(pub)
    kb = []
    if is_admin(uid):
        if p.get('priv'):
            if p['kind'] == 'mikrotik':
                kb.append([btn('📄 Команды MikroTik', f'wgc:{t}'), btn('📧 На почту', f'wge:{t}')])
                kb.append([btn('⚙️ Настройки MikroTik', f'wgmt:{t}')])
            else:
                kb.append([btn('🔳 QR-код', f'wgq:{t}'), btn('📄 Файл .conf', f'wgf:{t}')])
                kb.append([btn('📧 Отправить на почту', f'wge:{t}')])
        if p['kind'] != 'mikrotik':
            kb.append([btn('⏳ Срок доступа', f'wgx:{t}'), btn('🚦 Лимит трафика', f'wgl:{t}')])
        kb.append([btn('✏️ Переименовать', f'wgr:{t}'),
                   btn('⏸ Выключить' if p['enabled'] else '▶️ Включить', f'wgt:{t}')])
        kb.append([btn(('🔕 Не следить' if p.get('monitor') else '🔔 Следить за связью'), f'wgm:{t}'),
                   btn('🗑 Удалить', f'wgd:{t}')])
    kb.append([btn('🔄 Обновить', f'wgp:{t}'), btn('⬅️ Пиры', 'wg')])
    return '\n'.join(lines), kb


def scr_wg_exp(uid, pub, note=''):
    p = wg_state()['peers'][pub]
    t = tag(pub)
    cur = f'до {fmt_date(p["expires"])}' if p.get('expires') else 'бессрочно'
    text = (f'⏳ <b>Срок доступа: {h(p["name"])}</b>\n\nСейчас: {cur}\n\n'
            'Продление считается от текущей даты окончания (если она в будущем) или от сегодня. '
            'Когда срок закончится, клиент отключится сам, а вам придёт уведомление. '
            'За 3 дня бот предупредит заранее.')
    if note:
        text += '\n\n' + note
    kb = [[btn('+7 дней', f'wgxs:{t}:7'), btn('+1 месяц', f'wgxs:{t}:30'), btn('+3 месяца', f'wgxs:{t}:90')],
          [btn('+1 год', f'wgxs:{t}:365'), btn('📅 До даты…', f'wgxd:{t}')],
          [btn('♾ Бессрочно', f'wgxs:{t}:0')], [btn('⬅️ Назад', f'wgp:{t}')]]
    return text, kb


def scr_wg_lim(uid, pub, note=''):
    p = wg_state()['peers'][pub]
    t = tag(pub)
    u = sum(peer_usage(p)['month'])
    cur = f'{fmt_bytes(p["limit"])} в месяц' if p.get('limit') else 'без лимита'
    text = (f'🚦 <b>Лимит трафика: {h(p["name"])}</b>\n\nСейчас: {cur}\nИспользовано в этом месяце: {fmt_bytes(u)}\n\n'
            'Считается весь трафик клиента (скачал + отправил) с 1-го числа. При исчерпании клиент '
            'отключается до начала следующего месяца, при 80% бот предупредит.')
    if note:
        text += '\n\n' + note
    kb = [[btn(f'{g} ГБ', f'wgls:{t}:{g}') for g in (10, 30, 50)],
          [btn(f'{g} ГБ', f'wgls:{t}:{g}') for g in (100, 300, 1000)],
          [btn('✏️ Своё значение', f'wglc:{t}'), btn('♾ Без лимита', f'wgls:{t}:0')],
          [btn('⬅️ Назад', f'wgp:{t}')]]
    return text, kb


def scr_wg_stat(uid):
    w = wg_state()
    rows = []
    for pub, p in w['peers'].items():
        u = peer_usage(p)
        rows.append((sum(u['month']), p, u))
    rows.sort(key=lambda x: -x[0])
    top = max([r[0] for r in rows] or [1]) or 1
    lines = [f'📊 <b>Статистика клиентов</b> · {datetime.now().strftime("%m.%Y")}', '']
    if not rows:
        lines.append('Клиентов пока нет.')
    total = [0, 0]
    for used, p, u in rows:
        icon = KIND_ICON.get(p['kind'], '📱')
        lim = f' / {fmt_bytes(p["limit"])}' if p.get('limit') else ''
        frac = used / p['limit'] if p.get('limit') else used / top
        lines.append(f'{icon} <b>{h(p["name"])}</b>{"" if p["enabled"] else " ⏸"}')
        lines.append(f'<code>{bar(frac)}</code> {fmt_bytes(used)}{lim} · сегодня {fmt_bytes(sum(u["today"]))}')
        total[0] += u['month'][0]
        total[1] += u['month'][1]
    if rows:
        lines += ['', f'Всего за месяц: ↓ {fmt_bytes(total[0])}  ↑ {fmt_bytes(total[1])}']
    lines.append('<i>Полоса: доля от лимита, а без лимита — от самого активного клиента.</i>')
    return '\n'.join(lines), [[btn('🔄 Обновить', 'wgstat'), btn('⬅️ Пиры', 'wg')]]


def scr_wg_ep(uid, note=''):
    e = wg_eps()
    port = wg_port()
    dom, ip = e.get('domain'), e.get('ip')
    mails = sum(1 for p in wg_state()['peers'].values() if mass_target(p))
    lines = ['🌐 <b>Адрес для подключения</b>', '',
             f'🌐 Домен: ' + (f'<code>{h(dom)}</code> — основной' if dom else '<i>не задан</i>'),
             f'🔢 IP: ' + (f'<code>{h(ip)}</code>' + (' — запасной' if dom else ' — основной') if ip else '<i>не задан</i>'),
             f'🔌 Порт: <code>{port}</code>', '',
             'Эти адреса вписываются в конфиги клиентов. Домен лучше: если провайдер сменит IP или '
             'сработает резервный канал, достаточно поправить запись DNS — конфиги менять не придётся.',
             'Если заданы оба адреса, при выдаче конфига бот спросит, какой вписать.', '',
             '• Клиенты <b>в локальной сети</b>: локальный адрес Ubuntu, например <code>192.168.1.10</code>.',
             '• Клиенты <b>из интернета</b>: внешний IP или домен MikroTik, а на нём проброс UDP-порта на Ubuntu:',
             f'<code>/ip firewall nat add chain=dstnat in-interface-list=WAN protocol=udp dst-port={port} '
             f'action=dst-nat to-addresses={lan_ip() or "IP-шлюза"} to-ports={gw_listen_port()} comment="vpn-gateway wg"</code>',
             '',
             'Уже выданные конфиги сами не меняются: после смены адреса разошлите их заново.']
    if note:
        lines += ['', note]
    kb = [[btn('✏️ Домен', 'wgepd'), btn('✏️ IP', 'wgepi')]]
    if dom:
        kb.append([btn('🔎 Проверить домен', 'wgepc')] + ([btn('🗑 Убрать домен', 'wgepx:d')] if ip else []))
    if ip and dom:
        kb.append([btn('🗑 Убрать IP', 'wgepx:i')])
    if mails:
        kb.append([btn(f'📧 Разослать новые конфиги ({mails})', 'wgepm')])
    kb.append([btn('⬅️ Пиры', 'wg')])
    return '\n'.join(lines), kb


def via_choice(title, cb, back):
    """Экран выбора адреса для конфига. cb — начало callback, к нему добавится :d или :i."""
    e = wg_eps()
    return (f'{title}\n\nКаким адресом клиент будет подключаться?\n\n'
            f'🌐 <b>По домену</b> <code>{h(e["domain"])}</code> — рекомендуется: переживёт смену IP и '
            'переключение на резервного провайдера.\n'
            f'🔢 <b>По IP</b> <code>{h(e["ip"])}</code> — если у клиента не работает DNS или домен ещё не настроен.',
            [[btn('🌐 По домену', f'{cb}:d'), btn('🔢 По IP', f'{cb}:i')], [btn('✖️ Отмена', back)]])


def admin_note(uid, text):
    """Владельцу — о действиях других админов с клиентами."""
    add_event(f'{admin_name(uid)}: {text}')
    if not is_owner(uid):
        notify('actions', f'👤 {h(admin_name(uid))}: {h(text)}', exclude=uid)


def wg_issue(uid, chat, mid, pub, only, t, via=None):
    """Отправить QR/файл в чат, а под ним — свежее меню клиента."""
    wg_send_conf(chat, pub, only, via)
    p = wg_state()['peers'][pub]
    admin_note(uid, f'выдал {"QR-код" if only == "qr" else "конфиг"} клиента «{p["name"]}»')
    note = f'📤 Конфиг выдан с адресом <code>{h(wg_endpoint(via))}</code>.' if both_eps() else ''
    text, kb = scr_wg_peer(uid, pub, note)
    send(chat, text, kb)
    return None


def mass_target(p):
    # MikroTik в локальной сети подключается по адресу Ubuntu — ему смена внешнего адреса не нужна
    return bool(p.get('mail') and p.get('priv')) and not (p['kind'] == 'mikrotik' and (p.get('mt') or {}).get('local'))


def wg_mass(uid, chat, mid, via):
    """Разослать всем клиентам с почтой новые конфиги."""
    todo = [(pub, p) for pub, p in wg_state()['peers'].items() if mass_target(p)]
    ok, bad = [], []
    for i, (pub, p) in enumerate(todo, 1):
        edit(chat, mid, f'📧 Рассылаю конфиги: {i} из {len(todo)}…\n{h(p["name"])} → {h(p["mail"])}')
        try:
            wg_mail(pub, p['mail'], via)
            ok.append(p['name'])
        except Exception as ex:
            bad.append(f'{p["name"]}: {ex}')
    add_event(f'{admin_name(uid)} разослал конфиги WireGuard ({len(ok)} из {len(todo)}), адрес {wg_endpoint(via)}')
    note = f'📧 Отправлено {len(ok)} из {len(todo)} с адресом <code>{h(wg_endpoint(via))}</code>.'
    if bad:
        note += '\n🔴 Не ушло: ' + h('; '.join(bad))[:600]
    return scr_wg_ep(uid, note)


SCREENS = {'menu': scr_menu, 'status': scr_status, 'servers': scr_servers, 'traffic': scr_traffic,
           'manage': scr_manage, 'notif': scr_notif, 'admins': scr_admins, 'log': scr_log,
           'set': scr_settings, 'em': scr_email, 'subs': scr_subs, 'srv': scr_srv,
           'srvthr': scr_srv_thr, 'vs': scr_vs, 'bk': scr_bk, 'cl': scr_clean, 'wg': scr_wg, 'wgep': scr_wg_ep, 'wgstat': scr_wg_stat, 'swr': scr_sw_route, 'swl': scr_sw_list, 'swe': scr_sw_exc, 'svs': scr_svc, 'sw': scr_sw, 'sws': scr_sw_srv, 'swp': scr_sw_prio,
           'swi': lambda uid: scr_sw_choice(uid, 'i'), 'swt': lambda uid: scr_sw_choice(uid, 't')}
# клиентами WireGuard управляют все админы; общие настройки шлюза — только владелец
OWNER_ONLY = ('vs', 'bk', 'svc:', 'svcs:', 'admins', 'em', 'adm:', 'wgep',
              'upd:', 'subs', 'sub:', 'srvthr', 'srvt:', 'srvclean')

CONFIRM = {
    'mihomo': ('♻️ <b>Перезапустить mihomo?</b>\n\nVPN прервётся на 5–10 секунд, '
               'активные соединения оборвутся.', False),
    'wg': ('🔌 <b>Перезапустить WireGuard?</b>\n\nТуннели клиентов и MikroTik пропадут на несколько секунд, '
           'клиенты на это время потеряют связь.', False),
    'reboot': ('🖥 <b>Перезагрузить сервер?</b>\n\nVPN будет недоступен 1–2 минуты, '
               'клиенты на это время останутся без VPN.', True),
}
UNITS = {'mihomo': ('mihomo', 'mihomo'), 'wg': ('wg-quick@' + WG_IF, 'WireGuard')}


# ---------------- действия ----------------
def speed_test(url, opener, nbytes=SPEED_BYTES, limit=20):
    req = urllib.request.Request(url, headers={'Range': f'bytes=0-{nbytes - 1}', 'User-Agent': 'curl/8.5'})
    t0 = time.time()
    n = 0
    with opener.open(req, timeout=30) as r:
        while n < nbytes and time.time() - t0 < limit:
            chunk = r.read(262144)
            if not chunk:
                break
            n += len(chunk)
    return n, max(time.time() - t0, 0.001)


def direct_test_url():
    # российское зеркало: скорость канала провайдера без VPN и без замедлений зарубежных направлений
    for base in ('https://mirror.yandex.ru/ubuntu-releases/24.04/', 'https://mirror.selectel.ru/ubuntu-releases/24.04/'):
        try:
            with direct_opener.open(urllib.request.Request(base, headers={'User-Agent': 'curl/8.5'}), timeout=10) as r:
                m = re.search(r'ubuntu-24\.04[\d.]*-live-server-amd64\.iso', r.read().decode('utf-8', 'ignore'))
            if m:
                return base + m.group(0)
        except Exception as e:
            log('speed mirror', base, e)
    return None


# ---------------- настоящий пинг ----------------
PING_N = 10
PING_HOST = 'cp.cloudflare.com'      # отвечает 204 и держит keep-alive


def link_server(link):
    """(имя, сервер) из ссылки vless/trojan/ss/hysteria/vmess."""
    link = link.strip()
    if link.startswith('vmess://'):
        try:
            raw = link[8:]
            j = json.loads(base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', 'ignore'))
            return j.get('ps', ''), j.get('add', '')
        except Exception:
            return None
    if '://' not in link:
        return None
    try:
        u = urllib.parse.urlsplit(link)
        return urllib.parse.unquote(u.fragment), u.hostname or ''
    except Exception:
        return None


def server_addr(name):
    """Адрес сервера подписки по имени — из файла провайдера mihomo."""
    for sb in subs():
        nm = name
        if sb.get('prefix') and nm.startswith(sb['prefix']):
            nm = nm[len(sb['prefix']):]
        try:
            text = open(os.path.join(PROV_DIR, sb['id'] + '.yaml'), encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        if re.search(r'^proxies:', text, re.M):
            body = text.split('proxies:', 1)[1]
            for chunk in re.split(r'\n\s*-\s+(?=\{|name|["\']name)', '\n' + body):
                m = re.search(r'["\']?name["\']?\s*:\s*["\']?(.+?)["\']?\s*(?:,|\n|$)', chunk)
                if m and m.group(1).strip() == nm:
                    s = re.search(r'["\']?server["\']?\s*:\s*["\']?([A-Za-z0-9.:\[\]-]+)', chunk)
                    if s:
                        return s.group(1).strip('[]')
            continue
        raw = text.strip()
        if '://' not in raw:
            try:
                raw = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', 'ignore')
            except Exception:
                continue
        for line in re.split(r'\s+', raw):
            r = link_server(line)
            if r and r[0] == nm and r[1]:
                return r[1]
    return None


def ping_icmp(host, n=PING_N):
    """→ список RTT в мс (None — потеря) или None, если ICMP не проходит совсем."""
    try:
        r = subprocess.run(['ping', '-n', '-c', str(n), '-i', '0.3', '-W', '2', host],
                           capture_output=True, text=True, timeout=n * 2.5 + 10)
    except Exception:
        return None
    got = {int(m.group(1)): float(m.group(2)) for m in re.finditer(r'icmp_seq=(\d+).*?time=([\d.]+)', r.stdout)}
    if not got:
        return None
    return [got.get(i) for i in range(1, n + 1)]


def ping_http(host, proxy=None, n=PING_N, info=None):
    """RTT по одному TCP-соединению (keep-alive): каждый запрос — один круг до сервера и обратно.
    proxy — (адрес, порт) HTTP-прокси mihomo: тогда замер идёт через VPN.
    info — словарь: туда кладётся цепочка mihomo (через какой сервер реально пошло соединение)."""
    out = []
    s = None
    try:
        if proxy:
            s = socket.create_connection(proxy, timeout=10)
            s.sendall(f'CONNECT {host}:80 HTTP/1.1\r\nHost: {host}:80\r\n\r\n'.encode())
            if b' 200' not in http_head(s).split(b'\r\n', 1)[0]:
                raise RuntimeError('прокси не открыл соединение')
        else:
            s = socket.create_connection((host, 80), timeout=10)
        s.settimeout(3)
        req = (f'HEAD /generate_204 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5\r\n'
               'Connection: keep-alive\r\n\r\n').encode()
        s.sendall(req)                      # прогрев: первый запрос дольше (DNS, рукопожатия)
        http_head(s)
        if proxy and info is not None:
            info['chain'] = conn_chain(host)
        for _ in range(n):
            t0 = time.time()
            try:
                s.sendall(req)
                http_head(s)
                out.append((time.time() - t0) * 1000)
            except Exception:
                out.append(None)
                break
            time.sleep(0.2)
    finally:
        if s:
            s.close()
    out += [None] * (n - len(out))
    return out


def conn_chain(host):
    """Цепочка mihomo для открытого соединения с host: ['🇳🇱 NL', 'AUTO', 'PROXY'] или ['DIRECT']."""
    try:
        for c in (api('/connections') or {}).get('connections') or []:
            if (c.get('metadata') or {}).get('host') == host:
                return c.get('chains') or []
    except Exception:
        pass
    return None


def http_head(s):
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError('соединение закрыто')
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


def ping_stats(rtts):
    ok = [x for x in rtts if x is not None]
    loss = round(100 * (len(rtts) - len(ok)) / max(len(rtts), 1))
    if not ok:
        return f'нет ответа (потери {loss}%)'
    jit = sum(abs(a - b) for a, b in zip(ok, ok[1:])) / max(len(ok) - 1, 1)
    return f'{min(ok):.0f} / {sum(ok) / len(ok):.0f} / {jit:.0f} мс · потери {loss}%'


def flow_ping(cur):
    """Три замера: до VPN-сервера (ICMP), через VPN (до Google), напрямую (Яндекс)."""
    res = []
    addr = server_addr(cur) if cur and cur != '?' else None
    if addr:
        r = ping_icmp(addr)
        res.append(('🛰 До VPN-сервера', ping_stats(r) if r else 'ICMP закрыт на сервере',
                    f'{h(addr)}, ICMP напрямую'))
    else:
        res.append(('🛰 До VPN-сервера', 'адрес сервера не найден', ''))
    try:
        info = {}
        st = ping_stats(ping_http(PING_HOST, ('127.0.0.1', int(PROXY_URL.rsplit(':', 1)[1])), info=info))
        ch = info.get('chain')
        if ch and ch[0] == 'DIRECT':
            src = '⚠️ соединение пошло напрямую, а не через VPN — нажмите «Применить» в ⚙️ Настройки → Маршрутизация'
        else:
            src = f'сервер {h(ch[0] if ch else cur)} → Cloudflare'
        res.append(('🔒 Через VPN', st, src))
    except Exception as ex:
        res.append(('🔒 Через VPN', f'ошибка ({h(str(ex))[:60]})', ''))
    r = ping_icmp('77.88.8.8')
    if r:
        res.append(('🏠 Напрямую', ping_stats(r), 'Яндекс, ICMP'))
    else:
        try:
            res.append(('🏠 Напрямую', ping_stats(ping_http('ya.ru')), 'Яндекс, TCP'))
        except Exception as ex:
            res.append(('🏠 Напрямую', f'ошибка ({h(str(ex))[:60]})', ''))
    return res


# ---------------- «🔎 Куда идёт сайт» ----------------
SITE_TO = 10
site_last = {}          # uid → последний проверенный адрес (для кнопок «всегда через VPN / напрямую»)
RULE_RU = {
    ('GeoSite', 'ru-blocked'): 'в списке заблокированных в РФ',
    ('GeoIP', 'ru-blocked'): 'IP из списка заблокированных в РФ',
    ('GeoSite', 'category-ai-ru'): 'российский ИИ-сервис',
    ('GeoSite', 'category-ai-!cn'): 'зарубежный ИИ-сервис',
    ('GeoSite', 'ru-available-only-inside'): 'сайт работает только из России',
    ('GeoSite', 'category-ru'): 'российский сервис',
    ('GeoIP', 'RU'): 'сервер сайта находится в России',
    ('DomainSuffix', 'ru'): 'российский домен .ru',
    ('DomainSuffix', 'xn--p1ai'): 'российский домен .рф',
    ('DomainSuffix', 'su'): 'домен .su',
}


def proxy_port():
    return int(PROXY_URL.rsplit(':', 1)[1])


def site_host(text):
    t = text.strip()
    if '://' not in t:
        t = 'https://' + t
    try:
        u = urllib.parse.urlsplit(t)
        host = (u.hostname or '').rstrip('.').lower()
        host = host.encode('idna').decode()
        port = u.port or (80 if u.scheme == 'http' else 443)
    except Exception:
        return None, None
    if not re.match(r'^(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$', host) and not IP_RE.match(host):
        return None, None
    return host, port


def rule_text(rule, payload, chains):
    v = vpn()
    if rule in ('DomainSuffix', 'IPCIDR', 'Domain') and payload:
        p = payload.split('/')[0] if rule == 'IPCIDR' else payload
        if any(x == payload or x.split('/')[0] == p for x in v.get('rules_proxy', [])):
            return f'ваше исключение «всегда через VPN»: {payload}'
        if any(x == payload or x.split('/')[0] == p for x in v.get('rules_direct', [])):
            return f'ваше исключение «всегда напрямую»: {payload}'
    if rule == 'IPCIDR':
        try:
            if any(ipaddress.ip_network(payload).subnet_of(n) for n in PRIVATE + [ipaddress.ip_network('100.64.0.0/10')]):
                return 'локальная сеть'
        except ValueError:
            pass
    if any(c.startswith('VIA-') for c in chains or []):
        pid = next(c for c in chains if c.startswith('VIA-'))[4:]
        sb = sub_by_id(pid)
        return f'сервис через подписку «{sb["name"] if sb else pid}» ({rule} {payload})'
    if rule == 'Match':
        return 'всё остальное (правило по умолчанию)'
    return RULE_RU.get((rule, payload)) or f'{rule} {payload}'.strip()


def mihomo_dial_error(host, sport):
    """Если mihomo не смог соединиться, правило есть только в его журнале."""
    r = run(['journalctl', '-u', 'mihomo', '--since', '-2min', '-o', 'cat', '--no-pager'], 15)
    for line in reversed((r.stdout or '').splitlines()):
        m = re.search(r'dial (\S+) \(match ([^/)]*)/?([^)]*)\) [\d.]+:(\d+) --> ([^:\s]+):\d+ error: (.*?)"?$', line)
        if m and m.group(5) == host and (not sport or int(m.group(4)) == sport):
            return {'chain': m.group(1), 'rule': m.group(2), 'payload': m.group(3), 'err': m.group(6)}
    return None


def https_probe(sock, host, path='/'):
    """TLS с проверкой сертификата и HEAD-запрос поверх уже открытого соединения → код ответа"""
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(sock, server_hostname=host)
    ss.sendall(f'HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {CHROME_UA}\r\nAccept: */*\r\n'
               'Connection: close\r\n\r\n'.encode())
    line = http_head(ss).split(b'\r\n', 1)[0].decode('latin-1', 'ignore')
    m = re.match(r'HTTP/\S+ (\d{3})', line)
    return int(m.group(1)) if m else 0


def probe_err(ex):
    e = str(ex)
    if isinstance(ex, ssl.SSLCertVerificationError) or 'CERTIFICATE_VERIFY_FAILED' in e:
        return 'подменён сертификат (похоже на заглушку провайдера)'
    if isinstance(ex, (socket.timeout, TimeoutError)) or 'timed out' in e:
        return 'нет ответа (таймаут)'
    if isinstance(ex, ConnectionResetError) or 'reset' in e.lower():
        return 'соединение сброшено (похоже на блокировку)'
    if 'Name or service not known' in e or 'getaddrinfo' in e or 'nodename' in e:
        return 'адрес не находится в DNS'
    if 'refused' in e.lower():
        return 'соединение отклонено'
    if 'EOF' in e or 'eof' in e:
        return 'соединение оборвалось'
    return e[:120]


def site_conn(host, sport, wait=1.5):
    """Соединение в mihomo по нашему исходному порту: правило и цепочка (mihomo регистрирует его не сразу)."""
    t_end = time.time() + wait
    while True:
        for c in (api('/connections') or {}).get('connections') or []:
            md = c.get('metadata') or {}
            if md.get('host') == host and str(md.get('sourcePort')) == str(sport):
                return c
        if time.time() >= t_end:
            return None
        time.sleep(0.15)


def site_via_gateway(host, port):
    """Как пойдёт клиент: через mihomo, по тем же правилам."""
    res = {'rule': None, 'payload': '', 'chains': [], 'code': None, 'err': '', 'ms': None}
    s = None
    sport = 0
    t0 = time.time()
    try:
        s = socket.create_connection(('127.0.0.1', proxy_port()), timeout=SITE_TO)
        s.settimeout(SITE_TO)
        sport = s.getsockname()[1]
        s.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'.encode())
        head = http_head(s).split(b'\r\n', 1)[0]
        c = site_conn(host, sport)
        if c:
            res.update(rule=c.get('rule'), payload=c.get('rulePayload', ''), chains=c.get('chains') or [])
        if b' 200' not in head:
            raise RuntimeError('шлюз не смог открыть соединение')
        res['code'] = https_probe(s, host) if port == 443 else 0
        res['ms'] = (time.time() - t0) * 1000
    except Exception as ex:
        res['err'] = probe_err(ex)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    if not res['rule'] or res['err']:
        time.sleep(0.3)
        d = mihomo_dial_error(host, sport)
        if d:       # mihomo отвечает «200» ещё до соединения, настоящая причина — в его журнале
            if not res['rule']:
                res.update(rule=d['rule'], payload=d['payload'], chains=[d['chain']])
            res['code'] = None
            res['err'] = ('напрямую: ' if d['chain'] == 'DIRECT' else 'VPN-сервер не смог открыть сайт: ') \
                + dial_err_text(d['err'])
    return res


def dial_err_text(e):
    low = e.lower()
    for pat, txt in (('i/o timeout', 'нет ответа'), ('timeout', 'нет ответа'), ('deadline exceeded', 'нет ответа'),
                     ('refused', 'соединение отклонено'), ('no such host', 'адрес не находится в DNS'),
                     ("couldn't find ip", 'адрес не находится в DNS'), ('dns resolve failed', 'не удалось узнать адрес (DNS)'),
                     ('reset', 'соединение сброшено'),
                     ('network is unreachable', 'сеть недоступна'), ('eof', 'соединение оборвалось')):
        if pat in low:
            return txt
    return e[-120:]


def site_direct(host, port):
    """Напрямую с сервера, мимо VPN: открывается ли сайт у провайдера."""
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((host, port), timeout=8)
        s.settimeout(8)
        code = https_probe(s, host) if port == 443 else 0
        return {'code': code, 'ms': (time.time() - t0) * 1000, 'err': ''}
    except Exception as ex:
        return {'code': None, 'ms': None, 'err': probe_err(ex)}
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def site_ips(host):
    try:
        d = api(f'/dns/query?name={q(host)}&type=A', timeout=8) or {}
        return [a.get('data') for a in d.get('Answer') or [] if a.get('type') == 1][:4]
    except Exception:
        return []


def fmt_probe(r):
    if r.get('code'):
        return f'✅ открывается (ответ {r["code"]}, {r["ms"] / 1000:.1f} с)'
    if r.get('code') == 0 and not r.get('err'):
        return f'✅ соединение есть ({r["ms"] / 1000:.1f} с)'
    return f'🔴 {h(r.get("err") or "не открывается")}'


def site_check(uid, host, port):
    via = site_via_gateway(host, port)
    direct = site_direct(host, port)
    ips = site_ips(host)
    chains = via['chains'] or []
    is_direct = chains[:1] == ['DIRECT']
    lines = [f'🔎 <b>{h(host)}</b>' + (f':{port}' if port not in (80, 443) else ''), '']
    if via['rule']:
        lines.append(f'🧭 Правило: {h(rule_text(via["rule"], via["payload"], chains))}')
        srv = chains[0] if chains else '?'
        if srv in (SELECT_GROUP, AUTO_GROUP) or srv.startswith(('SUB-', 'VIA-')):
            try:
                srv = mode_and_current()[1]
            except Exception:
                pass
        lines.append('➡️ Идёт: ' + ('🏠 <b>напрямую</b>' if is_direct else f'🔒 <b>через VPN</b>, сервер {h(srv)}'))
    else:
        lines.append('🧭 Правило определить не удалось (mihomo не ответил).')
    lines.append('')
    lines.append(f'{"🏠" if is_direct else "🔒"} Как откроют клиенты: {fmt_probe(via)}')
    if not is_direct:
        lines.append(f'🏠 Напрямую, мимо VPN: {fmt_probe(direct)}')
    if ips:
        lines.append(f'🌐 DNS шлюза: <code>{h(", ".join(ips))}</code>')
    lines.append('')
    ok_via = bool(via.get('code')) or (via.get('code') == 0 and not via.get('err'))
    ok_dir = bool(direct.get('code')) or (direct.get('code') == 0 and not direct.get('err'))
    if ok_via:
        lines.append('✅ Всё в порядке.' + ('' if is_direct or not ok_dir or via['rule'] != 'Match' else
                     ' Напрямую сайт тоже открывается — если ему нужен российский IP (банк, госсервис, '
                     'стриминг), добавьте «Всегда напрямую».'))
    elif is_direct:
        lines.append('⚠️ Сайт должен идти напрямую, но напрямую не открывается. Если он заблокирован или '
                     'замедлен — добавьте «🔒 Всегда через VPN».')
    elif ok_dir:
        lines.append('⚠️ Через VPN не открывается, а напрямую — да. Похоже, сайт не пускает зарубежные IP: '
                     'добавьте «🏠 Всегда напрямую».')
    else:
        lines.append('🔴 Не открывается ни через VPN, ни напрямую: возможно, сайт сейчас не работает или '
                     'недоступен VPN-сервер (проверьте 🌍 Серверы).')
    site_last[uid] = host
    kb = [[btn('🔒 Всегда через VPN', 'site:p'), btn('🏠 Всегда напрямую', 'site:d')],
          [btn('🔎 Другой сайт', 'site'), btn('⬅️ Маршрутизация', 'swr')]]
    return '\n'.join(lines), kb


def site_prompt(uid):
    awaiting[uid] = ('site', None)
    return ('🔎 <b>Куда идёт сайт</b>\n\nОтправьте адрес сайта или ссылку, например <code>youtube.com</code> или '
            '<code>https://www.gosuslugi.ru/</code>.\n\nБот покажет, по какому правилу и через какой сервер его '
            'откроют клиенты, и проверит, открывается ли он через VPN и напрямую.\n\nОтмена: /cancel',
            [[btn('✖️ Отмена', 'swr')]])


def handle_site(uid, data, chat, mid):
    act = data.split(':')[1] if ':' in data else ''
    if act in ('p', 'd'):
        host = site_last.get(uid)
        t = norm_target(host or '')
        if not t:
            return site_prompt(uid)
        v = vpn()
        key, other = ('rules_proxy', 'rules_direct') if act == 'p' else ('rules_direct', 'rules_proxy')
        with lock:
            if t in v[other]:
                v[other].remove(t)
            if t not in v[key]:
                v[key].append(t)
            save_state()
        add_event(f'{admin_name(uid)} добавил исключение: {t} — ' + ('через VPN' if act == 'p' else 'напрямую'))
        return scr_sw_exc(uid, f'✅ <code>{h(t)}</code> — ' + ('всегда через VPN' if act == 'p' else 'всегда напрямую')
                          + '.\nНажмите «Применить», чтобы заработало (VPN прервётся на 5–10 секунд).')
    return site_prompt(uid)


def handle_site_input(uid, chat, text):
    host, port = site_host(text)
    if not host:
        send(chat, 'Не понял адрес. Пример: <code>youtube.com</code>. Ещё раз или /cancel.')
        return
    awaiting.pop(uid, None)
    r = send(chat, f'🔎 Проверяю <b>{h(host)}</b>: правило, путь, доступность через VPN и напрямую (до 30 секунд)…')
    try:
        t, kb = site_check(uid, host, port)
    except Exception as ex:
        log('site_check:', traceback.format_exc())
        t, kb = f'⚠️ Ошибка проверки: <code>{h(str(ex))[:200]}</code>', [[btn('⬅️ Маршрутизация', 'swr')]]
    if r:
        edit(chat, r['message_id'], t, kb)
    else:
        send(chat, t, kb)


def flow_speed(chat, mid):
    kb = [[btn('🔁 Ещё раз', 'speed'), btn('🏠 Меню', 'menu')]]
    if not speed_lock.acquire(blocking=False):
        edit(chat, mid, '⚡ Тест уже идёт, подождите немного.', kb)
        return
    try:
        try:
            _, cur = mode_and_current()
        except Exception:
            cur = '?'
        res = {}
        steps = [('vpn', '🔒 Через VPN', SPEED_URL, proxy_opener, f'сервер {h(cur)}, файл с Hetzner (Германия)'),
                 ('direct', '🏠 Без VPN (канал провайдера)', None, direct_opener, 'зеркало Яндекса, Россия')]
        head = '⚡ <b>Тест скорости</b>\n\n'
        edit(chat, mid, head + '⏳ 📶 Пинг: 10 замеров в каждую сторону…')
        try:
            pings = flow_ping(cur)
        except Exception as ex:
            log('ping:', traceback.format_exc())
            pings = [('📶 Пинг', f'ошибка ({h(str(ex))[:80]})', '')]
        ptxt = ('📶 <b>Пинг</b> <i>(мин / средн / джиттер)</i>\n'
                + '\n'.join(f'{t}: <b>{v}</b>' + (f'\n<i>{src}</i>' if src else '') for t, v, src in pings))
        for key, title, url, opener, src in steps:
            body = '\n'.join(f'{t}: <b>{res[k]}</b>' for k, t, *_ in steps if k in res)
            edit(chat, mid, f'{head}{ptxt}\n\n{body}\n⏳ {title}…')
            try:
                url = url or direct_test_url()
                if not url:
                    raise RuntimeError('зеркало недоступно')
                n, dt = speed_test(url, opener)
                res[key] = f'{fmt_mbit(n / dt)}'
            except Exception as e:
                res[key] = f'ошибка ({h(str(e))[:80]})'
        lines = ['⚡ <b>Тест скорости</b>', '', ptxt, '', '🚀 <b>Скорость загрузки</b>']
        for key, title, _, _, src in steps:
            lines.append(f'{title}: <b>{res[key]}</b>\n<i>{src}</i>')
        lines += ['', '<i>Если через VPN заметно медленнее, чем без него, попробуйте другой сервер в 🌍 Серверы. '
                      'Джиттер — насколько скачет пинг: для звонков и игр лучше до 20 мс.</i>']
        text = '\n'.join(lines)
    finally:
        speed_lock.release()
    edit(chat, mid, text, kb)


def grant_access(aid, name, by_uid):
    with lock:
        state['admins'][str(aid)] = {'name': name, 'notify': default_notify()}
        state['pending'].pop(str(aid), None)
        save_state()
    add_event(f'{admin_name(by_uid)} добавил администратора {name}')
    return send(int(aid), '✅ Вам выдан доступ к VPN-боту. Нажмите /start')


def handle_access_request(cq, uid, data, chat, mid):
    if not is_owner(uid):
        tg('answerCallbackQuery', callback_query_id=cq['id'], text='Только для владельца')
        return
    tg('answerCallbackQuery', callback_query_id=cq['id'])
    aid = data[4:]
    with lock:
        req = state['pending'].pop(aid, None)
        save_state()
    name = req['name'] if req else aid
    if data.startswith('acc:'):
        grant_access(aid, name, uid)
        edit(chat, mid, f'✅ Доступ выдан: {h(name)}')
    else:
        with lock:
            state['rejected'][aid] = time.time()
            save_state()
        edit(chat, mid, f'❌ Запрос отклонён: {h(name)} (повторные запросы 24 часа игнорируются)')


def handle_sw(uid, data, chat, mid):
    v = vpn()
    who = admin_name(uid)
    if data.startswith('swm:'):
        m = data[4:]
        with lock:
            if m in PRESETS:
                v['mode'] = m
                v['interval'], v['tolerance'] = PRESETS[m]
            elif m == 'priority':
                v['mode'] = 'priority'
            v['manual'] = False
            save_state()
        last_manual[0] = time.time()
        if m == 'priority':
            prio_tick(force=True)
        else:
            api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': AUTO_GROUP})
        add_event(f'{who}: режим переключения «{MODES[v["mode"]]}»')
        return scr_sw(uid, '✅ Режим выбран' + ('. Нажмите «Применить», чтобы новые значения заработали.'
                                                if vpn_dirty(v) else ''))
    if data.startswith(('swi:', 'swt:')):
        val = int(data[4:])
        with lock:
            v['interval' if data[2] == 'i' else 'tolerance'] = val
            v['mode'] = detect_mode(v)
            save_state()
        return scr_sw(uid)
    if data.startswith('swea:'):
        awaiting[uid] = ('rule_add', 'rules_direct' if data[5:] == 'd' else 'rules_proxy')
        where = 'напрямую' if data[5:] == 'd' else 'через VPN'
        return (f'➕ <b>Всегда {where}</b>\n\nОтправьте домен, ссылку или IP. Можно несколько через пробел, например:\n'
                '<code>sberbank.ru gosuslugi.ru 5.255.255.0/24</code>\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'swe')]])
    if data.startswith('swed:'):
        _, out, t = data.split(':', 2)
        key = 'rules_direct' if out == 'd' else 'rules_proxy'
        with lock:
            v[key] = [x for x in v.get(key, []) if tag(x) != t]
            save_state()
        return scr_sw_exc(uid, '🗑 Удалено')
    if data.startswith('swl:'):
        k = data[4:]
        with lock:
            cur = list(v.get('list_svc', LIST_DEFAULT))
            if k == '+all':
                cur = list(LIST_CATALOG)
            elif k == '+def':
                cur = list(LIST_DEFAULT)
            elif k in LIST_CATALOG:
                cur = [x for x in cur if x != k] if k in cur else cur + [k]
            v['list_svc'] = [x for x in LIST_CATALOG if x in cur]
            save_state()
        return scr_sw_list(uid)
    if data.startswith('swr:'):
        with lock:
            v['routing'] = data[4:] if data[4:] in ROUTING else 'all'
            save_state()
        return scr_sw_route(uid)
    if data.startswith('swx:'):
        names = [p['name'] for p in servers()]
        name = next((n for n in names if tag(n) == data[4:]), None)
        if name:
            with lock:
                if name in v['excluded']:
                    v['excluded'].remove(name)
                elif len([n for n in names if n not in v['excluded']]) > 1:
                    v['excluded'].append(name)
                else:
                    return scr_sw_srv(uid, '⚠️ Хотя бы один сервер должен остаться в автовыборе.')
                save_state()
        return scr_sw_srv(uid)
    if data.startswith(('swu:', 'swtop:')):
        order = prio_order(v, servers())
        t = data.split(':', 1)[1]
        name = next((n for n in order if tag(n) == t), None)
        if name:
            i = order.index(name)
            order.pop(i)
            order.insert(0 if data.startswith('swtop:') else max(i - 1, 0), name)
            with lock:
                v['priority'] = order
                save_state()
            prio_tick()
        return scr_sw_prio(uid)
    back = {'r': scr_sw_route, 'e': scr_sw_exc, 's': scr_svc, 'l': scr_sw_list}.get(data.rsplit(':', 1)[-1] if ':' in data else '', scr_sw)
    if data.startswith('swapply'):
        edit(chat, mid, '⏳ Применяю настройки, VPN прервётся на 5–10 секунд…')
        try:
            apply_vpn_config(v)
            time.sleep(5)
            if v['mode'] == 'priority' and not v['manual']:
                prio_tick(force=True)
            add_event(f'{who} применил настройки VPN ({MODES[v["mode"]]}, {ROUTING[v["routing"]][0]})')
            notify('actions', f'👤 {h(who)} изменил настройки VPN: {MODES[v["mode"]]}, '
                              f'{ROUTING[v["routing"]][0]}', exclude=uid)
            return back(uid, '✅ Настройки применены')
        except Exception as ex:
            return back(uid, f'🔴 Не удалось применить: <code>{h(str(ex))[:300]}</code>')
    if data.startswith('swreset'):
        a = v.get('applied') or {}
        with lock:
            v['interval'] = a.get('interval', v['interval'])
            v['tolerance'] = a.get('tolerance', v['tolerance'])
            v['excluded'] = list(a.get('excluded', v['excluded']))
            v['routing'] = a.get('routing', v.get('routing', 'all'))
            v['rules_direct'] = list(a.get('rules_direct', v.get('rules_direct', [])))
            v['rules_proxy'] = list(a.get('rules_proxy', v.get('rules_proxy', [])))
            v['svc'] = dict(a.get('svc', v.get('svc', {})))
            v['list_svc'] = list(a.get('list_svc', v.get('list_svc', LIST_DEFAULT)))
            v['mode'] = a.get('mode') or detect_mode(v)
            v['mode'] = 'priority' if v['mode'] == 'priority' else detect_mode(dict(v, mode=''))
            save_state()
        if v['mode'] == 'priority':
            prio_tick(force=True)
        elif not v['manual']:
            api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': AUTO_GROUP})
        return back(uid, '↩️ Изменения отменены' + (
            '' if not vpn_dirty(v) else '. Остался только переход конфига на новый формат — нажмите «Применить».'))
    return scr_sw(uid)


def handle_wg(uid, data, chat, mid):
    w = wg_state()
    who = admin_name(uid)
    cmd, _, arg = data.partition(':')
    if cmd == 'wg':
        return scr_wg(uid, page=int(arg or 0))
    if cmd in ('wgepd', 'wgepi'):
        d = cmd == 'wgepd'
        awaiting[uid] = ('wg_ep', 'd' if d else 'i')
        return (('✏️ <b>Домен для подключения</b>\n\nОтправьте имя, например <code>vpn.example.ru</code> или '
                 'DDNS MikroTik <code>xxxx.sn.mynetname.net</code>. Можно с портом: <code>vpn.example.ru:51820</code>.'
                 if d else
                 '✏️ <b>IP для подключения</b>\n\nОтправьте внешний IP, например <code>203.0.113.10</code>, '
                 'или локальный <code>192.168.1.10</code>. Можно с портом.') + '\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'wgep')]])
    if cmd == 'wgepx':
        wg_set_ep(arg, '')
        add_event(f'{who} убрал ' + ('домен' if arg == 'd' else 'IP') + ' для WireGuard')
        return scr_wg_ep(uid, '🗑 Убрано')
    if cmd == 'wgepc':
        edit(chat, mid, '🔎 Проверяю домен…')
        return scr_wg_ep(uid, check_domain(wg_eps().get('domain') or '')[1])
    if cmd == 'wgepm':
        n = sum(1 for p in w['peers'].values() if mass_target(p))
        if arg in ('d', 'i') or not both_eps():
            v = arg if arg in ('d', 'i') else ''
            return (f'📧 <b>Разослать новые конфиги?</b>\n\n{n} клиентам с сохранённой почтой придёт письмо с '
                    f'новым файлом и QR-кодом, адрес <code>{h(wg_endpoint(v or None))}</code>.\n'
                    'Ключи не меняются: старые конфиги продолжат работать, пока адрес доступен.',
                    [[btn('✅ Разослать', f'wgepmg:{v}'), btn('✖️ Отмена', 'wgep')]])
        return via_choice('📧 <b>Разослать новые конфиги</b>', 'wgepm', 'wgep')
    if cmd == 'wgepmg':
        return wg_mass(uid, chat, mid, arg or None)
    if cmd == 'wgadd':
        if arg not in KIND_RU:
            arg = 'phone'
        awaiting[uid] = ('wg_name', arg)
        ex = {'mikrotik': 'MikroTik дача', 'phone': 'Телефон Ивана', 'pc': 'Ноутбук Маши'}.get(arg, 'Телефон')
        return (f'➕ <b>Новый пир: {KIND_RU[arg]}</b>\n\nКак его назвать? Например: <code>{ex}</code>'
                + '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'wg')]])
    pub = peer_by_tag(arg.split(":")[0])
    if not pub:
        return scr_wg(uid, '⚠️ Пир не найден, список обновлён.')
    p = w['peers'][pub]
    if cmd == 'wgp':
        return scr_wg_peer(uid, pub)
    if cmd == 'wgmt' and p['kind'] == 'mikrotik' and p.get('priv'):
        ctx = mt_defaults(p['name'], pub)
        ctx['step'] = None
        awaiting[uid] = ('mt', ctx)
        return scr_mt(uid, ctx)
    t = tag(pub)
    via = arg.split(':')[1] if arg.count(':') else None
    fixed = p['kind'] == 'mikrotik' and ((p.get('mt') or {}).get('local') or (p.get('mt') or {}).get('via'))
    if cmd in ('wgc', 'wgq', 'wgf', 'wge', 'wges') and via is None and both_eps() and p.get('priv') and not fixed:
        what = {'wgq': 'QR-код', 'wgf': 'файл .conf', 'wgc': 'команды MikroTik'}.get(cmd, 'письмо с настройками')
        return via_choice(f'{KIND_ICON.get(p["kind"], "📱")} <b>{h(p["name"])}</b>: {what}', f'{cmd}:{t}', f'wgp:{t}')
    if cmd in ('wgc', 'wgq', 'wgf'):
        # файл — ниже, а свежее меню — уже под файлом (старое удаляется)
        return wg_issue(uid, chat, mid, pub, {'wgq': 'qr', 'wgf': 'file'}.get(cmd), t, via)
    if cmd in ('wge', 'wges'):
        e = email_cfg()
        if not p.get('priv'):
            return scr_wg_peer(uid, pub, '⚠️ Пир добавлен вручную, его конфиг бот выдать не может.')
        if not e['smtp'].get('host'):
            if not is_owner(uid):
                return scr_wg_peer(uid, pub, '📧 Почта для отправки ещё не настроена — попросите владельца бота '
                                             '(⚙️ Настройки → 📧 Почта).')
            return ('📧 <b>Почта ещё не настроена</b>\n\nЧтобы отправлять конфиги на почту, укажите ящик-отправитель: '
                    '⚙️ Настройки → 📧 Почта. Подойдут Яндекс, Mail.ru, Gmail или свой сервер.',
                    [[btn('📧 Настроить почту', 'em')], [btn('⬅️ Назад', f'wgp:{arg}')]])
        if cmd == 'wges' and p.get('mail'):
            edit(chat, mid, f'📧 Отправляю на {h(p["mail"])}…')
            return scr_wg_peer(uid, pub, wg_mail_send(uid, pub, p['mail'], via))
        awaiting[uid] = ('wg_mail', (pub, via))
        kb = [[btn(f'📨 {p["mail"]}'[:40], f'wges:{t}' + (f':{via}' if via else ''))]] if p.get('mail') else []
        kb.append([btn('✖️ Отмена', f'wgp:{t}')])
        return (f'📧 <b>Отправить «{h(p["name"])}» на почту</b>\n\nОтправьте адрес почты получателя. Ему придёт '
                'письмо с файлом настроек, QR-кодом и инструкцией для телефона и компьютера.'
                + (f'\n\nИли нажмите, чтобы отправить на прежний адрес.' if p.get('mail') else '')
                + '\n\nОтмена: /cancel', kb)
    if cmd == 'wgr':
        awaiting[uid] = ('wg_rename', pub)
        return (f'✏️ Новое имя для «{h(p["name"])}»?\n\nОтмена: /cancel', [[btn('✖️ Отмена', f'wgp:{arg}')]])
    if cmd == 'wgx':
        return scr_wg_exp(uid, pub)
    if cmd == 'wgl':
        return scr_wg_lim(uid, pub)
    if cmd == 'wgxd':
        awaiting[uid] = ('wg_exp_date', pub)
        return ('📅 До какой даты включительно действует доступ? Формат <code>ДД.ММ.ГГГГ</code>, '
                'например <code>01.12.2026</code>.\n\nОтмена: /cancel', [[btn('✖️ Отмена', f'wgx:{arg}')]])
    if cmd == 'wglc':
        awaiting[uid] = ('wg_limit', pub)
        return ('✏️ Лимит в гигабайтах в месяц (число), например <code>25</code>.\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', f'wgl:{arg}')]])
    if cmd in ('wgxs', 'wgls'):
        val = int(data.rsplit(':', 1)[1])
        if cmd == 'wgxs':
            base = max(time.time(), p.get('expires') or 0)
            new = None if val == 0 else end_of_day(date.fromtimestamp(base) + timedelta(days=val))
            note = set_peer_expiry(pub, new, who)
            return scr_wg_peer(uid, pub, note)
        note = set_peer_limit(pub, val * GB if val else None, who)
        return scr_wg_peer(uid, pub, note)
    if cmd == 'wgt' and not p['enabled']:
        if p.get('expires') and p['expires'] < time.time():
            return scr_wg_exp(uid, pub, '⚠️ Срок доступа истёк — сначала продлите его, клиент включится сам.')
        if p.get('limit') and sum(peer_usage(p)['month']) >= p['limit']:
            return scr_wg_lim(uid, pub, '⚠️ Лимит этого месяца исчерпан — увеличьте или снимите лимит.')
    if cmd in ('wgt', 'wgm'):
        key = 'enabled' if cmd == 'wgt' else 'monitor'
        with lock:
            p[key] = not p.get(key)
            if key == 'enabled':
                p['off_reason'] = None
            save_state()
        if cmd == 'wgt':
            wg_write()
            admin_note(uid, f'клиент «{p["name"]}» ' + ('включён' if p['enabled'] else 'выключен'))
        return scr_wg_peer(uid, pub)
    if cmd == 'wgd':
        warn = ('\n\n⚠️ Похоже, это основной MikroTik: после удаления он потеряет VPN.'
                if p.get('monitor') and p['kind'] == 'mikrotik' else '')
        return (f'🗑 Удалить пир <b>{h(p["name"])}</b>? Подключиться с его ключами больше будет нельзя.{warn}',
                [[btn('✅ Удалить', f'wgdd:{arg}'), btn('✖️ Отмена', f'wgp:{arg}')]])
    if cmd == 'wgdd':
        with lock:
            w['peers'].pop(pub, None)
            save_state()
        wg_write()
        add_event(f'{who} удалил пир «{p["name"]}»')
        notify('actions', f'👤 {h(who)} удалил пир WireGuard «{h(p["name"])}»', exclude=uid)
        return scr_wg(uid, f'🗑 Пир «{h(p["name"])}» удалён')
    return scr_wg(uid)


def handle_em(uid, data, chat, mid):
    e = email_cfg()
    parts = data.split(':')
    act = parts[1] if len(parts) > 1 else ''
    if act == 'on':
        with lock:
            e['enabled'] = not e['enabled']
            save_state()
        return scr_email(uid, '✅ Почта включена' if e['enabled'] else '⛔ Почта выключена')
    if act == 'k':
        with lock:
            e['kinds'][parts[2]] = not e['kinds'].get(parts[2])
            save_state()
        return scr_email(uid)
    if act == 'del':
        with lock:
            e['to'] = [a for a in e['to'] if tag(a) != parts[2]]
            save_state()
        return scr_email(uid, '🗑 Адрес удалён')
    if act == 'add':
        awaiting[uid] = ('add_email', None)
        return ('➕ <b>Новый получатель</b>\n\nОтправьте адрес почты сообщением. Можно несколько через пробел.'
                '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'em')]])
    if act == 'name':
        awaiting[uid] = ('mail_name', None)
        return (f'✏️ <b>Имя отправителя</b>\n\nСейчас: {h(e.get("from_name") or GW_NAME)}\n'
                'Так письма будут подписаны в почтовом ящике. Отправьте новое имя.\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'em')]])
    if act == 'smtp':
        kb = [[btn(f'{v[0]}', f'em:pv:{k}') for k, v in MAIL_PRESETS.items()],
              [btn('✏️ Другой сервер', 'em:pv:custom')], [btn('⬅️ Назад', 'em')]]
        return ('🔧 <b>Отправитель</b>\n\nС какой почты отправлять уведомления? Пароль от почты не подойдёт — '
                'нужен специальный «пароль приложения», я подскажу, где его взять.', kb)
    if act == 'pv':
        if parts[2] == 'custom':
            awaiting[uid] = ('smtp_host', {})
            return ('🔧 <b>Свой SMTP-сервер</b>\n\nОтправьте адрес и порт, например '
                    '<code>smtp.example.com:465</code> (465 — SSL, 587 — STARTTLS).\n\nОтмена: /cancel',
                    [[btn('✖️ Отмена', 'em')]])
        name, host, port, hint = MAIL_PRESETS[parts[2]]
        awaiting[uid] = ('smtp_user', {'host': host, 'port': port, 'hint': hint})
        return (f'🔧 <b>{name}: шаг 1 из 2</b>\n\nОтправьте адрес ящика, с которого слать письма '
                f'(например <code>name@{host.split(".", 1)[1]}</code>).\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'em')]])
    if act == 'test':
        edit(chat, mid, '✉️ Отправляю тестовое письмо…')
        try:
            send_mail(f'{GW_NAME}: тестовое письмо', 'Почтовые уведомления работают.\n\n'
                      f'Время: {time.strftime("%d.%m.%Y %H:%M:%S")}')
            with lock:
                e['last_error'] = ''
                save_state()
            return scr_email(uid, f'✅ Тестовое письмо отправлено на {h(", ".join(e["to"]))}')
        except Exception as ex:
            return scr_email(uid, f'🔴 Ошибка: <code>{h(str(ex))[:300]}</code>')
    return scr_email(uid)


def handle_callback(cq):
    uid = cq['from']['id']
    data = cq.get('data', '')
    msg = cq.get('message') or {}
    chat = msg.get('chat', {}).get('id')
    mid = msg.get('message_id')
    if data.startswith(('acc:', 'rej:')):
        handle_access_request(cq, uid, data, chat, mid)
        return
    if not is_admin(uid):
        tg('answerCallbackQuery', callback_query_id=cq['id'], text='⛔ Нет доступа')
        return
    tg('answerCallbackQuery', callback_query_id=cq['id'])
    if data == 'noop':
        return
    touch_admin(cq['from'])
    CTX.chat = chat
    CTX.frm = cq['from']
    if data == 'ok':                      # «✔️ Понятно» под уведомлением
        tg_del(chat, mid)
        return
    if data == 'nmenu':                   # меню из уведомления: само уведомление остаётся
        t, kb = scr_menu(uid)
        send(chat, t, kb)
        return
    if mid and ui['menu'].get(str(chat)) != mid:
        set_menu(chat, mid)               # нажали кнопку в другом сообщении — теперь меню здесь
    if data not in ('adm:add', 'em:add', 'em:name', 'wgepd', 'wgepi') and not data.startswith(
            ('wgadd:', 'wgr:', 'swea:', 'wgxd:', 'wglc:', 'em:pv:', 'sub:', 'vsw:', 'mtw:')):
        awaiting.pop(uid, None)
    who = h(admin_name(uid))
    try:
        if data.startswith(OWNER_ONLY) and not is_owner(uid):
            text, kb = scr_menu(uid)
        elif data in SCREENS:
            text, kb = SCREENS[data](uid)
        elif data.startswith('srv:'):
            want = data.split(':')[-1]
            match = [p['name'] for p in servers() if tag(p['name']) == want]
            if not match:
                text, kb = scr_servers(uid, '⚠️ Список серверов изменился, выберите ещё раз.')
                edit(chat, mid, text, kb)
                return
            name = match[0]
            last_manual[0] = time.time()
            if state.get('vpn'):
                with lock:
                    state['vpn']['manual'] = True
                    save_state()
            api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': name})
            add_event(f'{admin_name(uid)} выбрал сервер {name}')
            notify('actions', f'👤 {who} выбрал сервер <b>{h(name)}</b>', exclude=uid)
            text, kb = scr_servers(uid, f'✅ Выбран {h(name)}')
        elif data == 'auto':
            last_manual[0] = time.time()
            v = vpn()
            with lock:
                v['manual'] = False
                save_state()
            if v['mode'] == 'priority':
                prio_tick(force=True)
            else:
                api(f'/proxies/{SELECT_GROUP}', 'PUT', {'name': AUTO_GROUP})
            add_event(f'{admin_name(uid)} включил автовыбор')
            notify('actions', f'👤 {who} включил автовыбор сервера', exclude=uid)
            text, kb = scr_servers(uid, '✅ Включён автовыбор')
        elif data == 'ping':
            edit(chat, mid, '📶 Замеряю пинг всех серверов, до 15 секунд…')
            for sb in subs():
                api(f'/providers/proxies/{sb["id"]}/healthcheck', timeout=40)
            text, kb = scr_servers(uid, '📶 Пинг обновлён')
        elif data == 'speed':
            flow_speed(chat, mid)
            return
        elif data == 'do:update':
            edit(chat, mid, '🔄 Обновляю подписку…')
            errs = []
            for sb in subs():
                if sb.get('type') != 'file':
                    try:
                        api(f'/providers/proxies/{sb["id"]}', 'PUT', timeout=40)
                    except Exception as ex:
                        errs.append(f'{sb["name"]}: {ex}')
            add_event(f'{admin_name(uid)} обновил подписки')
            text, kb = scr_manage(uid, '✅ Подписки обновлены' if not errs else
                                  '⚠️ ' + h('; '.join(errs))[:300])
        elif data.startswith('ask:'):
            what = data[4:]
            if what not in CONFIRM or (CONFIRM[what][1] and not is_owner(uid)):
                return
            text = CONFIRM[what][0]
            kb = [[btn('✅ Да', f'yes:{what}'), btn('✖️ Отмена', 'manage')]]
        elif data == 'yes:reboot':
            if not is_owner(uid):
                return
            edit(chat, mid, '🖥 Сервер перезагружается. Бот вернётся через 1–2 минуты и пришлёт сообщение.')
            add_event(f'{admin_name(uid)}: перезагрузка сервера')
            notify('actions', f'👤 {who} перезагружает сервер', exclude=uid)
            time.sleep(2)
            run(['systemctl', 'reboot'], 10)
            return
        elif data.startswith('yes:') and data[4:] in UNITS:
            unit, label = UNITS[data[4:]]
            edit(chat, mid, f'⏳ Перезапускаю {label}…')
            r = run(['systemctl', 'restart', unit], 60)
            time.sleep(4)
            ok = r.returncode == 0
            add_event(f'{admin_name(uid)}: перезапуск {label}' + ('' if ok else ' (ошибка)'))
            notify('actions', f'👤 {who} перезапустил {label}', exclude=uid)
            text, kb = scr_manage(uid, f'✅ {label} перезапущен' if ok else
                                  f'🔴 Ошибка: <code>{h((r.stderr or "")[:300])}</code>')
        elif data.startswith('sub:'):
            text, kb = handle_sub(uid, data, chat, mid)
        elif data == 'site' or data.startswith('site:'):
            text, kb = handle_site(uid, data, chat, mid)
        elif data.startswith('mtw:'):
            res = handle_mtw(uid, data, chat, mid)
            if res is None:
                return
            text, kb = res
        elif data.startswith('bk:'):
            res = handle_bk(uid, data, chat, mid)
            if res is None:
                return
            text, kb = res
        elif data.startswith('cl:'):
            _, key, val = data.split(':')
            if key in CLEAN_DEFAULTS and int(val) in dict(CLEAN_TTLS):
                with lock:
                    clean_cfg(uid)[key] = int(val)
                    save_state()
            text, kb = scr_clean(uid, '✅ Сохранено. Действует для новых сообщений.')
        elif data == 'clean':
            text, kb = ('🧹 <b>Очистить чат?</b>\n\nУдалятся все сообщения этого чата за последние 48 часов: '
                        'уведомления, QR-коды, конфиги и файлы копий. Останется только меню. Сами настройки, '
                        'клиенты и копии на сервере не пострадают.',
                        [[btn('🧹 Очистить', 'clean:go'), btn('✖️ Отмена', 'menu')]])
        elif data == 'clean:go':
            edit(chat, mid, '🧹 Очищаю чат…')
            clean_chat(chat)
            text, kb = scr_menu(uid)
            text += '\n\n🧹 Чат очищен.'
        elif data.startswith('vsw:'):
            text, kb = handle_vsw(uid, data, chat, mid)
        elif data.startswith('vs:'):
            text, kb = handle_vs(uid, data, chat, mid)
        elif data.startswith('svc:') and data[4:] in SERVICES:
            text, kb = scr_svc_pick(uid, data[4:])
        elif data.startswith('svcs:'):
            _, key, pid = data.split(':', 2)
            v = vpn()
            if key in SERVICES:
                with lock:
                    v.setdefault('svc', {})
                    if pid == '-' or not sub_by_id(pid):
                        v['svc'].pop(key, None)
                    else:
                        v['svc'][key] = pid
                    save_state()
            text, kb = scr_svc(uid, '✅ Выбрано. Нажмите «Применить», чтобы заработало.' if vpn_dirty(v) else '')
        elif data.startswith('srvt:'):
            _, key, val = data.split(':')
            with lock:
                srv_cfg()[key] = float(val) if key == 'load' else int(val)
                save_state()
            text, kb = scr_srv_thr(uid, '✅ Сохранено')
        elif data == 'srvclean':
            text, kb = ('🧹 <b>Освободить место?</b>\n\nБудут сжаты журналы systemd (до 200 МБ), очищен кэш пакетов '
                        'apt и удалены старые копии конфигов. Настройки и клиенты не пострадают.',
                        [[btn('✅ Очистить', 'srvclean:go'), btn('✖️ Отмена', 'srv')]])
        elif data == 'srvclean:go':
            edit(chat, mid, '🧹 Освобождаю место…')
            freed, steps = srv_cleanup()
            add_event(f'{admin_name(uid)}: очистка диска, освобождено {fmt_bytes(max(freed, 0))}')
            text, kb = scr_srv(uid, f'✅ Освобождено {fmt_bytes(max(freed, 0))}: ' + '; '.join(steps))
        elif data.startswith('upd'):
            text, kb = scr_upd(uid) if data == 'upd' else handle_upd(uid, data, chat, mid)
        elif data.startswith('wg'):
            res = handle_wg(uid, data, chat, mid)
            if res is None:
                return
            text, kb = res
        elif data.startswith('sw'):
            text, kb = handle_sw(uid, data, chat, mid)
        elif data == 'gws':
            text, kb = scr_gws(uid)
        elif data.startswith('gw:'):
            res = handle_gw(uid, data, chat, mid)
            if res is None:
                return
            text, kb = res
        elif data.startswith('em:'):
            text, kb = handle_em(uid, data, chat, mid)
        elif data.startswith('nt:'):
            with lock:
                n = state['admins'][str(uid)]['notify']
                k = data[3:]
                n[k] = not n.get(k, True)
                save_state()
            text, kb = scr_notif(uid)
        elif data.startswith('adm:') and is_owner(uid):
            parts = data.split(':')
            if parts[1] == 'add':
                awaiting[uid] = ('add_admin', None)
                text = ('➕ <b>Новый администратор</b>\n\nОтправьте сообщением его Telegram ID (число). '
                        'Узнать ID можно у @userinfobot.\n\nОтмена: /cancel')
                kb = [[btn('✖️ Отмена', 'admins')]]
            elif parts[1] == 'gws':
                text, kb = scr_adm_gw(uid, parts[2])
            elif parts[1] == 'gw':
                a = state['admins'].get(parts[2])
                if a and (parts[3] == 'm' or parts[3] in gw_nodes()):
                    with lock:
                        have = a.setdefault('gw', ['m'])
                        if parts[3] in have:
                            have.remove(parts[3])
                        else:
                            have.append(parts[3])
                        save_state()
                    gw_sync_all()
                text, kb = scr_adm_gw(uid, parts[2])
            elif parts[1] == 'del':
                text = f'🗑 Удалить администратора <b>{h(admin_name(parts[2]))}</b>?'
                kb = [[btn('✅ Удалить', f'adm:rm:{parts[2]}'), btn('✖️ Отмена', 'admins')]]
            else:
                aid = parts[2]
                removed = None
                if int(aid) != OWNER:
                    with lock:
                        removed = state['admins'].pop(aid, None)
                        save_state()
                if removed:
                    add_event(f'{admin_name(uid)} удалил администратора {removed["name"]}')
                    send(int(aid), '⛔ Ваш доступ к VPN-боту отозван.')
                text, kb = scr_admins(uid, '✅ Администратор удалён' if removed else '')
        else:
            text, kb = scr_menu(uid)
    except Exception as e:
        log(traceback.format_exc())
        text, kb = f'⚠️ <b>Ошибка</b>\n<code>{h(str(e))[:300]}</code>', kb_back()
    edit(chat, mid, text, kb)


def set_peer_expiry(pub, ts, who):
    w = wg_state()
    p = w['peers'][pub]
    revived = False
    with lock:
        p['expires'] = ts
        p.setdefault('warned', {})['exp'] = None
        if not p['enabled'] and p.get('off_reason') == 'expired' and (ts is None or ts > time.time()):
            p['enabled'] = True
            p['off_reason'] = None
            revived = True
        save_state()
    if revived:
        wg_write()
    txt = f'до {fmt_date(ts)}' if ts else 'бессрочно'
    add_event(f'{who}: срок доступа «{p["name"]}» — {txt}')
    return f'✅ Срок доступа: {txt}' + ('. Клиент снова включён.' if revived else '')


def set_peer_limit(pub, limit, who):
    w = wg_state()
    p = w['peers'][pub]
    revived = False
    with lock:
        p['limit'] = limit
        p.setdefault('warned', {})['lim'] = None
        used = sum(peer_usage(p)['month'])
        if not p['enabled'] and p.get('off_reason') == 'limit' and (limit is None or used < limit):
            p['enabled'] = True
            p['off_reason'] = None
            revived = True
        save_state()
    if revived:
        wg_write()
    txt = f'{fmt_bytes(limit)} в месяц' if limit else 'без лимита'
    add_event(f'{who}: лимит «{p["name"]}» — {txt}')
    return f'✅ Лимит трафика: {txt}' + ('. Клиент снова включён.' if revived else '')


def handle_peer_input(uid, chat, kind, pub, text):
    if pub not in wg_state()['peers']:
        awaiting.pop(uid, None)
        send(chat, '⚠️ Клиент не найден.')
        return
    who = admin_name(uid)
    if kind == 'wg_exp_date':
        try:
            d = datetime.strptime(text.strip(), '%d.%m.%Y').date()
        except ValueError:
            send(chat, 'Нужна дата в формате <code>ДД.ММ.ГГГГ</code>. Ещё раз или /cancel.')
            return
        if end_of_day(d) < time.time():
            send(chat, 'Эта дата уже прошла. Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        note = set_peer_expiry(pub, end_of_day(d), who)
    else:
        try:
            gb = float(text.strip().replace(',', '.'))
            assert gb > 0
        except Exception:
            send(chat, 'Нужно положительное число гигабайт, например <code>25</code>. Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        note = set_peer_limit(pub, int(gb * GB), who)
    t, kb = scr_wg_peer(uid, pub, note)
    send(chat, t, kb)


def handle_rule_input(uid, chat, key, text):
    v = vpn()
    good, bad = [], []
    for part in re.split(r'[\s,]+', text.strip()):
        if part:
            (good if norm_target(part) else bad).append(norm_target(part) or part)
    if not good:
        send(chat, 'Не распознал ни одного домена или IP. Пример: <code>example.com</code> или '
                   '<code>1.2.3.0/24</code>. Ещё раз или /cancel.')
        return
    awaiting.pop(uid, None)
    other = 'rules_proxy' if key == 'rules_direct' else 'rules_direct'
    with lock:
        for t in good:
            if t in v[other]:
                v[other].remove(t)
            if t not in v[key]:
                v[key].append(t)
        save_state()
    add_event(f'{admin_name(uid)} добавил исключения: {", ".join(good)}')
    note = f'✅ Добавлено: {h(", ".join(good))}' + (f'\n⚠️ Не распознано: {h(", ".join(bad))}' if bad else '')
    t, kb = scr_sw_exc(uid, note + '\n\nНажмите «Применить», чтобы изменения заработали.')
    send(chat, t, kb)


def handle_wg_input(uid, chat, kind, wdata, text):
    w = wg_state()
    name = text.strip()[:40]
    if kind == 'wg_ep':
        host, port = split_hostport(name.lower())
        is_ip = bool(IP_RE.match(host)) and all(int(x) < 256 for x in host.split('.'))
        good = is_ip if wdata == 'i' else (bool(re.match(r'^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$', host))
                                           and not IP_RE.match(host))
        if not good or (port and not 0 < int(port) < 65536):
            send(chat, ('Нужен IP, например <code>203.0.113.10</code>.' if wdata == 'i' else
                        'Нужно доменное имя, например <code>vpn.example.ru</code>. IP задаётся отдельной кнопкой.')
                 + ' Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        wg_set_ep(wdata, host, port)
        add_event(f'{admin_name(uid)} задал ' + ('домен' if wdata == 'd' else 'IP') + f' WireGuard: {name}')
        note = '✅ Сохранено'
        if wdata == 'd':
            send(chat, '🔎 Проверяю домен…')
            note += '\n' + check_domain(host)[1]
        t, kb = scr_wg_ep(uid, note)
        send(chat, t, kb)
        return
    if not name:
        send(chat, 'Имя не может быть пустым. Ещё раз или /cancel.')
        return
    awaiting.pop(uid, None)
    if kind == 'wg_rename':
        if wdata in w['peers']:
            with lock:
                w['peers'][wdata]['name'] = name
                save_state()
            wg_write()
            t, kb = scr_wg_peer(uid, wdata, '✅ Переименован')
        else:
            t, kb = scr_wg(uid, '⚠️ Пир не найден')
        send(chat, t, kb)
        return
    if wdata == 'mikrotik':
        ctx = mt_defaults(name)
        awaiting[uid] = ('mt', ctx)
        t, kb = scr_mt(uid, ctx)
        send(chat, t, kb)
        return
    try:
        pub = wg_new_peer(name, wdata)
    except Exception as ex:
        t, kb = scr_wg(uid, f'🔴 Не удалось создать пир: <code>{h(str(ex))[:250]}</code>')
        send(chat, t, kb)
        return
    add_event(f'{admin_name(uid)} добавил пир «{name}»')
    notify('actions', f'👤 {h(admin_name(uid))} добавил пир WireGuard «{h(name)}»', exclude=uid)
    wg_send_conf(chat, pub)
    tips = {'mikrotik': f'Вставь команды из файла в терминал MikroTik, затем проверь: <code>/ping {WG_NET}.1</code>.',
            'pc': 'Установи WireGuard на компьютер и импортируй файл. QR можно получить кнопкой ниже.',
            }.get(wdata, 'Отсканируй QR-код в приложении WireGuard на телефоне. Файл .conf — кнопкой ниже.')
    t, kb = scr_wg_peer(uid, pub, f'✅ Пир создан. {tips}')
    send(chat, t, kb)


EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def wg_mail_send(uid, pub, addr, via=None):
    p = wg_state()['peers'][pub]
    try:
        wg_mail(pub, addr, via)
    except Exception as ex:
        log('wg_mail:', ex)
        return f'🔴 Письмо не отправлено: <code>{h(str(ex))[:250]}</code>'
    with lock:
        p['mail'] = addr
        save_state()
    admin_note(uid, f'отправил конфиг «{p["name"]}» на {addr}')
    return f'📧 Письмо с настройками отправлено на <b>{h(addr)}</b>.'


def handle_wg_mail_input(uid, chat, wdata, text):
    pub, via = wdata if isinstance(wdata, tuple) else (wdata, None)
    addr = text.strip()
    if not EMAIL_RE.match(addr):
        send(chat, 'Это не похоже на адрес почты. Ещё раз или /cancel.')
        return
    awaiting.pop(uid, None)
    if pub not in wg_state()['peers']:
        t, kb = scr_wg(uid, '⚠️ Пир не найден')
        send(chat, t, kb)
        return
    r = send(chat, f'📧 Отправляю на {h(addr)}…')
    t, kb = scr_wg_peer(uid, pub, wg_mail_send(uid, pub, addr, via))
    if r:
        edit(chat, r['message_id'], t, kb)
    else:
        send(chat, t, kb)


def handle_email_input(uid, chat, m, kind, wdata, text):
    e = email_cfg()
    if kind == 'add_email':
        addrs = [x for x in re.split(r'[\s,;]+', text) if x]
        bad = [x for x in addrs if not EMAIL_RE.match(x)]
        if not addrs or bad:
            send(chat, f'Не похоже на адрес почты: {h(" ".join(bad) or text)}. Ещё раз или /cancel.')
            return
        awaiting.pop(uid, None)
        with lock:
            for a in addrs:
                if a not in e['to']:
                    e['to'].append(a)
            if e['smtp'].get('host'):
                e['enabled'] = True
            save_state()
        t, kb = scr_email(uid, f'✅ Добавлено: {h(", ".join(addrs))}')
    elif kind == 'mail_name':
        awaiting.pop(uid, None)
        with lock:
            e['from_name'] = text.strip()[:60]
            save_state()
        t, kb = scr_email(uid, f'✅ Имя отправителя: {h(e["from_name"])}')
    elif kind == 'smtp_host':
        host, _, port = text.strip().partition(':')
        if not re.match(r'^[A-Za-z0-9.-]+$', host) or (port and not port.isdigit()):
            send(chat, 'Нужно в виде <code>smtp.example.com:465</code>. Ещё раз или /cancel.')
            return
        awaiting[uid] = ('smtp_user', {'host': host, 'port': int(port or 465), 'hint': ''})
        send(chat, '🔧 <b>Шаг 1 из 2</b>\n\nОтправьте адрес ящика отправителя (логин).\n\nОтмена: /cancel')
        return
    elif kind == 'smtp_user':
        if not EMAIL_RE.match(text.strip()):
            send(chat, 'Это не похоже на адрес почты. Ещё раз или /cancel.')
            return
        awaiting[uid] = ('smtp_pass', dict(wdata, user=text.strip()))
        send(chat, '🔧 <b>Шаг 2 из 2</b>\n\nОтправьте <b>пароль приложения</b> для этого ящика. '
                   + (h(wdata.get('hint', '')) + ' ' if wdata.get('hint') else '')
                   + 'Сообщение с паролем я сразу удалю из чата.\n\nОтмена: /cancel')
        return
    else:
        tg('deleteMessage', chat_id=chat, message_id=m['message_id'])
        awaiting.pop(uid, None)
        cfg = {'host': wdata['host'], 'port': wdata['port'], 'user': wdata['user'], 'pass': text.strip()}
        send(chat, '⏳ Проверяю вход на почтовый сервер…')
        try:
            smtp_connect(cfg).quit()
            with lock:
                e['smtp'] = cfg
                e['last_error'] = ''
                if not e['to']:
                    e['to'] = [cfg['user']]
                e['enabled'] = True
                save_state()
            add_event(f'{admin_name(uid)} изменил отправителя почты')
            t, kb = scr_email(uid, '✅ Отправитель сохранён, вход прошёл успешно. Почта включена — '
                                   'проверьте кнопкой «✉️ Тестовое письмо».')
        except Exception as ex:
            t, kb = scr_email(uid, f'🔴 Не удалось войти, настройки не изменены: <code>{h(str(ex))[:250]}</code>\n'
                                   'Проверьте, что это именно пароль приложения, а не обычный пароль от почты.')
    send(chat, t, kb)


def handle_message(m):
    if (m.get('chat') or {}).get('type') != 'private':
        return
    u = m.get('from') or {}
    uid = u.get('id')
    chat = m['chat']['id']
    text = (m.get('text') or '').strip()
    if not is_admin(uid):
        if time.time() - state['rejected'].get(str(uid), 0) < 86400:
            return
        if text.startswith('/start'):
            with lock:
                already = str(uid) in state['pending']
                if not already:
                    state['pending'][str(uid)] = {'name': user_label(u), 'ts': time.time()}
                    save_state()
            send(chat, f'⛔ У вас нет доступа к этому боту.\n\nВаш Telegram ID: <code>{uid}</code>\n'
                       + ('Запрос уже отправлен владельцу, ожидайте.' if already
                          else 'Запрос на доступ отправлен владельцу.'))
            if not already:
                send(OWNER, f'🙋 <b>Запрос доступа к боту</b>\n\n{h(user_label(u))}\nID: <code>{uid}</code>',
                     [[btn('✅ Дать доступ', f'acc:{uid}'), btn('❌ Отклонить', f'rej:{uid}')]])
        return
    touch_admin(u)
    CTX.chat = chat
    has_file = bool(m.get('document') or m.get('photo'))
    if not has_file and m.get('message_id'):
        tg('deleteMessage', chat_id=chat, message_id=m['message_id'])   # чистый чат: ввод не остаётся
    try:
        handle_admin_message(m, uid, chat, text)
    finally:
        if has_file:
            tg('deleteMessage', chat_id=chat, message_id=m['message_id'])


def handle_admin_message(m, uid, chat, text):
    cmd = text.split()[0].split('@')[0].lower() if text.startswith('/') else ''
    kind, wdata = awaiting.get(uid, (None, None))
    if cmd == '/cancel':
        awaiting.pop(uid, None)
    elif kind in ('sub_name', 'sub_url', 'sub_rename') and not cmd and is_owner(uid):
        handle_sub_input(uid, chat, m, kind, wdata, text)
        return
    elif kind in ('vs_host', 'vs_user', 'vs_auth') and not cmd and is_owner(uid):
        handle_vs_input(uid, chat, m, kind, wdata, text)
        return
    elif kind and kind.startswith('bk_') and not cmd and is_owner(uid):
        handle_bk_input(uid, chat, kind, wdata, text)
        return
    elif kind == 'mt' and not cmd:
        handle_mt_input(uid, chat, wdata, text, m)
        return
    elif kind == 'wg_mail' and not cmd:
        handle_wg_mail_input(uid, chat, wdata, text)
        return
    elif kind == 'site' and not cmd:
        handle_site_input(uid, chat, text)
        return
    elif kind == 'rule_add' and not cmd:
        handle_rule_input(uid, chat, wdata, text)
        return
    elif kind in ('wg_exp_date', 'wg_limit') and not cmd:
        handle_peer_input(uid, chat, kind, wdata, text)
        return
    elif kind in ('wg_name', 'wg_rename') and not cmd or kind == 'wg_ep' and not cmd and is_owner(uid):
        handle_wg_input(uid, chat, kind, wdata, text)
        return
    elif kind in ('add_email', 'smtp_host', 'smtp_user', 'smtp_pass', 'mail_name') and not cmd and is_owner(uid):
        handle_email_input(uid, chat, m, kind, wdata, text)
        return
    elif kind and kind.startswith('gw_') and not cmd and is_owner(uid):
        if kind == 'gw_code':
            gw_join(uid, chat, text)
        else:
            handle_gw_input(uid, chat, kind, wdata, text)
        return
    elif kind == 'add_admin' and not cmd:
        if not text.isdigit():
            send(chat, 'Нужно число — Telegram ID. Или /cancel для отмены.')
            return
        awaiting.pop(uid, None)
        info = tg('getChat', chat_id=int(text))
        name = user_label(info) if info else text
        sent = grant_access(text, name, uid)
        t, kb = scr_admins(uid, f'✅ Добавлен {h(name)}' + (
            '' if sent else '\n<i>Он ещё не писал боту: пусть откроет бота и нажмёт /start.</i>'))
        send(chat, t, kb)
        return
    if cmd == '/site':
        arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ''
        if arg:
            handle_site_input(uid, chat, arg)
        else:
            t, kb = site_prompt(uid)
            send(chat, t, kb)
        return
    if cmd == '/speed':
        r = send(chat, '⚡ Готовлю тест скорости…')
        if r:
            flow_speed(chat, r['message_id'])
        return
    key = {'/status': 'status', '/servers': 'servers', '/traffic': 'traffic', '/log': 'log',
           '/server': 'srv'}.get(cmd, 'menu')
    try:
        t, kb = SCREENS[key](uid)
    except Exception as e:
        t, kb = f'⚠️ <b>Ошибка</b>\n<code>{h(str(e))[:300]}</code>', kb_back()
    send(chat, t, kb)


# ---------------- обновления ----------------
def vtuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or '0'))


def raw_url(path):
    return f'https://raw.githubusercontent.com/{UPDATE_REPO}/{UPDATE_BRANCH}/{path}'


def fetch(url, timeout=30, binary=False):
    last = None
    for opener in (proxy_opener, direct_opener):
        try:
            req = urllib.request.Request(url + ('&' if '?' in url else '?') + f't={int(time.time())}',
                                         headers={'User-Agent': 'vpngw/' + BOT_VERSION, 'Cache-Control': 'no-cache'})
            with opener.open(req, timeout=timeout) as r:
                data = r.read()
            return data if binary else data.decode('utf-8', 'replace')
        except Exception as e:
            last = e
    raise RuntimeError(f'не удалось скачать {url}: {last}')


def check_update():
    txt = fetch(raw_url('VERSION')).split()
    latest, sha = txt[0], (txt[1] if len(txt) > 1 else '')
    changes = ''
    try:
        cl = fetch(raw_url('CHANGELOG.md'))
        parts = re.split(r'^## ', cl, flags=re.M)
        keep = [x for x in parts[1:] if vtuple(x.split()[0]) > vtuple(BOT_VERSION)]
        changes = '\n'.join('## ' + x.strip() for x in keep)
    except Exception:
        pass
    with lock:
        state['upd'] = {'latest': latest, 'sha': sha, 'changes': changes, 'checked': time.time(),
                        'notified': (state.get('upd') or {}).get('notified')}
        save_state()
    return state['upd']


def update_available():
    u = state.get('upd') or {}
    return bool(u.get('latest')) and vtuple(u['latest']) > vtuple(BOT_VERSION)


def mihomo_versions():
    cur = run([shutil.which('mihomo') or 'mihomo', '-v'], 10).stdout
    cur = (re.search(r'v\d+\.\d+\.\d+', cur) or [None])[0]
    latest = None
    try:
        latest = json.loads(fetch('https://api.github.com/repos/MetaCubeX/mihomo/releases/latest', 20))['tag_name']
    except Exception as e:
        log('mihomo latest:', e)
    return cur, latest


def mihomo_update():
    arch = {'x86_64': 'amd64-v1', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('неизвестная архитектура ' + platform.machine())
    rel = json.loads(fetch('https://api.github.com/repos/MetaCubeX/mihomo/releases/latest', 20))
    tagname = rel['tag_name']
    url = next((a['browser_download_url'] for a in rel.get('assets', [])
                if a['name'] == f'mihomo-linux-{arch}-{tagname}.deb'), None)
    if not url:
        raise RuntimeError('в релизе нет пакета для этой архитектуры')
    data = fetch(url, 300, binary=True)
    os.makedirs(UPDATE_DIR, exist_ok=True)
    deb = os.path.join(UPDATE_DIR, 'mihomo.deb')
    with open(deb, 'wb') as f:
        f.write(data)
    r = run(['apt-get', 'install', '-y', '-qq', deb], 300)
    if r.returncode != 0:
        raise RuntimeError('apt-get: ' + (r.stderr or r.stdout)[-300:])
    t = run(['mihomo', '-d', GEO_DIR, '-t'], 120)
    if t.returncode != 0:
        raise RuntimeError('новая версия mihomo не принимает конфиг: ' + (t.stdout + t.stderr)[-200:])
    run(['systemctl', 'restart', 'mihomo'], 60)
    return tagname


def start_self_update(chat):
    u = state.get('upd') or check_update()
    data = fetch(raw_url('install.sh'), 120, binary=True)
    if u.get('sha') and hashlib.sha256(data).hexdigest() != u['sha']:
        raise RuntimeError('контрольная сумма install.sh не совпала с VERSION — файл повреждён или ещё '
                           'не обновился на GitHub, попробуйте через пару минут')
    os.makedirs(UPDATE_DIR, exist_ok=True)
    path = os.path.join(UPDATE_DIR, 'install.sh')
    with open(path, 'wb') as f:
        f.write(data)
    os.chmod(path, 0o700)
    r = run(['bash', '-n', path], 20)
    if r.returncode != 0:
        raise RuntimeError('скачанный install.sh с ошибкой: ' + r.stderr[-200:])
    with lock:
        state['upd_pending'] = {'to': u.get('latest'), 'chat': chat, 'from': BOT_VERSION}
        save_state()
    unit = f'vpngw-update-{int(time.time())}'
    r = run(['systemd-run', f'--unit={unit}', '--collect', '/bin/bash', path, '--self-update'], 30)
    if r.returncode != 0:
        raise RuntimeError('не удалось запустить обновление: ' + r.stderr[-200:])


def report_update_result():
    if not os.path.exists(UPDATE_RESULT):
        return
    try:
        res = open(UPDATE_RESULT, encoding='utf-8').read().strip()
        os.remove(UPDATE_RESULT)
    except Exception:
        return
    pend = state.pop('upd_pending', None) or {}
    save_state()
    status, _, rest = res.partition(' ')
    if status == 'ok':
        text = f'✅ <b>Шлюз обновлён до версии {h(BOT_VERSION)}</b>'
        ch = (state.get('upd') or {}).get('changes')
        if ch:
            text += '\n\n' + h(ch[:1500])
        text += '\n\nЕсли в новой версии изменились настройки VPN, загляните в ⚙️ Настройки — там может быть кнопка «Применить».'
    else:
        text = (f'⚠️ <b>Обновление не удалось</b>, возвращена прежняя версия {h(BOT_VERSION)}.\n'
                f'<code>{h(rest[:400])}</code>')
    add_event(plain(text).split('\n')[0])
    notify('actions', text)


def scr_upd(uid, note=''):
    u = state.get('upd') or {}
    lines = ['🆕 <b>Обновления</b>', '', f'Установлена версия: <b>{h(BOT_VERSION)}</b>']
    if u.get('latest'):
        lines.append(f'На GitHub: <b>{h(u["latest"])}</b> (проверено {time.strftime("%d.%m %H:%M", time.localtime(u["checked"]))})')
    lines.append(f'Источник: <code>{h(UPDATE_REPO)}</code>, ветка {h(UPDATE_BRANCH)}')
    if update_available():
        lines += ['', '<b>Что нового:</b>', h((u.get('changes') or 'описание изменений не найдено')[:1500])]
    elif u.get('latest'):
        lines += ['', '✅ У вас последняя версия.']
    if note:
        lines += ['', note]
    kb = [[btn('🔍 Проверить сейчас', 'upd:check')]]
    if update_available():
        kb.insert(0, [btn(f'⬇️ Обновить до {u["latest"]}', 'upd:ask')])
    kb.append([btn('🧱 mihomo', 'upd:mh')])
    kb.append([btn('⬅️ Управление', 'manage'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def handle_upd(uid, data, chat, mid):
    act = data.split(':', 1)[1]
    if act == 'check':
        edit(chat, mid, '🔍 Проверяю GitHub…')
        try:
            check_update()
            return scr_upd(uid)
        except Exception as e:
            return scr_upd(uid, f'🔴 {h(str(e))[:300]}')
    if act == 'ask':
        u = state.get('upd') or {}
        return (f'⬇️ <b>Обновить шлюз до {h(u.get("latest", "?"))}?</b>\n\nОбновятся бот и утилита vpngw. '
                'Настройки, клиенты, админы и статистика сохранятся. Бот перезапустится и примерно через '
                'минуту пришлёт результат. Если новая версия не запустится, вернётся прежняя.\n\n'
                'VPN и WireGuard при этом не прерываются.',
                [[btn('✅ Обновить', 'upd:go'), btn('✖️ Отмена', 'upd')]])
    if act == 'go':
        edit(chat, mid, '⏳ Скачиваю обновление…')
        try:
            start_self_update(chat)
            add_event(f'{admin_name(uid)} запустил обновление до {state["upd"]["latest"]}')
            return ('⏳ <b>Обновление запущено.</b> Бот перезапустится и пришлёт результат примерно через минуту.',
                    [[btn('🏠 Меню', 'menu')]])
        except Exception as e:
            return scr_upd(uid, f'🔴 {h(str(e))[:400]}')
    if act == 'mh':
        edit(chat, mid, '🔍 Проверяю версию mihomo…')
        cur, latest = mihomo_versions()
        text = f'🧱 <b>mihomo</b>\n\nУстановлена: {h(cur or "?")}\nПоследняя: {h(latest or "не удалось узнать")}'
        kb = []
        if cur and latest and vtuple(latest) > vtuple(cur):
            text += '\n\nПри обновлении VPN прервётся на 10–20 секунд.'
            kb.append([btn(f'⬆️ Обновить до {latest}', 'upd:mhgo')])
        elif latest:
            text += '\n\n✅ Последняя версия.'
        kb.append([btn('⬅️ Обновления', 'upd')])
        return text, kb
    if act == 'mhgo':
        edit(chat, mid, '⏳ Обновляю mihomo, VPN ненадолго прервётся…')
        try:
            v = mihomo_update()
            add_event(f'{admin_name(uid)} обновил mihomo до {v}')
            return scr_upd(uid, f'✅ mihomo обновлён до {h(v)}')
        except Exception as e:
            return scr_upd(uid, f'🔴 {h(str(e))[:400]}')
    return scr_upd(uid)


# ---------------- клиенты: учёт трафика, сроки, лимиты ----------------
def peers_tick(live):
    w = state.get('wg')
    if not w:
        return
    now = time.time()
    today = date.today().isoformat()
    mk = month_key()
    cutoff = (date.today() - timedelta(days=100)).isoformat()
    changed_wg = False
    msgs = []
    with lock:
        for pub, p in w['peers'].items():
            lv = live.get(pub)
            raw = [lv['tx'], lv['rx']] if lv else [0, 0]       # tx шлюза = скачал клиент
            last = p.get('last') or [0, 0]
            d = [raw[i] - last[i] if raw[i] >= last[i] else raw[i] for i in (0, 1)]
            p['last'] = raw
            if d[0] or d[1]:
                st = p.setdefault('stats', {})
                t = st.setdefault(today, [0, 0])
                t[0] += d[0]
                t[1] += d[1]
                for k in [k for k in st if k < cutoff]:
                    del st[k]
            if p['kind'] == 'mikrotik':
                continue
            warned = p.setdefault('warned', {})
            used = sum(peer_usage(p)['month'])
            name = h(p['name'])
            if p['enabled'] and p.get('expires') and p['expires'] <= now:
                p['enabled'], p['off_reason'] = False, 'expired'
                changed_wg = True
                msgs.append(f'⌛ <b>Срок доступа истёк: {name}</b>\nКлиент отключён. Продлить: 🔐 WireGuard → {name} → ⏳ Срок доступа.')
            elif p['enabled'] and p.get('expires') and p['expires'] - now <= 3 * 86400 and warned.get('exp') != p['expires']:
                warned['exp'] = p['expires']
                msgs.append(f'⏳ <b>{name}</b>: доступ закончится {fmt_date(p["expires"])} (через {days_word(days_left(p["expires"]))})')
            if p['enabled'] and p.get('limit') and used >= p['limit']:
                p['enabled'], p['off_reason'] = False, 'limit'
                changed_wg = True
                msgs.append(f'🚫 <b>Лимит трафика исчерпан: {name}</b>\n{fmt_bytes(used)} из {fmt_bytes(p["limit"])}. '
                            'Клиент отключён до 1-го числа следующего месяца.')
            elif p['enabled'] and p.get('limit') and used >= 0.8 * p['limit'] and warned.get('lim') != mk:
                warned['lim'] = mk
                msgs.append(f'📊 <b>{name}</b>: израсходовано {fmt_bytes(used)} из {fmt_bytes(p["limit"])} (80%)')
            if not p['enabled'] and p.get('off_reason') == 'limit' and (not p.get('limit') or used < p['limit']):
                if not (p.get('expires') and p['expires'] <= now):
                    p['enabled'], p['off_reason'] = True, None
                    changed_wg = True
                    msgs.append(f'🟢 <b>{name}</b>: новый месяц, лимит обнулён — клиент снова включён.')
        save_state()
    if changed_wg:
        try:
            wg_write()
        except Exception as e:
            log('wg_write:', e)
    for m in msgs:
        add_event(plain(m).split('\n')[0])
        notify('billing', m)


def sub_tick():
    allw = state.setdefault('subwarn', {})
    if 'sent' in allw:                       # старый формат: одна подписка
        allw = state['subwarn'] = {subs()[0]['id']: allw}
    many = len(subs()) > 1
    msgs = []
    for sb in subs():
        try:
            si = provider(sb['id']).get('subscriptionInfo') or {}
        except Exception:
            continue
        nm = f' «{h(sb["name"])}»' if many else ''
        exp = si.get('Expire') or 0
        sw = allw.setdefault(sb['id'], {'expire': exp, 'sent': []})
        if exp and sw.get('expire') and exp > sw['expire'] + 3600:
            msgs.append(f'✅ <b>Подписка VPN{nm} продлена</b> до {fmt_date(exp)}')
            sw['sent'] = []
        sw['expire'] = exp
        if exp:
            left = days_left(exp)
            if exp <= time.time() and 'expired' not in sw['sent']:
                sw['sent'].append('expired')
                msgs.append(f'❌ <b>Подписка VPN{nm} закончилась!</b>\nЕё серверы перестанут работать. Продлите подписку у провайдера.')
            else:
                for thr in SUB_REMIND:
                    if left <= thr and str(thr) not in sw['sent']:
                        sw['sent'] += [str(x) for x in SUB_REMIND if x >= thr]
                        msgs.append(f'📅 <b>Подписка VPN{nm} заканчивается</b> {fmt_date(exp)} — осталось {days_word(left)}')
                        break
        total = si.get('Total') or 0
        used = (si.get('Upload') or 0) + (si.get('Download') or 0)
        if total and used >= 0.9 * total and f'traffic-{exp}' not in sw['sent']:
            sw['sent'].append(f'traffic-{exp}')
            msgs.append(f'📊 <b>Трафик подписки{nm} почти исчерпан</b>: {fmt_bytes(used)} из {fmt_bytes(total)}')
    save_state()
    for m in msgs:
        add_event(plain(m).split('\n')[0])
        notify('billing', m)


def update_tick():
    u = state.get('upd') or {}
    if time.time() - u.get('checked', 0) < 86400:
        return
    try:
        u = check_update()
    except Exception as e:
        log('проверка обновлений:', e)
        with lock:
            state.setdefault('upd', {})['checked'] = time.time()
            save_state()
        return
    if update_available() and u.get('notified') != u['latest']:
        with lock:
            state['upd']['notified'] = u['latest']
            save_state()
        text = (f'🆕 <b>Доступна новая версия шлюза: {h(u["latest"])}</b> (у вас {h(BOT_VERSION)})')
        if u.get('changes'):
            text += '\n\n' + h(u['changes'][:1200])
        with lock:
            owner_on = state['admins'].get(str(OWNER), {}).get('notify', {}).get('actions', True)
        if owner_on:
            send(OWNER, text, [[btn('⬇️ Обновить', 'upd:ask'), btn('Подробнее', 'upd')]])


# ---------------- фоновый наблюдатель ----------------
def watcher():
    prev = None
    dead_cnt = 0
    dead_alert = False
    api_bad = 0
    api_alert = False
    tun_cnt = {}
    tun_alert = {}
    last_tr = 0
    last_sub = 0
    last_srv = 0
    started = time.time()
    while True:
        try:
            mode, cur = mode_and_current()
            if api_alert:
                notify('dead', '🟢 <b>mihomo снова отвечает</b>')
                add_event('mihomo снова отвечает')
                api_alert = False
            api_bad = 0
            if mode == 'manual' and time.time() - last_manual[0] > 20 and not probe(cur):
                fallback_to_auto(cur)
                mode, cur = mode_and_current()
                prev = cur
                dead_cnt = 0
            if prev is not None and cur != prev:
                time.sleep(3)
                info = server_info(cur)
                add_event(f'Переключение: {prev} → {cur}')
                if time.time() - last_manual[0] > WATCH_EVERY * 2:
                        notify('switch', f'🔁 <b>VPN-сервер сменился</b>\n\n{h(prev)} → <b>{h(cur)}</b>\n'
                                     f'Режим: {MODE_RU[mode]}\n'
                                     f'Пинг: {fmt_delay(info)}\nВнешний IP: <code>{h(exit_ip())}</code>')
            prev = cur
            alive = server_info(cur).get('alive', True)
            dead_cnt = 0 if alive else dead_cnt + 1
            if dead_cnt >= 2 and not dead_alert:
                why = ('Ни один сервер не отвечает.' if mode != 'manual' else
                       'Выбранный вручную сервер не отвечает. Включите автовыбор или выберите другой.')
                notify('dead', f'🔴 <b>VPN не работает</b>\n\n{why}\nСервер: {h(cur)}')
                add_event(f'VPN недоступен ({cur})')
                dead_alert = True
            elif alive and dead_alert:
                notify('dead', f'🟢 <b>VPN снова работает</b>\nСервер: {h(cur)}')
                add_event('VPN восстановлен')
                dead_alert = False
            if time.time() - last_tr >= TRAFFIC_EVERY:
                sample_traffic()
                last_tr = time.time()
            prio_tick()
        except Exception as e:
            api_bad += 1
            log('ошибка наблюдателя:', e)
            if api_bad >= 3 and not api_alert:
                notify('dead', '🔴 <b>mihomo не отвечает</b>\n\nVPN на шлюзе не работает. '
                               'Попробуйте «🔧 Управление → ♻️ Перезапуск mihomo».')
                add_event('mihomo не отвечает')
                api_alert = True
        try:
            live = wg_live()['peers']
        except Exception:
            live = {}
        try:
            peers_tick(live)
        except Exception:
            log('peers_tick:', traceback.format_exc())
        try:
            route_tick()
        except Exception:
            log('route_tick:', traceback.format_exc())
        try:
            del_tick()
            backup_tick()
        except Exception:
            log('del/backup tick:', traceback.format_exc())
        if time.time() - last_srv >= 60:
            last_srv = time.time()
            try:
                srv_tick()
            except Exception:
                log('srv_tick:', traceback.format_exc())
        if time.time() - last_sub >= 3600:
            last_sub = time.time()
            try:
                sub_tick()
            except Exception:
                log('sub_tick:', traceback.format_exc())
        if os.path.exists(UPDATE_RESULT):
            report_update_result()
        if state.get('upd_pending') and time.time() - started > 300 and not os.path.exists(UPDATE_RESULT):
            with lock:
                state.pop('upd_pending', None)
                save_state()
        if time.time() - started > 120:
            try:
                update_tick()
            except Exception:
                log('update_tick:', traceback.format_exc())
        try:
            watched = [(pub, p) for pub, p in wg_state()['peers'].items() if p.get('monitor') and p['enabled']]
        except Exception:
            watched = []
        for pub, p in watched:
            lv = live.get(pub)
            down = not lv or lv['age'] is None or lv['age'] > WG_STALE
            tun_cnt[pub] = tun_cnt.get(pub, 0) + 1 if down else 0
            if tun_cnt[pub] >= 2 and not tun_alert.get(pub):
                extra = ('\nЕсли на MikroTik настроен резервный канал, он должен переключиться на него.'
                         if p['kind'] == 'mikrotik' else '')
                notify('tunnel', f'🔌 <b>Нет связи: {h(p["name"])}</b>\n\nТуннель WireGuard молчит.{extra}')
                add_event(f'Пропала связь: {p["name"]}')
                tun_alert[pub] = True
            elif not down and tun_alert.get(pub):
                notify('tunnel', f'🟢 <b>Связь восстановлена: {h(p["name"])}</b>')
                add_event(f'Связь восстановлена: {p["name"]}')
                tun_alert[pub] = False
        time.sleep(WATCH_EVERY)


def dispatch(u):
    try:
        if not LINK_MODE and gw_nodes() and gw_route(u):
            return
        if 'callback_query' in u:
            handle_callback(u['callback_query'])
        elif 'message' in u:
            handle_message(u['message'])
    except Exception:
        log(traceback.format_exc())


# ---------------- несколько шлюзов в одном боте ----------------
# Главный шлюз держит бота Telegram и сам подключается по SSH к ведомым шлюзам. На ведомом его ключ разрешён
# только для одной команды (restrict + forced command): переходник, который соединяет SSH-сессию с ботом ведомого.
# По этой сессии главный передаёт ведомому нажатия и сообщения тех, кто выбрал этот шлюз, а ведомый просит главного
# отправить ответы в Telegram. Своего бота ведомый не опрашивает.
LINK_DIR = '/var/lib/vpnbot/link'          # главный: свой ключ и ключи серверов ведомых (входит в бэкап)
LINK_SOCK = '/run/vpngw/link.sock'         # ведомый: сюда подключается переходник
LINK_USER = 'vpngw-link'
LINK_HOME = '/var/lib/vpngw-link'
LINK_PIPE = '/usr/local/lib/vpngw/link-pipe.py'
LINK_PIPE_SRC = r'''#!/usr/bin/python3
# Запускается sshd ведомого шлюза по ключу главного: соединяет SSH-сессию с ботом этого шлюза.
import os, select, socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/vpngw/link.sock')
except OSError:
    sys.stderr.write('vpngw-link: бот шлюза не запущен\n')
    sys.exit(1)
while True:
    r, _, _ = select.select([0, s], [], [])
    if 0 in r:
        d = os.read(0, 65536)
        if not d:
            break
        s.sendall(d)
    if s in r:
        d = s.recv(65536)
        if not d:
            break
        os.write(1, d)
'''
LINK_CALLS = {'sendMessage', 'editMessageText', 'editMessageReplyMarkup', 'deleteMessage', 'deleteMessages',
              'answerCallbackQuery', 'sendChatAction', 'getChat'}
CODE_PREFIX = 'VPNGW2-'
LINK_MODE = False             # этот бот — ведомый шлюз
links = {}                    # на главном: nid → живое соединение
links_lock = threading.Lock()
connectors = {}               # на главном: nid → поток, который держит соединение
link_cli = {'conn': None, 'up': False, 'n': 0, 'pending': {}, 'wlock': threading.Lock(),
            'nlock': threading.Lock(), 'since': 0}


# --- общее ---
def gw_nodes():
    return state.setdefault('nodes', {})


def gw_allowed(uid):
    """Какие шлюзы видит человек: 'm' — главный (этот), остальное — id ведомых."""
    ids = ['m'] + list(gw_nodes())
    if is_owner(uid):
        return ids
    a = state['admins'].get(str(uid)) or {}
    have = a.get('gw', ['m'])
    return [x for x in ids if x in have]


def gw_name(nid):
    return GW_NAME if nid == 'm' else (gw_nodes().get(nid) or {}).get('name', nid)


def gw_sel(uid):
    sel = ui.setdefault('gw', {}).get(str(uid), 'm')
    allowed = gw_allowed(uid)
    if sel not in allowed:
        sel = allowed[0] if allowed else 'm'
    return sel


def gw_set_sel(uid, nid):
    with ui_lock:
        ui.setdefault('gw', {})[str(uid)] = nid
    ui_save()


def gw_online(nid):
    with links_lock:
        return nid in links


def gw_row(uid):
    """Строка «шлюз» в главном меню: у ведомого всегда, у главного — если человеку доступно больше одного шлюза."""
    if LINK_MODE or len(gw_allowed(uid)) > 1:
        return [btn(f'🏢 Шлюз: {GW_NAME} ⇄'[:40], 'gws')]
    return None


def gw_prefix(text):
    """Уведомления помечаются шлюзом, когда шлюзов несколько."""
    if LINK_MODE or gw_nodes():
        return f'🏢 <i>{h(GW_NAME)}</i>\n' + text
    return text


def ssh_port():
    try:
        r = run(['sshd', '-T'], 10)
        m = re.search(r'^port (\d+)', r.stdout, re.M)
        return int(m.group(1)) if m else 22
    except Exception:
        return 22


def touch_alive():
    try:
        os.makedirs(os.path.dirname(ALIVE_FILE), exist_ok=True)
        with open(ALIVE_FILE, 'w') as f:
            f.write(str(time.time()))
    except Exception:
        pass


# --- главный: соединения с ведомыми ---
class Link:
    def __init__(self, nid, proc):
        self.nid, self.proc, self.wlock = nid, proc, threading.Lock()
        self.info, self.since, self.synced = {}, time.time(), None

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False) + '\n').encode()
        with self.wlock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.kill()
        except Exception:
            pass


def main_key():
    """Ключ главного шлюза: один на все ведомые. Возвращает открытую часть."""
    os.makedirs(LINK_DIR, mode=0o700, exist_ok=True)
    os.chmod(LINK_DIR, 0o700)
    key = f'{LINK_DIR}/id_ed25519'
    if not os.path.exists(key):
        r = run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'vpngw-main@{platform.node()}',
                 '-f', key], 30)
        if r.returncode != 0:
            raise RuntimeError('ssh-keygen: ' + (r.stderr or r.stdout)[-200:])
    return ' '.join(open(key + '.pub').read().split()[:2])


def gw_argv(nid, n):
    return ['ssh', '-T', '-i', f'{LINK_DIR}/id_ed25519', '-p', str(n['port']), '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={LINK_DIR}/known_{nid}', '-o', 'ConnectTimeout=15',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-o', 'LogLevel=ERROR',
            f'{LINK_USER}@{n["host"]}']


def gw_err_text(err):
    if not err:
        return ''
    if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in err or 'Host key verification failed' in err:
        return ('ключ SSH сервера изменился (сервер переустановлен или по этому адресу теперь другой сервер). '
                'Если вы его переустанавливали — нажмите «🔁 Принять новый ключ сервера».')
    if 'Permission denied' in err:
        return ('сервер не принял ключ главного: код подключения ещё не вставлен в бота этого шлюза '
                'или шлюз отключён от главного.')
    if re.search(r'timed out|No route|Network is unreachable', err):
        return 'сервер не отвечает по SSH: выключен, нет интернета или порт закрыт (проброс порта на роутере?).'
    if 'refused' in err:
        return 'на этом адресе и порту не запущен SSH.'
    if 'Could not resolve' in err:
        return 'не удалось найти адрес (ошибка в домене?).'
    if 'бот шлюза не запущен' in err:
        return 'бот на том шлюзе не запущен (systemctl status vpnbot).'
    return err[-200:]


def gw_connector(nid):
    """Держит соединение с одним ведомым шлюзом, пока он есть в списке."""
    delay = 5
    while LINK_MODE is False and nid in gw_nodes():
        n = dict(gw_nodes()[nid])
        err, ok = '', False
        try:
            p = subprocess.Popen(gw_argv(nid, n), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            lk = Link(nid, p)
            errs = []
            et = threading.Thread(target=lambda: errs.append(p.stderr.read().decode(errors='ignore')),
                                  daemon=True)
            et.start()
            try:
                lk.send({'t': 'welcome', 'nid': nid, 'name': n['name'], 'main': GW_NAME})
            except Exception:
                pass
            first = p.stdout.readline()
            msg = json.loads(first) if first.strip() else None
            if msg and msg.get('t') == 'hello' and msg.get('nid') == nid:
                ok = True
                gw_session(lk, msg)
            elif msg and msg.get('t') == 'hello':
                err = 'на этом адресе другой шлюз (код подключения от другого шлюза)'
            p.kill()
            p.wait(10)
            et.join(5)
            if not err:
                err = (errs[0] if errs else '').strip() or ('' if ok else 'соединение закрылось')
        except Exception as e:
            err = str(e)
        if nid not in gw_nodes():
            break
        with lock:
            gw_nodes()[nid]['err'] = '' if ok else err
            save_state()
        if not ok:
            delay = min(delay * 2, 60)
        else:
            delay = 5
        time.sleep(delay)
    with links_lock:
        connectors.pop(nid, None)


def gw_session(lk, hello):
    nid = lk.nid
    n = gw_nodes()[nid]
    with links_lock:
        old = links.get(nid)
        links[nid] = lk
    if old:
        old.close()
    lk.info = hello.get('info') or {}
    first = not n.get('paired')
    with lock:
        n['paired'] = True
        n['seen'] = time.time()
        n['err'] = ''
        save_state()
    try:
        gw_sync(lk)
        if first:
            add_event(f'Подключён шлюз {n["name"]}')
            notify('actions', f'🏢 Шлюз <b>{h(n["name"])}</b> подключён к этому боту.')
        elif n.get('alerted'):
            with lock:
                n['alerted'] = False
                save_state()
            notify('server', f'🟢 Шлюз <b>{h(n["name"])}</b> снова на связи.')
        for line in lk.proc.stdout:
            try:
                msg = json.loads(line)
            except Exception:
                continue
            t = msg.get('t')
            if t == 'info':
                lk.info = msg
                with lock:
                    n['seen'] = time.time()
                    n['ver'] = msg.get('ver')
            elif t in ('call', 'file', 'dl'):
                threading.Thread(target=link_exec, args=(lk, msg), daemon=True).start()
    except Exception as e:
        log('связь шлюзов:', e)
    finally:
        with links_lock:
            if links.get(nid) is lk:
                links.pop(nid)
        with lock:
            if nid in gw_nodes():
                gw_nodes()[nid]['seen'] = time.time()
                save_state()


def gw_chats(nid):
    return {int(a) for a in state['admins'] if nid in gw_allowed(int(a))}


def link_exec(lk, msg):
    """Вызов Telegram от ведомого шлюза — только разрешённые методы и только в чаты его админов."""
    res = None
    try:
        chats = gw_chats(lk.nid)
        t = msg['t']
        if t == 'call':
            m, p = msg.get('m'), msg.get('p') or {}
            if m == 'answerCallbackQuery' or (m in LINK_CALLS and 'chat_id' in p and int(p['chat_id']) in chats):
                res = tg(m, **p)
        elif t == 'file':
            if msg.get('m') in ('sendDocument', 'sendPhoto') and int(msg['chat']) in chats:
                res = tg_file(msg['m'], msg['chat'], msg['field'], msg['filename'],
                              base64.b64decode(msg['b64']), msg.get('caption'), msg.get('kb'), ttl_kind=None)
        elif t == 'dl':
            data = tg_download(msg['file_id'], min(int(msg.get('limit') or 65536), 20 << 20))
            res = base64.b64encode(data).decode() if data is not None else None
    except Exception as e:
        log('связь шлюзов: вызов', msg.get('m') or msg.get('t'), e)
    try:
        lk.send({'t': 'r', 'id': msg.get('id'), 'r': res})
    except Exception:
        pass


def gw_sync(lk):
    nid = lk.nid
    payload = {'t': 'sync', 'owner': OWNER, 'name': gw_name(nid), 'main': GW_NAME,
               'admins': {a: x['name'] for a, x in state['admins'].items() if nid in gw_allowed(int(a))}}
    if payload != lk.synced:
        lk.send(payload)
        lk.synced = payload


def gw_sync_all():
    with links_lock:
        cur = list(links.values())
    for lk in cur:
        try:
            gw_sync(lk)
        except Exception:
            pass


def gw_ensure_connectors():
    with links_lock:
        for nid in gw_nodes():
            if nid not in connectors:
                t = threading.Thread(target=gw_connector, args=(nid,), daemon=True)
                connectors[nid] = t
                t.start()


def gw_tick():
    """Главный: держит соединения, синхронизирует админов, тревожит, если ведомый пропал."""
    while True:
        try:
            gw_ensure_connectors()
            gw_sync_all()
            for nid, n in list(gw_nodes().items()):
                if not n.get('paired') or gw_online(nid) or n.get('alerted'):
                    continue
                if time.time() - (n.get('seen') or 0) > 180:
                    with lock:
                        n['alerted'] = True
                        save_state()
                    why = gw_err_text(n.get('err'))
                    notify('server', f'🔴 Шлюз <b>{h(n["name"])}</b> не на связи больше 3 минут.\n'
                                     'VPN на нём может работать, но управлять им сейчас нельзя.'
                                     + (f'\nПричина: {h(why)}' if why else ''))
        except Exception as e:
            log('связь шлюзов:', e)
        time.sleep(10)


def gw_route(u):
    """Главный: передать нажатие или сообщение выбранному ведомому шлюзу. True — передано."""
    cq = u.get('callback_query')
    m = u.get('message')
    src = (cq or m or {}).get('from') or {}
    uid = src.get('id')
    if not uid or not is_admin(uid):
        return False
    if cq:
        data = cq.get('data', '')
        if data in ('gws', 'ok', 'admins') or data.startswith(('gw:', 'acc:', 'rej:', 'adm:')):
            return False
        msg = cq.get('message') or {}
        with ui_lock:                     # кнопка в сообщении, которое прислал сам главный (его уведомление и т.п.)
            mine = str(msg.get('message_id')) in ui['msgs'].get(str(msg.get('chat', {}).get('id')), {})
        if mine:
            return False
    else:
        if (m.get('chat') or {}).get('type') != 'private' or uid in awaiting:
            return False
    sel = gw_sel(uid)
    if sel == 'm':
        return False
    if cq:
        awaiting.pop(uid, None)           # ввод, начатый на главном, больше не ждём
    with links_lock:
        lk = links.get(sel)
    if not lk:
        n = gw_nodes().get(sel) or {}
        why = gw_err_text(n.get('err'))
        text = (f'🔴 <b>Шлюз «{h(n.get("name", sel))}» не на связи</b>\n\n'
                + (f'Последняя связь: {fmt_ago(n["seen"])}.\n' if n.get('seen') else 'Он ещё ни разу не подключался.\n')
                + (f'Причина: {h(why)}\n' if why else '')
                + '\nВыберите другой шлюз или подождите — главный подключится к нему сам, как только сможет.')
        kb = [[btn('🏢 Шлюзы', 'gws')]]
        if cq:
            tg('answerCallbackQuery', callback_query_id=cq['id'])
            msg = cq.get('message') or {}
            CTX.chat = msg.get('chat', {}).get('id')
            edit(CTX.chat, msg.get('message_id'), text, kb)
        else:
            CTX.chat = m['chat']['id']
            if m.get('message_id'):
                tg('deleteMessage', chat_id=m['chat']['id'], message_id=m['message_id'])
            send(m['chat']['id'], text, kb)
        return True
    try:
        lk.send({'t': 'upd', 'u': u})
    except Exception as e:
        log('связь шлюзов: не передано', e)
        return False
    return True


# --- экраны главного ---
def scr_gws(uid, note=''):
    if LINK_MODE:                         # сюда ведомый не попадает: «gws» обрабатывает главный
        return scr_menu(uid)
    sel = gw_sel(uid)
    lines = ['🏢 <b>Шлюзы</b>', '', 'Какой шлюз открыть:', '']
    kb = []
    for nid in gw_allowed(uid):
        on = nid == 'm' or gw_online(nid)
        mark = '✅ ' if nid == sel else ''
        lines.append(f'{"🟢" if on else "🔴"} {mark}<b>{h(gw_name(nid))}</b>' + (' — главный' if nid == 'm' else ''))
        kb.append([btn(f'{mark}{"🟢" if on else "🔴"} {gw_name(nid)}'[:40], f'gw:s:{nid}')])
    if note:
        lines += ['', note]
    if is_owner(uid):
        kb.append([btn('⚙️ Управление шлюзами', 'gw:adm')])
    kb.append([btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_gw_adm(uid, note=''):
    lines = ['🏢 <b>Управление шлюзами</b>', '',
             'Этот шлюз — главный: у него бот Telegram. К ведомым шлюзам он сам подключается по SSH, '
             'их собственные боты молчат.', '',
             f'👑 <b>{h(GW_NAME)}</b> — главный, {h(platform.node())}']
    kb = []
    for nid, n in gw_nodes().items():
        on = gw_online(nid)
        st = ('🟢 на связи' if on else ('🔴 не на связи' if n.get('paired') else '⏳ ждёт кода'))
        lines.append(f'{"🟢" if on else "🔴"} <b>{h(n["name"])}</b> — {st} · <code>{h(n["host"])}:{n["port"]}</code>')
        kb.append([btn(f'{"🟢" if on else "🔴"} {n["name"]}'[:40], f'gw:n:{nid}')])
    lines += ['', 'Доступ админов к шлюзам: 👥 Админы → 🏢 у каждого админа.']
    if note:
        lines += ['', note]
    kb.append([btn('➕ Подключить шлюз', 'gw:new')])
    kb.append([btn('⬅️ Шлюзы', 'gws'), btn('🏠 Меню', 'menu')])
    return '\n'.join(lines), kb


def scr_gw_node(uid, nid, note=''):
    n = gw_nodes().get(nid)
    if not n:
        return scr_gw_adm(uid, '⚠️ Шлюз не найден')
    with links_lock:
        lk = links.get(nid)
    info = lk.info if lk else {}
    lines = [f'🏢 <b>{h(n["name"])}</b>', '', f'Адрес: <code>{h(n["host"])}:{n["port"]}</code> (SSH)']
    if lk:
        lines.append(f'🟢 На связи {fmt_dur(time.time() - lk.since)}')
        if info:
            lines.append(f'Сервер: {h(str(info.get("host", "?")))}, версия {h(str(info.get("ver", "?")))}')
            lines.append(f'Клиентов WireGuard: {info.get("peers", "?")} · mihomo: '
                         + ('🟢' if info.get('mihomo') else '🔴'))
    else:
        lines.append(f'🔴 Не на связи, последняя связь {fmt_ago(n.get("seen"))}' if n.get('paired') else
                     '⏳ Ждёт кода: вставьте код подключения в бота этого шлюза.')
        why = gw_err_text(n.get('err'))
        if why:
            lines.append(f'Причина: {h(why)}')
    admins = [x['name'] for a, x in state['admins'].items() if int(a) != OWNER and nid in gw_allowed(int(a))]
    lines.append('Админы: ' + (h(', '.join(admins)) if admins else 'только владелец'))
    if note:
        lines += ['', note]
    kb = [[btn('✏️ Переименовать', f'gw:ren:{nid}'), btn('🌐 Адрес', f'gw:addr:{nid}')],
          [btn('🔑 Код подключения', f'gw:code:{nid}')]]
    if 'IDENTIFICATION HAS CHANGED' in (n.get('err') or '') or 'Host key verification' in (n.get('err') or ''):
        kb.append([btn('🔁 Принять новый ключ сервера', f'gw:hk:{nid}')])
    kb += [[btn('🔌 Отключить шлюз', f'gw:del:{nid}')], [btn('⬅️ Шлюзы', 'gw:adm'), btn('🏠 Меню', 'menu')]]
    return '\n'.join(lines), kb


def gw_make_code(nid):
    n = gw_nodes()[nid]
    me = tg('getMe') or {}
    payload = {'v': 2, 'id': nid, 'name': n['name'], 'pub': main_key(), 'o': OWNER, 'bot': me.get('username', ''),
               'main': GW_NAME}
    return CODE_PREFIX + base64.urlsafe_b64encode(zlib.compress(json.dumps(payload).encode(), 9)).decode()


def gw_parse_code(text):
    t = re.sub(r'\s+', '', text or '')
    if not t.startswith(CODE_PREFIX):
        return None
    t = t[len(CODE_PREFIX):]
    try:
        c = json.loads(zlib.decompress(base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))))
    except Exception:
        return None
    if not isinstance(c, dict) or not all(isinstance(c.get(k), str) for k in ('id', 'pub', 'name')):
        return None
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', c['pub']) or not re.fullmatch(r'[0-9a-f]{8}', c['id']):
        return None
    return c


def gw_code_text(nid, code):
    n = gw_nodes()[nid]
    lines = [f'🔑 <b>Код подключения шлюза «{h(n["name"])}»</b>', '',
             '1. Откройте бота <b>того</b> шлюза, который подключаете.',
             '2. ⚙️ Настройки → 🏢 Шлюзы → 🔗 Подключить этот шлюз к главному боту.',
             '3. Отправьте ему этот код целиком (нажмите на код — он скопируется):', '',
             f'<code>{code}</code>', '',
             f'Потом этот бот сам подключится к тому серверу по SSH (<code>{h(n["host"])}:{n["port"]}</code>), '
             'бот того шлюза замолчит, а шлюз появится здесь: 🏢 Шлюз ⇄.', '',
             'Если тот сервер за роутером, на его роутере нужен проброс TCP-порта на SSH сервера. Для MikroTik:',
             f'<code>/ip firewall nat add chain=dstnat protocol=tcp dst-port={n["port"]} in-interface-list=WAN '
             f'action=dst-nat to-addresses=IP-сервера to-ports=22 comment="vpn-gateway: связь шлюзов"</code>', '',
             'В коде нет секретов: только открытый ключ этого бота. Подключиться по нему может лишь этот сервер. '
             'Сообщение удалится через час.']
    return '\n'.join(lines)


def gw_send_code(chat, nid):
    try:
        code = gw_make_code(nid)
    except Exception as e:
        raw_send(chat, f'🔴 Не удалось создать код: <code>{h(str(e))[:300]}</code>', ttl_kind='notif')
        return
    r = raw_send(chat, gw_code_text(nid, code))
    if r:
        track(chat, r['message_id'], 3600)


def gw_drop_node(nid):
    with lock:
        n = gw_nodes().pop(nid, None)
        for a in state['admins'].values():
            if nid in a.get('gw', []):
                a['gw'].remove(nid)
        save_state()
    with links_lock:
        lk = links.pop(nid, None)
    if lk:
        lk.close()
    try:
        os.remove(f'{LINK_DIR}/known_{nid}')
    except Exception:
        pass
    with ui_lock:
        for k, x in list(ui.get('gw', {}).items()):
            if x == nid:
                ui['gw'][k] = 'm'
    ui_save()
    return n


def handle_gw(uid, data, chat, mid):
    parts = data.split(':')
    act = parts[1] if len(parts) > 1 else ''
    nid = parts[2] if len(parts) > 2 else ''
    if act == 's':
        if nid not in gw_allowed(uid):
            return scr_gws(uid, '⚠️ Нет доступа к этому шлюзу')
        gw_set_sel(uid, nid)
        if nid == 'm':
            return scr_menu(uid)
        if not gw_online(nid):
            return scr_gws(uid, f'🔴 Шлюз «{h(gw_name(nid))}» сейчас не на связи. '
                                + h(gw_err_text(gw_nodes()[nid].get('err'))))
        # меню выбранного шлюза присылает он сам; старое меню убираем
        with ui_lock:
            if ui['menu'].get(str(chat)) == mid:
                ui['menu'].pop(str(chat), None)
        tg_del(chat, mid)
        gw_route({'message': {'chat': {'id': chat, 'type': 'private'},
                              'from': getattr(CTX, 'frm', None) or {'id': uid},
                              'text': '/start', 'message_id': 0, 'date': int(time.time())}})
        return None
    if not is_owner(uid):
        return scr_gws(uid)
    if act == 'set':
        if LINK_MODE:
            return scr_menu(uid)
        return scr_gw_adm(uid) if gw_nodes() else scr_gw_solo(uid)
    if act == 'solo':
        return scr_gw_solo(uid)
    if act == 'join':
        awaiting[uid] = ('gw_code', None)
        return ('🔗 <b>Подключение к главному боту</b>\n\nОтправьте код подключения из главного бота '
                '(🏢 Шлюзы → ⚙️ Управление шлюзами → ➕ Подключить шлюз).\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', 'gw:solo')]])
    if act == 'adm':
        return scr_gw_adm(uid)
    if act == 'new':
        awaiting[uid] = ('gw_name', None)
        return ('➕ <b>Новый шлюз</b>\n\nКак его назвать? Например <code>Офис</code> или <code>Москва-2</code>.'
                '\n\nОтмена: /cancel', [[btn('✖️ Отмена', 'gw:adm')]])
    if act == 'n':
        return scr_gw_node(uid, nid)
    if nid not in gw_nodes():
        return scr_gw_adm(uid, '⚠️ Шлюз не найден')
    n = gw_nodes()[nid]
    if act == 'ren':
        awaiting[uid] = ('gw_rename', nid)
        return (f'✏️ Новое имя для «{h(n["name"])}»?\n\nОтмена: /cancel', [[btn('✖️ Отмена', f'gw:n:{nid}')]])
    if act == 'addr':
        awaiting[uid] = ('gw_addr', nid)
        return (f'🌐 <b>Адрес шлюза «{h(n["name"])}»</b>\n\nСейчас: <code>{h(n["host"])}:{n["port"]}</code>.\n'
                'Отправьте новый: <code>адрес</code> или <code>адрес:порт</code>.\n\nОтмена: /cancel',
                [[btn('✖️ Отмена', f'gw:n:{nid}')]])
    if act == 'code':
        gw_send_code(chat, nid)
        return scr_gw_node(uid, nid, '🔑 Код отправлен отдельным сообщением.')
    if act == 'hk':
        try:
            os.remove(f'{LINK_DIR}/known_{nid}')
        except Exception:
            pass
        with lock:
            n['err'] = ''
            save_state()
        add_event(f'{admin_name(uid)}: принят новый ключ сервера шлюза {n["name"]}')
        return scr_gw_node(uid, nid, '🔁 Ключ сброшен: при следующем подключении будет принят новый.')
    if act == 'del':
        return (f'🔌 <b>Отключить шлюз «{h(n["name"])}»?</b>\n\nНа нём ничего не сломается: VPN продолжит работать, '
                'а его собственный бот снова заработает (если шлюз сейчас на связи). Если он не на связи, '
                'выполните на нём: <code>sudo python3 /usr/local/bin/vpnbot.py --unlink</code>',
                [[btn('🔌 Да, отключить', f'gw:dd:{nid}'), btn('✖️ Отмена', f'gw:n:{nid}')]])
    if act == 'dd':
        with links_lock:
            lk = links.get(nid)
        sent = False
        if lk:
            try:
                lk.send({'t': 'unlink'})
                sent = True
                time.sleep(1)
            except Exception:
                pass
        gw_drop_node(nid)
        add_event(f'Шлюз {n["name"]} отключён от бота')
        return scr_gw_adm(uid, f'🔌 Шлюз «{h(n["name"])}» отключён.' + (
            '' if sent else '\nОн был не на связи: выполните на нём '
                            '<code>sudo python3 /usr/local/bin/vpnbot.py --unlink</code>.'))
    return scr_gw_adm(uid)


HOST_PORT_RE = re.compile(r'^\s*(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::(\d{1,5}))?\s*$')


def parse_host_port(text):
    mt = HOST_PORT_RE.match(text or '')
    if not mt:
        return None
    port = int(mt.group(2) or 22)
    if not 1 <= port <= 65535:
        return None
    return mt.group(1).strip('[]'), port


def handle_gw_input(uid, chat, kind, wdata, text):
    if kind == 'gw_name':
        name = re.sub(r'\s+', ' ', text).strip()[:30]
        if not name:
            send(chat, 'Имя не может быть пустым. Или /cancel.')
            return
        awaiting[uid] = ('gw_host', name)
        send(chat, f'🌐 <b>Адрес шлюза «{h(name)}»</b>\n\nПо какому адресу этот бот будет подключаться к тому '
                   'серверу по SSH? Отправьте <code>IP</code>, <code>домен</code> или <code>адрес:порт</code>, '
                   'например <code>203.0.113.10</code> или <code>vpn2.example.com:2222</code>.\n\n'
                   'Если тот сервер в этой же сети — подойдёт его локальный IP. Если за роутером в другой сети — '
                   'внешний IP роутера и проброшенный порт.\n\nОтмена: /cancel',
             [[btn('✖️ Отмена', 'gw:adm')]])
        return
    if kind in ('gw_host', 'gw_addr'):
        hp = parse_host_port(text)
        if not hp:
            send(chat, 'Нужен адрес вида <code>203.0.113.10</code>, <code>vpn.example.com</code> '
                       'или <code>адрес:порт</code>. Или /cancel.')
            return
        awaiting.pop(uid, None)
        host, port = hp
        if kind == 'gw_host':
            nid = uuid.uuid4().hex[:8]
            with lock:
                gw_nodes()[nid] = {'v': 2, 'name': wdata, 'created': time.time(), 'host': host, 'port': port,
                                   'paired': False, 'err': ''}
                save_state()
            add_event(f'{admin_name(uid)} добавил шлюз {wdata} ({host}:{port})')
            t, kb = scr_gw_node(uid, nid, '🔑 Код подключения — в следующем сообщении.')
            send(chat, t, kb)
            gw_send_code(chat, nid)
            gw_ensure_connectors()
        else:
            if wdata in gw_nodes():
                with lock:
                    gw_nodes()[wdata].update(host=host, port=port, err='')
                    save_state()
                with links_lock:
                    lk = links.get(wdata)
                if lk:
                    lk.close()                 # переподключится уже по новому адресу
                try:
                    os.remove(f'{LINK_DIR}/known_{wdata}')
                except Exception:
                    pass
            t, kb = scr_gw_node(uid, wdata, '✅ Адрес изменён')
            send(chat, t, kb)
        return
    if kind == 'gw_rename':
        name = re.sub(r'\s+', ' ', text).strip()[:30]
        awaiting.pop(uid, None)
        if name and wdata in gw_nodes():
            with lock:
                gw_nodes()[wdata]['name'] = name
                save_state()
            gw_sync_all()
        t, kb = scr_gw_node(uid, wdata, '✅ Переименовано' if name else '')
        send(chat, t, kb)


def scr_adm_gw(uid, aid, note=''):
    a = state['admins'].get(aid)
    if not a:
        return scr_admins(uid, '⚠️ Админ не найден')
    have = a.get('gw', ['m'])
    lines = [f'🏢 <b>Шлюзы для {h(a["name"])}</b>', '', 'Отметьте, какими шлюзами этот админ может управлять:']
    if note:
        lines += ['', note]
    kb = [[btn((('✅ ' if nid in have else '▫️ ') + gw_name(nid))[:40], f'adm:gw:{aid}:{nid}')]
          for nid in ['m'] + list(gw_nodes())]
    kb.append([btn('⬅️ Админы', 'admins')])
    return '\n'.join(lines), kb


# --- ведомый ---
def link_write(obj):
    c = link_cli['conn']
    if not c or not link_cli['up']:
        raise RuntimeError('нет связи с главным ботом')
    data = (json.dumps(obj, ensure_ascii=False) + '\n').encode()
    with link_cli['wlock']:
        c.sendall(data)


def link_call(obj, timeout=60):
    with link_cli['nlock']:
        link_cli['n'] += 1
        i = link_cli['n']
    ev = threading.Event()
    link_cli['pending'][i] = [ev, None]
    obj['id'] = i
    try:
        link_write(obj)
        ev.wait(timeout)
        return link_cli['pending'][i][1]
    except Exception as e:
        log('связь с главным:', e)
        return None
    finally:
        link_cli['pending'].pop(i, None)


def link_info():
    try:
        ok = bool(api('/version'))
    except Exception:
        ok = False
    try:
        peers = len(wg_state()['peers'])
    except Exception:
        peers = '?'
    return {'t': 'info', 'ver': BOT_VERSION, 'host': platform.node(), 'peers': peers, 'mihomo': ok}


def link_apply_sync(msg):
    global OWNER, GW_NAME
    if not state.get('link'):
        return
    with lock:
        cfg = state['link']
        if msg.get('owner'):
            cfg['owner'] = OWNER = int(msg['owner'])
        if msg.get('name'):
            cfg['name'] = GW_NAME = msg['name']
        want = {str(a): n for a, n in (msg.get('admins') or {}).items()}
        want.setdefault(str(OWNER), str(OWNER))
        adm = state['admins']
        for a in list(adm):
            if a not in want:
                adm.pop(a)
        for a, name in want.items():
            adm.setdefault(a, {'name': name, 'notify': default_notify()})['name'] = name
        save_state()


def ensure_link_user(main_pub):
    """Ведомый: пользователь для входа главного, переходник и разрешённый ключ главного."""
    os.makedirs(os.path.dirname(LINK_PIPE), exist_ok=True)
    with open(LINK_PIPE + '.tmp', 'w') as f:
        f.write(LINK_PIPE_SRC)
    os.chmod(LINK_PIPE + '.tmp', 0o755)
    os.replace(LINK_PIPE + '.tmp', LINK_PIPE)
    if run(['id', LINK_USER], 5).returncode != 0:
        r = run(['useradd', '-r', '-m', '-d', LINK_HOME, '-s', '/bin/sh', LINK_USER], 30)
        if r.returncode != 0:
            raise RuntimeError('не удалось создать пользователя: ' + (r.stderr or '')[-200:])
    run(['usermod', '-p', '*', LINK_USER], 10)          # без пароля, но не заблокирован: вход только по ключу
    ssh = f'{LINK_HOME}/.ssh'
    os.makedirs(ssh, exist_ok=True)
    keys = f'{ssh}/authorized_keys'
    line = (f'restrict,command="/usr/bin/python3 {LINK_PIPE}" {main_pub}\n' if main_pub else '')
    with open(keys + '.tmp', 'w') as f:
        f.write(line)
    os.replace(keys + '.tmp', keys)
    for p, mode in ((LINK_HOME, 0o750), (ssh, 0o700), (keys, 0o600)):
        shutil.chown(p, LINK_USER, LINK_USER)
        os.chmod(p, mode)


def sshd_problem():
    """Почему главный не сможет войти по SSH на этот сервер (или '' если всё в порядке)."""
    if not shutil.which('sshd') and not os.path.exists('/usr/sbin/sshd'):
        return 'на сервере не установлен SSH-сервер: sudo apt install -y openssh-server'
    try:
        r = run(['sshd', '-T', '-C', f'user={LINK_USER},host=main,addr=127.0.0.1'], 10)
        cfg = r.stdout.lower()
        if re.search(r'^pubkeyauthentication no', cfg, re.M):
            return 'в настройках SSH выключен вход по ключам (PubkeyAuthentication no)'
        m = re.search(r'^allowusers (.+)$', cfg, re.M)
        if m and not any(x.split('@')[0] == LINK_USER for x in m.group(1).split()):
            return f'в настройках SSH стоит AllowUsers без {LINK_USER} — добавьте его в /etc/ssh/sshd_config'
        m = re.search(r'^denyusers (.+)$', cfg, re.M)
        if m and LINK_USER in m.group(1).split():
            return f'в настройках SSH пользователь {LINK_USER} запрещён (DenyUsers)'
    except Exception:
        pass
    return ''


def link_listener():
    """Ведомый: ждёт главного (переходник подключается к сокету) и обрабатывает его сообщения."""
    try:
        os.makedirs(os.path.dirname(LINK_SOCK), exist_ok=True)
        os.chmod(os.path.dirname(LINK_SOCK), 0o755)
        if os.path.exists(LINK_SOCK):
            os.remove(LINK_SOCK)
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(LINK_SOCK)
        shutil.chown(LINK_SOCK, 'root', LINK_USER)
        os.chmod(LINK_SOCK, 0o660)
        srv.listen(4)
    except Exception as e:
        log('связь с главным: сокет не открыт:', e)
        return
    while LINK_MODE:
        conn, _ = srv.accept()
        threading.Thread(target=link_conn, args=(conn,), daemon=True).start()


def link_conn(conn):
    f = conn.makefile('rb')
    try:
        first = json.loads(f.readline() or b'{}')
        cfg = state.get('link') or {}
        if first.get('t') != 'welcome':
            return
        if first.get('nid') != cfg.get('nid'):
            conn.sendall((json.dumps({'t': 'hello', 'nid': cfg.get('nid')}) + '\n').encode())
            return
        old = link_cli['conn']
        link_cli['conn'] = conn
        if old:
            try:
                old.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        link_cli['up'] = True
        link_cli['since'] = time.time()
        touch_alive()
        link_write({'t': 'hello', 'nid': cfg['nid'], 'info': link_info()})
        for line in f:
            try:
                msg = json.loads(line)
            except Exception:
                continue
            t = msg.get('t')
            if t == 'r':
                slot = link_cli['pending'].get(msg.get('id'))
                if slot:
                    slot[1] = msg.get('r')
                    slot[0].set()
            elif t == 'sync':
                link_apply_sync(msg)
            elif t == 'upd':
                threading.Thread(target=dispatch, args=(msg['u'],), daemon=True).start()
            elif t == 'unlink':
                link_off('главный бот отключил этот шлюз')
                return
    except Exception as e:
        log('связь с главным:', e)
    finally:
        if link_cli['conn'] is conn:
            link_cli['up'] = False
            link_cli['conn'] = None
            for slot in list(link_cli['pending'].values()):
                slot[0].set()
        try:
            conn.close()
        except Exception:
            pass


def link_heartbeat():
    while LINK_MODE:
        time.sleep(60)
        touch_alive()                     # для проверки обновления: бот жив, даже если главный недоступен
        if link_cli['up']:
            try:
                link_write(link_info())
            except Exception:
                pass


def link_off(why):
    """Стать снова самостоятельным: вернуть своих админов и перезапуститься со своим ботом."""
    with lock:
        cfg = state.pop('link', None) or {}
        if cfg.get('admins_local'):
            state['admins'] = cfg['admins_local']
        save_state()
    try:
        ensure_link_user('')                  # ключ главного больше не действует
    except Exception as e:
        log('связь с главным:', e)
    log('этот шлюз больше не ведомый:', why)
    add_event(f'Шлюз отключён от главного бота: {why}')
    subprocess.Popen(['systemctl', 'restart', 'vpnbot'])


def scr_gw_solo(uid, note=''):
    lines = ['🏢 <b>Шлюзы</b>', '',
             'Один бот может управлять несколькими шлюзами. Главный шлюз сам подключается к ведомым по SSH, '
             'боты ведомых молчат.', '',
             '➕ <b>Подключить другой шлюз сюда</b> — этот бот станет главным. Понадобится адрес того сервера, '
             'по которому до него можно достучаться по SSH отсюда.', '',
             '🔗 <b>Подключить этот шлюз к главному боту</b> — нужен код из главного бота. '
             'Этот бот после этого замолчит.']
    if note:
        lines += ['', note]
    kb = [[btn('➕ Подключить другой шлюз сюда', 'gw:new')],
          [btn('🔗 Подключить этот шлюз к главному', 'gw:join')],
          [btn('⬅️ Настройки', 'set'), btn('🏠 Меню', 'menu')]]
    return '\n'.join(lines), kb


def gw_join(uid, chat, text):
    awaiting.pop(uid, None)
    c = gw_parse_code(text)
    if not c:
        t, kb = scr_gw_solo(uid, '⚠️ Это не код подключения. Скопируйте его из главного бота целиком.')
        send(chat, t, kb)
        return
    if gw_nodes():
        t, kb = scr_gw_solo(uid, '⚠️ К этому боту уже подключены другие шлюзы — он главный. '
                                 'Сначала отключите их в «Управление шлюзами».')
        send(chat, t, kb)
        return
    if c.get('o') and int(c['o']) != OWNER:
        log('код подключения от другого владельца:', c.get('o'))
    prob = sshd_problem()
    if prob:
        t, kb = scr_gw_solo(uid, f'⚠️ Главный не сможет подключиться: {h(prob)}.')
        send(chat, t, kb)
        return
    try:
        ensure_link_user(c['pub'])
    except Exception as e:
        t, kb = scr_gw_solo(uid, f'🔴 Не удалось подготовить сервер: <code>{h(str(e))[:300]}</code>')
        send(chat, t, kb)
        return
    cfg = {'nid': c['id'], 'name': c['name'], 'owner': int(c.get('o') or OWNER), 'bot': c.get('bot', ''),
           'main': c.get('main', ''), 'main_pub': c['pub']}
    with lock:
        cfg['admins_local'] = json.loads(json.dumps(state['admins']))
        state['link'] = cfg
        save_state()
    add_event('Шлюз подключён к главному боту' + (f' @{cfg["bot"]}' if cfg['bot'] else ''))
    lan, pub = lan_ip(), public_ip()
    send(chat, '✅ <b>Готово: этот шлюз ждёт главного бота</b>' + (f' @{h(cfg["bot"])}' if cfg['bot'] else '') + '.\n\n'
         'В течение минуты главный подключится сюда по SSH, и шлюз появится в главном боте: 🏢 Шлюз ⇄ → '
         f'«{h(cfg["name"])}». Этот бот сейчас замолчит.\n\n'
         f'Адреса этого сервера: локальный <code>{h(lan or "?")}</code>, внешний <code>{h(pub or "?")}</code>, '
         f'SSH-порт {ssh_port()}. В главном боте должен быть указан адрес, по которому этот сервер доступен '
         'с главного (при необходимости — с пробросом порта на роутере).\n\n'
         'Если шлюз так и не появился: в главном боте откройте его — там будет причина. Вернуть этот бот: '
         '<code>sudo python3 /usr/local/bin/vpnbot.py --unlink</code>')
    time.sleep(1)
    subprocess.Popen(['systemctl', 'restart', 'vpnbot'])


RESTORED_FILE = '/var/lib/vpngw/restored.json'


def report_restored():
    """Первый запуск после восстановления из копии: установщик оставил отметку."""
    try:
        r = json.load(open(RESTORED_FILE, encoding='utf-8'))
    except Exception:
        r = {}
    try:
        os.remove(RESTORED_FILE)
    except Exception:
        pass
    port = wg_port()
    lines = ['♻️ <b>Шлюз восстановлен из резервной копии</b>', '',
             f'Копия от {h(r.get("created", "?"))}, сервер {h(r.get("from_host", "?"))}, версия {h(r.get("version", "?"))}.',
             f'Новый сервер: {h(platform.node())} ({h(lan_ip())}), бот {h(BOT_VERSION)}.',
             f'Клиентов WireGuard: {len(wg_state()["peers"])}, подписок: {len(subs())}.', '',
             '<b>Проверьте:</b>',
             f'• проброс UDP {port} на роутере ведёт на новый адрес <code>{h(lan_ip())}</code>;',
             '• домен для клиентов указывает на ваш внешний IP (🔐 WireGuard → 🌐 Адрес для подключения → 🔎);',
             '• старый сервер выключен — два бота с одним токеном мешают друг другу.']
    if r.get('new_link'):
        lines.append('• подписка привязана заново: старое устройство в личном кабинете можно удалить.')
    with lock:
        targets = [OWNER] if OWNER else []
    for uid in targets:
        raw_send(uid, '\n'.join(lines), [[btn('✔️ Понятно', 'ok'), btn('🏠 Меню', 'nmenu')]], ttl_kind='keep')
    add_event('Шлюз восстановлен из резервной копии')


def gw_startup_migrate():
    """Сброс связей в формате первой сборки 1.7 (там ведомый сам подключался к главному)."""
    cfg = state.get('link')
    if cfg and not cfg.get('main_pub'):           # схема первой сборки 1.7: ведомый сам ходил к главному
        log('связь с главным в старом формате — шлюз снова работает со своим ботом, подключите его заново')
        with lock:
            state.pop('link', None)
            if cfg.get('admins_local'):
                state['admins'] = cfg['admins_local']
            save_state()
        shutil.rmtree(LINK_DIR, ignore_errors=True)
        add_event('Связь с главным ботом сброшена после обновления — подключите шлюз заново новым кодом')
        cfg = None
    old = [nid for nid, n in (state.get('nodes') or {}).items() if n.get('v') != 2]
    if old:
        with lock:
            for nid in old:
                state['nodes'].pop(nid, None)
            save_state()
        add_event('Шлюзы, подключённые в старом формате, удалены из списка — подключите их заново новым кодом')
    return cfg


def startup_reports():
    if LINK_MODE:                         # сначала дождаться связи с главным ботом
        for _ in range(120):
            if link_cli['up']:
                break
            time.sleep(1)
    if os.path.exists(RESTORED_FILE):
        report_restored()
    elif os.path.exists(UPDATE_RESULT):
        report_update_result()
    elif not state.get('upd_pending'):
        notify('actions', f'✅ <b>Бот запущен</b> · версия {h(BOT_VERSION)}\nVPN-шлюз на связи.')


def main():
    global LINK_MODE, OWNER, GW_NAME
    load_state()
    cfg = gw_startup_migrate()
    if cfg:
        LINK_MODE = True
        OWNER = int(cfg.get('owner') or OWNER)
        GW_NAME = cfg.get('name') or GW_NAME
    ui_load()
    email_cfg()
    try:
        wg_state()
    except Exception as e:
        log('WireGuard будет прочитан позже:', e)
    try:
        vpn()
    except Exception as e:
        log('настройки VPN будут прочитаны позже:', e)
    if not LINK_MODE:
        keys = f'{LINK_HOME}/.ssh/authorized_keys'
        try:                                      # главный (или самостоятельный) шлюз чужих ключей не принимает
            if os.path.getsize(keys):
                open(keys, 'w').close()
        except OSError:
            pass
        threading.Thread(target=gw_tick, daemon=True).start()
    tg('setMyCommands', commands=[
        {'command': 'start', 'description': 'Главное меню'},
        {'command': 'status', 'description': 'Статус шлюза'},
        {'command': 'servers', 'description': 'Выбор сервера'},
        {'command': 'traffic', 'description': 'Трафик'},
        {'command': 'speed', 'description': 'Тест скорости'},
        {'command': 'server', 'description': 'Состояние сервера'},
        {'command': 'log', 'description': 'Журнал событий'},
        {'command': 'site', 'description': 'Куда идёт сайт: /site youtube.com'},
    ])
    threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=fmt_autoapply, daemon=True).start()
    if LINK_MODE:
        touch_alive()
        try:
            ensure_link_user(cfg.get('main_pub', ''))     # после восстановления из копии пользователя может не быть
        except Exception as e:
            log('связь с главным:', e)
        threading.Thread(target=link_listener, daemon=True).start()
        threading.Thread(target=link_heartbeat, daemon=True).start()
        threading.Thread(target=startup_reports, daemon=True).start()
        add_event('Бот запущен (ведомый шлюз)')
        log('бот запущен как ведомый шлюз, ждёт главного', cfg.get('bot', ''))
        while True:
            time.sleep(3600)
    startup_reports()
    add_event('Бот запущен')
    log('бот запущен, владелец', OWNER)
    offset = None
    while True:
        params = {'timeout': 25, 'allowed_updates': ['message', 'callback_query']}
        if offset:
            params['offset'] = offset
        res = tg('getUpdates', _timeout=35, **params)
        if res is None:
            time.sleep(3)
            continue
        try:
            os.makedirs(os.path.dirname(ALIVE_FILE), exist_ok=True)
            with open(ALIVE_FILE, 'w') as f:
                f.write(str(time.time()))
        except Exception:
            pass
        for u in res:
            offset = u['update_id'] + 1
            threading.Thread(target=dispatch, args=(u,), daemon=True).start()


def cli():
    # служебные команды для установщика: не требуют токена бота
    a = sys.argv[1:]
    if a[0] == '--render' and len(a) == 4:       # --render базовый.yaml параметры.json итог.yaml
        P = json.load(open(a[2], encoding='utf-8'))
        v = {'interval': P['interval'], 'tolerance': P['tolerance'], 'excluded': P['excluded'],
             'routing': P['routing'], 'rules_direct': P.get('rules_direct', []), 'rules_proxy': P.get('rules_proxy', [])}
        load_state()
        old = state.get('vpn') or {}
        v['rules_direct'] = P.get('rules_direct', old.get('rules_direct', []))
        v['rules_proxy'] = P.get('rules_proxy', old.get('rules_proxy', []))
        v['list_svc'] = old.get('list_svc', list(LIST_DEFAULT))
        state['subs'] = P['subs']
        ids = {x['id'] for x in P['subs']}
        v['svc'] = {k: x for k, x in (old.get('svc') or {}).items() if x in ids and k in SERVICES}
        out = render_config(open(a[1], encoding='utf-8').read(), v)
        with open(a[3], 'w', encoding='utf-8') as f:
            f.write(out)
        os.chmod(a[3], 0o600)
    elif a[0] == '--seed-vpn' and len(a) == 2:   # записать выбранные при установке настройки в состояние
        load_state()
        P = json.load(open(a[1], encoding='utf-8'))
        old = state.get('vpn') or {}
        v = {'mode': P['mode'], 'interval': P['interval'], 'tolerance': P['tolerance'], 'excluded': P['excluded'],
             'priority': old.get('priority', []), 'manual': False, 'routing': P['routing'],
             'rules_direct': old.get('rules_direct', []), 'rules_proxy': old.get('rules_proxy', []),
             'list_svc': old.get('list_svc', list(LIST_DEFAULT))}
        state['subs'] = P['subs']
        ids = {x['id'] for x in P['subs']}
        v['svc'] = {k: x for k, x in (old.get('svc') or {}).items() if x in ids and k in SERVICES}
        v['applied'] = dict(snapshot(v), mode=v['mode'])
        state['vpn'] = v
        save_state()
    elif a[0] == '--subs':                        # текущие подписки (для установщика)
        load_state()
        print(json.dumps(subs(), ensure_ascii=False))
    elif a[0] == '--vpn':                         # текущие настройки переключения (для установщика)
        load_state()
        print(json.dumps(state.get('vpn') or {}, ensure_ascii=False))
    elif a[0] == '--unlink':                     # ведомый шлюз снова работает со своим ботом
        load_state()
        if not state.get('link'):
            print('Этот шлюз и так работает со своим ботом.')
        else:
            link_off('отключён командой --unlink')
            print('Готово: шлюз отключён от главного бота, его собственный бот перезапускается.')
    elif a[0] == '--mark-applied':               # после восстановления: конфиг mihomo собран из текущих настроек
        load_state()
        v = state.get('vpn')
        if v:
            v['applied'] = dict(snapshot(vpn_migrate(v)), mode=v['mode'])
            save_state()
    elif a[0] == '--mt-check' and len(a) == 5:  # --mt-check вывод.txt подсеть(10.10.10) порт IP-сервера (для установщика)
        info = mt_parse(open(a[1], encoding='utf-8', errors='ignore').read())
        tunnel = ipaddress.ip_network(f'{a[2]}.0/24')
        nets = [str(x.network) for x, _ in info['addrs']]
        used = set(info['ports'])
        port = int(a[3])
        free_port = port
        while free_port in used:
            free_port += 10
        print(json.dumps({
            'addrs': len(info['addrs']), 'wg': len(info['ports']),
            'net_conflict': [f'{x} ({i})' if i else str(x) for x, i in info['addrs'] if x.network.overlaps(tunnel)],
            'port_used_by': info['ports'].get(port),
            'free_net': free_wg_net(nets, [a[4]]), 'free_port': free_port,
            'local': any(ipaddress.ip_address(a[4]) in x.network for x, _ in info['addrs']) if a[4] else False},
            ensure_ascii=False))
    elif a[0] == '--version':
        print(BOT_VERSION)
    else:
        sys.exit('неизвестная команда: ' + ' '.join(a))


if __name__ == '__main__':
    if CLI_MODE:
        cli()
    else:
        main()
