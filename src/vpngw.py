#!/usr/bin/env python3
# vpngw — служебная утилита VPN-шлюза (mihomo + WireGuard).
# Без аргументов — меню бота прямо в консоли; vpngw help — все команды. Работает и без Telegram.
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

STATE = '/var/lib/vpnbot/state.json'
CONF = '/etc/vpngw/install.conf'
WGC = '/etc/wireguard/wg0.conf'
OUT = '/root/wg-clients'
STUB_RE = re.compile(r'поддерживается|Превышено|устройств|not supported|limit', re.I)
KINDS = {'phone': 'телефон', 'pc': 'компьютер', 'mikrotik': 'MikroTik', 'device': 'устройство'}


# ---------------- общие ----------------
def sh(cmd, inp=None, check=False):
    r = subprocess.run(cmd, input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f'Ошибка: {" ".join(cmd)}: {r.stderr.strip()}')
    return r


def read_conf():
    c = {}
    try:
        for line in open(CONF, encoding='utf-8'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
                    v = v[1:-1]
                c[k.strip()] = v
    except FileNotFoundError:
        pass
    return c


def load_state():
    try:
        with open(STATE, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(st, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


class BotPaused:
    """Бот держит состояние в памяти — на время правки его нужно остановить."""
    def __enter__(self):
        self.was = sh(['systemctl', 'is-active', '--quiet', 'vpnbot']).returncode == 0
        if self.was:
            sh(['systemctl', 'stop', 'vpnbot'])
        return self

    def __exit__(self, *a):
        if self.was:
            sh(['systemctl', 'start', 'vpnbot'])


def translit(name):
    tr = dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
                  ['a', 'b', 'v', 'g', 'd', 'e', 'e', 'zh', 'z', 'i', 'y', 'k', 'l', 'm', 'n', 'o', 'p', 'r', 's',
                   't', 'u', 'f', 'h', 'ts', 'ch', 'sh', 'sch', '', 'y', '', 'e', 'yu', 'ya']))
    lat = ''.join(tr.get(c.lower(), c) for c in name)
    return (re.sub(r'[^A-Za-z0-9_-]+', '_', lat).strip('_') or 'peer')[:15]


# ---------------- подписка ----------------
def vless_to_proxy(link):
    u = urllib.parse.urlsplit(link.strip())
    if u.scheme != 'vless' or not u.hostname:
        return None
    qs = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    name = urllib.parse.unquote(u.fragment) or f'{u.hostname}:{u.port}'
    p = {'name': name, 'type': 'vless', 'server': u.hostname, 'port': int(u.port or 443),
         'uuid': urllib.parse.unquote(u.username or ''), 'udp': True, 'network': qs.get('type', 'tcp')}
    sec = qs.get('security', 'none')
    if sec in ('tls', 'reality'):
        p['tls'] = True
        if qs.get('sni'):
            p['servername'] = qs['sni']
        if qs.get('fp'):
            p['client-fingerprint'] = qs['fp']
    if sec == 'reality':
        # mlkem: Xray ≥ 26.9.8 без него не пускает клиента (mihomo ≥ 1.19.9 понимает), старым серверам не мешает
        p['reality-opts'] = {'public-key': qs.get('pbk', ''), 'short-id': qs.get('sid', ''),
                             'support-x25519mlkem768': True}
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


def links_from(text):
    t = text.strip()
    if 'vless://' not in t:
        try:
            t = base64.b64decode(t + '=' * (-len(t) % 4)).decode('utf-8', 'ignore')
        except Exception:
            return []
    return [x for x in re.split(r'\s+', t) if x.startswith('vless://')]


def yaml_names(text):
    sec = ('\n' + text).split('\nproxies:', 1)
    if len(sec) < 2:
        return []
    body = re.split(r'\n[A-Za-z][\w-]*:', sec[1], maxsplit=1)[0]
    names = []
    for m in re.finditer(r'^\s*-\s*(?:\{\s*)?["\']?name["\']?\s*:\s*(.+?)\s*$', body, re.M):
        n = m.group(1).rstrip(',}').strip()
        if len(n) >= 2 and n[0] == n[-1] and n[0] in '"\'':
            n = n[1:-1]
        names.append(n)
    return names


def cmd_analyze(path):
    """Печатает: OK, STUB_APP, LIMIT, EMPTY, а потом имена серверов по одному в строке."""
    text = open(path, encoding='utf-8', errors='ignore').read()
    names = yaml_names(text) or [p['name'] for p in map(vless_to_proxy, links_from(text)) if p]
    real = [n for n in names if not STUB_RE.search(n)]
    if real:
        print('OK')
        print('\n'.join(real))
    elif any(re.search('Превышено|устройств|limit', n, re.I) for n in names):
        print('LIMIT')
    elif names:
        print('STUB_APP')
    else:
        print('EMPTY')


def cmd_links2yaml(src, dst):
    proxies = [p for p in map(vless_to_proxy, links_from(open(src, encoding='utf-8').read())) if p]
    if not proxies:
        sys.exit('Не найдено ни одной ссылки vless://')
    with open(dst, 'w', encoding='utf-8') as f:
        f.write('proxies:\n' + ''.join(f'  - {json.dumps(p, ensure_ascii=False)}\n' for p in proxies))
    os.chmod(dst, 0o600)
    print('\n'.join(p['name'] for p in proxies))


# ---------------- конфиг mihomo ----------------
def cmd_gen_base(params_json, dst):
    """Базовая часть конфига (порты, TUN). Сниффер, подписки, DNS, группы и правила добавляет vpnbot.py --render."""
    P = json.load(open(params_json, encoding='utf-8'))
    q = lambda s: json.dumps(s, ensure_ascii=False)
    out = [
        'mixed-port: 7890', 'bind-address: 127.0.0.1', 'allow-lan: false', 'mode: rule', 'log-level: warning',
        'ipv6: false', 'external-controller: 127.0.0.1:9090', f'secret: {P["secret"]}', '',
        'tun:', '  enable: true', '  device: mihomo', '  stack: system', '  mtu: 1500',
        '  auto-route: false', '  auto-detect-interface: false', '  dns-hijack:', '    - any:53', '',
        ]   # сниффер, DNS, группы и правила дописывает vpnbot.py --render
    with open(dst, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')
    os.chmod(dst, 0o600)


# ---------------- WireGuard ----------------
def wg_state(st):
    c = read_conf()
    w = st.get('wg')
    if w is None:
        w = {'endpoint': c.get('WG_ENDPOINT', ''), 'peers': {}}
        st['wg'] = w
    return w


def net():
    return read_conf().get('WG_NET', '10.10.10')


def endpoint(w):
    c = read_conf()
    ep = w.get('endpoint') or c.get('WG_ENDPOINT', '')
    if ':' not in ep:
        ep = f'{ep}:{c.get("WG_PORT", "51820")}'
    return ep


def write_wg(w):
    txt = open(WGC, encoding='utf-8').read()
    head = txt.split('[Peer]')[0].rstrip() + '\n'
    blocks = ''
    for pub, p in w['peers'].items():
        if p.get('enabled', True):
            blocks += f'\n[Peer]\n# {p["name"]}\nPublicKey = {pub}\n'
            if p.get('psk'):
                blocks += f'PresharedKey = {p["psk"]}\n'
            blocks += f'AllowedIPs = {p["ip"]}/32\n'
    shutil.copy2(WGC, WGC + '.bak')
    with open(WGC + '.tmp', 'w', encoding='utf-8') as f:
        f.write(head + blocks)
    os.chmod(WGC + '.tmp', 0o600)
    os.replace(WGC + '.tmp', WGC)
    if sh(['systemctl', 'is-active', '--quiet', 'wg-quick@wg0']).returncode == 0:
        sh(['bash', '-c', 'wg syncconf wg0 <(wg-quick strip wg0)'], check=True)


def client_conf(w, pub):
    p = w['peers'][pub]
    spub = sh(['wg', 'show', 'wg0', 'public-key']).stdout.strip()
    if not spub:
        m = re.search(r'^PrivateKey\s*=\s*(\S+)', open(WGC, encoding='utf-8').read(), re.M)
        spub = sh(['wg', 'pubkey'], inp=m.group(1) + '\n').stdout.strip()
    mtu = 1280 if p['kind'] in ('phone', 'device') else 1380
    # DNS внутри туннеля (его перехватывает mihomo), ::/0 у телефонов — чтобы IPv6 не шёл мимо VPN (как в боте)
    allowed = '0.0.0.0/0, ::/0' if p['kind'] in ('phone', 'device') else '0.0.0.0/0'
    return '\n'.join(['[Interface]', f'PrivateKey = {p["priv"]}', f'Address = {p["ip"]}/32', f'DNS = {net()}.53',
                      f'MTU = {mtu}', '', '[Peer]', f'PublicKey = {spub}', f'PresharedKey = {p["psk"]}',
                      f'Endpoint = {endpoint(w)}', f'AllowedIPs = {allowed}', 'PersistentKeepalive = 25', ''])


def save_client_file(w, pub):
    os.makedirs(OUT, exist_ok=True)
    os.chmod(OUT, 0o700)
    path = os.path.join(OUT, translit(w['peers'][pub]['name']) + '.conf')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(client_conf(w, pub))
    os.chmod(path, 0o600)
    return path


def find_peer(w, key):
    items = list(w['peers'].items())
    if key.isdigit() and 1 <= int(key) <= len(items):
        return items[int(key) - 1][0]
    for pub, p in items:
        if p['name'].lower() == key.lower():
            return pub
    sys.exit(f'Клиент «{key}» не найден. Список: vpngw peers')


def cmd_add(name, kind):
    if kind not in ('phone', 'pc'):
        sys.exit('Тип клиента: phone или pc')
    with BotPaused():
        st = load_state()
        w = wg_state(st)
        if any(p['name'].lower() == name.lower() for p in w['peers'].values()):
            sys.exit(f'Клиент «{name}» уже есть')
        used = {p['ip'] for p in w['peers'].values()}
        ip = next((f'{net()}.{n}' for n in range(2, 255) if n != 53 and f'{net()}.{n}' not in used), None)
        if not ip:
            sys.exit('Закончились свободные адреса')
        priv = sh(['wg', 'genkey'], check=True).stdout.strip()
        pub = sh(['wg', 'pubkey'], inp=priv + '\n', check=True).stdout.strip()
        psk = sh(['wg', 'genpsk'], check=True).stdout.strip()
        w['peers'][pub] = {'name': name, 'kind': kind, 'ip': ip, 'psk': psk, 'priv': priv, 'enabled': True,
                           'monitor': False, 'created': time.time()}
        save_state(st)
        write_wg(w)
        print(save_client_file(w, pub))


def cmd_peers():
    w = wg_state(load_state())
    live = {}
    for ln in sh(['wg', 'show', 'wg0', 'latest-handshakes']).stdout.splitlines():
        f = ln.split()
        if len(f) == 2:
            live[f[0]] = int(f[1])
    if not w['peers']:
        print('Клиентов пока нет. Добавить: vpngw add "Имя" phone|pc')
        return
    for i, (pub, p) in enumerate(w['peers'].items(), 1):
        ts = live.get(pub, 0)
        reason = {'expired': 'срок истёк', 'limit': 'лимит исчерпан'}.get(p.get('off_reason'), 'выключен')
        st = reason if not p.get('enabled', True) else (
            'ещё не подключался' if not ts else f'был {int(time.time() - ts)} с назад')
        extra = ''
        if p.get('expires'):
            extra += ' до ' + time.strftime('%d.%m.%Y', time.localtime(p['expires']))
        if p.get('limit'):
            extra += f' лимит {p["limit"] / (1 << 30):.0f} ГБ/мес'
        print(f'{i:>2}. {p["name"]:<24} {KINDS.get(p["kind"], p["kind"]):<10} {p["ip"]:<14} {st}{extra}')


def cmd_qr(key):
    w = wg_state(load_state())
    pub = find_peer(w, key)
    if not w['peers'][pub].get('priv'):
        sys.exit('Этот клиент добавлен вручную, его ключа у шлюза нет.')
    conf = client_conf(w, pub)
    path = save_client_file(w, pub)
    print(f'\n  {w["peers"][pub]["name"]} — файл: {path}\n')
    subprocess.run(['qrencode', '-t', 'ansiutf8', '-m', '2'], input=conf.encode())


def cmd_status():
    for unit in ('mihomo', 'wg-quick@wg0', 'vpnbot'):
        r = sh(['systemctl', 'is-active', unit]).stdout.strip() or 'нет'
        print(f'{unit:<14} {r}')
    # ifconfig.me в конфиге идёт напрямую (из-за проверок MAX), поэтому адрес выхода — через icanhazip
    ip = sh(['curl', '-4', '-s', '-m', '10', '-x', 'http://127.0.0.1:7890', 'https://ipv4.icanhazip.com']).stdout.strip()
    print(f'{"IP через VPN":<14} {ip or "нет ответа"}')


# ---------------- консоль: меню, команды бота, живая панель ----------------
BOT = '/usr/local/bin/vpnbot.py'
SOCK = '/run/vpngw/cli.sock'
MIHOMO_CFG = '/etc/mihomo/config.yaml'
API = 'http://127.0.0.1:9090'
LOCAL = {}                       # команды, которые выполняет сама утилита (заполняется ниже)


def plain(text):
    import html
    text = re.sub(r'<a [^>]*href="([^"]+)"[^>]*>(.*?)</a>', r'\2 (\1)', text or '')
    return html.unescape(re.sub(r'<[^>]+>', '', text))


def bot_events(req):
    """Запрос к боту: через сокет запущенного бота, иначе — тот же код напрямую. Отдаёт события по одному."""
    import socket
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(SOCK)
        f = s.makefile('rwb')
        f.write(json.dumps(req, ensure_ascii=False).encode() + b'\n')
        f.flush()
        lines = (ln.decode('utf-8', 'replace') for ln in f)
    except OSError:
        p = subprocess.Popen(['python3', BOT, '--cli-direct', json.dumps(req, ensure_ascii=False)],
                             stdout=subprocess.PIPE, text=True)
        lines = p.stdout
    for ln in lines:
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        if ev.get('t') == 'done':
            return
        yield ev


def show_screen(scr, numbered=True):
    print(plain(scr.get('text', '')).strip())
    btns = [b for row in scr.get('kb') or [] for b in row]
    if numbered and btns:
        print()
        for i, b in enumerate(btns, 1):
            print(f'  {i:>2}. {b["text"]}' + (f'  → {b["url"]}' if b.get('url') else ''))
    return btns


def bot_cmd(req):
    """vpngw <команда бота>: промежуточные экраны — одной строкой, итоговый — целиком."""
    last, rc = None, 1
    for ev in bot_events(req):
        rc = 0 if rc == 1 and ev['t'] != 'err' else rc
        if ev['t'] == 'screen':
            if last:
                print('⏳ ' + plain(last['text']).strip().split('\n')[0][:150])
            last = ev
        elif ev['t'] == 'out':
            print(ev['text'])
        elif ev['t'] == 'err':
            print(ev['text'], file=sys.stderr)
            rc = 2
    if last:
        show_screen(last, numbered=False)
    return rc


def cmd_menu():
    """Меню бота в консоли: те же экраны и кнопки, выбор цифрой; текст — как сообщение боту."""
    req = {'press': 'menu'}
    while True:
        scr, errs = None, []
        for ev in bot_events(req):
            if ev['t'] == 'screen':
                scr = ev
                if sys.stdout.isatty():
                    print('\033[2J\033[H', end='')
                print('⏳ ' + plain(ev['text']).strip().split('\n')[0][:150], flush=True)
            elif ev['t'] in ('out', 'err'):
                errs.append(ev['text'])
        if sys.stdout.isatty():
            print('\033[2J\033[H', end='')
        print(f'━━ VPN-шлюз · меню консоли ━━ (q — выход, цифра — кнопка, текст — ответ боту)\n')
        btns = show_screen(scr) if scr else []
        for e in errs:
            print('\n' + e)
        try:
            ans = input('\n> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ans.lower() in ('q', 'й', 'exit', 'выход'):
            return
        if ans.isdigit() and 1 <= int(ans) <= len(btns):
            b = btns[int(ans) - 1]
            if b.get('data'):
                req = {'press': b['data']}
            else:
                print(f'Ссылка: {b.get("url")}')
                input('Enter — назад к меню ')
                req = {'press': 'menu'}
        elif ans:
            req = {'text': ans}
        else:
            req = {'press': 'menu'}


def mihomo_secret():
    try:
        return re.search(r'^secret:\s*(\S+)', open(MIHOMO_CFG, encoding='utf-8').read(), re.M).group(1)
    except Exception:
        return ''


def mapi(path, timeout=3):
    import urllib.request
    req = urllib.request.Request(API + path, headers={'Authorization': 'Bearer ' + mihomo_secret()})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return json.load(r)


SPARK = '▁▂▃▄▅▆▇█'


def spark(vals, top=None):
    if not vals:
        return ''
    top = top or max(vals) or 1
    return ''.join(SPARK[min(int(v / top * (len(SPARK) - 1) + 0.5), len(SPARK) - 1)] for v in vals)


def cpu_times():
    f = open('/proc/stat').readline().split()[1:]
    vals = list(map(int, f))
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals), idle


def default_iface():
    r = sh(['ip', 'route', 'show', 'default'])
    m = re.search(r'\bdev (\S+)', r.stdout)
    return m.group(1) if m else None


def iface_bytes(name):
    for ln in open('/proc/net/dev'):
        if ln.strip().startswith(name + ':'):
            f = ln.split(':', 1)[1].split()
            return int(f[0]), int(f[8])
    return 0, 0


def cmd_top():
    """Живая панель: процессор, память, сеть, соединения, сервер — каждую секунду, Ctrl+C — выход."""
    iface = default_iface() or 'eth0'
    hist = {'cpu': [], 'rx': [], 'tx': []}
    t0, i0 = cpu_times()
    rx0, tx0 = iface_bytes(iface)
    w0 = iface_bytes('wg0')
    ts0 = time.time()
    try:
        while True:
            time.sleep(1)
            t1, i1 = cpu_times()
            cpu = 100 * (1 - (i1 - i0) / max(t1 - t0, 1))
            t0, i0 = t1, i1
            now = time.time()
            dt = max(now - ts0, 0.001)
            ts0 = now
            rx1, tx1 = iface_bytes(iface)
            rx, tx = (rx1 - rx0) * 8 / dt / 1e6, (tx1 - tx0) * 8 / dt / 1e6
            rx0, tx0 = rx1, tx1
            w1 = iface_bytes('wg0')
            wrx, wtx = (w1[0] - w0[0]) * 8 / dt / 1e6, (w1[1] - w0[1]) * 8 / dt / 1e6
            w0 = w1
            for k, v in (('cpu', cpu), ('rx', rx), ('tx', tx)):
                hist[k] = (hist[k] + [v])[-40:]
            mem = {}
            for ln in open('/proc/meminfo'):
                k, v = ln.split(':', 1)
                mem[k] = int(v.split()[0]) // 1024
            used = mem.get('MemTotal', 0) - mem.get('MemAvailable', 0)
            try:
                conns = len(mapi('/connections').get('connections') or [])
                cur = mapi('/proxies/PROXY').get('now', '?')
                if cur in ('AUTO', 'PRIO'):
                    cur = cur + ' → ' + mapi(f'/proxies/{urllib.parse.quote(cur)}').get('now', '?')
                mh = 'работает'
            except Exception:
                conns, cur, mh = 0, '—', '❌ не отвечает'
            peers = 0
            for ln in sh(['wg', 'show', 'wg0', 'latest-handshakes']).stdout.splitlines():
                f = ln.split()
                if len(f) == 2 and f[1] != '0' and time.time() - int(f[1]) < 180:
                    peers += 1
            load = open('/proc/loadavg').read().split()[:3]
            print('\033[2J\033[H', end='')
            print(f'VPN-шлюз · {time.strftime("%H:%M:%S")} · Ctrl+C — выход\n')
            print(f'Процессор  {spark(hist["cpu"], 100):<40} {cpu:5.1f}%   нагрузка {" ".join(load)}')
            print(f'Память     {used} / {mem.get("MemTotal", 0)} МБ ({100 * used // max(mem.get("MemTotal", 1), 1)}%)')
            top_net = max(hist['rx'] + hist['tx'] + [1])
            print(f'Сеть ↓     {spark(hist["rx"], top_net):<40} {rx:6.1f} Мбит/с  ({iface})')
            print(f'Сеть ↑     {spark(hist["tx"], top_net):<40} {tx:6.1f} Мбит/с')
            print(f'WireGuard  ↓ {wrx:.1f} ↑ {wtx:.1f} Мбит/с · на связи клиентов: {peers}')
            print(f'mihomo     {mh} · соединений: {conns}')
            print(f'Сервер     {cur}')
    except KeyboardInterrupt:
        print()


def cmd_del(key):
    with BotPaused():
        st = load_state()
        w = wg_state(st)
        pub = find_peer(w, key)
        name = w['peers'][pub]['name']
        w['peers'].pop(pub)
        save_state(st)
        write_wg(w)
    for ext in ('.conf', '.rsc'):     # .rsc — от прежних версий
        p = os.path.join(OUT, translit(name) + ext)
        if os.path.exists(p):
            os.remove(p)
    print(f'Клиент «{name}» удалён.')


def cmd_restart(what):
    units = {'mihomo': ['mihomo'], 'bot': ['vpnbot'], 'wg': ['wg-quick@wg0'],
             'all': ['mihomo', 'wg-quick@wg0', 'vpnbot']}.get(what)
    if not units:
        sys.exit('vpngw restart <mihomo|bot|wg|all>')
    for u in units:
        r = sh(['systemctl', 'restart', u])
        print(f'{u}: {"перезапущен" if r.returncode == 0 else "ошибка: " + r.stderr.strip()}')


def cmd_logs(what, n='60'):
    files = {'install': '/var/log/vpngw-install.log', 'os': '/var/log/vpngw-os-upgrade.log'}
    units = {'bot': 'vpnbot', 'mihomo': 'mihomo', 'wg': 'wg-quick@wg0', 'zapret': 'vpngw-zapret'}
    if what in files:
        subprocess.run(['tail', '-n', str(n), files[what]])
    elif what in units:
        subprocess.run(['journalctl', '-u', units[what], '-n', str(n), '--no-pager'])
    else:
        sys.exit('vpngw logs <bot|mihomo|wg|zapret|install|os> [строк]')


def cmd_rollback():
    if sys.stdin.isatty() and input('Вернуть версию до последнего обновления? [y/N] ').strip().lower() not in ('y', 'д', 'да', 'yes'):
        return
    subprocess.run(['bash', '/usr/local/lib/vpngw/install.sh', '--rollback', 'вручную из консоли'])


LOCAL.update({
    'menu': (cmd_menu, (0, 0)), 'top': (cmd_top, (0, 0)), 'del': (cmd_del, (1, 1)),
    'restart': (cmd_restart, (1, 1)), 'logs': (cmd_logs, (1, 2)),
    'rollback': (cmd_rollback, (0, 0)),
})


HELP_LOCAL = """Управление VPN-шлюзом из консоли (нужен sudo). Без команды — меню.
  vpngw menu | status | top | peers | add "Имя" phone|pc | qr "Имя" | del "Имя"
  vpngw restart <служба> | logs <служба> [N] | rollback
Полная справка — vpngw help (её даёт бот; если он не отвечает, работают команды выше)."""


def main():
    a = sys.argv[1:]
    service = {'analyze': (cmd_analyze, (1, 1)), 'links2yaml': (cmd_links2yaml, (2, 2)),
               'gen-base': (cmd_gen_base, (2, 2))}
    local = dict(LOCAL, add=(cmd_add, (2, 2)), peers=(cmd_peers, (0, 0)), qr=(cmd_qr, (1, 1)),
                 status=(cmd_status, (0, 0)))
    if a and a[0] in service:
        fn, (lo, hi) = service[a[0]]
        if not lo <= len(a) - 1 <= hi:
            sys.exit('неверные аргументы')
        return fn(*a[1:])
    if os.geteuid() != 0:
        sys.exit('Нужны права root: sudo vpngw ' + ' '.join(a))
    if not a:
        if sys.stdin.isatty():
            return cmd_menu()
        a = ['help']
    if a[0] in ('-h', '--help'):
        a = ['help']
    if a[0] in local:
        fn, (lo, hi) = local[a[0]]
        if not lo <= len(a) - 1 <= hi:
            print(HELP_LOCAL)
            sys.exit(1)
        return fn(*a[1:])
    if a[0] == 'help':
        if bot_cmd({'argv': a}) == 1:          # бот не ответил вовсе
            print(HELP_LOCAL)
        return
    req = {'argv': a}
    if a[:2] == ['backup', 'check'] and sys.stdin.isatty():
        import getpass
        req['pw'] = getpass.getpass('Пароль копии (Enter — пароль автокопий этого шлюза): ')
    rc = bot_cmd(req)
    if rc == 1:
        sys.exit('Бот не ответил (ни через сокет, ни напрямую). Посмотрите: vpngw logs bot')
    sys.exit(rc and 1)


if __name__ == '__main__':
    main()
