#!/usr/bin/env python3
# vpngw — служебная утилита VPN-шлюза (mihomo + WireGuard).
# Используется установщиком и вручную:  vpngw peers | vpngw add ИМЯ phone|pc | vpngw qr ИМЯ | vpngw status
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
    ip = sh(['curl', '-s', '-m', '10', '-x', 'http://127.0.0.1:7890', 'https://ifconfig.me/ip']).stdout.strip()
    print(f'{"IP через VPN":<14} {ip or "нет ответа"}')


def main():
    a = sys.argv[1:]
    cmds = {
        'analyze': (cmd_analyze, 1), 'links2yaml': (cmd_links2yaml, 2), 'gen-base': (cmd_gen_base, 2),
        'add': (cmd_add, 2), 'peers': (cmd_peers, 0), 'qr': (cmd_qr, 1),
        'status': (cmd_status, 0),
    }
    if not a or a[0] not in cmds or len(a) - 1 != cmds[a[0]][1]:
        print('Использование:\n  vpngw status            — состояние шлюза\n  vpngw peers             — клиенты WireGuard\n'
              '  vpngw add "Имя" phone   — новый клиент (phone или pc)\n  vpngw qr "Имя"|номер    — QR-код и файл клиента')
        sys.exit(1)
    cmds[a[0]][0](*a[1:])


if __name__ == '__main__':
    main()
