"""«Помощь»: проверка DNS, проверка отдельного сайта и отчёт для помощи."""
from __future__ import annotations

import ipaddress
import json
import logging
import platform
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from . import APP_NAME, __version__, winutil
from . import log as applog

log = logging.getLogger("lazeyka.help")

DNS_PROBE_DOMAINS = ("discord.com", "gateway.discord.gg", "www.youtube.com", "redirector.googlevideo.com",
                     "web.telegram.org")
DOH_PROVIDERS = (
    {"id": "cloudflare", "name": "Cloudflare", "ip": "1.1.1.1"},
    {"id": "google", "name": "Google", "ip": "8.8.8.8"},
    {"id": "quad9", "name": "Quad9", "ip": "9.9.9.9"},
)
DOH_JSON = "https://cloudflare-dns.com/dns-query?name={name}&type=A"
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _curl() -> str:
    return winutil.system32("curl.exe")


# Адреса-заглушки DNS у VPN-программ (fake-ip): Xray и mihomo — 198.18.0.0/15, режим «Internal»
# у клиентов на Xray — 240.0.0.0/4, mihomo для IPv6 — 2001:2::/64.
FAKE_IP_NETS = tuple(ipaddress.ip_network(n) for n in ("198.18.0.0/15", "240.0.0.0/4", "2001:2::/64"))


def is_fake_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in FAKE_IP_NETS)


_fake = is_fake_ip


def _bogus(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_reserved


def system_resolve(name: str) -> list[str] | None:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except OSError:
        return None


def doh_resolve(name: str) -> list[str] | None:
    """Ответ Cloudflare DNS через HTTPS — провайдер его не видит и не подменит."""
    res = winutil.run([_curl(), "-q", "--noproxy", "*", "-s", "-m", "6", "--connect-timeout", "4",
                       "-H", "accept: application/dns-json", DOH_JSON.format(name=name)], timeout=12)
    try:
        data = json.loads(res.out)
    except ValueError:
        return None
    answers = [a.get("data") for a in data.get("Answer") or [] if a.get("type") == 1]
    return sorted({a for a in answers if isinstance(a, str)})


def _provider_ms(ip: str) -> int | None:
    started = time.monotonic()
    res = winutil.run([_curl(), "-q", "--noproxy", "*", "-I", "-s", "-o", "NUL", "-m", "5", "--connect-timeout", "4", f"https://{ip}/"],
                      timeout=10)
    return round((time.monotonic() - started) * 1000) if res.code == 0 else None


def check_dns(doh_enabled: bool) -> dict:
    """Подменяет ли провайдер адреса нужных сайтов и какие защищённые DNS сейчас доступны."""
    spoofed: list[str] = []
    vpn_dns: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        sys_answers = dict(zip(DNS_PROBE_DOMAINS, pool.map(system_resolve, DNS_PROBE_DOMAINS)))
        doh_answers = dict(zip(DNS_PROBE_DOMAINS, pool.map(doh_resolve, DNS_PROBE_DOMAINS)))
        latency = list(pool.map(lambda p: _provider_ms(p["ip"]), DOH_PROVIDERS))
    for name in DNS_PROBE_DOMAINS:
        mine, honest = sys_answers[name], doh_answers[name]
        if mine and any(_fake(ip) for ip in mine):
            vpn_dns.append(name)  # отвечает VPN-программа (fake-ip), провайдер тут ни при чём
            continue
        if not honest:
            continue  # честного ответа нет — сравнивать не с чем
        # Осторожный признак подмены: провайдер не отвечает или отвечает «служебным» адресом.
        if not mine or any(_bogus(ip) for ip in mine):
            spoofed.append(name)
    providers = [dict(p, ok=ms is not None, ms=ms) for p, ms in zip(DOH_PROVIDERS, latency)]
    if vpn_dns and not spoofed:
        message = ("Адреса сейчас выдаёт VPN-программа (режим fake-ip) — при включённом VPN это нормально. "
                   "Чтобы проверить DNS провайдера, выключите VPN и повторите проверку.")
    elif spoofed:
        message = ("Провайдер подменяет адреса: " + ", ".join(spoofed) + ". Включите DNS через HTTPS — "
                   "без этого обход может не помочь.")
    elif not doh_enabled:
        message = ("Подмены не видно, но DNS через HTTPS выключен. Его стоит включить: провайдер может начать "
                   "подменять адреса в любой момент.")
    else:
        message = "DNS в порядке: подмены нет, DNS через HTTPS включён."
    return {"doh_enabled": doh_enabled, "spoofed": spoofed, "vpn_dns": vpn_dns, "providers": providers,
            "message": message, "at": time.time()}


def normalize_domain(text: str) -> str | None:
    value = (text or "").strip().lower()
    value = re.sub(r"^[a-z]+://", "", value).split("/")[0].split(":")[0].strip(".")
    if value.startswith("www."):
        value = value[4:]
    return value if _DOMAIN.match(value) else None


def check_site(domain: str) -> dict:
    """Почему не открывается сайт: DNS, блокировка или сайт лежит."""
    name = normalize_domain(domain)
    if not name:
        return {"ok": False, "error": "Введите адрес сайта, например example.com"}
    mine = system_resolve(name)
    honest = doh_resolve(name)
    resolve: list[str] = []
    if mine and honest and any(_fake(ip) for ip in mine):
        # Адрес выдала VPN-программа (fake-ip): проверяем сайт по настоящему адресу.
        resolve = ["--resolve", f"{name}:443:{honest[0]}"]
        mine = honest
    if not mine or any(_bogus(ip) for ip in mine):
        if honest:
            return {"ok": True, "domain": name, "verdict": "dns", "can_add": False,
                    "advice": "Провайдер подменяет адрес сайта. Включите DNS через HTTPS — проверка DNS ниже."}
        return {"ok": True, "domain": name, "verdict": "down", "can_add": False,
                "advice": "Такого сайта нет или он не отвечает — дело не в блокировке."}
    res = winutil.run([_curl(), "-q", "--noproxy", "*", "-I", "-s", "-o", "NUL", "-m", "8", "--connect-timeout", "5",
                       *resolve, f"https://{name}/"], timeout=14)
    if res.code == 0:
        return {"ok": True, "domain": name, "verdict": "works", "can_add": False,
                "advice": "Сайт открывается. Если в браузере нет — очистите кэш браузера или проверьте блокировщик рекламы."}
    return {"ok": True, "domain": name, "verdict": "blocked", "can_add": True,
            "advice": "Сайт не открывается. Добавьте его в «Мои сайты» — обход начнёт его обрабатывать."}


def build_report(state: dict, log_tail: list[dict]) -> str:
    """Отчёт для помощи: без ключа прокси, имени пользователя и путей профиля."""
    z, tg = state.get("zapret", {}), state.get("tg", {})
    gf = z.get("game_filter") or {}
    lines = [
        f"{APP_NAME} {__version__}",
        f"Windows: {platform.platform()} ({platform.machine()})",
        f"Администратор: {'да' if state.get('app', {}).get('admin') else 'нет'}",
        "",
        f"zapret: {z.get('status')} · режим {z.get('mode')} · пакет {(z.get('pack') or {}).get('version')}",
        f"Стратегия: {z.get('strategy')}",
        f"Игровой фильтр: {gf.get('mode')} (TCP {gf.get('tcp')}, UDP {gf.get('udp')})",
        f"IPSet: {(z.get('ipset') or {}).get('mode')}",
    ]
    if z.get("error"):
        lines.append(f"Ошибка обхода: {z['error']}")
    check = z.get("check") or {}
    if check.get("results"):
        lines.append("Проверка: " + ", ".join(f"{r['label']} {'✓' if r['ok'] else '✗'} ({r['detail']})"
                                             for r in check["results"]))
    v = state.get("vpn") or {}
    if v:
        filt = v.get("filter") or {}
        where = (f" ({v.get('label')}, {'весь трафик' if v.get('full_tunnel') else 'часть трафика'})"
                 if v.get("active") else "")
        applied = filt.get("mode")
        if applied == "vpn":
            applied += f": интерфейсов {len(filt.get('interfaces') or [])}, серверов {len(filt.get('servers') or [])}"
        elif filt.get("error"):
            applied += f": {filt['error']}"
        lines.append(f"VPN: {'есть' if v.get('active') else 'нет'}{where} · совместимость "
                     f"{'вкл' if v.get('compat') else 'выкл'} · фильтр {applied}")
        adapters = [f"{a.get('name')} — {a.get('kind')}{'/' + a['role'] if a.get('role') else ''}"
                    for a in v.get("adapters") or []]
        if adapters:
            lines.append("Подключения: " + "; ".join(adapters))
        routes = (v.get("routes") or {}).get("items") or []
        if routes:
            lines.append("Что куда идёт: " + ", ".join(f"{r['label']} — {r['via']}" for r in routes))
    lines += _vpnclient_lines(state.get("vpnclient"))
    found = _vpnclient_help_lines(state.get("vpnclient_help"))
    if found:
        lines += ["Следы VPN и аварий:"] + found
    lines += ["", f"Telegram-прокси: {tg.get('status')} · ядро {tg.get('version')} ({tg.get('core')})"]
    stats = tg.get("stats") or {}
    if stats:
        lines.append(f"Соединения: активных {stats.get('active')}, всего {stats.get('total')}, "
                     f"WS {stats.get('ws')}, Cloudflare {stats.get('cf')}, TCP {stats.get('tcp_fallback')}")
    diag = (state.get("diag") or {}).get("items") or []
    problems = [i for i in diag if i.get("status") in ("warn", "error")]
    if problems:
        lines += ["", "Диагностика:"] + [f"- {i['title']}: {i['text']}" for i in problems]
    errors = [ln for ln in log_tail if ln.get("lvl") in ("warn", "error")][-15:]
    if errors:
        lines += ["", "Последние предупреждения:"]
        lines += [f"- {time.strftime('%H:%M:%S', time.localtime(ln['t']))} "
                  f"{_hide_addresses(ln['msg']) if ln.get('src') == 'vpn' else ln['msg']}" for ln in errors]
    return _scrub("\n".join(lines), state)


def _vpnclient_lines(vc: dict | None) -> list[str]:
    """Свой VPN в отчёте: только сводка — без имён и адресов серверов, ссылок и подписок."""
    if not isinstance(vc, dict):
        return []
    if not vc.get("available", True):
        return ["", f"Свой VPN: недоступен ({vc.get('unavailable_reason') or 'причина не указана'})"]
    servers = vc.get("servers") or []
    subs = vc.get("subscriptions") or []
    supported = sum(1 for s in servers if isinstance(s, dict) and s.get("supported"))
    head = (f"Свой VPN: {vc.get('status')} · режим {vc.get('mode')} · подписок {len(subs)}, "
            f"серверов {len(servers)} (поддерживается {supported})")
    if vc.get("status") == "running":
        head += " · выход проверен" if vc.get("verified") else " · выход не проверен"
    lines = ["", head]
    sel = vc.get("selected") or {}
    if sel:
        lines.append(f"Выбран: {'«Самый быстрый»' if sel.get('kind') == 'auto' else 'сервер'} · "
                     f"{sel.get('proto')}/{sel.get('transport')}/{sel.get('security')} · ядро {sel.get('engine')}")
    if vc.get("error_kind") or vc.get("error"):
        lines.append(f"Ошибка своего VPN: {vc.get('error_kind') or 'other'}")
    cores = vc.get("cores") or {}
    if cores:
        lines.append("Ядра: " + ", ".join(
            f"{name} {c.get('version') or '—'}{'' if c.get('installed') else ' (не установлено)'}"
            for name, c in cores.items() if isinstance(c, dict)))
    routing = vc.get("routing") or {}
    if routing:
        lines.append(f"Маршруты: {routing.get('preset')} · через обход "
                     f"{'вкл' if routing.get('via_zapret') else 'выкл'} ({routing.get('bypass')})")
    conflict = vc.get("conflict") or {}
    if conflict:
        lines.append(f"Конфликт: {conflict.get('kind')} ({conflict.get('label')})")
    return lines


def _vpnclient_help_lines(items: list | None) -> list[str]:
    """Находки панели «Свой VPN не подключается»: мёртвый прокси, DNS после чужого VPN, адаптер."""
    found = [i for i in items or [] if isinstance(i, dict) and i.get("level") in ("warn", "error")]
    return [f"- {i.get('title')}" for i in found]


_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
_HOST = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63})(?![\w-])")
_FILE_EXT = {"exe", "dll", "json", "dat", "txt", "srs", "log", "zip", "conf", "yaml", "yml", "py", "go"}


def _ip_or_keep(match: re.Match) -> str:
    try:
        ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)   # «07:00:00» в выводе ядра — время, а не адрес
    return "<адрес>"


def _hide_addresses(text: str) -> str:
    """Строки журнала своего VPN: адреса и домены серверов в отчёт не идут (имена файлов — идут)."""
    text = _IPV4.sub(_ip_or_keep, text)
    text = _IPV6.sub(_ip_or_keep, text)
    return _HOST.sub(lambda m: m.group(0) if m.group(1).lower() in _FILE_EXT else "<домен>", text)


def _server_addresses(state: dict) -> set[str]:
    """IP серверов VPN и выхода, которые знает состояние: их тоже прячем из всего отчёта."""
    v = state.get("vpn") or {}
    filt = v.get("filter") or {}
    found = {*map(str, v.get("servers") or []), *map(str, filt.get("servers") or []),
             *map(str, filt.get("servers_seen") or [])}
    exit_ip = ((state.get("vpnclient") or {}).get("exit") or {}).get("ip")
    if exit_ip:
        found.add(str(exit_ip))
    return {ip for ip in found if len(ip) >= 3}


def _scrub(text: str, state: dict) -> str:
    secret = ((state.get("tg_settings") or {}).get("secret")) or ""
    if secret:
        text = text.replace(secret, "<ключ>")
    text = re.sub(r"dd[0-9a-f]{32}", "dd<ключ>", text)
    text = re.sub(r"(?i)C:\\Users\\[^\\\s]+", r"C:\\Users\\<пользователь>", text)
    text = applog.scrub(text)   # секреты своего VPN: ключи, ссылки, адреса подписок
    for ip in sorted(_server_addresses(state), key=len, reverse=True):
        text = re.sub(rf"(?<![\w.:]){re.escape(ip)}(?![\w.:])", "<адрес>", text)
    return text
