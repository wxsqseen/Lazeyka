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
        lines += [f"- {time.strftime('%H:%M:%S', time.localtime(ln['t']))} {ln['msg']}" for ln in errors]
    return _scrub("\n".join(lines), state)


def _scrub(text: str, state: dict) -> str:
    secret = ((state.get("tg_settings") or {}).get("secret")) or ""
    if secret:
        text = text.replace(secret, "<ключ>")
    text = re.sub(r"dd[0-9a-f]{32}", "dd<ключ>", text)
    text = re.sub(r"(?i)C:\\Users\\[^\\\s]+", r"C:\\Users\\<пользователь>", text)
    return text
