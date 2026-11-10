"""Пробы сайта по шагам — напрямую (мимо VPN) и через свой VPN.

Факты собирают «Рентген сайта» (помощь), распознавание белых списков мобильного интернета и умный
маршрут своего VPN; вывод из фактов — чистые функции (verdict, blocked_reason, classify_network),
их и проверяют тесты."""
from __future__ import annotations

import ipaddress
import logging
import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

from . import __version__, winutil

log = logging.getLogger("lazeyka.siteprobe")

UA = f"Lazeyka/{__version__} (site check)"     # одна и та же напрямую и через VPN: ответы сравнимы
TIMEOUT = 8
CONNECT_TIMEOUT = 5                              # в curl 8 сюда входит и рукопожатие TLS
FREEZE_TIMEOUT = 6
FREEZE_BAND = (8_000, 40_000)    # ответ замер в этой полосе — обрыв после ~16 КБ (вживую: 15,6–25,6 КБ)

# Белые списки мобильных операторов: эти сайты в них всегда (Госуслуги, VK, Яндекс), а обычные зарубежные
# сайты без блокировок — нет. Отвечают первые, молчат все вторые — оператор пускает только по списку.
WHITELIST_ANCHORS = ("https://ya.ru", "https://vk.com", "https://www.gosuslugi.ru")
OPEN_ANCHORS = ("https://example.com", "https://github.com", "https://1.1.1.1/cdn-cgi/trace",
                "https://www.debian.org")

# Строки curl -v: TCP соединился и пошло рукопожатие TLS; рукопожатие закончилось. Время соединения curl 8
# при обрыве на TLS отдаёт нулём (рукопожатие входит в «соединение»), поэтому шаг — по этим строкам.
_TCP_UP = re.compile(r"ALPN[:,] (?:curl offers|offering)|schannel: disabled automatic|Established connection"
                     r"|SSL connection using")
_TLS_UP = re.compile(r"Established connection|ALPN: server accepted|SSL connection using")
CERT_CODES = frozenset({51, 60})                 # CURLE_PEER_FAILED_VERIFICATION: сертификат не этого сайта
# Российский удостоверяющий центр Минцифры: им подписаны Сбер, ВТБ, Т-Банк, РЖД… Windows, Chrome и Firefox ему не
# доверяют — это «ошибка сертификата», но не подмена провайдером (проверено вживую 2026-11-10).
RU_CA = ("Russian Trusted Root CA", "Russian Trusted Sub CA")


@dataclass(frozen=True)
class Attempt:
    """Одна попытка открыть https://сайт/. stage: ok — сайт ответил (status — код HTTP); tcp — не
    соединилось; tls — соединилось, но рукопожатие TLS оборвалось или замерло; cert — ответил не тот
    сертификат; stall — рукопожатие прошло, а ответа нет; fail — через VPN не открылось (шаг не виден)."""

    stage: str
    status: int | None = None

    @property
    def ok(self) -> bool:
        return self.stage == "ok"


@dataclass
class Facts:
    domain: str
    dns: str = "ok"                  # ok | spoofed (провайдер подменяет адрес) | missing (имени нет нигде)
    direct: Attempt | None = None    # None — не проверяли: адреса нет
    frozen: bool | None = None       # обрыв после ~16 КБ (только когда сайт ответил напрямую)
    vpn: Attempt | None = None       # через свой VPN; None — VPN не включён
    ru_ca: bool = False              # сертификат российского удостоверяющего центра (Минцифры)
    zapret: str | None = None        # handles | skips | off | None (обход недоступен)
    whitelist: bool = False          # мобильный интернет по белому списку
    own_vpn: bool = False            # у своего VPN есть серверы: можно предложить «через VPN»


# ------------------------------------------------------------ пробы

def parse_attempt(code: int, out: str, err: str) -> Attempt:
    """Итог curl -I -v -w "%{http_code} %{time_appconnect}" → Attempt."""
    m = re.match(r"^(\d{3})\s+([\d.]+)", (out or "").strip())
    status = int(m.group(1)) if m else 0
    secured = bool(m) and float(m.group(2)) > 0
    if code == 0 and status:
        return Attempt("ok", status)
    if code in CERT_CODES:
        return Attempt("cert")
    if secured or _TLS_UP.search(err or ""):
        return Attempt("stall")
    if _TCP_UP.search(err or ""):
        return Attempt("tls")
    return Attempt("tcp")


def _curl_args(domain: str, ip: str | None, bind: str | None, timeout: int) -> list[str]:
    # -q первым и --noproxy: ни .curlrc, ни переменные окружения не уведут пробу в прокси. Отзыв сертификата
    # не проверяем: сервер отзыва за блокировкой или белым списком дал бы ложный «обрыв на TLS».
    args = [winutil.system32("curl.exe"), "-q", "--noproxy", "*", "-s", "-o", "NUL", "-A", UA, "--ssl-no-revoke",
            "-m", str(timeout), "--connect-timeout", str(min(timeout, CONNECT_TIMEOUT))]
    if ip:
        args += ["--resolve", f"{domain}:443:{ip}"]
    if bind:
        args += ["-4", "--interface", bind]
    return args


def direct_attempt(domain: str, ip: str | None, bind: str | None = None, timeout: int = TIMEOUT,
                   insecure: bool = False) -> Attempt:
    """Напрямую: bind — IPv4 прямого подключения (мимо туннеля VPN), ip — адрес сайта для проб; insecure — без
    проверки сертификата (сайт с сертификатом Минцифры: подлинность уже проверил russian_ca)."""
    args = _curl_args(domain, ip, bind, timeout) + ["-I", "-v", "-w", "%{http_code} %{time_appconnect}",
                                                     *(["-k"] if insecure else []), f"https://{domain}/"]
    res = winutil.run(args, timeout=timeout + 6)
    return parse_attempt(res.code, res.out, res.err)


def russian_ca(domain: str, ip: str, bind: str | None = None) -> bool:
    """Сертификат сайта выдал российский удостоверяющий центр (RU_CA) — по издателю, без проверки цепочки."""
    import socket
    from cryptography import x509
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), timeout=CONNECT_TIMEOUT,
                                      source_address=(bind, 0) if bind else None) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
        issuer = x509.load_der_x509_certificate(der).issuer.rfc4514_string()
    except (OSError, ValueError):
        return False
    return any(name in issuer for name in RU_CA)


def parse_freeze(code: int, out: str) -> bool | None:
    """Итог curl -r 0-65535 -w "%{size_download}": замер в полосе FREEZE_BAND и время вышло — обрыв после ~16 КБ;
    пришло больше полосы — большие ответы проходят; страница меньше полосы — не сказать (None)."""
    m = re.match(r"^(\d+)", (out or "").strip())
    got = int(m.group(1)) if m else 0
    if code == 28 and FREEZE_BAND[0] <= got <= FREEZE_BAND[1]:
        return True
    return False if got > FREEZE_BAND[1] else None


def freeze_check(domain: str, ip: str | None, bind: str | None = None) -> bool | None:
    """Замирает ли ответ после ~16 КБ (так провайдеры режут сайты на зарубежных хостингах): первые 64 КБ страницы.
    Отправка 64 КБ, как у «Проверки DPI» обхода, для любого сайта не годится: многие на POST с телом не отвечают
    вовсе (example.com молчит до тайм-аута) — вышел бы ложный обрыв."""
    args = _curl_args(domain, ip, bind, FREEZE_TIMEOUT) + ["-r", "0-65535", "-w", "%{size_download}",
                                                           f"https://{domain}/"]
    res = winutil.run(args, timeout=FREEZE_TIMEOUT + 6)
    return parse_freeze(res.code, res.out)


def vpn_attempt(domain: str, opener: Any, timeout: int = TIMEOUT) -> Attempt:
    """Через свой VPN (служебный вход ядра): opener — manager.proxy_opener."""
    request = urllib.request.Request(f"https://{domain}/", method="HEAD", headers={"User-Agent": UA})
    try:
        with opener.open(request, timeout=timeout) as resp:
            return Attempt("ok", int(resp.status))
    except urllib.error.HTTPError as exc:
        return Attempt("ok", int(exc.code))
    except urllib.error.URLError as exc:
        return Attempt("cert" if isinstance(exc.reason, ssl.SSLCertVerificationError) else "fail")
    except ssl.SSLCertVerificationError:
        return Attempt("cert")
    except (OSError, ValueError):
        return Attempt("fail")


def _bogus(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_reserved


def resolve(domain: str) -> tuple[str, list[str]]:
    """(dns, адреса для проб). Системный DNS дал настоящий адрес — ok и он (по нему пойдёт и браузер);
    адрес-заглушка VPN-программы (fake-ip) — ok и адрес из DNS через HTTPS; провайдер не ответил или
    ответил служебным адресом — spoofed и адрес из DNS через HTTPS; имени нет нигде — missing."""
    from .helpdesk import doh_resolve, is_fake_ip, system_resolve
    mine = system_resolve(domain) or []
    if mine and not any(_bogus(ip) or is_fake_ip(ip) for ip in mine):
        return "ok", mine
    honest = doh_resolve(domain) or []
    if mine and any(is_fake_ip(ip) for ip in mine):
        return "ok", honest
    return ("spoofed", honest) if honest else ("missing", [])


def inspect(domain: str, *, bind: str | None = None, vpn_opener: Any = None, zapret: str | None = None,
            own_vpn: bool = False, network_mode: Callable[[], str] | None = None) -> Facts:
    """Все факты о сайте: адрес, путь напрямую (до двух адресов), обрыв после 16 КБ, путь через VPN и — если
    напрямую не открылось — не белый ли список у оператора."""
    dns, ips = resolve(domain)
    facts = Facts(domain, dns, zapret=zapret, own_vpn=own_vpn)
    if not ips:
        return facts
    with ThreadPoolExecutor(max_workers=2) as pool:
        via_vpn = pool.submit(vpn_attempt, domain, vpn_opener) if vpn_opener is not None else None
        direct = direct_attempt(domain, ips[0], bind)
        if direct.stage == "tcp" and len(ips) > 1:
            direct = direct_attempt(domain, ips[1], bind)   # закрыт один адрес — браузер возьмёт другой
        if direct.stage == "cert" and russian_ca(domain, ips[0], bind):
            facts.ru_ca = True
            direct = direct_attempt(domain, ips[0], bind, insecure=True)
        if direct.ok:
            facts.frozen = freeze_check(domain, ips[0], bind)
        facts.direct = direct
        facts.vpn = via_vpn.result() if via_vpn is not None else None
        if facts.ru_ca and facts.vpn is not None and facts.vpn.stage == "cert":
            facts.vpn = Attempt("ok")       # тот же сертификат Минцифры: через VPN сайт тоже отвечает
    if not direct.ok and network_mode is not None:
        try:
            facts.whitelist = network_mode() == "whitelist"
        except Exception:  # noqa: BLE001 — без этого факта вывод всё равно есть
            log.debug("Режим сети не проверен", exc_info=True)
    return facts


def network_mode(bind: str | None = None) -> str:
    """open — обычный интернет; whitelist — оператор пускает только по белому списку; offline — связи нет."""
    from .zapret.tester import curl_check
    urls = WHITELIST_ANCHORS + OPEN_ANCHORS
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        got = dict(zip(urls, pool.map(lambda u: curl_check(u, "http", 5, None, bind) == "ok", urls)))
    return classify_network(sum(got[u] for u in WHITELIST_ANCHORS), sum(got[u] for u in OPEN_ANCHORS))


def classify_network(white: int, open_: int) -> str:
    """Сколько ответило сайтов из белого списка и обычных зарубежных → режим сети. Хоть один обычный ответил —
    белого списка нет; два из белого списка при молчании всех обычных — белый список."""
    if open_:
        return "open"
    return "whitelist" if white >= 2 else "offline"


# ------------------------------------------------------------ паспорт провайдера

# Популярные сайты, по которым видно, что и как режет провайдер (сайт, имя для человека).
PASSPORT_SITES = (
    ("www.youtube.com", "YouTube"), ("discord.com", "Discord"), ("web.telegram.org", "Telegram"),
    ("www.instagram.com", "Instagram"), ("x.com", "X"), ("www.facebook.com", "Facebook"),
    ("www.linkedin.com", "LinkedIn"), ("chatgpt.com", "ChatGPT"), ("rutracker.org", "Rutracker"),
    ("medium.com", "Medium"), ("www.patreon.com", "Patreon"), ("github.com", "GitHub"),
    ("www.wikipedia.org", "Википедия"), ("ya.ru", "Яндекс"), ("www.gosuslugi.ru", "Госуслуги"),
)
SHORT = {"works": "открывается", "dns": "открывается, но провайдер подменяет адрес", "down": "не отвечает",
         "ru_ca": "открывается, сертификат Минцифры",
         "unreachable": "адрес не отвечает", "ip": "провайдер закрыл адрес", "dpi": "провайдер режет по имени",
         "freeze": "замирает после ~16 КБ", "cert": "вместо сайта отвечает провайдер",
         "geo": "сам не пускает из России", "vpn_refused": "не пускает через VPN", "whitelist": "белый список"}
CUT = frozenset({"ip", "dpi", "freeze", "cert"})          # это режет провайдер


# ------------------------------------------------------------ вывод

WHY_LABELS = {
    "ip": "провайдер закрыл адрес сайта",
    "dpi": "провайдер режет по имени сайта",
    "freeze": "соединение замирает после ~16 КБ",
    "cert": "вместо сайта отвечает провайдер",
    "geo": "сайт не пускает из России",
    "vpn": "не пускает через VPN",
}

_DPI_STAGES = frozenset({"tls"})
_FREEZE_STAGES = frozenset({"stall"})


def blocked_reason(facts: Facts) -> str | None:
    """Почему сайт не открывается напрямую (ключ WHY_LABELS) — или None: открывается либо не ясно. Не
    решает, поможет ли VPN: это смотрит тот, кто зовёт (facts.vpn)."""
    direct = facts.direct
    if direct is None:
        return None
    if direct.stage == "tcp":
        return "ip"
    if direct.stage in _DPI_STAGES:
        return "dpi"
    if direct.stage in _FREEZE_STAGES or (direct.ok and facts.frozen):
        return "freeze"
    if direct.stage == "cert":
        return "cert"
    if direct.ok and direct.status == 451:
        return "geo"
    return None


def vpn_works(attempt: Attempt | None) -> bool:
    return attempt is not None and attempt.ok and attempt.status not in (403, 451)


def _step(step_id: str, label: str, state: bool | None, detail: str) -> dict:
    return {"id": step_id, "label": label, "ok": state, "detail": detail}


def _steps(f: Facts) -> list[dict]:
    """Слои «Рентгена»: что проверено и где оборвалось. ok=None — до этого шага проба не дошла."""
    d = f.direct
    dns_detail = {"ok": "настоящий адрес", "spoofed": "провайдер подменяет адрес",
                  "missing": "имя не находится ни у провайдера, ни в DNS через HTTPS"}[f.dns]
    steps = [_step("dns", "Адрес сайта (DNS)", f.dns == "ok", dns_detail)]
    reached_tcp = d is not None and d.stage != "tcp"
    reached_tls = d is not None and d.stage in ("ok", "stall")
    if d is None:
        steps.append(_step("tcp", "Соединение с сервером", None, "не проверялось: адреса нет"))
    else:
        steps.append(_step("tcp", "Соединение с сервером", reached_tcp,
                           "есть" if reached_tcp else "адрес не отвечает"))
    if reached_tcp:
        tls_detail = {"tls": "оборвалось на имени сайта", "cert": "сертификат не этого сайта"}.get(d.stage, "есть")
        if f.ru_ca:
            tls_detail = "есть, сертификат российского удостоверяющего центра (Минцифры)"
        steps.append(_step("tls", "Защищённое соединение", reached_tls, tls_detail))
    if reached_tls:
        if d.ok:
            answer = f"код {d.status}" + (" — сайт не пускает из этой страны" if d.status == 451 else "")
            steps.append(_step("answer", "Ответ сайта", d.status != 451, answer))
        else:
            steps.append(_step("answer", "Ответ сайта", False, "соединение есть, а ответа нет"))
    if d is not None and d.ok and f.frozen is not None:
        steps.append(_step("freeze", "Большие ответы", not f.frozen,
                           "замирают после ~16 КБ" if f.frozen else "проходят"))
    if f.vpn is not None:
        if f.vpn.ok:
            label = (f"код {f.vpn.status}" if f.vpn.status else "отвечает") + (
                " — сайт не пускает" if f.vpn.status in (403, 451) else "")
            steps.append(_step("vpn", "Через свой VPN", vpn_works(f.vpn), label))
        else:
            steps.append(_step("vpn", "Через свой VPN", False, "не открывается"))
    return steps


_DNS_NOTE = "Ещё провайдер подменяет адрес сайта — включите DNS через HTTPS (проверка DNS ниже)."


def verdict(f: Facts) -> dict:
    """Факты → {verdict, advice, steps, fixes}. fixes — кнопки: add_site («Мои сайты» обхода), vpn_site
    (свой VPN: «только через VPN»), direct_site (свой VPN: «мимо VPN»)."""
    steps = _steps(f)
    dns_note = f" {_DNS_NOTE}" if f.dns == "spoofed" else ""

    def out(kind: str, advice: str, fixes: list[str] | None = None) -> dict:
        return {"verdict": kind, "advice": advice, "steps": steps, "fixes": fixes or []}

    if f.dns == "missing" or f.direct is None:
        return out("down", "Такого сайта нет или он не отвечает — дело не в блокировке.")
    vpn_fix = ["vpn_site"] if f.own_vpn and (f.vpn is None or vpn_works(f.vpn)) else []
    reason = blocked_reason(f)
    if f.whitelist and not f.direct.ok:
        return out("whitelist", "Мобильный оператор сейчас пускает только к сайтам из белого списка (Госуслуги, VK, "
                   "Яндекс…). Обход тут не поможет; открыть сайт можно только через сервер VPN, до которого "
                   "оператор пускает." + (" Через ваш сервер сайт открывается." if vpn_works(f.vpn) else ""),
                   ["vpn_site"] if vpn_works(f.vpn) else [])
    if reason == "ip":
        if vpn_works(f.vpn):
            return out("ip", "Провайдер закрыл адрес сайта: соединение не устанавливается. Обход тут не поможет — "
                       "через ваш VPN сайт открывается." + dns_note, vpn_fix)
        if f.vpn is None:
            hint = (" Включите свой VPN и проверьте ещё раз — станет ясно, что именно." if f.own_vpn else "")
            return out("unreachable", "Адрес сайта не отвечает: либо провайдер его закрыл, либо сайт лежит." + hint
                       + dns_note)
        return out("down", "Сайт не отвечает ни напрямую, ни через ваш VPN — похоже, он сейчас не работает.")
    if reason in ("dpi", "freeze", "cert"):
        what = {"dpi": "Провайдер обрывает соединение на имени сайта — так работает его фильтр (DPI).",
                "freeze": "Соединение устанавливается, но замирает — так провайдеры режут сайты на зарубежных "
                          "хостингах (обрыв после ~16 КБ).",
                "cert": "Вместо сайта отвечает провайдер: сертификат не этого сайта (страница-заглушка)."}[reason]
        via = " Через ваш VPN сайт открывается." if vpn_works(f.vpn) else ""
        if f.zapret == "skips":
            return out(reason, f"{what} Обход этот сайт сейчас не обрабатывает — добавьте его в «Мои сайты»."
                       + via + dns_note, ["add_site"] + vpn_fix)
        if f.zapret == "off":
            return out(reason, f"{what} Добавьте сайт в «Мои сайты» и включите обход." + via + dns_note,
                       ["add_site"] + vpn_fix)
        if f.zapret == "handles":
            return out(reason, f"{what} Обход этот сайт обрабатывает, но нынешняя стратегия его не пробивает." +
                       (" Надёжнее — через свой VPN." if vpn_fix else "") + via + dns_note, vpn_fix)
        return out(reason, what + via + dns_note, vpn_fix)
    if reason == "geo":
        return out("geo", "Сайт сам не пускает пользователей из России (ответ 451) — обход тут не поможет, нужен VPN."
                   + (" Через ваш VPN он открывается." if vpn_works(f.vpn) else ""), vpn_fix)
    if f.vpn is not None and not vpn_works(f.vpn) and f.direct.ok and f.direct.status not in (403, 451):
        return out("vpn_refused", "Напрямую сайт открывается, а через ваш VPN — нет: сайт не пускает из-за границы "
                   "или с адресов VPN. Пустите его мимо VPN.", ["direct_site"])
    if f.direct.ok and f.direct.status == 403 and vpn_works(f.vpn):
        return out("geo", "Напрямую сайт отказывает (403), а через ваш VPN открывается — он не пускает из России.",
                   vpn_fix)
    if f.dns == "spoofed":
        return out("dns", "Сайт открывается по настоящему адресу, но провайдер подменяет адрес. Включите DNS через "
                   "HTTPS — проверка DNS ниже.")
    if f.ru_ca:
        return out("ru_ca", "Сайт открывается, но его сертификат выдал российский удостоверяющий центр (Минцифры). "
                   "Chrome, Edge и Firefox без него покажут ошибку сертификата — откройте сайт в Яндекс Браузере "
                   "или установите сертификат Минцифры (инструкция — на Госуслугах).")
    return out("works", "Сайт открывается. Если в браузере нет — очистите кэш браузера или проверьте блокировщик "
               "рекламы.")
