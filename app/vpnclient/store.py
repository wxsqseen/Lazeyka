"""profiles.json своего VPN: подписки, серверы, группы, выбор, задержки, свои имена (план 5.2, 5.8).

Всё держится в памяти под RLock и пишется атомарно (tmp + os.replace). Папка с файлом закрыта от
других пользователей: при первом создании вызывается secure(папка). Битый файл не теряется молча:
копия profiles.json.bad-<время>, пустое хранилище и load_error с причиной. Обновление подписки
сопоставляет серверы (key() → имя → хост+порт+учётные данные → хост+порт, всё при уникальности) и
переносит выбор, задержки и свои имена; ошибка или 0 серверов список не стирают.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable
from urllib.parse import urlsplit

from ..errors import UserError
from .model import SUB_FORMATS, Group, Server, Subscription

if TYPE_CHECKING:
    from .subscription import Decoded

log = logging.getLogger("lazeyka.vpnclient.store")

SCHEMA = 1
MAX_SUBSCRIPTIONS = 50
MAX_SERVERS = 2000
MAX_NAME = 100
AUTO = "auto:"                     # выбор «Самый быстрый»: auto:<id группы> или auto:<id подписки>
ANY: Any = object()                # servers(ANY) — все; servers(None) — добавленные отдельными ссылками


class StoreError(UserError):
    pass


@dataclass
class MergeReport:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)    # add_servers: сервер уже был, а параметры ссылки — новые
    selection: tuple[str, str | None] | None = None    # (старый, новый), если выбранный сменился; новый None — исчез
    suggested: str | None = None                       # чем заменить исчезнувший выбор (решает менеджер)
    skipped: int = 0                                   # не вошли: лимит серверов или сервер уже есть в другой подписке
    remapped: dict[str, str] = field(default_factory=dict)   # старый id → новый: сервер узнан, а ключ сменился


@dataclass
class _State:
    subs: list[Subscription] = field(default_factory=list)
    servers: list[Server] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    selected: str | None = None
    latency: dict[str, dict[str, Any]] = field(default_factory=dict)
    speed: dict[str, dict[str, Any]] = field(default_factory=dict)


# ------------------------------------------------------------ разбор файла

def _build(cls: Any, item: Any) -> Any:
    if not isinstance(item, dict):
        return None
    try:
        return cls.from_dict(item)
    except (TypeError, ValueError):
        return None


def _items(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    return value if isinstance(value, list) else []


def _parse_state(data: Any) -> tuple[_State, int]:
    """(состояние, сколько записей пропущено). ValueError — файл целиком не подходит."""
    if not isinstance(data, dict):
        raise ValueError("не объект JSON")
    if data.get("schema") != SCHEMA:
        raise ValueError(f"версия схемы {data.get('schema')!r}, а нужна {SCHEMA}")
    state, skipped = _State(), 0
    for item in _items(data, "subscriptions"):
        sub = _build(Subscription, item)
        if sub is None or not sub.id or any(s.id == sub.id for s in state.subs):
            skipped += 1
            continue
        state.subs.append(sub)
    sub_ids = {s.id for s in state.subs}
    server_ids: set[str] = set()
    for item in _items(data, "servers"):
        server = _build(Server, item)
        if server is not None and not server.id:
            server.id = server.key()
        if server is None or server.id in server_ids or (server.sub is not None and server.sub not in sub_ids):
            skipped += 1
            continue
        server_ids.add(server.id)
        state.servers.append(server)
    for item in _items(data, "groups"):
        group = _build(Group, item)
        if group is None or not group.id or any(g.id == group.id for g in state.groups):
            skipped += 1
            continue
        group.members = [m for m in group.members if m in server_ids]
        if group.fallback not in server_ids:
            group.fallback = None
        state.groups.append(group)
    selected = data.get("selected")
    state.selected = selected if isinstance(selected, str) and _valid_selection(state, selected) else None
    for key in ("latency", "speed"):
        table = data.get(key) if isinstance(data.get(key), dict) else {}
        setattr(state, key, {k: dict(v) for k, v in table.items() if k in server_ids and isinstance(v, dict)})
    return state, skipped


def _valid_selection(state: _State, selection: str) -> bool:
    if selection.startswith(AUTO):
        target = selection[len(AUTO):]
        return any(g.id == target for g in state.groups) or any(s.id == target for s in state.subs)
    return any(s.id == selection for s in state.servers)


def url_key(url: str) -> str:
    """Адрес подписки для сравнения: схема и хост без учёта регистра, без завершающего «/»."""
    parts = urlsplit((url or "").strip())
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.rstrip('/')}?{parts.query}"


# ------------------------------------------------------------ сопоставление при обновлении

def _name_of(server: Server) -> Any:
    return server.name.strip() or None


def _credentials_of(server: Server) -> Any:
    creds = (server.uuid or "", server.password or "", server.username or "",
             str((server.wg or {}).get("private_key") or ""))
    return (server.host, server.port, creds) if any(creds) else None


def _address_of(server: Server) -> Any:
    return (server.host, server.port)


def _link_fields(server: Server) -> dict[str, Any]:
    """Всё, что пришло из ссылки, — без служебного (id, подписка) и своего имени человека."""
    data = server.to_dict()
    for key in ("id", "sub", "custom_name"):
        data.pop(key, None)
    return data


def _unique(servers: Iterable[Server], key_of: Callable[[Server], Any]) -> dict[Any, Server]:
    seen: dict[Any, list[Server]] = {}
    for server in servers:
        key = key_of(server)
        if key is not None:
            seen.setdefault(key, []).append(server)
    return {key: items[0] for key, items in seen.items() if len(items) == 1}


def match_servers(old: list[Server], new: list[Server]) -> dict[str, Server]:
    """{id нового: прежний сервер}. Шаги по плану 5.8; на каждом шаге — только однозначные пары
    среди ещё не сопоставленных (за одним CDN-хостом бывает много серверов)."""
    pairs: dict[str, Server] = {}
    old_left = {s.id: s for s in old}
    new_left = {s.id: s for s in new}
    for server_id in [i for i in new_left if i in old_left]:
        pairs[server_id] = old_left.pop(server_id)
        del new_left[server_id]
    for key_of in (_name_of, _credentials_of, _address_of):
        olds = _unique(old_left.values(), key_of)
        for key, server in _unique(new_left.values(), key_of).items():
            previous = olds.get(key)
            if previous is not None:
                pairs[server.id] = previous
                del old_left[previous.id]
                del new_left[server.id]
    return pairs


# ------------------------------------------------------------ хранилище

class ProfileStore:
    """Профили своего VPN в одном файле. Методы возвращают копии: менять их — не менять хранилище."""

    def __init__(self, path: Path, *, secure: Callable[[Path], None] | None = None):
        self.path = Path(path)
        self._secure = secure
        self._secured = False          # папку закрываем перед первой записью, даже если она уже была
        self._lock = threading.RLock()
        self._state = _State()
        self._readonly = False
        self.load_error: str | None = None
        self.load()

    # ---------------------------------------------------------------- файл

    def load(self) -> None:
        """Прочитать файл заново. Нет файла — пустое хранилище; битый — копия .bad-<время> и пусто.
        load_error не сбрасывается: сообщение о битом файле доживает до показа человеку."""
        with self._lock:
            self._state, self._readonly = _State(), False
            try:
                raw = self.path.read_bytes()
            except FileNotFoundError:
                return
            except OSError as exc:
                raise StoreError(f"Не удалось прочитать профили VPN ({exc.strerror or type(exc).__name__})") from None
            try:
                state, skipped = _parse_state(json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, ValueError) as exc:
                self._quarantine(str(exc) or type(exc).__name__)
                return
            self._state = state
            if skipped:
                self.load_error = f"В файле профилей VPN пропущены повреждённые записи: {skipped}"
                log.warning(self.load_error)

    def _quarantine(self, reason: str) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        bad = self.path.with_name(f"{self.path.name}.bad-{stamp}")
        number = 1
        while bad.exists():
            bad = self.path.with_name(f"{self.path.name}.bad-{stamp}-{number}")
            number += 1
        try:
            shutil.copy2(self.path, bad)
        except OSError as exc:
            # Копию сделать не вышло — затирать нельзя: хранилище только для чтения до следующего запуска.
            self._readonly = True
            self.load_error = (f"Файл профилей VPN повреждён ({reason}), а копию сохранить не удалось "
                               f"({exc.strerror or type(exc).__name__}) — изменения не сохраняются")
            log.warning(self.load_error)
            return
        self.load_error = (f"Файл профилей VPN повреждён ({reason}) — он сохранён как {bad.name}, "
                           "список серверов начат заново")
        log.warning(self.load_error)
        self.save()

    def _dump(self) -> dict[str, Any]:
        state = self._state
        return {
            "schema": SCHEMA,
            "subscriptions": [s.to_dict() for s in state.subs],
            "servers": [s.to_dict() for s in state.servers],
            "groups": [g.to_dict() for g in state.groups],
            "selected": state.selected,
            "latency": copy.deepcopy(state.latency),
            "speed": copy.deepcopy(state.speed),
        }

    def _ensure_folder(self) -> None:
        """Папка могла появиться раньше с правами по наследству (пароль локального порта, счётчики
        трафика) — закрываем её от других пользователей перед первой записью в любом случае."""
        if self._secured:
            return
        folder = self.path.parent
        existed = folder.exists()
        folder.mkdir(parents=True, exist_ok=True)
        if self._secure is not None:
            try:
                self._secure(folder)
            except Exception as exc:  # чужая функция «Связки»: любая её ошибка — секреты в открытую папку не пишем
                if not existed:
                    try:
                        folder.rmdir()
                    except OSError:
                        pass
                raise StoreError(f"Не удалось закрыть папку профилей VPN от других пользователей: {exc}") from exc
        self._secured = True

    def save(self) -> None:
        with self._lock:
            if self._readonly:
                raise StoreError(self.load_error or "Профили VPN открыты только для чтения")
            self._ensure_folder()
            payload = json.dumps(self._dump(), ensure_ascii=False, indent=1)
            tmp = self.path.with_name(self.path.name + ".tmp")
            try:
                with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            except OSError as exc:
                try:
                    tmp.unlink()
                except OSError:
                    pass
                raise StoreError(f"Не удалось сохранить профили VPN ({exc.strerror or type(exc).__name__})") from None

    # ---------------------------------------------------------------- чтение

    def subscriptions(self) -> list[Subscription]:
        with self._lock:
            return copy.deepcopy(self._state.subs)

    def subscription(self, sub_id: str) -> Subscription | None:
        with self._lock:
            return copy.deepcopy(self._sub(sub_id))

    def servers(self, sub: str | None = ANY) -> list[Server]:
        with self._lock:
            return [copy.deepcopy(s) for s in self._state.servers if sub is ANY or s.sub == sub]

    def server(self, server_id: str) -> Server | None:
        with self._lock:
            return copy.deepcopy(self._server(server_id))

    def groups(self, sub: str | None = ANY) -> list[Group]:
        with self._lock:
            return [copy.deepcopy(g) for g in self._state.groups if sub is ANY or g.sub == sub]

    def group(self, group_id: str) -> Group | None:
        with self._lock:
            return copy.deepcopy(next((g for g in self._state.groups if g.id == group_id), None))

    def selected(self) -> str | None:
        with self._lock:
            return self._state.selected

    def latency(self, server_id: str | None = None) -> dict[str, Any]:
        """Все задержки {id: {ms, at, error}} или запись одного сервера ({} — не проверялся)."""
        with self._lock:
            if server_id is None:
                return copy.deepcopy(self._state.latency)
            return dict(self._state.latency.get(server_id) or {})

    def speed(self, server_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if server_id is None:
                return copy.deepcopy(self._state.speed)
            return dict(self._state.speed.get(server_id) or {})

    def _sub(self, sub_id: str) -> Subscription | None:
        return next((s for s in self._state.subs if s.id == sub_id), None)

    def _server(self, server_id: str) -> Server | None:
        return next((s for s in self._state.servers if s.id == server_id), None)

    # ---------------------------------------------------------------- подписки

    def add_subscription(self, sub: Subscription) -> Subscription:
        """Новая подписка (id и added_at ставятся, если пусты). Адрес — один раз на подписку."""
        with self._lock:
            state = self._state
            if len(state.subs) >= MAX_SUBSCRIPTIONS:
                raise StoreError(f"Подписок может быть не больше {MAX_SUBSCRIPTIONS}")
            if not (sub.url or "").strip():
                raise StoreError("У подписки нет адреса")
            if any(url_key(s.url) == url_key(sub.url) for s in state.subs):
                raise StoreError("Эта подписка уже добавлена")
            new = copy.deepcopy(sub)
            new.url = sub.url.strip()
            if new.id and self._sub(new.id) is not None:
                raise StoreError("Подписка с таким id уже есть")
            while not new.id or self._sub(new.id) is not None:
                new.id = "s-" + secrets.token_hex(3)
            new.added_at = new.added_at or time.time()
            state.subs.append(new)
            self.save()
            return copy.deepcopy(new)

    def update_subscription(self, sub_id: str, **values: Any) -> Subscription:
        """Изменить поля подписки (имена — как в model.Subscription, кроме id)."""
        with self._lock:
            sub = self._sub(sub_id)
            if sub is None:
                raise StoreError("Нет такой подписки")
            unknown = set(values) - {f.name for f in fields(Subscription)} | ({"id"} & set(values))
            if unknown:
                raise ValueError(f"неизвестные поля подписки: {', '.join(sorted(unknown))}")
            if "url" in values:
                url = str(values["url"] or "").strip()
                if not url:
                    raise StoreError("У подписки нет адреса")
                if any(s.id != sub_id and url_key(s.url) == url_key(url) for s in self._state.subs):
                    raise StoreError("Эта подписка уже добавлена")
                values["url"] = url
            for name, value in values.items():
                setattr(sub, name, copy.deepcopy(value))
            self.save()
            return copy.deepcopy(sub)

    def remove_subscription(self, sub_id: str) -> list[str]:
        """Удалить подписку с её серверами и группами; возвращает id удалённых серверов."""
        with self._lock:
            state = self._state
            if self._sub(sub_id) is None:
                raise StoreError("Нет такой подписки")
            removed = [s.id for s in state.servers if s.sub == sub_id]
            gone_groups = {g.id for g in state.groups if g.sub == sub_id}
            state.subs = [s for s in state.subs if s.id != sub_id]
            state.servers = [s for s in state.servers if s.sub != sub_id]
            state.groups = [g for g in state.groups if g.sub != sub_id]
            self._forget(removed)
            if state.selected in removed or state.selected in {AUTO + sub_id} | {AUTO + g for g in gone_groups}:
                state.selected = None
            self.save()
            return removed

    def _forget(self, server_ids: Iterable[str]) -> None:
        for server_id in server_ids:
            self._state.latency.pop(server_id, None)
            self._state.speed.pop(server_id, None)

    def _apply_meta(self, sub: Subscription, decoded: Decoded, now: float) -> None:
        """Поля провайдера — из последнего ответа; имя и интервал — только если провайдер их прислал."""
        meta = decoded.meta
        if decoded.format in SUB_FORMATS:
            sub.format = decoded.format
        sub.updated_at = now
        if decoded.servers:
            sub.last_ok_at = now
            sub.error = None
        sub.userinfo = dict(meta.userinfo)
        sub.refill_at = meta.refill_at
        sub.support_url = meta.support_url
        sub.web_page_url = meta.web_page_url
        sub.announce = meta.announce
        sub.description = meta.description
        sub.fallback_urls = list(meta.fallback_urls)
        if meta.update_hours:
            sub.update_hours = meta.update_hours
        if not sub.name and meta.title:
            sub.name = meta.title

    def apply_decoded(self, sub_id: str, decoded: Decoded, *, now: float | None = None) -> MergeReport:
        """Обновление подписки: сопоставить серверы, перенести выбор, задержки и свои имена.
        0 серверов список не стирает (обновляются только сведения провайдера)."""
        with self._lock:
            state = self._state
            sub = self._sub(sub_id)
            if sub is None:
                raise StoreError("Нет такой подписки")
            self._apply_meta(sub, decoded, time.time() if now is None else now)
            old = [s for s in state.servers if s.sub == sub_id]
            if not decoded.servers:
                self.save()
                return MergeReport(kept=[s.id for s in old])
            fresh, skipped = self._incoming(sub_id, decoded.servers)
            pairs = match_servers(old, fresh)
            report = MergeReport(skipped=skipped)
            for server in fresh:
                previous = pairs.get(server.id)
                if previous is None:
                    report.added.append(server.id)
                    continue
                report.kept.append(server.id)
                server.custom_name = previous.custom_name
                if previous.id != server.id:
                    report.remapped[previous.id] = server.id
            matched = {s.id for s in pairs.values()}
            report.removed = [s.id for s in old if s.id not in matched]
            for old_id, new_id in report.remapped.items():
                for table in (state.latency, state.speed):
                    if old_id in table:
                        table[new_id] = table.pop(old_id)
            self._forget(report.removed)
            self._replace_servers(sub_id, fresh)
            old_groups = [g for g in state.groups if g.sub == sub_id]
            new_groups = self._incoming_groups(sub_id, decoded.groups, {s.id for s in fresh})
            state.groups = [g for g in state.groups if g.sub != sub_id] + new_groups
            report.selection, report.suggested = self._carry_selection(sub_id, report, old_groups, new_groups, fresh)
            self.save()
            return report

    def _incoming(self, sub_id: str, servers: list[Server]) -> tuple[list[Server], int]:
        """Серверы подписки без дублей; чужие (уже есть в другой подписке или отдельно) и сверх лимита — мимо."""
        foreign = {s.id for s in self._state.servers if s.sub != sub_id}
        fresh: list[Server] = []
        seen: set[str] = set()
        skipped = 0
        for item in servers:
            server = copy.deepcopy(item)
            server.sub = sub_id
            server.id = server.id or server.key()
            if server.id in seen:
                continue
            if server.id in foreign:
                skipped += 1
                continue
            seen.add(server.id)
            fresh.append(server)
        room = max(MAX_SERVERS - len(foreign), 0)
        if len(fresh) > room:
            skipped += len(fresh) - room
            fresh = fresh[:room]
        return fresh, skipped

    @staticmethod
    def _incoming_groups(sub_id: str, groups: list[Group], valid: set[str]) -> list[Group]:
        result = []
        for item in groups:
            group = copy.deepcopy(item)
            group.sub = sub_id
            group.members = [m for m in group.members if m in valid]
            if group.fallback not in valid:
                group.fallback = None
            if group.members:
                result.append(group)
        return result

    def _replace_servers(self, sub_id: str, fresh: list[Server]) -> None:
        """Серверы подписки встают на место прежних — порядок списка у человека не прыгает."""
        servers = self._state.servers
        position = next((i for i, s in enumerate(servers) if s.sub == sub_id), len(servers))
        rest = [s for s in servers if s.sub != sub_id]
        before = sum(1 for s in servers[:position] if s.sub != sub_id)
        self._state.servers = rest[:before] + fresh + rest[before:]

    def _carry_selection(self, sub_id: str, report: MergeReport, old_groups: list[Group],
                         new_groups: list[Group], fresh: list[Server]) -> tuple[tuple[str, str | None] | None, str | None]:
        state = self._state
        selected = state.selected
        if not selected:
            return None, None
        if selected in report.remapped:
            state.selected = report.remapped[selected]
            return (selected, state.selected), None
        if selected in report.removed:
            new_ids = {g.id for g in new_groups}
            home = next((g for g in old_groups if selected in g.members and g.id in new_ids), None)
            suggestion = AUTO + home.id if home else (fresh[0].id if fresh else None)
            return (selected, None), suggestion
        target = selected[len(AUTO):] if selected.startswith(AUTO) else None
        old_group = next((g for g in old_groups if g.id == target), None)
        if old_group is None or any(g.id == target for g in new_groups):
            return None, None
        same = [g for g in new_groups if g.name == old_group.name]
        if not same and len(old_groups) == 1 and len(new_groups) == 1:
            same = new_groups
        if len(same) == 1:
            state.selected = AUTO + same[0].id
            return (selected, state.selected), None
        return (selected, None), AUTO + sub_id

    # ---------------------------------------------------------------- серверы

    def add_servers(self, servers: list[Server]) -> MergeReport:
        """Серверы из отдельных ссылок (sub = None). Такой же сервер уже есть: отдельный — обновляется
        параметрами новой ссылки (в key() нет ключа REALITY, отпечатка, ALPN, extra XHTTP — их провайдер
        меняет, а повторная вставка ссылки — способ их обновить), своё имя остаётся; сервер подписки — kept
        (его параметры ведёт провайдер)."""
        with self._lock:
            state = self._state
            # Сервер, сохранённый прежним выпуском под прежним id (key() с тех пор уточнялся — например,
            # у WireGuard добавился ключ клиента), узнаётся и по нынешнему key(): повторная ссылка не дублирует.
            known: dict[str, Server] = {}
            for stored in state.servers:
                known.setdefault(stored.id, stored)
                known.setdefault(stored.key(), stored)
            report = MergeReport()
            new: list[Server] = []
            replaced: dict[int, Server] = {}           # место в списке → сервер с новыми параметрами
            for item in servers:
                server = copy.deepcopy(item)
                server.sub = None
                server.id = server.key()
                stored = known.get(server.id)
                if stored is None:
                    known[server.id] = server
                    new.append(server)
                    continue
                place = next((i for i, s in enumerate(state.servers) if s is stored), None)
                if stored.sub is None and place is not None and _link_fields(stored) != _link_fields(server):
                    server.id, server.custom_name = stored.id, stored.custom_name
                    replaced[place] = server
                    known[server.id] = known[server.key()] = server
                    report.updated.append(server.id)
                else:
                    report.kept.append(stored.id)
            if len(state.servers) + len(new) > MAX_SERVERS:
                raise StoreError(f"Серверов может быть не больше {MAX_SERVERS}")
            for place, server in replaced.items():
                state.servers[place] = server
            state.servers.extend(new)
            report.added = [s.id for s in new]
            if new or replaced:
                self.save()
            return report

    def remove_server(self, server_id: str) -> bool:
        """Удалить сервер. Сервер подписки вернётся при её обновлении: список ведёт провайдер."""
        with self._lock:
            state = self._state
            if self._server(server_id) is None:
                return False
            state.servers = [s for s in state.servers if s.id != server_id]
            for group in state.groups:
                group.members = [m for m in group.members if m != server_id]
                if group.fallback == server_id:
                    group.fallback = None
            gone = {g.id for g in state.groups if not g.members}
            state.groups = [g for g in state.groups if g.members]
            self._forget([server_id])
            if state.selected == server_id or state.selected in {AUTO + g for g in gone}:
                state.selected = None
            self.save()
            return True

    def rename_server(self, server_id: str, name: str | None) -> Server:
        """Своё имя сервера; пустое — вернуть имя провайдера."""
        with self._lock:
            server = self._server(server_id)
            if server is None:
                raise StoreError("Нет такого сервера")
            cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", name or "").strip()[:MAX_NAME]
            server.custom_name = cleaned or None
            self.save()
            return copy.deepcopy(server)

    def select(self, selection: str | None) -> None:
        """Выбрать сервер, «auto:<группа>» или «auto:<подписка>»; None — снять выбор."""
        with self._lock:
            if selection is not None and not _valid_selection(self._state, selection):
                raise StoreError("Нет такого сервера или группы")
            self._state.selected = selection
            self.save()

    def set_latency(self, server_id: str, ms: int | None, error: str | None = None, *,
                    reason: dict | None = None, at: float | None = None, save: bool = True) -> None:
        """Задержка сервера. Пачкой — save=False у всех и один save() в конце. reason — чья сторона у
        «нет ответа» (diagnose.Reason.public): {side, code, text, advice}."""
        with self._lock:
            if self._server(server_id) is None:
                return                       # сервер успели удалить, пока шла проверка
            entry = {"ms": None if ms is None else int(ms), "at": time.time() if at is None else at, "error": error}
            if reason:
                entry["reason"] = dict(reason)
            self._state.latency[server_id] = entry
            if save:
                self.save()

    def set_speed(self, server_id: str, mbps: float | None, error: str | None = None, *,
                  at: float | None = None, save: bool = True) -> None:
        with self._lock:
            if self._server(server_id) is None:
                return
            self._state.speed[server_id] = {"mbps": None if mbps is None else round(float(mbps), 1),
                                            "at": time.time() if at is None else at, "error": error}
            if save:
                self.save()

    # ---------------------------------------------------------------- резервная копия

    def export_data(self) -> dict[str, Any]:
        """Всё содержимое (с секретами) — для резервной копии с паролем."""
        with self._lock:
            return self._dump()

    def import_data(self, data: dict[str, Any]) -> MergeReport:
        """Добавить содержимое резервной копии (schema 1) к текущему: подписка узнаётся по адресу,
        сервер — по id; что уже есть, остаётся как есть (kept), сверх лимитов — skipped."""
        try:
            incoming, _ = _parse_state(copy.deepcopy(data))
        except ValueError as exc:
            raise StoreError(f"Резервная копия профилей не подходит: {exc}") from None
        with self._lock:
            state = self._state
            report = MergeReport()
            subs: dict[str, str] = {}                   # id подписки в копии → id у нас
            for sub in incoming.subs:
                original = sub.id
                same = next((s for s in state.subs if url_key(s.url) == url_key(sub.url)), None)
                if same is not None:
                    subs[original] = same.id
                    continue
                if len(state.subs) >= MAX_SUBSCRIPTIONS:
                    continue                          # её серверы ниже уйдут в skipped
                while self._sub(sub.id) is not None:
                    sub.id = "s-" + secrets.token_hex(3)
                state.subs.append(sub)
                subs[original] = sub.id
            known = {s.id for s in state.servers}
            for server in incoming.servers:
                if server.sub is not None:
                    if server.sub not in subs:
                        report.skipped += 1
                        continue
                    server.sub = subs[server.sub]
                if server.id in known:
                    report.kept.append(server.id)
                    continue
                if len(state.servers) >= MAX_SERVERS:
                    report.skipped += 1
                    continue
                state.servers.append(server)
                known.add(server.id)
                report.added.append(server.id)
                for target, source in ((state.latency, incoming.latency), (state.speed, incoming.speed)):
                    if server.id in source:
                        target[server.id] = source[server.id]
            groups = {g.id for g in state.groups}
            for group in incoming.groups:
                if group.sub is not None and group.sub not in subs:
                    continue
                group.sub = subs.get(group.sub) if group.sub is not None else None
                group.members = [m for m in group.members if m in known]
                if group.id not in groups and group.members:
                    state.groups.append(group)
            selected = incoming.selected
            if selected and selected.startswith(AUTO) and selected[len(AUTO):] in subs:
                selected = AUTO + subs[selected[len(AUTO):]]
            if state.selected is None and selected and _valid_selection(state, selected):
                state.selected = selected
            self.save()
            return report
