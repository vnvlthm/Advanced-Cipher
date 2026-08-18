"""
Explorer Advance — Cipher / EFS

NiceGUI front-end for finding Encrypting File System (EFS) files and folders
and for learning the built-in Windows `cipher` command. Selected items can
be decrypted with `cipher /D` after a confirmation. Folders can be encrypted
with `cipher /E` from the Encrypt tab. Wipe stays reserved for a later tab.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from nicegui import run, ui

import cipher_docs
import cipher_ops

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "user_config.json"
APP_HOST = "127.0.0.1"
APP_PORT = 8766


@dataclass
class AppConfig:
    last_path: str = ""
    recursive: bool = True
    include_hidden: bool = False
    skip_system: bool = True
    scan_all_drives: bool = False
    include_removable: bool = False
    encrypt_path: str = ""
    encrypt_recursive: bool = True
    encrypt_include_hidden: bool = True
    encrypt_stop_on_error: bool = False
    scan_view: str = "items"


def load_config() -> AppConfig:
    if not CONFIG_PATH.is_file():
        return AppConfig(last_path=str(Path.home()))
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        known = {f.name for f in AppConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        cfg = AppConfig(**{k: v for k, v in data.items() if k in known})
        if not cfg.last_path:
            cfg.last_path = str(Path.home())
        return cfg
    except Exception:
        return AppConfig(last_path=str(Path.home()))


def save_config(cfg: AppConfig) -> None:
    try:
        CONFIG_PATH.write_text(
            json.dumps(asdict(cfg), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


cfg = load_config()
scan_job: Optional[cipher_ops.ScanProgress] = None


def _row_from_event(e: Any) -> dict:
    args = getattr(e, "args", e)
    if isinstance(args, list):
        args = args[0] if args else {}
    return args if isinstance(args, dict) else {}


def _path_from_event(e: Any) -> str:
    """Pull a filesystem path out of a table slot / row-dblclick event."""
    args = getattr(e, "args", e)
    chunks = args if isinstance(args, list) else [args]
    for item in chunks:
        if isinstance(item, str):
            text = item.strip()
            if len(text) >= 2 and (text[1] == ":" or text.startswith("\\\\")):
                return text
        elif isinstance(item, dict):
            text = str(item.get("path") or "").strip()
            if text:
                return text
    return ""


def _safe_open_explorer(path: str) -> None:
    path = (path or "").strip()
    if not path:
        ui.notify("Could not read that row’s path.", type="warning")
        return
    try:
        cipher_ops.open_in_explorer(path)
        ui.notify(f"Opened in Explorer:\n{path}", type="positive")
    except Exception as exc:
        ui.notify(f"Could not open Explorer: {exc}", type="negative")


def _copy_path(path: str) -> None:
    path = (path or "").strip()
    if not path:
        ui.notify("Could not read that row’s path.", type="warning")
        return
    ui.clipboard.write(path)
    ui.notify("Path copied", type="positive")


def _sort_rows_folders_first(rows: list[dict]) -> list[dict]:
    """Folders first, then files; name then path within each group."""

    def key(row: dict) -> tuple[int, str, str]:
        kind = row.get("kind") or ""
        rank = row.get("kind_rank")
        if rank is None:
            rank = 0 if kind == "Folder" else 1
        name = str(row.get("name") or "").casefold()
        path = str(row.get("path") or "").casefold()
        return (int(rank), name, path)

    return sorted(rows, key=key)


_EXPLORER_OPEN_CAP = 8


def _copy_paths(paths: list[str]) -> None:
    cleaned = [p for p in paths if p]
    if not cleaned:
        return
    ui.clipboard.write("\n".join(cleaned))
    if len(cleaned) == 1:
        ui.notify("Path copied", type="positive")
    else:
        ui.notify(f"{len(cleaned)} paths copied", type="positive")


def _open_many_in_explorer(paths: list[str]) -> None:
    cleaned = [p for p in paths if p]
    if not cleaned:
        return
    if len(cleaned) == 1:
        _safe_open_explorer(cleaned[0])
        return

    by_parent: dict[str, list[str]] = {}
    for path in cleaned:
        by_parent.setdefault(str(Path(path).parent), []).append(path)

    if len(by_parent) == 1:
        _safe_open_explorer(cleaned[0])
        ui.notify(
            f"{len(cleaned)} items in the same folder — revealed the first.",
            type="positive",
        )
        return

    opened = 0
    errors = 0
    for items in list(by_parent.values())[:_EXPLORER_OPEN_CAP]:
        try:
            cipher_ops.open_in_explorer(items[0])
            opened += 1
        except Exception:
            errors += 1
    extra = ""
    if len(by_parent) > _EXPLORER_OPEN_CAP:
        extra = f" (first {_EXPLORER_OPEN_CAP} of {len(by_parent)} folders)"
        ui.notify(
            f"Capped at {_EXPLORER_OPEN_CAP} Explorer windows so the desktop is not flooded.",
            type="info",
        )
    if errors == 0:
        ui.notify(f"Opened {opened} folder(s) in Explorer{extra}.", type="positive")
    else:
        ui.notify(f"Opened {opened} folder(s); {errors} failed{extra}.", type="warning")


def _open_many_parents(paths: list[str]) -> None:
    cleaned = [p for p in paths if p]
    if not cleaned:
        return

    parents: list[str] = []
    seen: set[str] = set()
    for path in cleaned:
        folder = Path(path)
        try:
            if folder.is_file() or not folder.exists():
                folder = folder.parent
        except OSError:
            folder = folder.parent
        key = str(folder).casefold()
        if key in seen:
            continue
        seen.add(key)
        parents.append(str(folder))

    if len(parents) == 1:
        try:
            cipher_ops.open_folder(parents[0])
            ui.notify(f"Opened folder:\n{parents[0]}", type="positive")
        except Exception as exc:
            ui.notify(f"Could not open folder: {exc}", type="negative")
        return

    opened = 0
    errors = 0
    for folder in parents[:_EXPLORER_OPEN_CAP]:
        try:
            cipher_ops.open_folder(folder)
            opened += 1
        except Exception:
            errors += 1
    extra = ""
    if len(parents) > _EXPLORER_OPEN_CAP:
        extra = f" (first {_EXPLORER_OPEN_CAP} of {len(parents)})"
        ui.notify(
            f"Capped at {_EXPLORER_OPEN_CAP} Explorer windows so the desktop is not flooded.",
            type="info",
        )
    if errors == 0:
        ui.notify(f"Opened {opened} parent folder(s){extra}.", type="positive")
    else:
        ui.notify(f"Opened {opened} folder(s); {errors} failed{extra}.", type="warning")


def show_decrypt_dialog(
    rows: list[dict],
    *,
    on_done: Callable[[list[cipher_ops.DecryptResult]], None],
) -> None:
    paths = [str(row.get("path")) for row in rows if row.get("path")]
    if not paths:
        ui.notify("Check one or more rows first.", type="warning")
        return

    n_files = sum(1 for row in rows if row.get("kind") == "File")
    n_folders = sum(1 for row in rows if row.get("kind") == "Folder")
    has_volume_root = any(
        cipher_ops.is_drive_root(str(row.get("path") or "")) for row in rows
    )
    preview_limit = 8
    state = {"recursive": True, "running": False}

    with ui.dialog() as dialog, ui.card().classes("w-[760px] max-w-[96vw]"):
        dialog.props("persistent")
        ui.label("Remove EFS encryption").classes("text-subtitle1 font-bold")
        ui.label(
            "This runs cipher /D as the current Windows user. Files are "
            "rewritten as plaintext on disk. You must already be able to "
            "open them (your certificate, or a recovery agent)."
        ).classes("text-body2")

        confirm_box = ui.column().classes("w-full gap-2")
        progress_box = ui.column().classes("w-full gap-2")
        result_box = ui.column().classes("w-full gap-2")
        progress_box.visible = False
        result_box.visible = False

        with confirm_box:
            if n_folders and n_files:
                mix = f"{n_files:,} file(s) and {n_folders:,} folder(s)"
            elif n_folders:
                mix = f"{n_folders:,} folder(s)"
            else:
                mix = f"{n_files:,} file(s)"
            ui.label(f"{len(rows):,} selected — {mix}.").classes("text-body2")
            for row in rows[:preview_limit]:
                kind = row.get("kind") or "Item"
                name = row.get("name") or row.get("path") or ""
                path = row.get("path") or ""
                ui.label(f"{kind}: {name}").classes("text-body2")
                ui.label(path).classes("text-caption text-grey-8 break-all -mt-2")
            extra = len(rows) - preview_limit
            if extra > 0:
                ui.label(f"+{extra:,} more").classes("text-caption text-grey-7")

            w_recursive = ui.checkbox(
                "Also decrypt everything inside selected folders (cipher /D /S)",
                value=True,
            ).tooltip(
                "Without this, a folder only loses the “encrypt new files” "
                "mark. Files already inside stay encrypted."
            )
            if n_folders == 0:
                w_recursive.visible = False

            ui.label("Commands that will run").classes("text-caption text-grey-8")
            cmd_host = ui.column().classes("w-full gap-1")

            def render_plan() -> None:
                if cmd_host.is_deleted:
                    return
                state["recursive"] = bool(w_recursive.value)
                plan = cipher_ops.plan_decrypt(
                    paths,
                    recursive_folders=state["recursive"],
                )
                cmd_host.clear()
                with cmd_host:
                    if not plan:
                        ui.label("Nothing to decrypt — those paths are gone.").classes(
                            "text-negative"
                        )
                        return
                    for item in plan[:preview_limit]:
                        ui.code(item.command).classes("w-full")
                    leftover = len(plan) - preview_limit
                    if leftover > 0:
                        ui.label(f"+{leftover:,} more cipher command(s)").classes(
                            "text-caption text-grey-7"
                        )

            w_recursive.on_value_change(lambda _e: render_plan())
            render_plan()

            w_ack = ui.checkbox(
                "I understand a drive root is selected — this can decrypt "
                "EFS items across that volume."
            )
            if not has_volume_root:
                w_ack.visible = False

        with progress_box:
            progress_label = ui.label("Decrypting…").classes("text-body2")
            ui.spinner(size="lg").classes("mx-auto my-2")
            ui.label("Leave this window open until cipher finishes.").classes(
                "text-caption text-grey-7"
            )

        with result_box:
            result_title = ui.label("").classes("text-subtitle2")
            result_body = ui.code("").classes("w-full")

        with ui.row().classes("w-full justify-end gap-2"):
            cancel_btn = ui.button("Cancel", on_click=dialog.close).props("flat")
            decrypt_btn = ui.button(
                "Decrypt selected",
                icon="lock_open",
            ).props("unelevated color=negative")
            close_btn = ui.button("Close", on_click=dialog.close).props("flat")
            close_btn.visible = False

        def refresh_decrypt_btn() -> None:
            if state["running"]:
                decrypt_btn.disable()
                return
            if has_volume_root and not w_ack.value:
                decrypt_btn.disable()
            else:
                decrypt_btn.enable()

        w_ack.on_value_change(lambda _e: refresh_decrypt_btn())
        refresh_decrypt_btn()

        async def start_decrypt() -> None:
            if state["running"]:
                return
            if has_volume_root and not w_ack.value:
                ui.notify("Confirm the drive-root warning first.", type="warning")
                return
            state["running"] = True
            state["recursive"] = bool(w_recursive.value)
            refresh_decrypt_btn()
            cancel_btn.visible = False
            decrypt_btn.visible = False
            confirm_box.visible = False
            progress_box.visible = True
            progress_label.set_text("Starting cipher /D…")

            prog = cipher_ops.DecryptProgress()

            def tick() -> None:
                if progress_label.is_deleted:
                    return
                with prog.lock:
                    done = prog.done
                    total = prog.total
                    current = prog.current
                    message = prog.message
                if total:
                    loc = current if len(current) < 80 else "…" + current[-77:]
                    progress_label.set_text(
                        f"Decrypting {done} / {total}"
                        + (f" — {loc}" if loc else "")
                    )
                elif message:
                    progress_label.set_text(message)

            timer = ui.timer(0.35, tick)

            def worker() -> list[cipher_ops.DecryptResult]:
                return cipher_ops.decrypt_paths(
                    paths,
                    recursive_folders=state["recursive"],
                    progress=prog,
                )

            try:
                results = await run.io_bound(worker)
            except Exception as exc:
                timer.deactivate()
                progress_box.visible = False
                result_box.visible = True
                close_btn.visible = True
                result_title.set_text("Decrypt failed to start")
                result_body.set_content(str(exc))
                ui.notify(str(exc), type="negative")
                return

            timer.deactivate()
            on_done(results)

            ok = sum(1 for item in results if item.ok)
            failed = [item for item in results if not item.ok]
            leftover = sum(1 for item in results if item.still_encrypted)
            progress_box.visible = False
            result_box.visible = True
            close_btn.visible = True

            if not results:
                result_title.set_text("Nothing was decrypted.")
                result_body.set_content("No matching paths were left to pass to cipher.")
            elif not failed:
                result_title.set_text(
                    f"Decrypted {ok:,} target(s). They are now plaintext on disk."
                )
            else:
                result_title.set_text(
                    f"Decrypted {ok:,} of {len(results):,} target(s). "
                    f"{len(failed):,} failed"
                    + (f", {leftover:,} still encrypted" if leftover else "")
                    + "."
                )

            chunks: list[str] = []
            for item in results:
                mark = "OK" if item.ok else "FAILED"
                block = f"[{mark}] {item.command}"
                if item.text:
                    block += "\n" + item.text
                if item.still_encrypted:
                    block += "\n(Still has the Encrypted NTFS attribute.)"
                chunks.append(block)
            result_body.set_content("\n\n".join(chunks) or "(no cipher output)")

            if failed:
                ui.notify(
                    f"Decrypted {ok:,}; {len(failed):,} failed.",
                    type="warning",
                )
            elif ok:
                ui.notify(f"Decrypted {ok:,} item(s).", type="positive")

        decrypt_btn.on_click(start_decrypt)

    dialog.open()


def show_encrypt_dialog(
    rows: list[dict],
    *,
    recursive_folders: bool,
    include_hidden: bool,
    stop_on_error: bool,
    on_done: Callable[[list[cipher_ops.EncryptResult]], None],
) -> None:
    paths = [str(row.get("path")) for row in rows if row.get("path")]
    if not paths:
        ui.notify("Add one or more folders first.", type="warning")
        return

    n_files = sum(1 for row in rows if row.get("kind") == "File")
    n_folders = sum(1 for row in rows if row.get("kind") == "Folder")
    has_volume_root = any(
        cipher_ops.is_drive_root(str(row.get("path") or "")) for row in rows
    )
    blocked = [row for row in rows if not row.get("can_encrypt", True)]
    preview_limit = 8
    state = {
        "recursive": recursive_folders,
        "hidden": include_hidden,
        "abort": stop_on_error,
        "running": False,
    }

    with ui.dialog() as dialog, ui.card().classes("w-[760px] max-w-[96vw]"):
        dialog.props("persistent")
        ui.label("Encrypt with EFS").classes("text-subtitle1 font-bold")
        ui.label(
            "This runs cipher /E as the current Windows user. Files are "
            "rewritten encrypted on disk. Only this account (and any recovery "
            "agent) will be able to open them. Run as yourself — not as "
            "another administrator — or the files encrypt for that account."
        ).classes("text-body2")

        confirm_box = ui.column().classes("w-full gap-2")
        progress_box = ui.column().classes("w-full gap-2")
        result_box = ui.column().classes("w-full gap-2")
        progress_box.visible = False
        result_box.visible = False

        with confirm_box:
            if n_folders and n_files:
                mix = f"{n_files:,} file(s) and {n_folders:,} folder(s)"
            elif n_folders:
                mix = f"{n_folders:,} folder(s)"
            else:
                mix = f"{n_files:,} file(s)"
            ui.label(f"{len(rows):,} selected — {mix}.").classes("text-body2")
            for row in rows[:preview_limit]:
                kind = row.get("kind") or "Item"
                name = row.get("name") or row.get("path") or ""
                path = row.get("path") or ""
                status = row.get("status") or ""
                extra = f" — {status}" if status else ""
                ui.label(f"{kind}: {name}{extra}").classes("text-body2")
                ui.label(path).classes("text-caption text-grey-8 break-all -mt-2")
            extra = len(rows) - preview_limit
            if extra > 0:
                ui.label(f"+{extra:,} more").classes("text-caption text-grey-7")

            if blocked:
                ui.label(
                    f"{len(blocked):,} item(s) cannot be encrypted (missing or not NTFS) "
                    "and will be skipped."
                ).classes("text-negative text-body2")

            w_recursive = ui.checkbox(
                "Also encrypt everything inside selected folders (cipher /E /S)",
                value=recursive_folders,
            ).tooltip(
                "Without this, the folder is marked so new files encrypt, and "
                "files sitting directly in it are encrypted. Subfolders stay "
                "plaintext."
            )
            if n_folders == 0:
                w_recursive.visible = False

            w_hidden = ui.checkbox(
                "Include hidden / system files (cipher /H)",
                value=include_hidden,
            )
            w_abort = ui.checkbox(
                "Stop on the first error (cipher /B)",
                value=stop_on_error,
            )

            ui.label("Commands that will run").classes("text-caption text-grey-8")
            cmd_host = ui.column().classes("w-full gap-1")

            def render_plan() -> None:
                if cmd_host.is_deleted:
                    return
                state["recursive"] = bool(w_recursive.value)
                state["hidden"] = bool(w_hidden.value)
                state["abort"] = bool(w_abort.value)
                eligible = [
                    str(row.get("path"))
                    for row in rows
                    if row.get("path") and row.get("can_encrypt", True)
                ]
                plan = cipher_ops.plan_encrypt(
                    eligible,
                    recursive_folders=state["recursive"],
                    include_hidden=state["hidden"],
                    stop_on_error=state["abort"],
                )
                cmd_host.clear()
                with cmd_host:
                    if not plan:
                        ui.label(
                            "Nothing to encrypt — those paths are gone or not NTFS."
                        ).classes("text-negative")
                        return
                    for item in plan[:preview_limit]:
                        ui.code(item.command).classes("w-full")
                    leftover = len(plan) - preview_limit
                    if leftover > 0:
                        ui.label(f"+{leftover:,} more cipher command(s)").classes(
                            "text-caption text-grey-7"
                        )

            w_recursive.on_value_change(lambda _e: render_plan())
            w_hidden.on_value_change(lambda _e: render_plan())
            w_abort.on_value_change(lambda _e: render_plan())
            render_plan()

            w_ack = ui.checkbox(
                "I understand only this Windows user (and any recovery agent) "
                "can open these files. I have a certificate backup, or I accept "
                "the risk of losing access."
            )
            w_root = ui.checkbox(
                "I understand a drive root is selected — this can encrypt "
                "EFS items across that volume."
            )
            if not has_volume_root:
                w_root.visible = False

        with progress_box:
            progress_label = ui.label("Encrypting…").classes("text-body2")
            ui.spinner(size="lg").classes("mx-auto my-2")
            ui.label("Leave this window open until cipher finishes.").classes(
                "text-caption text-grey-7"
            )

        with result_box:
            result_title = ui.label("").classes("text-subtitle2")
            result_body = ui.code("").classes("w-full")

        with ui.row().classes("w-full justify-end gap-2"):
            cancel_btn = ui.button("Cancel", on_click=dialog.close).props("flat")
            encrypt_btn = ui.button(
                "Encrypt selected",
                icon="lock",
            ).props("unelevated color=primary")
            close_btn = ui.button("Close", on_click=dialog.close).props("flat")
            close_btn.visible = False

        def refresh_encrypt_btn() -> None:
            if state["running"]:
                encrypt_btn.disable()
                return
            eligible = any(row.get("can_encrypt", True) for row in rows)
            if not eligible or not w_ack.value or (has_volume_root and not w_root.value):
                encrypt_btn.disable()
            else:
                encrypt_btn.enable()

        w_ack.on_value_change(lambda _e: refresh_encrypt_btn())
        w_root.on_value_change(lambda _e: refresh_encrypt_btn())
        refresh_encrypt_btn()

        async def start_encrypt() -> None:
            if state["running"]:
                return
            if not w_ack.value:
                ui.notify("Confirm the certificate warning first.", type="warning")
                return
            if has_volume_root and not w_root.value:
                ui.notify("Confirm the drive-root warning first.", type="warning")
                return
            state["running"] = True
            state["recursive"] = bool(w_recursive.value)
            state["hidden"] = bool(w_hidden.value)
            state["abort"] = bool(w_abort.value)
            refresh_encrypt_btn()
            cancel_btn.visible = False
            encrypt_btn.visible = False
            confirm_box.visible = False
            progress_box.visible = True
            progress_label.set_text("Starting cipher /E…")

            prog = cipher_ops.EncryptProgress()

            def tick() -> None:
                if progress_label.is_deleted:
                    return
                with prog.lock:
                    done = prog.done
                    total = prog.total
                    current = prog.current
                    message = prog.message
                if total:
                    loc = current if len(current) < 80 else "…" + current[-77:]
                    progress_label.set_text(
                        f"Encrypting {done} / {total}"
                        + (f" — {loc}" if loc else "")
                    )
                elif message:
                    progress_label.set_text(message)

            timer = ui.timer(0.35, tick)
            eligible = [
                str(row.get("path"))
                for row in rows
                if row.get("path") and row.get("can_encrypt", True)
            ]

            def worker() -> list[cipher_ops.EncryptResult]:
                return cipher_ops.encrypt_paths(
                    eligible,
                    recursive_folders=state["recursive"],
                    include_hidden=state["hidden"],
                    stop_on_error=state["abort"],
                    progress=prog,
                )

            try:
                results = await run.io_bound(worker)
            except Exception as exc:
                timer.deactivate()
                progress_box.visible = False
                result_box.visible = True
                close_btn.visible = True
                result_title.set_text("Encrypt failed to start")
                result_body.set_content(str(exc))
                ui.notify(str(exc), type="negative")
                return

            timer.deactivate()
            on_done(results)

            ok = sum(1 for item in results if item.ok)
            failed = [item for item in results if not item.ok]
            leftover = sum(1 for item in results if item.still_plain)
            partial = sum(
                1
                for item in results
                if item.ok and item.returncode not in (0, None)
            )
            progress_box.visible = False
            result_box.visible = True
            close_btn.visible = True

            if not results:
                result_title.set_text("Nothing was encrypted.")
                result_body.set_content("No matching NTFS paths were left to pass to cipher.")
            elif not failed:
                extra = (
                    f" cipher reported errors on {partial:,} target(s) — "
                    "check the log for files that may still be plaintext."
                    if partial
                    else " New files dropped in those folders will be encrypted too."
                )
                result_title.set_text(f"Encrypted {ok:,} target(s).{extra}")
            else:
                result_title.set_text(
                    f"Encrypted {ok:,} of {len(results):,} target(s). "
                    f"{len(failed):,} failed"
                    + (f", {leftover:,} still plaintext" if leftover else "")
                    + "."
                )

            chunks: list[str] = []
            for item in results:
                mark = "OK" if item.ok else "FAILED"
                block = f"[{mark}] {item.command}"
                if item.text:
                    block += "\n" + item.text
                if item.still_plain:
                    block += "\n(Still missing the Encrypted NTFS attribute.)"
                chunks.append(block)
            result_body.set_content("\n\n".join(chunks) or "(no cipher output)")

            if failed:
                ui.notify(
                    f"Encrypted {ok:,}; {len(failed):,} failed.",
                    type="warning",
                )
            elif ok:
                ui.notify(f"Encrypted {ok:,} item(s).", type="positive")

        encrypt_btn.on_click(start_encrypt)

    dialog.open()


# ---------------------------------------------------------------------------
# Tab 1 — Find encrypted
# ---------------------------------------------------------------------------


def build_scanner_tab() -> None:
    drives = cipher_ops.list_local_drives(include_removable=True)
    ntfs_fixed = [d for d in drives if d.ntfs and d.kind == "Fixed"]
    ntfs_all = [d for d in drives if d.ntfs]

    table_columns = [
        {
            "name": "kind",
            "label": "Type",
            "field": "kind_rank",
            "sortable": True,
            "align": "left",
            "style": "width: 7.5rem",
            "headerStyle": "width: 7.5rem",
        },
        {
            "name": "name",
            "label": "Name",
            "field": "name",
            "sortable": True,
            "align": "left",
            "classes": "ellipsis",
            "style": "width: 16rem; max-width: 16rem",
            "headerStyle": "width: 16rem; max-width: 16rem",
        },
        {
            "name": "path",
            "label": "Path",
            "field": "path",
            "sortable": True,
            "align": "left",
            "classes": "ellipsis",
            "style": "max-width: 0",
            "headerStyle": "max-width: 0",
        },
        {
            "name": "size_label",
            "label": "Size",
            "field": "size_label",
            "sortable": True,
            "align": "right",
            "style": "width: 6.5rem",
            "headerStyle": "width: 6.5rem",
        },
        {
            "name": "modified",
            "label": "Modified",
            "field": "modified",
            "sortable": True,
            "align": "left",
            "style": "width: 11rem",
            "headerStyle": "width: 11rem",
        },
        {
            "name": "actions",
            "label": "",
            "field": "actions",
            "align": "right",
            "required": True,
            "style": "width: 8rem",
            "headerStyle": "width: 8rem",
        },
    ]

    with ui.column().classes("w-full max-w-[96rem] mx-auto p-4 gap-4"):
        with ui.card().classes("w-full"):
            ui.markdown(
                "**Find EFS-encrypted files and folders** on this PC, then open "
                "their location in Explorer or decrypt a selection with `cipher /D`. "
                "Use **Folders with files** to list every folder that *contains* "
                "encrypted files (even if the folder itself is not marked encrypted), "
                "then decrypt that folder. Detection uses the NTFS *Encrypted* "
                "attribute (the same padlock Explorer shows) — it does not parse "
                "the localized `cipher` text. Details still come from `cipher /c`."
            )
            cert_label = ui.label("Reading EFS certificate…").classes(
                "text-caption text-grey-8 mt-2"
            )

            async def load_cert() -> None:
                if cert_label.is_deleted:
                    return
                text = await run.io_bound(cipher_ops.cipher_current_certificate)
                if cert_label.is_deleted:
                    return
                one_line = " ".join(text.split())
                if len(one_line) > 180:
                    one_line = one_line[:177] + "…"
                cert_label.set_text(one_line or "No EFS certificate reported.")
                cert_label.tooltip(text)

            ui.timer(0.05, load_cert, once=True)

        with ui.card().classes("w-full"):
            ui.label("Where to look").classes("text-subtitle1 font-bold")

            path_row = ui.row().classes("w-full items-end gap-2 no-wrap")
            with path_row:
                w_path = (
                    ui.input(
                        "Folder to scan",
                        value=cfg.last_path,
                        placeholder=r"C:\Users\You\Documents",
                    )
                    .classes("flex-grow")
                    .props("clearable")
                )

                def browse() -> None:
                    picked = cipher_ops.pick_folder(
                        w_path.value or cfg.last_path,
                        title="Select folder to scan",
                    )
                    if picked:
                        w_path.value = picked

                ui.button(icon="folder_open", on_click=browse).props("flat round").tooltip(
                    "Browse…"
                )

            with ui.row().classes("w-full flex-wrap gap-4 items-center"):
                w_recursive = ui.checkbox("Recursive", value=cfg.recursive)
                w_skip = ui.checkbox(
                    "Skip Windows / system folders",
                    value=cfg.skip_system,
                ).tooltip(
                    "Skips WinSxS, Recycle Bin, System Volume Information, and "
                    "(when scanning a drive root) Windows and Program Files."
                )
                w_hidden = ui.checkbox(
                    "Include hidden / system items",
                    value=cfg.include_hidden,
                )
                w_all = ui.checkbox(
                    "All local NTFS drives",
                    value=cfg.scan_all_drives,
                ).tooltip("Ignore the folder box and walk every fixed NTFS volume.")
                w_removable = ui.checkbox(
                    "Include removable NTFS",
                    value=cfg.include_removable,
                ).bind_visibility_from(w_all, "value")

            chips = ui.row().classes("flex-wrap gap-1")
            with chips:
                ui.label("NTFS volumes:").classes("text-caption text-grey-8 self-center")
                for drive in drives:
                    color = "primary" if drive.ntfs else "grey"
                    label = f"{drive.letter}: {drive.filesystem} ({drive.kind})"
                    ui.badge(label, color=color).props("outline")

            if not ntfs_fixed:
                ui.label(
                    "No fixed NTFS volume was detected. EFS only exists on NTFS."
                ).classes("text-negative")

        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center gap-3 flex-wrap"):
                scan_btn = ui.button(
                    "Find encrypted items",
                    icon="search",
                    on_click=lambda: None,
                ).props("unelevated size=lg")
                stop_btn = ui.button("Stop", icon="stop", on_click=lambda: None).props(
                    "outline color=negative"
                )
                stop_btn.disable()
                ui.button(
                    "Save settings",
                    icon="save",
                    on_click=lambda: persist_settings(),
                ).props("flat")

            progress = ui.linear_progress(show_value=False).classes("w-full")
            progress.visible = False
            status = ui.label("Ready. Choose a folder and click Find encrypted items.").classes(
                "text-caption text-grey-8"
            )

        with ui.card().classes("w-full mb-16"):
            with ui.row().classes("w-full items-center justify-between flex-wrap gap-2"):
                with ui.column().classes("gap-0"):
                    summary = ui.label("No scan yet.").classes("text-subtitle2")
                    ui.label(
                        "Check one or more rows to use the action bar at the bottom."
                    ).classes("text-caption text-grey-7")
                with ui.row().classes("items-center gap-2 flex-wrap"):
                    selection_chip = (
                        ui.button(
                            "Actions",
                            icon="checklist",
                            on_click=lambda: show_selection_dock(),
                        )
                        .props("unelevated")
                        .tooltip("Show the action bar for the checked items")
                    )
                    selection_chip.visible = False
                    w_view = ui.toggle(
                        {
                            "items": "All items",
                            "containers": "Folders with files",
                        },
                        value=(
                            cfg.scan_view
                            if cfg.scan_view in {"items", "containers"}
                            else "items"
                        ),
                    ).props("no-caps unelevated").tooltip(
                        "All items: every encrypted file and folder. "
                        "Folders with files: unique parent folders of those "
                        "files, so you can decrypt a whole folder at once."
                    )
                    ui.button(
                        "Folders first",
                        icon="folder",
                        on_click=lambda: sort_folders_first(),
                    ).props("outline").tooltip(
                        "Show every folder, then every file. "
                        "Same as clicking the Type column (once)."
                    )
                    filter_input = (
                        ui.input(placeholder="Filter name or path…")
                        .props("dense clearable debounce=200")
                        .classes("w-64")
                    )

            table = ui.table(
                columns=table_columns,
                rows=[],
                row_key="path",
                selection="multiple",
                pagination={
                    "rowsPerPage": 25,
                    "sortBy": "kind",
                    "descending": False,
                },
            ).classes("w-full").props('table-style="table-layout: fixed; width: 100%"')
            table.add_slot(
                "body-cell-kind",
                """
                <q-td :props="props">
                    <q-icon
                        :name="props.row.kind === 'Folder' ? 'folder' : 'insert_drive_file'"
                        :color="props.row.kind === 'Folder' ? 'amber-8' : 'primary'"
                        size="sm"
                        class="q-mr-xs"
                    />
                    {{ props.row.kind }}
                </q-td>
                """,
            )
            table.add_slot(
                "body-cell-name",
                """
                <q-td :props="props">
                    <div class="ellipsis">{{ props.row.name }}</div>
                    <div v-if="props.row.file_count" class="text-caption text-grey-7">
                        {{ props.row.file_count }} encrypted
                        {{ props.row.file_count === 1 ? 'file' : 'files' }}
                        <span v-if="props.row.encrypted_folder"> · folder marked encrypted</span>
                    </div>
                    <q-tooltip class="text-body2" max-width="36rem">
                        {{ props.row.name }}
                    </q-tooltip>
                </q-td>
                """,
            )
            table.add_slot(
                "body-cell-path",
                """
                <q-td :props="props" style="max-width: 0; overflow: hidden;">
                    <div class="ellipsis">{{ props.row.path }}</div>
                    <q-tooltip class="text-body2" max-width="40rem">
                        {{ props.row.path }}
                    </q-tooltip>
                </q-td>
                """,
            )
            table.add_slot(
                "body-cell-actions",
                """
                <q-td :props="props" style="width: 8rem; white-space: nowrap;">
                    <q-btn flat dense round icon="folder_open" color="primary"
                           @click.stop="$parent.$emit('open_explorer', props.row.path)">
                        <q-tooltip>Reveal in Explorer</q-tooltip>
                    </q-btn>
                    <q-btn flat dense round icon="info" color="secondary"
                           @click.stop="$parent.$emit('show_info', props.row.path)">
                        <q-tooltip>cipher /c details</q-tooltip>
                    </q-btn>
                    <q-btn flat dense round icon="content_copy"
                           @click.stop="$parent.$emit('copy_path', props.row.path)">
                        <q-tooltip>Copy path</q-tooltip>
                    </q-btn>
                </q-td>
                """,
            )

            filter_input.bind_value(table, "filter")

            with ui.row().classes("w-full items-center gap-2 flex-wrap"):
                ui.button(
                    "Reveal in Explorer",
                    icon="folder_open",
                    on_click=lambda: act_selected("open"),
                ).props("unelevated")
                ui.button(
                    "Open parent folder",
                    icon="drive_file_move",
                    on_click=lambda: act_selected("folder"),
                ).props("outline")
                ui.button(
                    "cipher /c details",
                    icon="info",
                    on_click=lambda: act_selected("info"),
                ).props("outline color=secondary")
                ui.button(
                    "Copy path",
                    icon="content_copy",
                    on_click=lambda: act_selected("copy"),
                ).props("flat")
                ui.button(
                    "Decrypt",
                    icon="lock_open",
                    on_click=lambda: act_selected("decrypt"),
                ).props("outline color=negative").tooltip(
                    "Remove EFS encryption with cipher /D. "
                    "In Folders with files, this decrypts the folder tree (/D /S)."
                )
                ui.button(
                    "Clear results",
                    icon="delete_outline",
                    on_click=lambda: clear_results(),
                ).props("flat")

        def sort_folders_first() -> None:
            rows = list(table.rows or [])
            if not rows:
                ui.notify("Scan first, then you can group folders at the top.", type="info")
                return
            table.rows = _sort_rows_folders_first(rows)
            pag = table.pagination
            if isinstance(pag, dict):
                table.pagination = {**pag, "sortBy": "kind", "descending": False}
            ui.notify("Folders first, then files.", type="positive")

        scan_items: list[dict] = []
        view_state = {
            "mode": cfg.scan_view if cfg.scan_view in {"items", "containers"} else "items"
        }

        def persist_settings(*, notify: bool = True) -> None:
            cfg.last_path = (w_path.value or "").strip()
            cfg.recursive = bool(w_recursive.value)
            cfg.include_hidden = bool(w_hidden.value)
            cfg.skip_system = bool(w_skip.value)
            cfg.scan_all_drives = bool(w_all.value)
            cfg.include_removable = bool(w_removable.value)
            cfg.scan_view = view_state["mode"]
            save_config(cfg)
            if notify:
                ui.notify("Settings saved", type="positive")

        def displayed_rows() -> list[dict]:
            if view_state["mode"] == "containers":
                return cipher_ops.containing_folder_rows(scan_items)
            return list(scan_items)

        def update_summary(shown: list[dict]) -> None:
            n_files = sum(1 for row in scan_items if row.get("kind") == "File")
            n_dirs = sum(1 for row in scan_items if row.get("kind") == "Folder")
            if view_state["mode"] == "containers":
                marked = sum(1 for row in shown if row.get("encrypted_folder"))
                extra = f" · {marked:,} also marked encrypted" if marked else ""
                summary.set_text(
                    f"{len(shown):,} folder(s) with encrypted files — "
                    f"{n_files:,} file(s){extra}."
                )
            else:
                summary.set_text(
                    f"{len(scan_items):,} encrypted item(s) — "
                    f"{n_files:,} file(s), {n_dirs:,} folder(s)."
                )

        def render_view(*, clear_selection: bool = False) -> None:
            shown = displayed_rows()
            if view_state["mode"] != "containers":
                shown = _sort_rows_folders_first(shown)
            selected_paths = set()
            if not clear_selection:
                selected_paths = {
                    str(row.get("path")) for row in selected_rows() if row.get("path")
                }
            table.rows = shown
            table.selected = [
                row for row in shown if str(row.get("path")) in selected_paths
            ]
            update_summary(shown)
            refresh_selection_ui()

        def set_view() -> None:
            mode = w_view.value if w_view.value in {"items", "containers"} else "items"
            if mode == view_state["mode"] and table.rows:
                return
            view_state["mode"] = mode
            persist_settings(notify=False)
            if not scan_items:
                table.rows = []
                table.selected = []
                if mode == "containers":
                    summary.set_text("No scan yet. Folders with files will list parent folders.")
                else:
                    summary.set_text("No scan yet.")
                refresh_selection_ui()
                return
            render_view(clear_selection=True)
            if mode == "containers":
                ui.notify(
                    f"{len(table.rows or []):,} folder(s) contain encrypted files.",
                    type="info",
                )

        def selected_rows() -> list[dict]:
            return list(table.selected or [])

        def selected_paths() -> list[str]:
            return [str(row.get("path")) for row in selected_rows() if row.get("path")]

        def require_selection() -> list[str]:
            paths = selected_paths()
            if not paths:
                ui.notify("Check one or more rows first.", type="warning")
            return paths

        def drop_unencrypted_rows() -> None:
            kept = []
            for row in list(scan_items):
                path = str(row.get("path") or "")
                if path and cipher_ops.is_encrypted_path(path):
                    kept.append(row)
            scan_items[:] = kept
            render_view(clear_selection=False)

        def confirm_decrypt() -> None:
            rows = selected_rows()
            if not rows:
                ui.notify("Check one or more rows first.", type="warning")
                return

            def after(results: list[cipher_ops.DecryptResult]) -> None:
                drop_unencrypted_rows()
                ok = sum(1 for item in results if item.ok)
                failed = sum(1 for item in results if not item.ok)
                if ok and not failed:
                    status.set_text(f"Decrypted {ok:,} selected target(s) with cipher /D.")
                elif ok or failed:
                    status.set_text(
                        f"cipher /D finished: {ok:,} decrypted, {failed:,} failed."
                    )

            show_decrypt_dialog(rows, on_done=after)

        def act_selected(action: str) -> None:
            paths = require_selection()
            if not paths:
                return
            if action == "open":
                _open_many_in_explorer(paths)
            elif action == "folder":
                _open_many_parents(paths)
            elif action == "info":
                show_info_dialog(paths)
            elif action == "copy":
                _copy_paths(paths)
            elif action == "decrypt":
                confirm_decrypt()

        selection_ui = {"dock_hidden": False}

        def _selection_preview(rows: list[dict], *, limit: int = 4) -> str:
            names = [str(row.get("name") or row.get("path") or "") for row in rows]
            names = [name for name in names if name]
            if not names:
                return ""
            text = " · ".join(names[:limit])
            extra = len(names) - limit
            if extra > 0:
                text += f"  +{extra:,} more"
            return text

        def refresh_selection_ui() -> None:
            if sel_title.is_deleted:
                return
            rows = selected_rows()
            count = len(rows)
            if count == 0:
                sel_title.set_text("No items selected")
                sel_names.set_text("")
                selection_chip.visible = False
                selection_dock.visible = False
                return
            label = "1 item selected" if count == 1 else f"{count:,} items selected"
            sel_title.set_text(label)
            sel_names.set_text(_selection_preview(rows))
            selection_chip.set_text(f"{label} — Actions")
            selection_chip.visible = True
            selection_dock.visible = not selection_ui["dock_hidden"]

        def show_selection_dock() -> None:
            if not selected_rows():
                ui.notify("Check one or more rows first.", type="warning")
                return
            selection_ui["dock_hidden"] = False
            refresh_selection_ui()

        def hide_selection_dock() -> None:
            selection_ui["dock_hidden"] = True
            selection_dock.visible = False

        def on_table_select(_e=None) -> None:
            if not selected_rows():
                selection_ui["dock_hidden"] = False
            refresh_selection_ui()

        def clear_selection() -> None:
            table.selected = []
            selection_ui["dock_hidden"] = False
            refresh_selection_ui()

        def clear_results() -> None:
            scan_items.clear()
            table.rows = []
            table.selected = []
            selection_ui["dock_hidden"] = False
            refresh_selection_ui()
            summary.set_text("No scan yet.")
            status.set_text("Results cleared.")

        table.on_select(on_table_select)

        with ui.element("div").classes(
            "fixed left-0 right-0 bottom-0 z-[4000] flex justify-center p-3 pointer-events-none"
        ) as selection_dock:
            with ui.card().classes("pointer-events-auto shadow-2xl").style(
                "box-shadow: 0 10px 32px rgba(21, 101, 192, 0.28);"
            ):
                with ui.row().classes("items-center gap-3 flex-wrap"):
                    with ui.column().classes("gap-0 min-w-[10rem] max-w-[22rem]"):
                        sel_title = ui.label("No items selected").classes(
                            "text-subtitle2 font-bold"
                        )
                        sel_names = ui.label("").classes(
                            "text-caption text-grey-8 break-all"
                        )
                    ui.button(
                        "Reveal in Explorer",
                        icon="folder_open",
                        on_click=lambda: act_selected("open"),
                    ).props("unelevated")
                    ui.button(
                        "Open parent folder",
                        icon="drive_file_move",
                        on_click=lambda: act_selected("folder"),
                    ).props("outline")
                    ui.button(
                        "cipher /c details",
                        icon="info",
                        on_click=lambda: act_selected("info"),
                    ).props("outline color=secondary")
                    ui.button(
                        "Copy path",
                        icon="content_copy",
                        on_click=lambda: act_selected("copy"),
                    ).props("flat")
                    ui.button(
                        "Decrypt",
                        icon="lock_open",
                        on_click=lambda: act_selected("decrypt"),
                    ).props("outline color=negative").tooltip(
                        "Remove EFS encryption with cipher /D"
                    )
                    ui.button(
                        "Clear selection",
                        icon="deselect",
                        on_click=lambda: clear_selection(),
                    ).props("flat")
                    ui.button(
                        "Clear results",
                        icon="delete_outline",
                        on_click=lambda: clear_results(),
                    ).props("flat")
                    ui.button(icon="close", on_click=hide_selection_dock).props(
                        "flat round dense"
                    ).tooltip("Hide this bar")
        selection_dock.visible = False

        def apply_rows(rows: list[dict]) -> None:
            scan_items[:] = list(rows)
            selection_ui["dock_hidden"] = False
            render_view(clear_selection=True)

        def refresh_live() -> None:
            if status.is_deleted:
                return
            job = scan_job
            if job is None or not job.running:
                return
            with job.lock:
                scanned = job.scanned
                found = job.found
                errors = job.errors
                current = job.current
                rows = list(job.rows)
            scan_items[:] = rows
            if view_state["mode"] == "containers":
                shown = cipher_ops.containing_folder_rows(rows)
                table.rows = shown
                summary.set_text(
                    f"{len(shown):,} folder(s) with encrypted files so far…"
                )
            else:
                table.rows = rows
                summary.set_text(f"{found:,} encrypted item(s) so far…")
            loc = current if len(current) < 90 else "…" + current[-87:]
            extra = f" · {errors} access error(s)" if errors else ""
            status.set_text(f"Scanned {scanned:,} · found {found:,}{extra} · {loc}")

        ui.timer(0.4, refresh_live)

        def request_stop() -> None:
            job = scan_job
            if job and job.running:
                job.cancel_event.set()
                status.set_text("Stopping…")

        stop_btn.on_click(request_stop)

        async def start_scan() -> None:
            global scan_job
            if scan_job and scan_job.running:
                ui.notify("A scan is already running.", type="warning")
                return

            persist_settings(notify=False)
            if cfg.scan_all_drives:
                roots = cipher_ops.ntfs_scan_roots(include_removable=cfg.include_removable)
                if not roots:
                    ui.notify("No NTFS volume to scan.", type="negative")
                    return
            else:
                folder = (w_path.value or "").strip()
                if not folder:
                    ui.notify("Choose a folder to scan.", type="warning")
                    return
                if not Path(folder).exists():
                    ui.notify(f"Path does not exist:\n{folder}", type="negative")
                    return
                roots = [folder]

            job = cipher_ops.ScanProgress(running=True)
            scan_job = job
            scan_items.clear()
            table.rows = []
            table.selected = []
            selection_ui["dock_hidden"] = False
            refresh_selection_ui()
            summary.set_text("Scanning…")
            progress.visible = True
            progress.props("indeterminate")
            scan_btn.disable()
            stop_btn.enable()
            where = ", ".join(roots)
            status.set_text(f"Scanning {where}…")

            def worker() -> None:
                cipher_ops.scan_encrypted(
                    roots,
                    recursive=cfg.recursive,
                    include_hidden=cfg.include_hidden,
                    skip_system=cfg.skip_system,
                    progress=job,
                )

            try:
                await run.io_bound(worker)
            except Exception as exc:
                status.set_text(f"Scan failed: {exc}")
                ui.notify(str(exc), type="negative")
            finally:
                progress.visible = False
                scan_btn.enable()
                stop_btn.disable()

            with job.lock:
                rows = list(job.rows)
                message = job.message
                cancelled = job.cancelled
                scanned = job.scanned
                errors = job.errors
            apply_rows(rows)
            extra = f" · {errors} access error(s)" if errors else ""
            prefix = "Cancelled." if cancelled else "Done."
            status.set_text(f"{prefix} {message} · looked at {scanned:,} item(s){extra}")
            if cancelled:
                ui.notify("Scan stopped.", type="warning")
            elif not rows:
                ui.notify(
                    "No encrypted files or folders in that scope.",
                    type="info",
                )
            else:
                ui.notify(f"Found {len(rows):,} encrypted item(s).", type="positive")

        scan_btn.on_click(start_scan)
        w_path.on("keydown.enter", start_scan)
        w_view.on_value_change(lambda _e: set_view())

        table.on("open_explorer", lambda e: _safe_open_explorer(_path_from_event(e)))
        table.on("copy_path", lambda e: _copy_path(_path_from_event(e)))
        table.on("show_info", lambda e: show_info_dialog(_path_from_event(e)))
        table.on(
            "rowDblclick",
            lambda e: _safe_open_explorer(_path_from_event(e)),
            js_handler="(_evt, row) => emit(row && row.path)",
        )


def show_info_dialog(path: str | list[str]) -> None:
    if isinstance(path, str):
        paths = [path] if path else []
    else:
        paths = [item for item in path if item]
    if not paths:
        return

    current = {"path": paths[0]}
    picker_limit = 40
    shown_paths = paths[:picker_limit]

    with ui.dialog() as dialog, ui.card().classes("w-[820px] max-w-[95vw]"):
        if len(paths) > 1:
            ui.label(f"cipher /c details — {len(paths):,} items").classes(
                "text-subtitle1 font-bold"
            )
            picker = ui.select(
                options=shown_paths,
                value=current["path"],
                label="Item",
                with_input=len(shown_paths) > 8,
            ).classes("w-full")
            if len(paths) > picker_limit:
                ui.label(
                    f"Showing the first {picker_limit} of {len(paths):,} selected items."
                ).classes("text-caption text-grey-8")
        else:
            picker = None

        path_label = ui.label(current["path"]).classes("text-subtitle2 break-all")
        spinner = ui.spinner(size="lg").classes("mx-auto my-4")
        body = ui.code("").classes("w-full")
        body.visible = False
        with ui.row().classes("w-full justify-end gap-2"):
            ui.button(
                "Reveal in Explorer",
                icon="folder_open",
                on_click=lambda: _safe_open_explorer(current["path"]),
            ).props("outline")
            ui.button("Close", on_click=dialog.close).props("flat")

        async def fill() -> None:
            if body.is_deleted:
                return
            target = current["path"]
            listing = await run.io_bound(cipher_ops.cipher_listing, target)
            details = await run.io_bound(cipher_ops.cipher_file_info, target)
            if body.is_deleted or current["path"] != target:
                return
            parts = []
            if listing:
                parts.append(listing)
            if details and details != listing:
                parts.append(details)
            body.set_content("\n\n".join(parts) or "(no cipher output)")
            spinner.visible = False
            body.visible = True

        def reload(target: str) -> None:
            if not target:
                return
            current["path"] = target
            path_label.set_text(target)
            spinner.visible = True
            body.visible = False
            ui.timer(0.05, fill, once=True)

        if picker is not None:
            picker.on("update:model-value", lambda e: reload(e.args or picker.value))

        ui.timer(0.05, fill, once=True)

    dialog.open()


# ---------------------------------------------------------------------------
# Tab 2 — Encrypt folders
# ---------------------------------------------------------------------------


def build_encrypt_tab() -> None:
    start_path = cfg.encrypt_path or cfg.last_path
    targets: list[dict] = []

    def inspect_row(path: str) -> dict:
        info = cipher_ops.inspect_path(path)
        return {
            "path": info.path,
            "name": info.name,
            "kind": info.kind,
            "encrypted": info.encrypted,
            "ntfs": info.ntfs,
            "filesystem": info.filesystem,
            "readonly": info.readonly,
            "drive_root": info.drive_root,
            "exists": info.exists,
            "status": info.status_label,
            "can_encrypt": info.can_encrypt,
        }

    with ui.column().classes("w-full max-w-[96rem] mx-auto p-4 gap-4"):
        with ui.card().classes("w-full"):
            ui.markdown(
                "**Encrypt folders with EFS** using `cipher /E`. The folder is "
                "marked so files added later stay encrypted. Tick **Also encrypt "
                "everything inside** to walk the tree (`/S`). This is the same "
                "padlock Explorer shows — it is **not** BitLocker."
            )
            cert_label = ui.label("Reading EFS certificate…").classes(
                "text-caption text-grey-8 mt-2"
            )

            async def load_cert() -> None:
                if cert_label.is_deleted:
                    return
                text = await run.io_bound(cipher_ops.cipher_current_certificate)
                if cert_label.is_deleted:
                    return
                one_line = " ".join(text.split())
                if len(one_line) > 180:
                    one_line = one_line[:177] + "…"
                cert_label.set_text(one_line or "No EFS certificate reported.")
                cert_label.tooltip(text)

            ui.timer(0.05, load_cert, once=True)

        with ui.card().classes("w-full"):
            ui.label("Folders to encrypt").classes("text-subtitle1 font-bold")
            ui.label(
                "Add one or more folders. Each one is encrypted as the current "
                "Windows user. EFS works only on NTFS."
            ).classes("text-body2")

            path_row = ui.row().classes("w-full items-end gap-2 no-wrap")
            with path_row:
                w_path = (
                    ui.input(
                        "Folder to encrypt",
                        value=start_path,
                        placeholder=r"C:\Users\You\Private",
                    )
                    .classes("flex-grow")
                    .props("clearable")
                )

                def browse() -> None:
                    picked = cipher_ops.pick_folder(
                        w_path.value or start_path,
                        title="Select folder to encrypt",
                    )
                    if picked:
                        w_path.value = picked

                ui.button(icon="folder_open", on_click=browse).props("flat round").tooltip(
                    "Browse…"
                )
                add_btn = ui.button("Add folder", icon="create_new_folder").props(
                    "unelevated"
                )

            list_host = ui.column().classes("w-full gap-2 mt-2")
            empty_label = ui.label(
                "No folders added yet. Browse or type a path, then click Add folder."
            ).classes("text-caption text-grey-7")

        with ui.card().classes("w-full"):
            ui.label("Cipher options").classes("text-subtitle1 font-bold")
            w_recursive = ui.checkbox(
                "Also encrypt everything inside selected folders (cipher /E /S)",
                value=cfg.encrypt_recursive,
            ).tooltip(
                "Without this, only the folder mark and files sitting directly "
                "in it are encrypted. Subfolders stay plaintext."
            )
            w_hidden = ui.checkbox(
                "Include hidden / system files (cipher /H)",
                value=cfg.encrypt_include_hidden,
            )
            w_abort = ui.checkbox(
                "Stop on the first error (cipher /B)",
                value=cfg.encrypt_stop_on_error,
            )
            ui.label("Commands that will run").classes("text-caption text-grey-8 mt-2")
            cmd_host = ui.column().classes("w-full gap-1")

        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center gap-3 flex-wrap"):
                encrypt_btn = ui.button(
                    "Encrypt folders",
                    icon="lock",
                ).props("unelevated size=lg")
                ui.button(
                    "Save settings",
                    icon="save",
                    on_click=lambda: persist_encrypt_settings(),
                ).props("flat")
                ui.button(
                    "Clear list",
                    icon="delete_outline",
                    on_click=lambda: clear_targets(),
                ).props("flat")
            status = ui.label(
                "Add a folder, review the cipher /E command, then encrypt."
            ).classes("text-caption text-grey-8")

        def persist_encrypt_settings(*, notify: bool = True) -> None:
            cfg.encrypt_path = (w_path.value or "").strip() or (
                targets[0]["path"] if targets else cfg.encrypt_path
            )
            cfg.encrypt_recursive = bool(w_recursive.value)
            cfg.encrypt_include_hidden = bool(w_hidden.value)
            cfg.encrypt_stop_on_error = bool(w_abort.value)
            if cfg.encrypt_path and not cfg.last_path:
                cfg.last_path = cfg.encrypt_path
            save_config(cfg)
            if notify:
                ui.notify("Settings saved", type="positive")

        def render_plan() -> None:
            if cmd_host.is_deleted:
                return
            eligible = [row["path"] for row in targets if row.get("can_encrypt")]
            plan = cipher_ops.plan_encrypt(
                eligible,
                recursive_folders=bool(w_recursive.value),
                include_hidden=bool(w_hidden.value),
                stop_on_error=bool(w_abort.value),
            )
            cmd_host.clear()
            with cmd_host:
                if not plan:
                    ui.label("Add an NTFS folder to preview the cipher command.").classes(
                        "text-caption text-grey-7"
                    )
                    return
                for item in plan[:8]:
                    ui.code(item.command).classes("w-full")
                leftover = len(plan) - 8
                if leftover > 0:
                    ui.label(f"+{leftover:,} more cipher command(s)").classes(
                        "text-caption text-grey-7"
                    )

        def refresh_encrypt_btn() -> None:
            if any(row.get("can_encrypt") for row in targets):
                encrypt_btn.enable()
            else:
                encrypt_btn.disable()

        def refresh_targets() -> None:
            if list_host.is_deleted:
                return
            list_host.clear()
            empty_label.visible = not targets
            with list_host:
                for index, row in enumerate(targets):
                    with ui.row().classes(
                        "w-full items-center gap-3 flex-wrap border rounded p-2"
                    ):
                        icon_name = (
                            "folder" if row.get("kind") == "Folder" else "insert_drive_file"
                        )
                        icon_color = (
                            "amber-8" if row.get("kind") == "Folder" else "primary"
                        )
                        ui.icon(icon_name, color=icon_color).classes("text-2xl")
                        with ui.column().classes("gap-0 flex-grow min-w-[12rem]"):
                            ui.label(row.get("name") or row["path"]).classes(
                                "text-body2 font-bold"
                            )
                            ui.label(row["path"]).classes(
                                "text-caption text-grey-8 break-all"
                            )
                        with ui.row().classes("items-center gap-1 flex-wrap"):
                            if row.get("can_encrypt"):
                                color = (
                                    "teal" if row.get("encrypted") else "primary"
                                )
                            elif not row.get("exists"):
                                color = "orange"
                            else:
                                color = "negative"
                            ui.badge(row.get("status") or "", color=color).props(
                                "outline"
                            )
                            if row.get("drive_root"):
                                ui.badge("Drive root", color="orange").props("outline")
                            if row.get("readonly"):
                                ui.badge("Read-only", color="orange").props(
                                    "outline"
                                ).tooltip(
                                    "cipher cannot encrypt read-only files. "
                                    "Clear that attribute first."
                                )
                        ui.button(
                            icon="folder_open",
                            on_click=lambda _e, path=row["path"]: _safe_open_explorer(
                                path
                            ),
                        ).props("flat round dense").tooltip("Reveal in Explorer")
                        ui.button(
                            icon="info",
                            on_click=lambda _e, path=row["path"]: show_info_dialog(
                                path
                            ),
                        ).props("flat round dense").tooltip("cipher /c details")
                        ui.button(
                            icon="close",
                            on_click=lambda _e, i=index: remove_target(i),
                        ).props("flat round dense").tooltip("Remove")
            refresh_encrypt_btn()
            render_plan()

        def add_folder(raw: Optional[str] = None) -> None:
            text = (raw if raw is not None else (w_path.value or "")).strip().strip('"')
            if not text:
                ui.notify("Choose a folder first.", type="warning")
                return
            try:
                path = str(Path(text).expanduser().resolve())
            except OSError:
                path = str(Path(text).expanduser())
            info = inspect_row(path)
            key = info["path"].casefold()
            if any(str(row["path"]).casefold() == key for row in targets):
                ui.notify("That path is already in the list.", type="info")
                w_path.value = info["path"]
                return
            if not info["exists"]:
                ui.notify(f"Path does not exist:\n{info['path']}", type="negative")
                return
            if not info["ntfs"]:
                fs = info["filesystem"] or "unknown"
                ui.notify(
                    f"EFS only works on NTFS. This volume is {fs}.",
                    type="negative",
                )
            targets.append(info)
            w_path.value = info["path"]
            persist_encrypt_settings(notify=False)
            refresh_targets()
            if info["can_encrypt"] and info["kind"] == "File":
                ui.notify(
                    "Added a file. Encrypting the parent folder is safer so new "
                    "saves stay encrypted.",
                    type="info",
                )
            elif info["can_encrypt"]:
                ui.notify(f"Added {info['name']}", type="positive")

        def remove_target(index: int) -> None:
            if 0 <= index < len(targets):
                targets.pop(index)
                refresh_targets()

        def clear_targets() -> None:
            targets.clear()
            refresh_targets()
            status.set_text("List cleared.")

        def confirm_encrypt() -> None:
            typed = (w_path.value or "").strip()
            if typed and not targets:
                add_folder(typed)
            if not targets:
                ui.notify("Add one or more folders first.", type="warning")
                return
            eligible = [row for row in targets if row.get("can_encrypt")]
            if not eligible:
                ui.notify(
                    "None of the added paths can be encrypted (need an existing NTFS folder).",
                    type="warning",
                )
                return
            persist_encrypt_settings(notify=False)
            fresh = [inspect_row(row["path"]) for row in targets]
            targets[:] = fresh
            refresh_targets()

            def after(results: list[cipher_ops.EncryptResult]) -> None:
                by_path = {item.path.casefold(): item for item in results}
                for row in targets:
                    result = by_path.get(str(row["path"]).casefold())
                    if result is None:
                        continue
                    updated = inspect_row(row["path"])
                    row.update(updated)
                refresh_targets()
                ok = sum(1 for item in results if item.ok)
                failed = sum(1 for item in results if not item.ok)
                if ok and not failed:
                    status.set_text(f"Encrypted {ok:,} target(s) with cipher /E.")
                elif ok or failed:
                    status.set_text(
                        f"cipher /E finished: {ok:,} encrypted, {failed:,} failed."
                    )

            show_encrypt_dialog(
                list(targets),
                recursive_folders=bool(w_recursive.value),
                include_hidden=bool(w_hidden.value),
                stop_on_error=bool(w_abort.value),
                on_done=after,
            )

        add_btn.on_click(lambda _e: add_folder())
        encrypt_btn.on_click(confirm_encrypt)
        w_path.on("keydown.enter", lambda _e: add_folder())
        w_recursive.on_value_change(lambda _e: render_plan())
        w_hidden.on_value_change(lambda _e: render_plan())
        w_abort.on_value_change(lambda _e: render_plan())
        refresh_targets()


# ---------------------------------------------------------------------------
# Tab 3 — Manual
# ---------------------------------------------------------------------------


def build_manual_tab() -> None:
    with ui.column().classes("w-full max-w-6xl mx-auto p-4 gap-4"):
        with ui.card().classes("w-full"):
            ui.label("Cipher manual").classes("text-h6")
            ui.markdown(
                "A field guide to **`cipher.exe`**, the Windows command that "
                "manages **Encrypting File System (EFS)** files and folders. "
                "Switches below match `cipher /?` on this PC — including newer "
                "ones (`/P`, `/FLUSHCACHE`, `/USER`, `/ECC`) that older Microsoft "
                "pages omit."
            )

        with ui.card().classes("w-full"):
            ui.markdown(cipher_docs.OVERVIEW_MD)

        with ui.card().classes("w-full"):
            ui.label("Quick start").classes("text-subtitle1 font-bold")
            ui.markdown(cipher_docs.QUICKSTART_MD)

        with ui.card().classes("w-full"):
            ui.label("Safety").classes("text-subtitle1 font-bold")
            ui.markdown(cipher_docs.SAFETY_MD)

        with ui.expansion("Full switch list (same as Command map)", icon="list").classes(
            "w-full"
        ):
            ui.markdown(
                "See the **Command map** tab for every switch, an example, and "
                "whether this app already wraps it."
            )
            for group, cmds in cipher_docs.commands_by_group():
                ui.label(group).classes("text-subtitle2 mt-3")
                lines = [
                    f"- `{c['switch']}` — **{c['title']}** — {c['summary']}" for c in cmds
                ]
                ui.markdown("\n".join(lines))

        with ui.card().classes("w-full"):
            ui.label("Not the same as…").classes("text-subtitle1 font-bold")
            ui.markdown(
                "- **BitLocker** — whole-volume encryption. `manage-bde`, not `cipher`.\n"
                "- **NTFS permissions** — who can *see* a path. EFS is who can "
                "*decrypt the bytes*. You usually need both.\n"
                "- **ZIP / 7-Zip passwords** — archive encryption, not EFS.\n"
                "- **`ConvertTo-SecureString`** — PowerShell secret encoding, unrelated."
            )


# ---------------------------------------------------------------------------
# Tab 4 — Command map (possibilities + later UI)
# ---------------------------------------------------------------------------


def build_command_map_tab() -> None:
    with ui.column().classes("w-full max-w-6xl mx-auto p-4 gap-4"):
        with ui.card().classes("w-full"):
            ui.label("What cipher can do").classes("text-h6")
            ui.markdown(cipher_docs.ROADMAP_MD)
            with ui.row().classes("gap-2 flex-wrap"):
                ui.badge("In this app", color="positive")
                ui.badge("UI later", color="grey")
                ui.badge("Destructive", color="negative")

        filter_box = (
            ui.input(placeholder="Filter switches…")
            .props("dense clearable debounce=200 outlined")
            .classes("w-full max-w-md")
        )

        cards_host = ui.column().classes("w-full gap-3")

        def render(query: str = "") -> None:
            cards_host.clear()
            q = (query or "").strip().lower()
            with cards_host:
                shown = 0
                for group, cmds in cipher_docs.commands_by_group():
                    filtered = [
                        c
                        for c in cmds
                        if not q
                        or q in c["switch"].lower()
                        or q in c["title"].lower()
                        or q in c["summary"].lower()
                        or q in c["group"].lower()
                    ]
                    if not filtered:
                        continue
                    ui.label(group).classes("text-subtitle1 font-bold mt-2")
                    for cmd in filtered:
                        shown += 1
                        danger = cmd["danger"]
                        with ui.card().classes("w-full"):
                            with ui.row().classes(
                                "w-full items-start justify-between gap-2 flex-wrap"
                            ):
                                with ui.column().classes("gap-0"):
                                    ui.label(cmd["title"]).classes("text-subtitle1 font-bold")
                                    ui.label(cmd["syntax"]).classes(
                                        "text-caption font-mono text-grey-8"
                                    )
                                with ui.row().classes("gap-1"):
                                    ui.badge(cmd["switch"], color="primary")
                                    ui.badge(
                                        cipher_docs.STATUS_LABEL[cmd["status"]],
                                        color=cipher_docs.STATUS_COLOR[cmd["status"]],
                                    )
                                    if danger:
                                        ui.badge("Destructive", color="negative")
                            ui.label(cmd["summary"]).classes("text-body2")
                            with ui.expansion("Details & examples", icon="code").classes(
                                "w-full"
                            ):
                                ui.markdown(cmd["details"])
                                for ex in cmd["examples"]:
                                    ui.code(ex).classes("w-full")
                                    ui.button(
                                        "Copy",
                                        icon="content_copy",
                                        on_click=lambda _e, example=ex: (
                                            ui.clipboard.write(example),
                                            ui.notify("Copied", type="positive"),
                                        ),
                                    ).props("flat dense")
                if shown == 0:
                    ui.label("No command matches that filter.").classes("text-grey-7")

        render()
        filter_box.on("update:model-value", lambda e: render(e.args or ""))


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


@ui.page("/")
def index() -> None:
    ui.colors(primary="#1565C0", secondary="#00897B", accent="#FF8F00")

    if not cipher_ops.is_windows():
        with ui.column().classes("w-full max-w-xl mx-auto p-8"):
            ui.label("Windows only").classes("text-h5")
            ui.label("`cipher` and EFS exist only on Windows / NTFS.")
        return

    with ui.header().classes("items-center justify-between px-4"):
        with ui.row().classes("items-center gap-3"):
            ui.icon("lock", size="md")
            ui.label("Explorer Advance").classes("text-h6")
            ui.badge("Cipher / EFS").props("outline color=white")
        ui.label("Find encrypted files · encrypt folders · learn cipher.exe").classes(
            "text-caption opacity-80"
        )
        ui.label(f"Local only · http://{APP_HOST}:{APP_PORT}").classes(
            "text-caption opacity-70"
        )

    with ui.tabs().classes("w-full px-2").props("active-color=primary indicator-color=primary") as tabs:
        tab_scan = ui.tab("scan", label="Find encrypted", icon="search")
        tab_encrypt = ui.tab("encrypt", label="Encrypt", icon="lock")
        tab_manual = ui.tab("manual", label="Cipher manual", icon="menu_book")
        tab_map = ui.tab("map", label="Command map", icon="map")

    with ui.tab_panels(tabs, value=tab_scan).classes("w-full"):
        with ui.tab_panel(tab_scan).classes("p-0"):
            build_scanner_tab()
        with ui.tab_panel(tab_encrypt).classes("p-0"):
            build_encrypt_tab()
        with ui.tab_panel(tab_manual).classes("p-0"):
            build_manual_tab()
        with ui.tab_panel(tab_map).classes("p-0"):
            build_command_map_tab()


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title="Explorer Advance — Cipher",
        reload=False,
        host=APP_HOST,
        port=APP_PORT,
        show=True,
        favicon="🔐",
    )
