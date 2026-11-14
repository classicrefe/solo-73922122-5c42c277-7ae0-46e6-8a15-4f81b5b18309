"""归档服务层：上传/下载状态机、密钥轮换与崩溃恢复。

并发模型：单进程、多线程（FastAPI 线程池）。所有 SQLite 访问与共享状态
均在一把可重入锁内串行化；SQLite 额外开启 WAL + busy_timeout 兜底。
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag

from . import crypto
from .db import connect

MAX_FILE_SIZE = 8 * 1024 * 1024  # 每件不超过 8 MiB
WORKER_POLL_SECONDS = 0.1
GATE_WAIT_SECONDS = 1.0


class ServiceError(Exception):
    """业务错误，status_code 由 main 层映射为 HTTP 状态码。"""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class PauseGate:
    """演示用暂停门：关闭（paused）后，到达检查点的会话在此等待。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self._open = threading.Event()
        self._open.set()  # 默认放行
        self._cond = threading.Condition()
        self.waiting = 0

    def pause(self) -> None:
        with self._cond:
            self._open.clear()
            self._cond.notify_all()

    def resume(self) -> None:
        with self._cond:
            self._open.set()
            self._cond.notify_all()

    @property
    def paused(self) -> bool:
        return not self._open.is_set()

    def wait_if_closed(self, stop_event: threading.Event) -> None:
        """阻塞等待至闸门重新打开或服务关闭。调用方不得持有 Service.lock，
        否则控制闸门的请求会因拿不到锁而死锁。"""
        if self._open.is_set():
            return
        with self._cond:
            self.waiting += 1
            try:
                while not self._open.is_set():
                    self._cond.wait(timeout=GATE_WAIT_SECONDS)
                    if self._open.is_set():
                        break
                    if stop_event.is_set():
                        raise ServiceError("服务正在关闭，等待暂停点的会话被中断", 503)
            finally:
                self.waiting -= 1
                self._cond.notify_all()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Service:
    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.keys_dir = os.path.join(self.data_dir, "keys")
        self.vault_dir = os.path.join(self.data_dir, "vault")
        self.staging_dir = os.path.join(self.data_dir, "staging")
        self.db_path = os.path.join(self.data_dir, "archive.db")
        for d in (self.keys_dir, self.vault_dir, self.staging_dir):
            os.makedirs(d, exist_ok=True)

        self.lock = threading.RLock()
        self.conn: sqlite3.Connection = connect(self.db_path)
        self.stop_event = threading.Event()
        # upload_id -> DEK（明文 DEK 只存在于内存，绝不落盘）
        self._upload_deks: dict[str, bytes] = {}
        # repair_id -> 备份原件明文（仅在内存中参与校验/重加密，绝不落盘）
        self._repair_plaintexts: dict[str, bytes] = {}
        # kek_id -> 明文 KEK 的内存缓存（落盘副本只在 keys/ 目录）
        self._kek_cache: dict[int, bytes] = {}
        # 运行中的轮换线程（同期只允许一个）
        self._rotation_thread: threading.Thread | None = None

        self.upload_gate = PauseGate("upload_register")
        self.download_gate = PauseGate("download_unwrap")

        self._recover()
        self._ensure_rotation_worker()

    def close(self) -> None:
        self.stop_event.set()
        with self.lock:
            self.conn.close()

    # ------------------------------------------------------------------ #
    # 基础工具
    # ------------------------------------------------------------------ #
    @contextlib.contextmanager
    def _unlocked_wait(self, gate: PauseGate):
        """在暂停门处等待时临时释放 Service.lock，醒来重新取锁。

        避免“会话持锁等待闸门、而切换闸门的请求无法获取锁”的死锁。
        唤醒后调用方必须重新读取数据库行并复查状态。
        """
        self.lock.release()
        try:
            gate.wait_if_closed(self.stop_event)
            yield
        finally:
            self.lock.acquire()

    def _now(self) -> str:
        return utcnow()

    def _row(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params).fetchall())

    def _touch(self, table: str, id_col: str, row_id: str) -> None:
        self.conn.execute(
            f"UPDATE {table} SET updated_at=? WHERE {id_col}=?",
            (self._now(), row_id),
        )

    def _kek_path(self, key_id: str) -> str:
        return os.path.join(self.keys_dir, f"{key_id}.kek")

    def _blob_path(self, file_id: str) -> str:
        return os.path.join(self.vault_dir, f"{file_id}.blob")

    def _staging_path(self, upload_id: str, nonce: bytes) -> str:
        return os.path.join(self.staging_dir, f"{upload_id}.{nonce.hex()}.staging")

    def _repair_new_path(self, repair_id: str) -> str:
        """修复新密文的暂存路径（与原件备份不同，落盘的只是 DEK 加密后的密文）。"""
        return os.path.join(self.staging_dir, f"repair-{repair_id}.new")

    def _repair_backup_path(self, file_id: str) -> str:
        """替换密文时对旧密文的同目录备份路径（同目录保证 os.replace 原子）。"""
        return os.path.join(self.vault_dir, f"{file_id}.blob.bak")

    def _get_kek(self, kek_pk: int) -> bytes:
        kek = self._kek_cache.get(kek_pk)
        if kek is not None:
            return kek
        row = self._row("SELECT key_id FROM project_keys WHERE id=?", (kek_pk,))
        if row is None:
            raise ServiceError("课题密钥不存在", 500)
        kek = crypto.load_kek_file(self._kek_path(row["key_id"]))
        self._kek_cache[kek_pk] = kek
        return kek

    def _active_key(self) -> sqlite3.Row | None:
        return self._row("SELECT * FROM project_keys WHERE status='active' ORDER BY id DESC LIMIT 1")

    def _active_rotation(self) -> sqlite3.Row | None:
        return self._row(
            "SELECT * FROM rotations WHERE state IN ('running','completing') "
            "ORDER BY id DESC LIMIT 1"
        )

    # ------------------------------------------------------------------ #
    # 启动恢复
    # ------------------------------------------------------------------ #
    def _recover(self) -> None:
        """进程重启后清理在途会话、续办未完成的轮换。

        已归档文件（files 表 + vault 密文）永远保留，且其 DEK 始终可由
        某个未删除的 KEK 解封——只有在没有任何引用/在途使用后旧 KEK 才会删除。
        """
        with self.lock:
            now = self._now()

            # 1) 未完成上传：内存 DEK 已随进程消失，暂存密文无法登记，清理。
            pending_uploads = self._all(
                "SELECT * FROM uploads WHERE state IN ('created','pending_register')"
            )
            for up in pending_uploads:
                self._unlink_quiet(up["staging_path"])
                self.conn.execute(
                    "UPDATE uploads SET state='failed', error=?, updated_at=? WHERE id=?",
                    ("进程重启，内存数据密钥丢失，上传中断并清理暂存密文", now, up["id"]),
                )
                self._upload_deks.pop(up["upload_id"], None)

            # 2) 未完成下载：标记中断并清除受理快照中的封装材料
            #   （受理会话不跨进程恢复，客户端可重新发起）。
            self.conn.execute(
                "UPDATE downloads SET state='interrupted', wrapped_dek=NULL, dek_nonce=NULL, "
                "nonce=NULL, updated_at=? WHERE state IN ('accepted','unwrapping')",
                (now,),
            )

            # 2b) 未完成修复：内存中的备份原件已随进程消失，无法继续，标记中断；
            #     已在内存中（尚未落盘）的明文本来就没有磁盘副本需要清理。
            self.conn.execute(
                "UPDATE repairs SET state='interrupted', wrapped_dek=NULL, dek_nonce=NULL, "
                "nonce=NULL, error=?, updated_at=? WHERE state IN ('accepted','verified')",
                ("进程重启，内存中的备份原件丢失，修复中断", now),
            )
            self._repair_plaintexts.clear()

            # 2c) 修复替换的崩溃对账：保证 files 行始终指向一份可读密文。
            #   - staging/repair-*.new：新密文暂存，未提交前一律可删；
            #   - vault/*.blob.bak：os.replace 交换产生的旧密文备份。若 files 行
            #     的 nonce 与现网 blob 不匹配而与备份匹配（事务未提交即崩溃），
            #     用备份还原现网副本；已完成修复遗留的备份直接删除。
            self._reconcile_repair_leftovers_locked()

            # 3) 清理没有任何 upload 引用的孤儿暂存文件（上次崩溃残留）。
            referenced = {
                r["staging_path"]
                for r in self._all(
                    "SELECT staging_path FROM uploads WHERE staging_path IS NOT NULL"
                )
            }
            for name in os.listdir(self.staging_dir):
                path = os.path.join(self.staging_dir, name)
                if path not in referenced:
                    self._unlink_quiet(path)

            # 4) 续办/收尾未完成的轮换。
            rot = self._active_rotation()
            if rot is not None:
                old = self._row("SELECT * FROM project_keys WHERE id=?", (rot["old_kek_id"],))
                new = self._row("SELECT * FROM project_keys WHERE id=?", (rot["new_kek_id"],))
                old_file_exists = old is not None and os.path.exists(self._kek_path(old["key_id"]))
                new_file_exists = new is not None and os.path.exists(self._kek_path(new["key_id"]))
                if not new_file_exists:
                    # 极端情况：新 KEK 行已提交但密钥文件未落地（写文件前崩溃）。
                    # 此时还没有任何文件用新 KEK 封装，重新生成并补齐文件即可。
                    new_kek = crypto.new_kek()
                    crypto.save_kek_file(new["path"], new_kek)
                    self._kek_cache[new["id"]] = new_kek
                    new_file_exists = True
                if not old_file_exists:
                    # 旧 KEK 文件已被删除：重封装/收尾事实上已完成，补完状态。
                    if old is not None and old["status"] != "deleted":
                        self.conn.execute(
                            "UPDATE project_keys SET status='deleted', deleted_at=? WHERE id=?",
                            (now, old["id"]),
                        )
                    self.conn.execute(
                        "UPDATE rotations SET state='completed', completed_at=?, "
                        "rewrapped=total, blocking_uploads=0, blocking_downloads=0, "
                        "message=COALESCE(message, '重启时检测到旧课题密钥文件已删除') WHERE id=?",
                        (now, rot["id"]),
                    )
                else:
                    # 旧 KEK 还在：保持 running，后台线程继续重封装与收尾。
                    self.conn.execute(
                        "UPDATE rotations SET state='running', completed_at=NULL WHERE id=?",
                        (rot["id"],),
                    )

            # 5) 确保始终存在一个可用课题密钥（首次启动生成）。
            self._ensure_active_key_locked()
            self.conn.commit()

    def _ensure_active_key_locked(self) -> sqlite3.Row:
        active = self._active_key()
        if active is not None:
            return active
        key_id = uuid.uuid4().hex
        kek = crypto.new_kek()
        path = self._kek_path(key_id)
        crypto.save_kek_file(path, kek)
        now = self._now()
        cur = self.conn.execute(
            "INSERT INTO project_keys (key_id, path, status, created_at) VALUES (?,?, 'active', ?)",
            (key_id, path, now),
        )
        self.conn.commit()
        self._kek_cache[cur.lastrowid] = kek
        return self._row("SELECT * FROM project_keys WHERE id=?", (cur.lastrowid,))  # type: ignore[return-value]

    def _ensure_rotation_worker(self) -> None:
        with self.lock:
            rot = self._active_rotation()
            if rot is None:
                return
            if self._rotation_thread is not None and self._rotation_thread.is_alive():
                return
            t = threading.Thread(
                target=self._rotation_worker,
                args=(rot["rotation_id"],),
                name=f"rotation-{rot['rotation_id'][:8]}",
                daemon=True,
            )
            self._rotation_thread = t
            t.start()

    @staticmethod
    def _unlink_quiet(path: str | None) -> None:
        if path:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)

    def _reconcile_repair_leftovers_locked(self) -> None:
        """启动时对账修复替换可能留下的临时/备份文件，恢复“原有可读副本”。

        崩溃点与处理（全程在恢复阶段、无并发）：
        * 新密文还在 staging/（尚未替换现网 blob）：直接删除，files 行未动；
        * 现网 blob 已被换成新密文、旧密文留在 *.bak，但事务未提交
          （files.nonce 仍与备份一致）：用备份还原现网副本；
        * 事务已提交（files.nonce 与现网一致）但备份未及删除：删除备份；
        * 找不到任何 files 行引用的游离备份：直接删除。
        """
        for name in list(os.listdir(self.staging_dir)):
            if name.startswith("repair-") and name.endswith(".new"):
                self._unlink_quiet(os.path.join(self.staging_dir, name))

        for name in list(os.listdir(self.vault_dir)):
            if not name.endswith(".blob.bak"):
                continue
            file_id = name[: -len(".blob.bak")]
            backup_path = os.path.join(self.vault_dir, name)
            blob_path = self._blob_path(file_id)
            f = self._row("SELECT * FROM files WHERE file_id=?", (file_id,))
            if f is None:
                self._unlink_quiet(backup_path)
                continue
            live_nonce = self._blob_nonce_quiet(blob_path)
            backup_nonce = self._blob_nonce_quiet(backup_path)
            if live_nonce is not None and live_nonce == f["nonce"]:
                # 事务已提交，新密文生效：备份是收尾残留。
                self._unlink_quiet(backup_path)
            elif backup_nonce is not None and backup_nonce == f["nonce"]:
                # 事务未提交即崩溃：files 行仍登记旧密文，还原可读副本。
                os.replace(backup_path, blob_path)
            else:
                # 两边都对不上：保留 files 行登记对应的现网副本，丢弃游离备份。
                self._unlink_quiet(backup_path)

    def _blob_nonce_quiet(self, path: str) -> bytes | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(crypto.NONCE_SIZE)
        except OSError:
            return None

    # ------------------------------------------------------------------ #
    # 上传：created -> pending_register（暂停点：待登记）-> completed
    # ------------------------------------------------------------------ #
    def create_upload(self, filename: str, declared_size: int) -> dict[str, Any]:
        filename = self._validate_filename(filename)
        if not isinstance(declared_size, int) or declared_size <= 0:
            raise ServiceError("文件大小必须为正整数", 422)
        if declared_size > MAX_FILE_SIZE:
            raise ServiceError(
                f"文件超过 8 MiB 上限（申报 {declared_size} 字节）", 413
            )
        with self.lock:
            upload_id = uuid.uuid4().hex
            now = self._now()
            self.conn.execute(
                "INSERT INTO uploads (upload_id, filename, declared_size, state, created_at, updated_at) "
                "VALUES (?,?,?, 'created', ?, ?)",
                (upload_id, filename, declared_size, now, now),
            )
            self.conn.commit()
            return {"upload_id": upload_id, "state": "created", "max_size": MAX_FILE_SIZE}

    def save_upload_content(self, upload_id: str, content: bytes) -> dict[str, Any]:
        if len(content) > MAX_FILE_SIZE:
            raise ServiceError("文件超过 8 MiB 上限", 413)
        with self.lock:
            up = self._row("SELECT * FROM uploads WHERE upload_id=?", (upload_id,))
            if up is None:
                raise ServiceError("上传会话不存在", 404)
            if up["state"] != "created":
                raise ServiceError(f"上传会话状态为 {up['state']}，不能再写入内容", 409)
            if len(content) != up["declared_size"]:
                raise ServiceError(
                    f"内容长度 {len(content)} 与申报大小 {up['declared_size']} 不一致", 422
                )

            dek = crypto.new_dek()  # 独立随机 DEK，仅驻内存
            nonce = crypto.new_nonce()
            ciphertext = crypto.encrypt_blob(dek, nonce, content)
            staging_path = self._staging_path(upload_id, nonce)
            self._atomic_write(staging_path, nonce + ciphertext)
            digest = hashlib.sha256(content).hexdigest()

            self.conn.execute(
                "UPDATE uploads SET state='pending_register', sha256=?, staging_path=?, "
                "nonce=?, updated_at=? WHERE id=?",
                (digest, staging_path, nonce, self._now(), up["id"]),
            )
            self.conn.commit()
            self._upload_deks[upload_id] = dek
            return {
                "upload_id": upload_id,
                "state": "pending_register",
                "sha256": digest,
                "paused_at_register": self.upload_gate.paused,
            }

    def complete_upload(self, upload_id: str) -> dict[str, Any]:
        with self.lock:
            up = self._row("SELECT * FROM uploads WHERE upload_id=?", (upload_id,))
            if up is None:
                raise ServiceError("上传会话不存在", 404)
            if up["state"] == "completed":
                return self._upload_payload(up)
            if up["state"] != "pending_register":
                raise ServiceError(f"上传会话状态为 {up['state']}，无法登记", 409)

            dek = self._upload_deks.get(upload_id)
            if dek is None:
                # 进程重启后内存 DEK 已丢失（恢复阶段通常已标记 failed，这里兜底）。
                self._unlink_quiet(up["staging_path"])
                self.conn.execute(
                    "UPDATE uploads SET state='failed', error=?, updated_at=? WHERE id=?",
                    ("内存数据密钥已丢失", self._now(), up["id"]),
                )
                self.conn.commit()
                raise ServiceError("数据密钥已不在内存（可能经历重启），请重新上传", 409)

            # 暂停点：上传待登记。轮换期间门开着时照常登记，且恒用当前 active KEK，
            # 因此收尾后绝不会留下对旧 KEK 的引用。等待期间释放锁，避免与闸门控制死锁。
            if self.upload_gate.paused:
                with self._unlocked_wait(self.upload_gate):
                    pass

            # 等待结束后重新读取行，防止等待期间状态变化。
            up = self._row("SELECT * FROM uploads WHERE id=?", (up["id"],))
            if up is None or up["state"] != "pending_register":
                raise ServiceError("上传会话在暂停期间状态发生变化", 409)

            active = self._ensure_active_key_locked()
            dek_nonce = crypto.new_nonce()
            wrapped_dek = crypto.wrap_dek(self._get_kek(active["id"]), dek_nonce, dek)

            file_id = uuid.uuid4().hex
            blob_path = self._blob_path(file_id)
            # 密文从暂存目录原子移入密文目录；原件明文从未落盘。
            os.replace(up["staging_path"], blob_path)
            now = self._now()
            cur = self.conn.execute(
                "INSERT INTO files (file_id, filename, size, sha256, blob_path, nonce, "
                "current_kek_id, wrapped_dek, dek_nonce, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    file_id,
                    up["filename"],
                    up["declared_size"],
                    up["sha256"],
                    blob_path,
                    up["nonce"],
                    active["id"],
                    wrapped_dek,
                    dek_nonce,
                    now,
                ),
            )
            self.conn.execute(
                "UPDATE uploads SET state='completed', file_id=?, updated_at=? WHERE id=?",
                (cur.lastrowid, now, up["id"]),
            )
            self.conn.commit()
            self._upload_deks.pop(upload_id, None)
            return self._upload_payload(
                self._row("SELECT * FROM uploads WHERE id=?", (up["id"],))  # type: ignore[arg-type]
            )

    def abort_upload(self, upload_id: str) -> dict[str, Any]:
        with self.lock:
            up = self._row("SELECT * FROM uploads WHERE upload_id=?", (upload_id,))
            if up is None:
                raise ServiceError("上传会话不存在", 404)
            if up["state"] in ("completed", "aborted", "failed"):
                return self._upload_payload(up)
            self._unlink_quiet(up["staging_path"])
            self.conn.execute(
                "UPDATE uploads SET state='aborted', updated_at=? WHERE id=?",
                (self._now(), up["id"]),
            )
            self.conn.commit()
            self._upload_deks.pop(upload_id, None)
            return self._upload_payload(
                self._row("SELECT * FROM uploads WHERE id=?", (up["id"],))  # type: ignore[arg-type]
            )

    def _upload_payload(self, up: sqlite3.Row) -> dict[str, Any]:
        return {
            "upload_id": up["upload_id"],
            "filename": up["filename"],
            "state": up["state"],
            "file_id": self._row("SELECT file_id FROM files WHERE id=?", (up["file_id"],))["file_id"]
            if up["file_id"]
            else None,
            "error": up["error"],
        }

    # ------------------------------------------------------------------ #
    # 下载：accepted -> 暂停点（待解封）-> unwrapping -> completed
    # ------------------------------------------------------------------ #
    def accept_download(self, file_id: str) -> dict[str, Any]:
        with self.lock:
            f = self._row("SELECT * FROM files WHERE file_id=?", (file_id,))
            if f is None:
                raise ServiceError("文件不存在", 404)
            download_id = uuid.uuid4().hex
            now = self._now()
            # 受理即快照：即使随后轮换重封装了 files 行，在途下载仍持有
            # 旧封装副本与旧 KEK 标识，必须能把原件读完。
            self.conn.execute(
                "INSERT INTO downloads (download_id, file_id, kek_id, wrapped_dek, dek_nonce, "
                "nonce, state, created_at, updated_at) VALUES (?,?,?,?,?,?, 'accepted', ?, ?)",
                (
                    download_id,
                    f["id"],
                    f["current_kek_id"],
                    f["wrapped_dek"],
                    f["dek_nonce"],
                    f["nonce"],
                    now,
                    now,
                ),
            )
            self.conn.commit()
            return {
                "download_id": download_id,
                "file_id": file_id,
                "filename": f["filename"],
                "state": "accepted",
            }

    def open_download(self, download_id: str) -> dict[str, Any]:
        """解封并读完原件密文，返回明文字节（仅存在于内存，随响应返回不落盘）。"""
        with self.lock:
            dl = self._row("SELECT * FROM downloads WHERE download_id=?", (download_id,))
            if dl is None:
                raise ServiceError("下载会话不存在", 404)
            if dl["state"] == "completed":
                raise ServiceError("下载会话已完成，请重新发起下载", 410)
            if dl["state"] in ("interrupted", "aborted"):
                raise ServiceError(f"下载会话状态为 {dl['state']}，请重新发起", 409)

            # 暂停点：下载待解封。等待期间释放锁，避免与闸门控制死锁。
            if self.download_gate.paused:
                with self._unlocked_wait(self.download_gate):
                    pass
            dl = self._row("SELECT * FROM downloads WHERE id=?", (dl["id"],))
            if dl is None or dl["state"] not in ("accepted", "unwrapping"):
                raise ServiceError("下载会话在暂停期间状态发生变化", 409)

            f = self._row("SELECT * FROM files WHERE id=?", (dl["file_id"],))
            if f is None:
                raise ServiceError("归档文件已不存在", 404)

            self.conn.execute(
                "UPDATE downloads SET state='unwrapping', updated_at=? WHERE id=?",
                (self._now(), dl["id"]),
            )
            self.conn.commit()

            # 用受理时快照的 KEK / 封装 DEK 解封——不依赖 files 行当前值。
            try:
                kek_row = self._row("SELECT * FROM project_keys WHERE id=?", (dl["kek_id"],))
                if kek_row is None:
                    raise ServiceError("课题密钥记录缺失，无法解封", 500)
                if not os.path.exists(self._kek_path(kek_row["key_id"])):
                    raise ServiceError(
                        "课题密钥文件已被删除，在途下载无法解封（收尾逻辑不应允许此情况）", 500
                    )
                kek = self._get_kek(kek_row["id"])
                dek = crypto.unwrap_dek(kek, dl["dek_nonce"], dl["wrapped_dek"])

                with open(f["blob_path"], "rb") as bf:
                    blob = bf.read()
                nonce, ciphertext = blob[: crypto.NONCE_SIZE], blob[crypto.NONCE_SIZE:]
                try:
                    plaintext = crypto.decrypt_blob(dek, nonce, ciphertext)
                except InvalidTag:
                    raise ServiceError(
                        "密文完整性校验失败（GCM 标签不匹配），归档密文可能已损坏，"
                        "请用留存的原件备份发起修复",
                        500,
                    )

                if hashlib.sha256(plaintext).hexdigest() != f["sha256"]:
                    raise ServiceError("解密后摘要校验失败，原件可能已损坏", 500)
            except (ServiceError, InvalidTag):
                # 读取失败：释放该下载会话并清空快照封装材料，避免在途计数
                # 永久阻塞轮换收尾；客户端可重新发起下载（或先修复密文）。
                self.conn.execute(
                    "UPDATE downloads SET state='interrupted', wrapped_dek=NULL, dek_nonce=NULL, "
                    "nonce=NULL, updated_at=? WHERE id=?",
                    (self._now(), dl["id"]),
                )
                self.conn.commit()
                if isinstance(sys.exc_info()[1], ServiceError):
                    raise
                raise ServiceError("解封或解密失败，归档密文/封装材料可能已损坏", 500)

            # 读完原件后清除受理快照中的封装材料：终态下载不再持有任何 KEK 引用。
            self.conn.execute(
                "UPDATE downloads SET state='completed', wrapped_dek=NULL, dek_nonce=NULL, "
                "nonce=NULL, updated_at=? WHERE id=?",
                (self._now(), dl["id"]),
            )
            self.conn.commit()
            return {
                "filename": f["filename"],
                "content": plaintext,
                "sha256": f["sha256"],
            }

    def abort_download(self, download_id: str) -> dict[str, Any]:
        with self.lock:
            dl = self._row("SELECT * FROM downloads WHERE download_id=?", (download_id,))
            if dl is None:
                raise ServiceError("下载会话不存在", 404)
            if dl["state"] in ("completed", "aborted", "interrupted"):
                return {"download_id": download_id, "state": dl["state"]}
            self.conn.execute(
                "UPDATE downloads SET state='aborted', wrapped_dek=NULL, dek_nonce=NULL, "
                "nonce=NULL, updated_at=? WHERE id=?",
                (self._now(), dl["id"]),
            )
            self.conn.commit()
            return {"download_id": download_id, "state": "aborted"}

    # ------------------------------------------------------------------ #
    # 密文修复（备份恢复）：accepted -> verified -> completed
    #   仅当备份的大小与 SHA-256 均与登记值相符时，才用该件 DEK 重新加密
    #   并替换密文；file_id/摘要等登记信息不变，原件明文与 DEK 绝不落盘。
    # ------------------------------------------------------------------ #
    def create_repair(self, file_id: str, declared_size: int) -> dict[str, Any]:
        if not isinstance(declared_size, int) or declared_size <= 0:
            raise ServiceError("文件大小必须为正整数", 422)
        if declared_size > MAX_FILE_SIZE:
            raise ServiceError(
                f"备份超过 8 MiB 上限（申报 {declared_size} 字节）", 413
            )
        with self.lock:
            f = self._row("SELECT * FROM files WHERE file_id=?", (file_id,))
            if f is None:
                raise ServiceError("归档文件不存在", 404)
            if declared_size != f["size"]:
                raise ServiceError(
                    f"备份大小 {declared_size} 与登记大小 {f['size']} 不一致，拒绝修复", 422
                )
            # 同一件影像同时只允许一个在途修复，避免替换互相覆盖。
            busy = self._row(
                "SELECT id FROM repairs WHERE file_id=? AND state IN ('accepted','verified')",
                (f["id"],),
            )
            if busy is not None:
                raise ServiceError("该影像已有进行中的修复会话，请先完成或中止", 409)

            repair_id = uuid.uuid4().hex
            now = self._now()
            # 受理即快照 KEK 标识与封装 DEK：在途修复会阻止旧 KEK 退役，
            # 因此即使随后发起轮换，迟到的修复仍能用快照材料解封该件 DEK。
            self.conn.execute(
                "INSERT INTO repairs (repair_id, file_id, declared_size, state, kek_id, "
                "wrapped_dek, dek_nonce, nonce, created_at, updated_at) "
                "VALUES (?,?,?, 'accepted', ?,?,?,?,?,?)",
                (
                    repair_id,
                    f["id"],
                    declared_size,
                    f["current_kek_id"],
                    f["wrapped_dek"],
                    f["dek_nonce"],
                    f["nonce"],
                    now,
                    now,
                ),
            )
            self.conn.commit()
            return {
                "repair_id": repair_id,
                "file_id": file_id,
                "filename": f["filename"],
                "state": "accepted",
                "expected_size": f["size"],
                "expected_sha256": f["sha256"],
            }

    def save_repair_content(self, repair_id: str, content: bytes) -> dict[str, Any]:
        """接收备份原件：大小与 SHA-256 双校验通过后，明文仅驻内存等待替换。"""
        if len(content) > MAX_FILE_SIZE:
            raise ServiceError("备份超过 8 MiB 上限，拒绝修复", 413)
        with self.lock:
            rp = self._row("SELECT * FROM repairs WHERE repair_id=?", (repair_id,))
            if rp is None:
                raise ServiceError("修复会话不存在", 404)
            if rp["state"] not in ("accepted", "verified"):
                raise ServiceError(f"修复会话状态为 {rp['state']}，不能再写入备份", 409)

            f = self._row("SELECT * FROM files WHERE id=?", (rp["file_id"],))
            if f is None:
                raise ServiceError("归档文件已不存在", 404)

            if len(content) != rp["declared_size"] or len(content) != f["size"]:
                self._fail_repair_locked(
                    rp, f"备份大小 {len(content)} 与登记大小 {f['size']} 不一致"
                )
                raise ServiceError(
                    f"备份大小 {len(content)} 与登记大小 {f['size']} 不一致，拒绝修复", 422
                )
            digest = hashlib.sha256(content).hexdigest()
            if digest != f["sha256"]:
                self._fail_repair_locked(rp, "备份 SHA-256 与登记摘要不一致")
                raise ServiceError("备份 SHA-256 与登记摘要不一致，拒绝修复", 422)

            now = self._now()
            self.conn.execute(
                "UPDATE repairs SET state='verified', sha256=?, updated_at=? WHERE id=?",
                (digest, now, rp["id"]),
            )
            self.conn.commit()
            # 双校验通过：备份原件明文只放内存，绝不落盘。
            self._repair_plaintexts[repair_id] = content
            return {
                "repair_id": repair_id,
                "file_id": f["file_id"],
                "state": "verified",
                "sha256": digest,
                "size": len(content),
            }

    def complete_repair(self, repair_id: str) -> dict[str, Any]:
        """用该件数据密钥重新加密备份并原子替换密文；任何失败都保住原有副本。"""
        with self.lock:
            rp = self._row("SELECT * FROM repairs WHERE repair_id=?", (repair_id,))
            if rp is None:
                raise ServiceError("修复会话不存在", 404)
            if rp["state"] == "completed":
                return self._repair_payload(rp)
            if rp["state"] not in ("accepted", "verified"):
                raise ServiceError(f"修复会话状态为 {rp['state']}，无法完成修复", 409)

            content = self._repair_plaintexts.get(repair_id)
            if content is None:
                # 进程重启后内存明文已丢失（恢复阶段通常已标记 interrupted，这里兜底）。
                self._fail_repair_locked(rp, "备份原件已不在内存（可能经历重启），请重新发起修复")
                raise ServiceError("备份原件已不在内存（可能经历重启），请重新发起修复", 409)

            f = self._row("SELECT * FROM files WHERE id=?", (rp["file_id"],))
            if f is None:
                raise ServiceError("归档文件已不存在", 404)

            new_path: str | None = None
            backup_path: str | None = None
            try:
                # 1) 用受理快照中的 KEK/封装 DEK 解封该件数据密钥。旧 KEK 在
                #    在途修复结束前不会被轮换收尾删除，因此这里恒可解封。
                kek_row = self._row("SELECT * FROM project_keys WHERE id=?", (rp["kek_id"],))
                if kek_row is None or not os.path.exists(self._kek_path(kek_row["key_id"])):
                    raise ServiceError("快照课题密钥不可用，无法解封该件数据密钥", 500)
                try:
                    dek = crypto.unwrap_dek(
                        self._get_kek(kek_row["id"]), rp["dek_nonce"], rp["wrapped_dek"]
                    )
                except InvalidTag:
                    raise ServiceError("封装数据密钥解封失败，拒绝替换密文", 500)

                # 2) 同一 DEK、新随机 nonce 重新加密备份原件（明文不落盘）。
                new_nonce = crypto.new_nonce()
                ciphertext = crypto.encrypt_blob(dek, new_nonce, content)
                new_path = self._repair_new_path(repair_id)
                self._atomic_write(new_path, new_nonce + ciphertext)

                # 3) 同目录原子交换：旧密文先改名备份，再放新密文。
                #    任何一步失败现网 blob 都保持原样，原有可读副本不丢失。
                blob_path = f["blob_path"]
                backup_path = self._repair_backup_path(f["file_id"])
                self._unlink_quiet(backup_path)
                os.replace(blob_path, backup_path)
                try:
                    os.replace(new_path, blob_path)
                except BaseException:
                    # 新密文落位失败：立即还原旧密文，恢复到修复前状态。
                    with contextlib.suppress(OSError):
                        os.replace(backup_path, blob_path)
                    raise

                # 4) 元数据与替换在同一事务提交；file_id/文件名/大小/摘要均不变。
                now = self._now()
                self.conn.execute(
                    "UPDATE files SET nonce=? WHERE id=?", (new_nonce, f["id"])
                )
                # 先前已受理但尚未读取（或正在解封）的下载：把 nonce 快照指向
                # 新密文，其 DEK 未变，恢复后读取得到的是完整原件。
                self.conn.execute(
                    "UPDATE downloads SET nonce=?, updated_at=? "
                    "WHERE file_id=? AND state IN ('accepted','unwrapping')",
                    (new_nonce, now, f["id"]),
                )
                self.conn.execute(
                    "UPDATE repairs SET state='completed', nonce=?, wrapped_dek=NULL, "
                    "dek_nonce=NULL, updated_at=? WHERE id=?",
                    (new_nonce, now, rp["id"]),
                )
                self.conn.commit()
            except ServiceError:
                # 业务失败：清理暂存、确保旧副本在位，修复会话标记 failed 后可重新发起。
                self._rollback_repair_files(rp, f, new_path, backup_path)
                self._fail_repair_locked(rp, "修复替换失败，已保留原有可读副本")
                raise
            except Exception as exc:
                # 任何替换异常都不能破坏现网可读副本：还原现场并转为业务错误。
                self._rollback_repair_files(rp, f, new_path, backup_path)
                self._fail_repair_locked(rp, f"修复过程异常，已保留原有可读副本：{exc}")
                raise ServiceError(f"修复替换失败，已保留原有可读副本：{exc}", 500)

            # 5) 提交后再删除旧密文备份；若此处崩溃，重启对账会识别已提交状态并清理。
            self._unlink_quiet(backup_path)
            self._repair_plaintexts.pop(repair_id, None)
            return self._repair_payload(
                self._row("SELECT * FROM repairs WHERE id=?", (rp["id"],))  # type: ignore[arg-type]
            )

    def _rollback_repair_files(
        self,
        rp: sqlite3.Row,
        f: sqlite3.Row,
        new_path: str | None,
        backup_path: str | None,
    ) -> None:
        """替换失败后恢复现场：旧密文还原到 blob_path，新密文暂存删除。"""
        blob_path = f["blob_path"]
        if backup_path and os.path.exists(backup_path):
            if not os.path.exists(blob_path):
                with contextlib.suppress(OSError):
                    os.replace(backup_path, blob_path)
            else:
                # 现网副本仍在（例如失败发生在第一次 replace 之前）：丢弃备份。
                self._unlink_quiet(backup_path)
        if new_path:
            self._unlink_quiet(new_path)

    def _fail_repair_locked(self, rp: sqlite3.Row, error: str) -> None:
        self._repair_plaintexts.pop(rp["repair_id"], None)
        self.conn.execute(
            "UPDATE repairs SET state='failed', error=?, wrapped_dek=NULL, dek_nonce=NULL, "
            "nonce=NULL, updated_at=? WHERE id=?",
            (error, self._now(), rp["id"]),
        )
        self.conn.commit()

    def abort_repair(self, repair_id: str) -> dict[str, Any]:
        with self.lock:
            rp = self._row("SELECT * FROM repairs WHERE repair_id=?", (repair_id,))
            if rp is None:
                raise ServiceError("修复会话不存在", 404)
            if rp["state"] in ("completed", "aborted", "failed", "interrupted"):
                return self._repair_payload(rp)
            f = self._row("SELECT * FROM files WHERE id=?", (rp["file_id"],))
            # 在途中止：清理可能已暂存的新密文，现网密文从未被改动。
            self._unlink_quiet(self._repair_new_path(repair_id))
            if f is not None:
                self._unlink_quiet(self._repair_backup_path(f["file_id"]))
            self._repair_plaintexts.pop(repair_id, None)
            self.conn.execute(
                "UPDATE repairs SET state='aborted', wrapped_dek=NULL, dek_nonce=NULL, "
                "nonce=NULL, updated_at=? WHERE id=?",
                (self._now(), rp["id"]),
            )
            self.conn.commit()
            return self._repair_payload(
                self._row("SELECT * FROM repairs WHERE id=?", (rp["id"],))  # type: ignore[arg-type]
            )

    def _repair_payload(self, rp: sqlite3.Row) -> dict[str, Any]:
        f = self._row("SELECT file_id, filename FROM files WHERE id=?", (rp["file_id"],))
        return {
            "repair_id": rp["repair_id"],
            "file_id": f["file_id"] if f else None,
            "filename": f["filename"] if f else None,
            "state": rp["state"],
            "sha256": rp["sha256"],
            "error": rp["error"],
        }

    def list_repairs(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._all(
                "SELECT r.repair_id, r.state, r.declared_size, r.sha256, r.error, "
                "r.created_at, r.updated_at, f.file_id AS file_id, f.filename AS filename "
                "FROM repairs r JOIN files f ON f.id=r.file_id ORDER BY r.id DESC"
            )
            return [dict(r) for r in rows]

    def corrupt_file_for_demo(self, file_id: str) -> dict[str, Any]:
        """演示辅助：翻转 vault 密文若干字节，制造 GCM 标签校验失败的损坏场景。

        只动密文文件，不触碰数据库登记信息与密钥；损坏后下载应报错，
        用留存的原件备份修复后恢复可读。
        """
        with self.lock:
            f = self._row("SELECT * FROM files WHERE file_id=?", (file_id,))
            if f is None:
                raise ServiceError("文件不存在", 404)
            with open(f["blob_path"], "r+b") as fh:
                fh.seek(crypto.NONCE_SIZE + 7)
                byte = fh.read(1)
                fh.seek(crypto.NONCE_SIZE + 7)
                fh.write(bytes([byte[0] ^ 0xFF]))
                fh.flush()
                os.fsync(fh.fileno())
            return {"file_id": file_id, "state": "corrupted", "blob_path": f["blob_path"]}

    # ------------------------------------------------------------------ #
    # 密钥轮换：同期只允许一个；只重封装 DEK，不改原件密文
    # ------------------------------------------------------------------ #
    def start_rotation(self) -> dict[str, Any]:
        with self.lock:
            if self._active_rotation() is not None:
                raise ServiceError("已有轮换进行中，同期只允许轮换一次", 409)
            old = self._ensure_active_key_locked()

            new_key_id = uuid.uuid4().hex
            new_kek = crypto.new_kek()
            new_path = self._kek_path(new_key_id)
            crypto.save_kek_file(new_path, new_kek)  # 先持久化新 KEK 文件

            now = self._now()
            cur = self.conn.execute(
                "INSERT INTO project_keys (key_id, path, status, created_at) "
                "VALUES (?,?, 'active', ?)",
                (new_key_id, new_path, now),
            )
            new_pk = cur.lastrowid
            self._kek_cache[new_pk] = new_kek

            total = self._row("SELECT COUNT(*) AS c FROM files WHERE current_kek_id=?", (old["id"],))["c"]
            # 旧 KEK 立即转入 rotating：新上传只会封装到新 active KEK。
            self.conn.execute(
                "UPDATE project_keys SET status='rotating' WHERE id=?", (old["id"],)
            )
            rotation_id = uuid.uuid4().hex
            self.conn.execute(
                "INSERT INTO rotations (rotation_id, old_kek_id, new_kek_id, state, total, "
                "rewrapped, started_at) VALUES (?,?,?, 'running', ?, 0, ?)",
                (rotation_id, old["id"], new_pk, total, now),
            )
            self.conn.commit()

            t = threading.Thread(
                target=self._rotation_worker,
                args=(rotation_id,),
                name=f"rotation-{rotation_id[:8]}",
                daemon=True,
            )
            self._rotation_thread = t
            t.start()
            return self.rotation_status()

    def _rotation_worker(self, rotation_id: str) -> None:
        while not self.stop_event.is_set():
            with self.lock:
                rot = self._row(
                    "SELECT * FROM rotations WHERE rotation_id=?", (rotation_id,)
                )
                if rot is None or rot["state"] == "completed":
                    return
                old = self._row("SELECT * FROM project_keys WHERE id=?", (rot["old_kek_id"],))
                new = self._row("SELECT * FROM project_keys WHERE id=?", (rot["new_kek_id"],))
                if old is None or new is None:
                    return
                # 旧 KEK 文件已不在（例如外部清理/重启竞态）：直接补完状态。
                if not os.path.exists(self._kek_path(old["key_id"])):
                    self._finalize_rotation_locked(rot)
                    return

                # 1) 重封装仍引用旧 KEK 的已归档文件（每次一件，可被重启打断后续办）。
                target = self._row(
                    "SELECT * FROM files WHERE current_kek_id=? ORDER BY id LIMIT 1",
                    (old["id"],),
                )
                if target is not None:
                    self._rewrap_one_locked(target, old, new, rot)
                    continue

                # 2) 等待在途会话全部结束（在途修复同样阻塞旧 KEK 退役）。
                blocking_uploads = self._row(
                    "SELECT COUNT(*) AS c FROM uploads "
                    "WHERE state IN ('created','pending_register')"
                )["c"]
                blocking_downloads = self._row(
                    "SELECT COUNT(*) AS c FROM downloads "
                    "WHERE state IN ('accepted','unwrapping')"
                )["c"]
                blocking_repairs = self._row(
                    "SELECT COUNT(*) AS c FROM repairs "
                    "WHERE state IN ('accepted','verified') AND kek_id=?",
                    (old["id"],),
                )["c"]
                self.conn.execute(
                    "UPDATE rotations SET state='completing', blocking_uploads=?, "
                    "blocking_downloads=?, blocking_repairs=? WHERE id=?",
                    (blocking_uploads, blocking_downloads, blocking_repairs, rot["id"]),
                )
                self.conn.commit()

                if blocking_uploads == 0 and blocking_downloads == 0 and blocking_repairs == 0:
                    # 3) 所有旧钥引用与在途使用均已结束，实际删除旧 KEK 文件后才报完成。
                    self._finalize_rotation_locked(rot)
                    return
            time.sleep(WORKER_POLL_SECONDS)

    def _rewrap_one_locked(
        self,
        f: sqlite3.Row,
        old: sqlite3.Row,
        new: sqlite3.Row,
        rot: sqlite3.Row,
    ) -> None:
        old_kek = self._get_kek(old["id"])
        dek = crypto.unwrap_dek(old_kek, f["dek_nonce"], f["wrapped_dek"])
        new_nonce = crypto.new_nonce()
        new_wrapped = crypto.wrap_dek(self._get_kek(new["id"]), new_nonce, dek)
        # 只更新封装信息，blob_path / nonce（原件密文）保持不变。
        self.conn.execute(
            "UPDATE files SET current_kek_id=?, wrapped_dek=?, dek_nonce=? WHERE id=?",
            (new["id"], new_wrapped, new_nonce, f["id"]),
        )
        self.conn.execute(
            "UPDATE rotations SET rewrapped=rewrapped+1 WHERE id=?", (rot["id"],)
        )
        self.conn.commit()

    def _finalize_rotation_locked(self, rot: sqlite3.Row) -> None:
        old = self._row("SELECT * FROM project_keys WHERE id=?", (rot["old_kek_id"],))
        # 最终防线：确认数据库中确实没有任何旧 KEK 引用与在途使用。
        refs = self._row(
            "SELECT COUNT(*) AS c FROM files WHERE current_kek_id=?", (rot["old_kek_id"],)
        )["c"]
        up = self._row(
            "SELECT COUNT(*) AS c FROM uploads WHERE state IN ('created','pending_register')"
        )["c"]
        dl = self._row(
            "SELECT COUNT(*) AS c FROM downloads WHERE state IN ('accepted','unwrapping') "
            "AND kek_id=?",
            (rot["old_kek_id"],),
        )["c"]
        # 在途修复持有旧 KEK 的封装快照：未结束前旧钥文件不得删除，
        # 否则“迟到的修复”将无法解封 DEK、变成不可解密文件。
        rp = self._row(
            "SELECT COUNT(*) AS c FROM repairs WHERE state IN ('accepted','verified') "
            "AND kek_id=?",
            (rot["old_kek_id"],),
        )["c"]
        # 强不变量：数据库中不允许再保留任何指向旧 KEK 的封装 DEK（终态下载/修复已清空）。
        residual = self._row(
            "SELECT COUNT(*) AS c FROM downloads WHERE kek_id=? AND wrapped_dek IS NOT NULL",
            (rot["old_kek_id"],),
        )["c"]
        residual_rp = self._row(
            "SELECT COUNT(*) AS c FROM repairs WHERE kek_id=? AND wrapped_dek IS NOT NULL",
            (rot["old_kek_id"],),
        )["c"]
        if refs or up or dl or rp or residual or residual_rp:
            return  # 条件未满足，下一轮再检查。

        path = self._kek_path(old["key_id"])
        self._unlink_quiet(path)  # 旧钥文件实际删除
        if os.path.exists(path):
            return
        self._kek_cache.pop(old["id"], None)
        now = self._now()
        self.conn.execute(
            "UPDATE project_keys SET status='deleted', deleted_at=? WHERE id=?",
            (now, old["id"]),
        )
        self.conn.execute(
            "UPDATE rotations SET state='completed', completed_at=?, blocking_uploads=0, "
            "blocking_downloads=0, blocking_repairs=0, "
            "message='旧钥引用与在途使用全部结束，旧课题密钥文件已删除' WHERE id=?",
            (now, rot["id"]),
        )
        self.conn.commit()

    def rotation_status(self) -> dict[str, Any]:
        with self.lock:
            rot = self._active_rotation()
            if rot is None:
                last = self._row(
                    "SELECT * FROM rotations ORDER BY id DESC LIMIT 1"
                )
                payload: dict[str, Any] = {
                    "active": False,
                    "state": "idle",
                    "last": self._rotation_brief(last) if last else None,
                }
            else:
                payload = {"active": True, **self._rotation_brief(rot)}
            active_key = self._active_key()
            payload["active_kek"] = (
                {"id": active_key["id"], "key_id": active_key["key_id"], "created_at": active_key["created_at"]}
                if active_key
                else None
            )
            payload["gates"] = {
                "upload_register": {
                    "paused": self.upload_gate.paused,
                    "waiting": self.upload_gate.waiting,
                },
                "download_unwrap": {
                    "paused": self.download_gate.paused,
                    "waiting": self.download_gate.waiting,
                },
            }
            return payload

    @staticmethod
    def _rotation_brief(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "rotation_id": row["rotation_id"],
            "state": row["state"],
            "total": row["total"],
            "rewrapped": row["rewrapped"],
            "blocking_uploads": row["blocking_uploads"],
            "blocking_downloads": row["blocking_downloads"],
            "blocking_repairs": row["blocking_repairs"],
            "old_kek_id": row["old_kek_id"],
            "new_kek_id": row["new_kek_id"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "message": row["message"],
        }

    # ------------------------------------------------------------------ #
    # 列表与演示门控制
    # ------------------------------------------------------------------ #
    def list_files(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._all(
                "SELECT f.*, k.key_id AS kek_key_id FROM files f "
                "JOIN project_keys k ON k.id=f.current_kek_id ORDER BY f.id"
            )
            return [
                {
                    "file_id": r["file_id"],
                    "filename": r["filename"],
                    "size": r["size"],
                    "sha256": r["sha256"],
                    "kek_id": r["current_kek_id"],
                    "kek_key_id": r["kek_key_id"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def list_keys(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._all(
                "SELECT id, key_id, status, created_at, deleted_at FROM project_keys ORDER BY id"
            )
            return [dict(r) | {"file_exists": os.path.exists(self._kek_path(r["key_id"]))} for r in rows]

    def list_uploads(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._all(
                "SELECT u.upload_id, u.filename, u.state, u.declared_size, u.sha256, u.error, "
                "u.created_at, u.updated_at, f.file_id AS file_id FROM uploads u "
                "LEFT JOIN files f ON f.id=u.file_id ORDER BY u.id DESC"
            )
            return [dict(r) for r in rows]

    def list_downloads(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._all(
                "SELECT d.download_id, d.state, d.kek_id, d.created_at, d.updated_at, "
                "f.file_id AS file_id, f.filename AS filename FROM downloads d "
                "JOIN files f ON f.id=d.file_id ORDER BY d.id DESC"
            )
            return [dict(r) for r in rows]

    def set_gate(self, name: str, paused: bool) -> dict[str, Any]:
        gate = {
            "upload_register": self.upload_gate,
            "download_unwrap": self.download_gate,
        }.get(name)
        if gate is None:
            raise ServiceError(f"未知暂停点 {name}", 404)
        with self.lock:
            if paused:
                gate.pause()
            else:
                gate.resume()
        return self.rotation_status()["gates"]

    # ------------------------------------------------------------------ #
    def _atomic_write(self, path: str, data: bytes) -> None:
        tmp = f"{path}.tmp-{uuid.uuid4().hex}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            self._unlink_quiet(tmp)

    @staticmethod
    def _validate_filename(filename: str) -> str:
        filename = (filename or "").strip()
        if not filename:
            raise ServiceError("文件名不能为空", 422)
        if len(filename) > 200:
            raise ServiceError("文件名过长", 422)
        if "\x00" in filename or os.sep in filename or (os.altsep and os.altsep in filename):
            raise ServiceError("文件名不得包含路径分隔符", 422)
        if filename in (".", ".."):
            raise ServiceError("文件名非法", 422)
        if not filename.lower().endswith((".tif", ".tiff")):
            raise ServiceError("仅接收 TIFF 影像（.tif/.tiff）", 422)
        return filename
