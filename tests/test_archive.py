"""端到端不变量测试。

覆盖：
1. 上传/下载往返一致，密文与密钥分目录、原件明文与 DEK 永不落盘；
2. 8 MiB 上限；
3. 轮换只重封装 DEK、原件密文字节不变、旧 KEK 文件删除后才报完成；
4. 上传待登记暂停：收尾后不留下旧钥引用；
5. 下载待解封暂停：已受理下载必须读完原件；
6. 轮换中重启自动续办，已归档文件始终可解密；
7. 同期只允许一次轮换；
8. 密文修复（备份恢复）：双校验、原子替换保住可读副本、在途修复阻塞
   旧钥退役、迟到修复仍可解密、重启对账与已受理下载的原件完整性。
"""

from __future__ import annotations

import hashlib
import os
import threading
import time

import pytest

from app.main import app
from app.service import MAX_FILE_SIZE
from fastapi.testclient import TestClient


def make_tiff(size: int, seed: int = 1) -> bytes:
    """生成带 II 字节序魔数的最小 TIFF 风格字节串（内容可任意）。"""
    header = b"II\x2a\x00" + size.to_bytes(4, "little")
    body = bytes(((i * 37 + seed) & 0xFF) for i in range(size - len(header)))
    return header + body


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("等待条件超时")


@pytest.fixture()
def tmp_data(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture()
def svc(tmp_data, monkeypatch):
    monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
    with TestClient(app) as client:
        from app.main import service as current
        yield client, current


def _upload(client: TestClient, content: bytes, name: str = "image.tif") -> str:
    r = client.post("/api/uploads", json={"filename": name, "size": len(content)})
    assert r.status_code == 201, r.text
    upload_id = r.json()["upload_id"]
    r = client.put(f"/api/uploads/{upload_id}/content", content=content)
    assert r.status_code == 200, r.text
    r = client.post(f"/api/uploads/{upload_id}/complete")
    assert r.status_code == 200, r.text
    return r.json()["file_id"]


def _download(client: TestClient, file_id: str) -> bytes:
    r = client.post(f"/api/files/{file_id}/downloads")
    assert r.status_code == 201, r.text
    dl = r.json()["download_id"]
    r = client.get(f"/api/downloads/{dl}/content")
    assert r.status_code == 200, r.text
    return r.content


class TestArchive:
    def test_roundtrip_and_plaintext_never_on_disk(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(4096, seed=7)
        digest = hashlib.sha256(payload).hexdigest()

        file_id = _upload(client, payload)
        got = _download(client, file_id)
        assert got == payload
        assert client.get("/api/files").json()[0]["sha256"] == digest

        # 不变量：vault/staging 下任何文件都不含 TIFF 明文魔数；keys 与 vault 分目录。
        for root, _dirs, files in os.walk(tmp_data):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    data = f.read()
                if "vault" in path or "staging" in path:
                    assert payload not in data
                    assert b"II\x2a\x00" not in data, f"密文文件中出现明文魔数: {path}"
                if "vault" in path:
                    assert "keys" not in path
        assert os.path.isdir(os.path.join(tmp_data, "keys"))
        assert os.path.isdir(os.path.join(tmp_data, "vault"))
        assert os.path.isdir(os.path.join(tmp_data, "staging"))

        # DEK 明文不落盘：数据库内只允许出现封装后的 BLOB；KEK 字节本身只在 keys/*.kek。
        import sqlite3

        conn = sqlite3.connect(os.path.join(tmp_data, "archive.db"))
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"project_keys", "files", "uploads", "downloads", "rotations"} <= tables
        kek_path = service.list_keys()[0]["key_id"]
        with open(os.path.join(tmp_data, "keys", kek_path + ".kek"), "rb") as f:
            kek_bytes = f.read()
        for (blob,) in conn.execute("SELECT wrapped_dek FROM files WHERE wrapped_dek IS NOT NULL"):
            assert blob != kek_bytes
        # 已完成下载的受理快照封装材料必须已清空，不残留可解封的旧钥引用。
        assert conn.execute(
            "SELECT COUNT(*) FROM downloads WHERE state='completed' AND wrapped_dek IS NOT NULL"
        ).fetchone()[0] == 0
        conn.close()

    def test_size_limit_enforced(self, svc):
        client, _ = svc
        r = client.post("/api/uploads", json={"filename": "big.tif", "size": MAX_FILE_SIZE + 1})
        assert r.status_code == 413
        payload = make_tiff(MAX_FILE_SIZE + 1)
        r = client.post("/api/uploads", json={"filename": "big.tif", "size": len(payload)})
        assert r.status_code == 413

    def test_rotation_rewraps_dek_only_and_deletes_old_kek(self, svc, tmp_data):
        client, service = svc
        f1 = _upload(client, make_tiff(1024, 1), "a.tif")
        f2 = _upload(client, make_tiff(2048, 2), "b.tif")

        keys_before = {k["id"]: k for k in client.get("/api/keys").json()}
        old_kek = next(k for k in keys_before.values() if k["status"] == "active")
        blob_before = {}
        for f in client.get("/api/files").json():
            with open(os.path.join(tmp_data, "vault", f["file_id"] + ".blob"), "rb") as fh:
                blob_before[f["file_id"]] = fh.read()

        r = client.post("/api/rotations")
        assert r.status_code == 201
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        status = client.get("/api/rotations/current").json()
        assert status["last"]["rewrapped"] == 2

        # 旧 KEK 文件实际删除，新 KEK 接管；密文原件逐字节未变。
        old_path = os.path.join(tmp_data, "keys", old_kek["key_id"] + ".kek")
        assert not os.path.exists(old_path)
        for f in client.get("/api/files").json():
            assert f["kek_id"] != old_kek["id"]
            with open(os.path.join(tmp_data, "vault", f["file_id"] + ".blob"), "rb") as fh:
                assert fh.read() == blob_before[f["file_id"]]

        # 所有已归档文件仍可解密且内容一致。
        assert _download(client, f1) == make_tiff(1024, 1)
        assert _download(client, f2) == make_tiff(2048, 2)

        keys_after = {k["id"]: k for k in client.get("/api/keys").json()}
        assert keys_after[old_kek["id"]]["status"] == "deleted"
        assert keys_after[old_kek["id"]]["file_exists"] is False

    def test_concurrent_rotation_rejected(self, svc):
        client, service = svc
        _upload(client, make_tiff(512))
        client.post("/api/demo/gates/upload_register", json={"paused": True})
        try:
            # 造一个卡在待登记的上传，使轮换收尾保持 running。
            r = client.post("/api/uploads", json={"filename": "hold.tif", "size": 8})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=make_tiff(8, 3))
            t = threading.Thread(target=lambda: client.post(f"/api/uploads/{uid}/complete"))
            t.start()
            wait_until(lambda: service.upload_gate.waiting == 1)

            assert client.post("/api/rotations").status_code == 201
            wait_until(lambda: client.get("/api/rotations/current").json()["active"])
            r2 = client.post("/api/rotations")
            assert r2.status_code == 409

            client.post("/api/demo/gates/upload_register", json={"paused": False})
            t.join(timeout=10)
            wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        finally:
            client.post("/api/demo/gates/upload_register", json={"paused": False})

    def test_upload_paused_at_register_leaves_no_old_key_reference(self, svc):
        client, service = svc
        _upload(client, make_tiff(700), "before.tif")
        old_kek_id = client.get("/api/rotations/current").json()["active_kek"]["id"]

        client.post("/api/demo/gates/upload_register", json={"paused": True})
        payload = make_tiff(900, 9)
        r = client.post("/api/uploads", json={"filename": "during.tif", "size": len(payload)})
        uid = r.json()["upload_id"]
        assert client.put(f"/api/uploads/{uid}/content", content=payload).status_code == 200

        done = {}
        t = threading.Thread(target=lambda: done.update(
            client.post(f"/api/uploads/{uid}/complete").json()))
        t.start()
        wait_until(lambda: service.upload_gate.waiting == 1)

        # 轮换发起并完成全部重封装，但因待登记上传而停在收尾。
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: (
            (s := client.get("/api/rotations/current").json())["active"]
            and s["state"] == "completing"))
        st = client.get("/api/rotations/current").json()
        assert st["blocking_uploads"] == 1

        # 恢复上传：用新 active KEK 封装 DEK 并登记。
        client.post("/api/demo/gates/upload_register", json={"paused": False})
        t.join(timeout=10)
        assert done["state"] == "completed"
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])

        files = {f["filename"]: f for f in client.get("/api/files").json()}
        assert files["during.tif"]["kek_id"] != old_kek_id
        assert files["before.tif"]["kek_id"] != old_kek_id
        assert _download(client, files["during.tif"]["file_id"]) == payload
        # 旧钥文件已删除，且没有任何 files 行引用它。
        old = next(k for k in client.get("/api/keys").json() if k["id"] == old_kek_id)
        assert old["status"] == "deleted" and old["file_exists"] is False

    def test_download_paused_at_unwrap_must_finish_reading(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(1500, 5)
        file_id = _upload(client, payload)
        old_kek_id = client.get("/api/rotations/current").json()["active_kek"]["id"]

        client.post("/api/demo/gates/download_unwrap", json={"paused": True})
        r = client.post(f"/api/files/{file_id}/downloads")
        dl_id = r.json()["download_id"]
        result = {}
        t = threading.Thread(target=lambda: result.update(
            client.get(f"/api/downloads/{dl_id}/content").json() if False else
            {"resp": client.get(f"/api/downloads/{dl_id}/content")}))
        t.start()
        wait_until(lambda: service.download_gate.waiting == 1)

        # 轮换期间下载照常受理；收尾必须等这个在途下载。
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: (
            (s := client.get("/api/rotations/current").json())["active"]
            and s["state"] == "completing"))
        st = client.get("/api/rotations/current").json()
        assert st["blocking_downloads"] == 1
        old_path = os.path.join(
            tmp_data, "keys",
            next(k["key_id"] for k in client.get("/api/keys").json() if k["id"] == old_kek_id) + ".kek")
        assert os.path.exists(old_path), "在途下载结束前旧钥文件不得删除"

        client.post("/api/demo/gates/download_unwrap", json={"paused": False})
        t.join(timeout=10)
        resp = result["resp"]
        assert resp.status_code == 200
        assert resp.content == payload  # 已受理下载读完原件
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        assert not os.path.exists(old_path)

    def test_uploads_and_downloads_continue_during_rotation(self, svc):
        client, _ = svc
        first = make_tiff(800, 1)
        fid = _upload(client, first)

        errors: list[str] = []
        uploaded: list[str] = []

        def do_uploads():
            try:
                for i in range(3):
                    p = make_tiff(400 + i, 100 + i)
                    uploaded.append(_upload(client, p, f"during{i}.tif"))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"upload: {exc}")

        def do_downloads():
            try:
                for _ in range(3):
                    assert _download(client, fid) == first
            except Exception as exc:  # noqa: BLE001
                errors.append(f"download: {exc}")

        tu = threading.Thread(target=do_uploads)
        td = threading.Thread(target=do_downloads)
        tu.start(); td.start()
        assert client.post("/api/rotations").status_code == 201
        tu.join(timeout=15); td.join(timeout=15)
        assert not errors, errors
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        status = client.get("/api/rotations/current").json()
        # 轮换期间新上传的文件也都封装在新 KEK 上且可解密。
        active_kek = status["active_kek"]["id"]
        for f in client.get("/api/files").json():
            assert f["kek_id"] == active_kek
        for new_id in uploaded:
            assert _download(client, new_id) is not None

    def test_restart_mid_rotation_resumes_and_files_remain_decodable(self, tmp_data, monkeypatch):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payloads = {f"img{i}.tif": make_tiff(300 + i * 17, i) for i in range(4)}
        with TestClient(app) as client:
            ids = {name: _upload(client, p) for name, p in payloads.items()}

        # 第二次启动：发起轮换，并留一个“待登记”上传使收尾阶段无法结束，
        # 然后干净退出进程（不依赖阻塞线程），数据库停在轮换未完成状态。
        with TestClient(app) as client:
            client.post("/api/demo/gates/upload_register", json={"paused": True})
            r = client.post("/api/uploads", json={"filename": "hold.tif", "size": 8})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=make_tiff(8, 44))
            assert client.get("/api/uploads").json()[0]["state"] == "pending_register"

            assert client.post("/api/rotations").status_code == 201
            wait_until(lambda: (
                (s := client.get("/api/rotations/current").json())["active"]
                and s["state"] == "completing"))
            st = client.get("/api/rotations/current").json()
            assert st["blocking_uploads"] == 1
            client.post("/api/demo/gates/upload_register", json={"paused": False})
        # 进程退出：待登记上传的内存 DEK 随进程消失，轮换停在未完成状态。

        # 第三次启动：自动续办至完成。
        with TestClient(app) as client:
            wait_until(lambda: (
                (s := client.get("/api/rotations/current").json())["active"] is False
                and s["last"] is not None and s["last"]["state"] == "completed"))
            st = client.get("/api/rotations/current").json()
            assert st["last"]["rewrapped"] == st["last"]["total"] == 4
            for name, p in payloads.items():
                assert _download(client, ids[name]) == p
            # 所有 KEK 文件中只剩当前 active 的一个。
            keys = client.get("/api/keys").json()
            existing = [k for k in keys if k["file_exists"]]
            assert len(existing) == 1 and existing[0]["status"] == "active"

    def test_restart_recovers_pending_upload_and_staging(self, tmp_data, monkeypatch):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payload = make_tiff(600, 11)
        with TestClient(app) as client:
            r = client.post("/api/uploads", json={"filename": "orphan.tif", "size": len(payload)})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=payload)
            assert client.get("/api/uploads").json()[0]["state"] == "pending_register"

        with TestClient(app) as client:
            up = client.get("/api/uploads").json()[0]
            assert up["state"] == "failed"
            # 暂存密文已清理，目录无孤儿。
            staging = os.path.join(tmp_data, "staging")
            assert os.listdir(staging) == []
            # 重新上传仍然成功。
            new_id = _upload(client, payload, "orphan.tif")
            assert _download(client, new_id) == payload


def _repair(client: TestClient, file_id: str, backup: bytes) -> dict:
    r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(backup)})
    assert r.status_code == 201, r.text
    rid = r.json()["repair_id"]
    r = client.put(f"/api/repairs/{rid}/content", content=backup)
    assert r.status_code == 200, r.text
    r = client.post(f"/api/repairs/{rid}/complete")
    assert r.status_code == 200, r.text
    return r.json()


class TestRepair:
    def test_repair_restores_corrupted_blob_and_keeps_identity(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(2048, 3)
        file_id = _upload(client, payload)
        before = client.get("/api/files").json()[0]

        # 损坏 vault 密文：下载应报 GCM 完整性失败。
        r = client.post(f"/api/files/{file_id}/demo/corrupt")
        assert r.status_code == 200
        r = client.post(f"/api/files/{file_id}/downloads")
        dl = r.json()["download_id"]
        r = client.get(f"/api/downloads/{dl}/content")
        assert r.status_code == 500 and "GCM" in r.json()["error"]

        # 用留存的原件备份修复。
        done = _repair(client, file_id, payload)
        assert done["state"] == "completed" and done["file_id"] == file_id

        # 文件 ID、大小、摘要等登记信息不变，仅密文 nonce 变化。
        after = next(f for f in client.get("/api/files").json() if f["file_id"] == file_id)
        assert after["file_id"] == before["file_id"]
        assert after["sha256"] == before["sha256"]
        assert after["size"] == before["size"]
        assert after["filename"] == before["filename"]
        assert after["created_at"] == before["created_at"]
        import sqlite3

        conn = sqlite3.connect(os.path.join(tmp_data, "archive.db"))
        row = conn.execute("SELECT nonce FROM files WHERE file_id=?", (file_id,)).fetchone()
        conn.close()
        assert row[0] is not None
        # 新下载得到完整原件；可重复修复。
        assert _download(client, file_id) == payload
        assert _repair(client, file_id, payload)["state"] == "completed"
        assert _download(client, file_id) == payload

    def test_repair_rejects_size_or_digest_mismatch(self, svc, tmp_data):
        client, _ = svc
        payload = make_tiff(1200, 4)
        file_id = _upload(client, payload)

        # 大小不符（受理阶段即拒绝）。
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload) + 1})
        assert r.status_code == 422
        # 同大小但内容不同 -> SHA-256 不符，写入阶段拒绝，会话 failed。
        wrong = make_tiff(1200, 99)
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(wrong)})
        rid = r.json()["repair_id"]
        r = client.put(f"/api/repairs/{rid}/content", content=wrong)
        assert r.status_code == 422 and "SHA-256" in r.json()["error"]
        rp = next(x for x in client.get("/api/repairs").json() if x["repair_id"] == rid)
        assert rp["state"] == "failed"
        # 失败后原密文仍可读，且可以重新发起修复。
        assert _download(client, file_id) == payload
        assert _repair(client, file_id, payload)["state"] == "completed"
        assert _download(client, file_id) == payload

    def test_repair_enforces_8mib_limit_and_plaintext_never_on_disk(self, svc, tmp_data):
        client, _ = svc
        payload = make_tiff(4096, 6)
        file_id = _upload(client, payload)

        r = client.post(f"/api/files/{file_id}/repairs", json={"size": MAX_FILE_SIZE + 1})
        assert r.status_code == 413
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        rid = r.json()["repair_id"]
        r = client.put(f"/api/repairs/{rid}/content", content=b"x" * (MAX_FILE_SIZE + 1))
        assert r.status_code == 413
        # 超限内容被拒后会话仍停在 accepted，中止后才能重新发起。
        assert client.post(f"/api/repairs/{rid}/abort").status_code == 200

        # 修复全流程后，磁盘上任何文件都不含备份明文/TIFF 魔数，
        # 数据库内不残留修复会话的封装材料。
        _repair(client, file_id, payload)
        for root, _dirs, files in os.walk(tmp_data):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as fh:
                    data = fh.read()
                if "vault" in path or "staging" in path:
                    assert payload not in data
                    assert b"II\x2a\x00" not in data
        # 修复结束后无 .new/.bak 残留。
        assert os.listdir(os.path.join(tmp_data, "staging")) == []
        assert [n for n in os.listdir(os.path.join(tmp_data, "vault")) if n.endswith((".bak", ".new"))] == []
        import sqlite3

        conn = sqlite3.connect(os.path.join(tmp_data, "archive.db"))
        assert conn.execute(
            "SELECT COUNT(*) FROM repairs WHERE state='completed' AND wrapped_dek IS NOT NULL"
        ).fetchone()[0] == 0
        conn.close()

    def test_inflight_repair_blocks_old_kek_retirement_late_repair_still_decodable(
        self, svc, tmp_data
    ):
        client, _ = svc
        payload = make_tiff(1800, 8)
        file_id = _upload(client, payload)
        old_kek_id = client.get("/api/rotations/current").json()["active_kek"]["id"]
        old_path = os.path.join(
            tmp_data, "keys",
            next(k["key_id"] for k in client.get("/api/keys").json() if k["id"] == old_kek_id)
            + ".kek")

        # 先受理修复并完成双校验（备份明文驻内存），再发起轮换。
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        rid = r.json()["repair_id"]
        assert client.put(f"/api/repairs/{rid}/content", content=payload).status_code == 200
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: (
            (s := client.get("/api/rotations/current").json())["active"]
            and s["state"] == "completing"))
        st = client.get("/api/rotations/current").json()
        assert st["blocking_repairs"] == 1
        assert os.path.exists(old_path), "在途修复结束前旧 KEK 文件不得删除"

        # “迟到”的修复此刻才完成替换：仍能用快照旧 KEK 解封 DEK。
        r = client.post(f"/api/repairs/{rid}/complete")
        assert r.status_code == 200 and r.json()["state"] == "completed"
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        assert not os.path.exists(old_path)
        # 旧钥退役后修复件仍可解密，且封装已随轮换迁到新 KEK。
        assert _download(client, file_id) == payload
        f = next(x for x in client.get("/api/files").json() if x["file_id"] == file_id)
        assert f["kek_id"] != old_kek_id

    def test_repair_after_completed_rotation_uses_current_key(self, svc, tmp_data):
        client, _ = svc
        payload = make_tiff(900, 12)
        file_id = _upload(client, payload)
        client.post("/api/rotations")
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])

        # 旧 KEK 已退役：新受理的修复快照指向当前 active KEK，修复照常成功。
        r = client.post(f"/api/files/{file_id}/demo/corrupt")
        assert r.status_code == 200
        done = _repair(client, file_id, payload)
        assert done["state"] == "completed"
        assert _download(client, file_id) == payload

    def test_failed_replacement_keeps_readable_copy(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(700, 13)
        file_id = _upload(client, payload)
        blob_path = os.path.join(tmp_data, "vault", file_id + ".blob")
        with open(blob_path, "rb") as fh:
            good_blob = fh.read()

        # 让“新密文落位”抛错：替换流程必须还原旧密文，修复会话 failed。
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        rid = r.json()["repair_id"]
        client.put(f"/api/repairs/{rid}/content", content=payload)
        original_replace = os.replace

        def broken_replace(src, dst):
            if str(dst) == blob_path and str(src).endswith(".new"):
                raise OSError("模拟新密文落位失败")
            return original_replace(src, dst)

        import app.service as service_mod

        service_mod.os.replace = broken_replace
        try:
            r = client.post(f"/api/repairs/{rid}/complete")
            assert r.status_code == 500
        finally:
            service_mod.os.replace = original_replace

        with open(blob_path, "rb") as fh:
            assert fh.read() == good_blob, "原有可读副本必须保留"
        rp = next(x for x in client.get("/api/repairs").json() if x["repair_id"] == rid)
        assert rp["state"] == "failed"
        assert _download(client, file_id) == payload
        assert os.listdir(os.path.join(tmp_data, "staging")) == []
        # 重复修复仍可用。
        assert _repair(client, file_id, payload)["state"] == "completed"
        assert _download(client, file_id) == payload

    def test_restart_mid_repair_interrupts_and_reconciles(self, tmp_data, monkeypatch):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payload = make_tiff(1500, 15)
        with TestClient(app) as client:
            file_id = _upload(client, payload)
            r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
            rid = r.json()["repair_id"]
            client.put(f"/api/repairs/{rid}/content", content=payload)
            assert client.get("/api/repairs").json()[0]["state"] == "verified"

        # 重启：内存备份明文丢失，在途修复标记 interrupted，可重新发起。
        with TestClient(app) as client:
            rp = client.get("/api/repairs").json()[0]
            assert rp["state"] == "interrupted"
            assert _download(client, file_id) == payload
            assert _repair(client, file_id, payload)["state"] == "completed"
            assert _download(client, file_id) == payload

    def test_restart_reconciles_uncommitted_swap_and_committed_backup(
        self, tmp_data, monkeypatch
    ):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payload = make_tiff(1100, 16)
        with TestClient(app) as client:
            file_id = _upload(client, payload)
            r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
            rid = r.json()["repair_id"]
            client.put(f"/api/repairs/{rid}/content", content=payload)

            # 手动推进到“现网已换成新密文、旧密文在 .bak、事务未提交”的崩溃点：
            # complete 内部先做两次 os.replace 再写数据库，这里直接模拟磁盘状态。
            from app.main import service as current

            f = current._row("SELECT * FROM files WHERE file_id=?", (file_id,))
            blob_path = f["blob_path"]
            backup_path = os.path.join(tmp_data, "vault", file_id + ".blob.bak")
            new_path = os.path.join(tmp_data, "staging", f"repair-{rid}.new")
            # 用服务原语造一份合法新密文写到暂存（借助一次完整修复后再制造场景过于绕，
            # 直接复用加密原语与该件 DEK 的内存解封结果）。
            from app import crypto

            kek = current._get_kek(f["current_kek_id"])
            dek = crypto.unwrap_dek(kek, f["dek_nonce"], f["wrapped_dek"])
            nonce = crypto.new_nonce()
            current._atomic_write(new_path, nonce + crypto.encrypt_blob(dek, nonce, payload))
            import os as _os

            _os.replace(blob_path, backup_path)  # 现网位置空出
            _os.replace(new_path, blob_path)     # 新密文落位，但 DB 仍登记旧 nonce
            # 同时留一个游离的 .new 孤儿
            with open(os.path.join(tmp_data, "staging", "repair-orphan.new"), "wb") as fh:
                fh.write(b"orphan")

        # 重启对账：files.nonce 与 .bak 一致 -> 还原旧密文，清理孤儿。
        with TestClient(app) as client:
            assert not os.path.exists(backup_path)
            assert _download(client, file_id) == payload
            assert os.listdir(os.path.join(tmp_data, "staging")) == []
            # 旧修复会话被标记 interrupted，重新修复成功。
            assert client.get("/api/repairs").json()[0]["state"] == "interrupted"
            assert _repair(client, file_id, payload)["state"] == "completed"
            assert _download(client, file_id) == payload

    def test_accepted_download_before_repair_gets_full_original_afterward(self, svc):
        client, _ = svc
        payload = make_tiff(1300, 21)
        file_id = _upload(client, payload)

        # 修复受理前先受理一个下载（停在 accepted，尚未解封读取）。
        r = client.post(f"/api/files/{file_id}/downloads")
        dl_id = r.json()["download_id"]
        assert r.json()["state"] == "accepted"

        # 损坏并修复。
        client.post(f"/api/files/{file_id}/demo/corrupt")
        assert _repair(client, file_id, payload)["state"] == "completed"

        # 先前已受理但尚未读取的下载同样得到完整原件。
        r = client.get(f"/api/downloads/{dl_id}/content")
        assert r.status_code == 200
        assert r.content == payload
        # 修复后的新下载也一致。
        assert _download(client, file_id) == payload

    def test_failed_corrupt_download_releases_session_and_rotation_completes(self, svc):
        client, _ = svc
        payload = make_tiff(800, 31)
        file_id = _upload(client, payload)
        client.post(f"/api/files/{file_id}/demo/corrupt")
        dl_id = client.post(f"/api/files/{file_id}/downloads").json()["download_id"]
        assert client.get(f"/api/downloads/{dl_id}/content").status_code == 500
        # 失败的下载会话被释放为 interrupted，不再阻塞轮换收尾。
        dl = next(d for d in client.get("/api/downloads").json() if d["download_id"] == dl_id)
        assert dl["state"] == "interrupted"
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        # 修复后重新下载得到完整原件。
        assert _repair(client, file_id, payload)["state"] == "completed"
        assert _download(client, file_id) == payload

    def test_only_one_inflight_repair_per_file(self, svc):
        client, _ = svc
        payload = make_tiff(500, 22)
        file_id = _upload(client, payload)
        r = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        assert r.status_code == 201
        r2 = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        assert r2.status_code == 409
        # 中止后可重新发起。
        rid = r.json()["repair_id"]
        assert client.post(f"/api/repairs/{rid}/abort").status_code == 200
        r3 = client.post(f"/api/files/{file_id}/repairs", json={"size": len(payload)})
        assert r3.status_code == 201
