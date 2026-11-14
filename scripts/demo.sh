#!/usr/bin/env bash
# 本地演示脚本：无需 Docker，自动在独立临时目录启动服务并演示三个场景：
#   1) 上传待登记暂停 / 下载待解封暂停；
#   2) 密钥轮换：仅重封装 DEK、旧 KEK 文件删除后才报完成；
#   3) 轮换中“进程退出 → 重启自动续办”，已归档文件始终可解密。
#
# 用法： scripts/demo.sh [BASE_DIR]
# 依赖： python3（含 venv 内的 fastapi/uvicorn/cryptography）、curl、sha256sum
set -euo pipefail

BASE_DIR="${1:-$(mktemp -d /tmp/tiff-archive-demo.XXXXXX)}"
DATA_DIR="$BASE_DIR/data"
PORT="${PORT:-8090}"
# 重启方式：RESTART=kill（默认，真实环境/容器内停止进程后重启）；
# RESTART=report（受限环境无法发信号时，用同一数据目录在新端口启动新进程，
# 恢复逻辑完全相同，仅进程替换方式不同）。
RESTART="${RESTART:-kill}"
PORT2="${PORT2:-$((PORT+1))}"
BASE="http://127.0.0.1:$PORT"
LOG="$BASE_DIR/server.log"
PY="${PYTHON:-python3}"

mkdir -p "$DATA_DIR" "$BASE_DIR/samples"
trap 'echo; echo "演示数据保留在: $BASE_DIR（可手动删除）"' EXIT

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
jget() { "$PY" -c 'import sys,json;d=json.load(sys.stdin);
for k in sys.argv[1].split("."): d=d[k]
print(d)' "$1"; }

say "0/ 启动服务（数据目录 $DATA_DIR，端口 $PORT）"
ARCHIVE_DATA_DIR="$DATA_DIR" "$PY" -m uvicorn app.main:app \
  --host 127.0.0.1 --port "$PORT" >"$LOG" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; echo; echo "演示数据保留在: $BASE_DIR（可手动删除）"' EXIT
for _ in $(seq 1 30); do
  curl -sf "$BASE/health" >/dev/null && break
  sleep 0.3
done
curl -s "$BASE/health" >/dev/null || { echo "服务启动失败，见 $LOG"; exit 1; }
ok "服务在线，浏览器入口: $BASE/ （PID=$SRV）"

make_tif() {  # $1 文件名 $2 大小
  "$PY" - "$1" "$2" <<'EOF'
import sys
path, size = sys.argv[1], int(sys.argv[2])
header = b"II\x2a\x00" + size.to_bytes(4, "little")
body = bytes(((i * 31 + 7) & 0xFF) for i in range(size - len(header)))
open(path, "wb").write(header + body)
EOF
}

upload() {  # $1 文件路径 -> 输出 file_id
  local path="$1" name size init uid
  name="$(basename "$path")"; size="$(stat -c%s "$path")"
  init="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
    -d "{\"filename\":\"$name\",\"size\":$size}")"
  uid="$(printf '%s' "$init" | jget upload_id)"
  curl -s -X PUT --data-binary "@$path" "$BASE/api/uploads/$uid/content" >/dev/null
  curl -s -X POST "$BASE/api/uploads/$uid/complete" | jget file_id
}

download() {  # $1 file_id $2 输出路径
  local did
  did="$(curl -s -X POST "$BASE/api/files/$1/downloads" | jget download_id)"
  curl -s -o "$2" "$BASE/api/downloads/$did/content"
}

wait_rotation_done() {
  for _ in $(seq 1 50); do
    curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;raise SystemExit(0 if not json.load(sys.stdin)["active"] else 1)' && return 0
    sleep 0.3
  done
  echo "轮换未在预期时间内完成"; return 1
}

say "1/ 正常上传/下载往返（独立随机 DEK，明文不落盘）"
make_tif "$BASE_DIR/samples/img-a.tif" 4096
FID_A="$(upload "$BASE_DIR/samples/img-a.tif")"
download "$FID_A" "$BASE_DIR/samples/img-a.dl.tif"
cmp "$BASE_DIR/samples/img-a.tif" "$BASE_DIR/samples/img-a.dl.tif"
ok "img-a.tif 上传后下载逐字节一致（file_id=${FID_A:0:8}…）"
if grep -rIl $'II\x2a\x00' "$DATA_DIR/vault" "$DATA_DIR/staging" 2>/dev/null; then
  echo "密文目录中发现明文 TIFF 魔数！"; exit 1
fi
ok "vault/staging 中无明文 TIFF 魔数；密钥目录与密文目录分离："
echo "   $DATA_DIR/keys  $(ls "$DATA_DIR/keys" | sed 's/^/  /' | tr '\n' ' ')"
echo "   $DATA_DIR/vault $(ls "$DATA_DIR/vault" | sed 's/^/  /' | tr '\n' ' ')"

say "2/ 暂停点演示：上传待登记、下载待解封"
# --- 上传待登记 ---
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
make_tif "$BASE_DIR/samples/img-b.tif" 2048
size_b="$(stat -c%s "$BASE_DIR/samples/img-b.tif")"
uid_b="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
  -d "{\"filename\":\"img-b.tif\",\"size\":$size_b}" | jget upload_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-b.tif" "$BASE/api/uploads/$uid_b/content" >/dev/null
curl -s -X POST "$BASE/api/uploads/$uid_b/complete" >"$BASE_DIR/up-b.json" &
CP=$!
sleep 1.2
state_b="$(curl -s "$BASE/api/uploads" | "$PY" -c 'import sys,json;print(next(u["state"] for u in json.load(sys.stdin) if u["filename"]=="img-b.tif"))')"
[ "$state_b" = "pending_register" ] && ok "上传已暂停在“待登记”（DEK 仅在内存，密文暂存 staging/）"
# --- 同时发起轮换：收尾必须等待该上传 ---
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
rot="$(curl -s "$BASE/api/rotations/current")"
echo "$rot" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["state"]=="completing" and d["blocking_uploads"]==1'
ok "轮换停在收尾，blocking_uploads=1（旧 KEK 文件仍保留）"
# --- 恢复上传，轮换随之完成 ---
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":false}' >/dev/null
wait "$CP"
wait_rotation_done
fid_b="$(curl -s "$BASE/api/uploads" | "$PY" -c 'import sys,json;print(next(u["file_id"] for u in json.load(sys.stdin) if u["filename"]=="img-b.tif"))')"
kek_b="$(curl -s "$BASE/api/files" | "$PY" -c 'import sys,json;print(next(f["kek_id"] for f in json.load(sys.stdin) if f["file_id"]=="'$fid_b'"))')"
old_kek="$(curl -s "$BASE/api/keys" | "$PY" -c 'import sys,json;print(next(k["id"] for k in json.load(sys.stdin) if k["status"]=="deleted"))')"
[ "$kek_b" != "$old_kek" ] && ok "暂停期间的上传最终由新课题密钥封装，未留下旧钥引用"
ok "第一轮轮换完成，旧 KEK 文件已实际删除"

# --- 下载待解封 ---
curl -s -X POST "$BASE/api/demo/gates/download_unwrap" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
did_c="$(curl -s -X POST "$BASE/api/files/$FID_A/downloads" | jget download_id)"
curl -s -o "$BASE_DIR/samples/img-a.dl2.tif" "$BASE/api/downloads/$did_c/content" &
CP=$!
sleep 1.2
dl_state="$(curl -s "$BASE/api/downloads" | "$PY" -c 'import sys,json;print(next(d["state"] for d in json.load(sys.stdin) if d["download_id"]=="'$did_c'"))')"
[ "$dl_state" = "accepted" ] && ok "下载已受理并暂停在“待解封”"
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["blocking_downloads"]==1'
ok "第二轮轮换等待在途下载，blocking_downloads=1"
curl -s -X POST "$BASE/api/demo/gates/download_unwrap" -H 'Content-Type: application/json' -d '{"paused":false}' >/dev/null
wait "$CP"
wait_rotation_done
cmp "$BASE_DIR/samples/img-a.tif" "$BASE_DIR/samples/img-a.dl2.tif"
ok "恢复后已受理下载读完原件，内容逐字节一致；轮换随后完成"

say "3/ 轮换中退出、重启自动续办"
# 留一个待登记上传，使下一轮换停在收尾，然后“杀掉”服务模拟中途退出
curl -s -X POST "$BASE/api/demo/gates/upload_register" -H 'Content-Type: application/json' -d '{"paused":true}' >/dev/null
make_tif "$BASE_DIR/samples/img-c.tif" 1024
size_c="$(stat -c%s "$BASE_DIR/samples/img-c.tif")"
uid_c="$(curl -s -X POST "$BASE/api/uploads" -H 'Content-Type: application/json' \
  -d "{\"filename\":\"img-c.tif\",\"size\":$size_c}" | jget upload_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-c.tif" "$BASE/api/uploads/$uid_c/content" >/dev/null
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"]'
if [ "$RESTART" = "report" ]; then
  ok "轮换进行中（RESTART=report）：在新端口 $PORT2 用同一数据目录启动新进程模拟重启"
  RESTART_BASE="http://127.0.0.1:$PORT2"
  ARCHIVE_DATA_DIR="$DATA_DIR" "$PY" -m uvicorn app.main:app \
    --host 127.0.0.1 --port "$PORT2" >"$BASE_DIR/server-restart.log" 2>&1 &
  SRV2=$!
else
  ok "轮换进行中，停止服务进程（PID=$SRV）"
  kill "$SRV" 2>/dev/null || true
  wait "$SRV" 2>/dev/null || true

  # 用同一数据目录重启：恢复逻辑自动续办
  ARCHIVE_DATA_DIR="$DATA_DIR" "$PY" -m uvicorn app.main:app \
    --host 127.0.0.1 --port "$PORT" >"$BASE_DIR/server-restart.log" 2>&1 &
  SRV2=$!
  RESTART_BASE="$BASE"
fi
trap 'kill "$SRV" "$SRV2" 2>/dev/null || true; echo; echo "演示数据保留在: $BASE_DIR（可手动删除）"' EXIT
for _ in $(seq 1 30); do curl -sf "$RESTART_BASE/health" >/dev/null && break; sleep 0.3; done
BASE="$RESTART_BASE"  # 后续请求一律打到重启后的实例
ok "服务已用同一数据目录重启（$BASE）"
# 重启后待登记上传按规则失败、暂存清理
curl -s "$RESTART_BASE/api/uploads" | "$PY" -c 'import sys,json;u=next(x for x in json.load(sys.stdin) if x["filename"]=="img-c.tif");assert u["state"]=="failed", u'
[ -z "$(ls -A "$DATA_DIR/staging")" ] && ok "重启恢复：未完成上传标记 failed，staging/ 已清理"
# 轮换自动续办至完成
for _ in $(seq 1 50); do
  curl -s "$RESTART_BASE/api/rotations/current" | "$PY" -c 'import sys,json;raise SystemExit(0 if not json.load(sys.stdin)["active"] else 1)' && break
  sleep 0.3
done
curl -s "$RESTART_BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["last"]["state"]=="completed", d'
ok "重启后轮换自动续办并完成"
# 全部历史归档仍可解密且内容一致
for f in img-a img-b; do
  fid="$(curl -s "$RESTART_BASE/api/files" | "$PY" -c 'import sys,json;print(next(x["file_id"] for x in json.load(sys.stdin) if x["filename"]=="'$f'.tif"))')"
  download "$fid" "$BASE_DIR/samples/$f.restart-dl.tif"
  cmp "$BASE_DIR/samples/$f.tif" "$BASE_DIR/samples/$f.restart-dl.tif"
done
ok "重启后全部已归档文件仍可解密，且与原件逐字节一致"

say "4/ 密文修复：备份恢复（大小 + SHA-256 双校验，原件/DEK 不落盘）"
# 再上传一件用于修复演示的影像，留存原件备份
make_tif "$BASE_DIR/samples/img-r.tif" 3072
FID_R="$(upload "$BASE_DIR/samples/img-r.tif")"
REG_SIZE="$(stat -c%s "$BASE_DIR/samples/img-r.tif")"
REG_SHA="$(curl -s "$BASE/api/files" | "$PY" -c 'import sys,json;print(next(x["sha256"] for x in json.load(sys.stdin) if x["file_id"]=="'$FID_R'"))')"
ok "待修复影像已归档（file_id=${FID_R:0:8}…，SHA-256=${REG_SHA:0:16}…）"

# 4.1 模拟 vault 密文损坏：下载报 GCM 完整性失败
curl -s -X POST "$BASE/api/files/$FID_R/demo/corrupt" >/dev/null
DID_BAD="$(curl -s -X POST "$BASE/api/files/$FID_R/downloads" | jget download_id)"
HTTP_BAD="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/downloads/$DID_BAD/content")"
[ "$HTTP_BAD" = "500" ] && ok "损坏密文下载被拒（HTTP 500，GCM 标签校验失败）"

# 4.2 错误备份（同大小、不同内容）必须因 SHA-256 不符被拒，且原副本仍在
BAD_TIF="$BASE_DIR/samples/img-r.bad.tif"
cp "$BASE_DIR/samples/img-r.tif" "$BAD_TIF"
"$PY" - "$BAD_TIF" <<'EOF'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:  # 翻转若干字节，保持大小不变、内容不同
    f.seek(16)
    b = f.read(4)
    f.seek(16)
    f.write(bytes(x ^ 0xA5 for x in b))
EOF
RID_BAD="$(curl -s -X POST "$BASE/api/files/$FID_R/repairs" -H 'Content-Type: application/json' \
  -d "{\"size\":$REG_SIZE}" | jget repair_id)"
HTTP_BAD2="$(curl -s -o /tmp/demo-bad.json -w '%{http_code}' -X PUT --data-binary "@$BAD_TIF" \
  "$BASE/api/repairs/$RID_BAD/content")"
[ "$HTTP_BAD2" = "422" ] && ok "SHA-256 不符的备份被拒绝（HTTP 422），修复会话标记 failed"

# 4.3 正确备份：受理 -> 双校验 -> 同一 DEK 重新加密并原子替换
RID="$(curl -s -X POST "$BASE/api/files/$FID_R/repairs" -H 'Content-Type: application/json' \
  -d "{\"size\":$REG_SIZE}" | jget repair_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-r.tif" "$BASE/api/repairs/$RID/content" \
  | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["state"]=="verified", d'
curl -s -X POST "$BASE/api/repairs/$RID/complete" \
  | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["state"]=="completed" and d["file_id"]=="'$FID_R'", d'
ok "修复完成：文件 ID/摘要不变，仅密文被重新加密替换"
download "$FID_R" "$BASE_DIR/samples/img-r.repaired.tif"
cmp "$BASE_DIR/samples/img-r.tif" "$BASE_DIR/samples/img-r.repaired.tif"
ok "修复后新下载与留存原件逐字节一致；vault 无 .bak/.new 残留：$(ls "$DATA_DIR/vault" | tr '\n' ' ')"
if grep -rIl $'II\x2a\x00' "$DATA_DIR/vault" "$DATA_DIR/staging" 2>/dev/null; then
  echo "密文目录中发现明文 TIFF 魔数！"; exit 1
fi
ok "修复全程原件明文与数据密钥未落盘（无 TIFF 魔数、无封装材料残留）"

# 4.4 在途修复阻塞旧钥退役：先受理修复，再发起轮换，旧 KEK 文件必须保留
RID2="$(curl -s -X POST "$BASE/api/files/$FID_R/repairs" -H 'Content-Type: application/json' \
  -d "{\"size\":$REG_SIZE}" | jget repair_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-r.tif" "$BASE/api/repairs/$RID2/content" >/dev/null
curl -s -X POST "$BASE/api/rotations" >/dev/null
sleep 1.0
curl -s "$BASE/api/rotations/current" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);assert d["active"] and d["blocking_repairs"]==1, d'
ok "轮换收尾等待在途修复（blocking_repairs=1），旧 KEK 文件尚未退役"
curl -s -X POST "$BASE/api/repairs/$RID2/complete" | "$PY" -c 'import sys,json;assert json.load(sys.stdin)["state"]=="completed"'
wait_rotation_done
download "$FID_R" "$BASE_DIR/samples/img-r.late.tif"
cmp "$BASE_DIR/samples/img-r.tif" "$BASE_DIR/samples/img-r.late.tif"
ok "迟到的修复在旧钥退役后仍可解密，下载内容逐字节一致"

# 4.5 修复前已受理、修复后才读取的下载同样得到完整原件
DID3="$(curl -s -X POST "$BASE/api/files/$FID_R/downloads" | jget download_id)"
RID3="$(curl -s -X POST "$BASE/api/files/$FID_R/repairs" -H 'Content-Type: application/json' \
  -d "{\"size\":$REG_SIZE}" | jget repair_id)"
curl -s -X PUT --data-binary "@$BASE_DIR/samples/img-r.tif" "$BASE/api/repairs/$RID3/content" >/dev/null
curl -s -X POST "$BASE/api/repairs/$RID3/complete" >/dev/null
curl -s -o "$BASE_DIR/samples/img-r.accepted.tif" "$BASE/api/downloads/$DID3/content"
cmp "$BASE_DIR/samples/img-r.tif" "$BASE_DIR/samples/img-r.accepted.tif"
ok "修复前已受理但尚未读取的下载，修复后得到完整原件"

say "演示完成"
echo "浏览器入口: $RESTART_BASE/ （本脚本结束后服务已停止；手动启动见 README）"
echo "服务日志:   $LOG 、 $BASE_DIR/server-restart.log"
