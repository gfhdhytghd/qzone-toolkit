"""
qzone-serv-UDS | 通过 Unix Domain Socket 的串行发送服务

Socket 与运行模式
- 协议/类型：Unix Domain Socket（AF_UNIX, SOCK_STREAM）。
- 路径：默认 `./qzone_uds.sock`，可通过环境变量 `QZONE_UDS_PATH` 覆盖。
- 权限：遵从进程 `umask` 创建 socket 文件（建议使用仅属主可读写的权限）。
- 连接模型：每个客户端连接仅承载一次请求。
  - 客户端写入完整 JSON 后关闭写端（EOF）。
  - 服务端读取至 EOF，解析并入队串行处理，随后写回结果并关闭连接。
- 并发/顺序：服务内部维护一个队列和单一 worker，确保严格串行处理，按接入顺序依次发送，避免并发导致的状态/额度问题。

输入/输出约定
- 输入（客户端 -> 服务端）：一段 JSON 文本（无长度前缀/分隔符，EOF 作为消息结束标记）。
  {
    "text": "说说内容",
    "image": ["http(s)://...", "file:///path/to/img.jpg", "data:image/...;base64,......", "<base64>"] ,  // 可选
    "cookies": { "uin": "o12345678", "skey": "...", "p_skey": "...", ... }
  }
- 输出（服务端 -> 客户端）：一行纯文本结果字符串，然后断开连接。
  - "success"：发布成功
  - "failed"：cookies 无效/过期或下游失败
  - 其他中文错误串：如 "文本处理错误"、"图像处理错误"、"空间发送解析提交数据失败"

调试与日志
- 日志：`logs/qzone_uds.log`（可用 `QZONE_LOG_DIR` 变更目录）。
- 调试：设置 `QZONE_DEBUG=1` 输出更详细的请求/响应与预览。

兼容性说明
- 请求结构、字段与管道版 `qzone-serv-pipe.py` 保持一致，便于替换接入。
"""

import os
import json
import traceback
import base64
import requests
import re
import gc
import time
import logging
import socket
import threading
import queue
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


# =========================
# Debug / Logging Settings
# =========================
DEBUG = os.getenv("QZONE_DEBUG", "0").lower() in ("1", "true", "yes", "y")
LOG_DIR = os.getenv("QZONE_LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("qzone_uds")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
_fmt = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_fh = RotatingFileHandler(
    os.path.join(LOG_DIR, "qzone_uds.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
)
_fh.setFormatter(_fmt)
_sh = logging.StreamHandler()
_sh.setFormatter(_fmt)
logger.handlers.clear()
logger.addHandler(_fh)
logger.addHandler(_sh)


SENSITIVE_KEYS = {"skey", "p_skey", "pt4_token", "RK", "ptcz", "uin", "p_uin", "pt2gguin", "qzone_check"}


def _mask(v: str, keep_head: int = 3, keep_tail: int = 3) -> str:
    try:
        s = str(v)
    except Exception:
        return "***"
    if len(s) <= keep_head + keep_tail + 3:
        return "***"
    return f"{s[:keep_head]}***{s[-keep_tail:]}"


def scrub_dict(d: dict) -> dict:
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        if k in SENSITIVE_KEYS:
            out[k] = _mask(v)
        else:
            out[k] = v
    return out


def save_response_body(prefix: str, content: bytes) -> str:
    """保存响应体到日志目录，仅在 DEBUG 时调用。"""
    fname = f"{prefix}_{int(time.time()*1000)}.resp"
    fpath = os.path.join(LOG_DIR, fname)
    try:
        with open(fpath, "wb") as f:
            f.write(content)
    except Exception as e:
        logger.warning(f"保存响应体失败: {e}")
    return fpath


# URL definitions
GET_VISITOR_AMOUNT_URL = (
    "https://h5.qzone.qq.com/proxy/domain/g.qzone.qq.com/cgi-bin/friendshow/cgi_get_visitor_more?uin={}&mask=7&g_tk={}&page=1&fupdate=1&clear=1"
)
UPLOAD_IMAGE_URL = "https://up.qzone.qq.com/cgi-bin/upload/cgi_upload_image"
EMOTION_PUBLISH_URL = (
    "https://user.qzone.qq.com/proxy/domain/taotao.qzone.qq.com/cgi-bin/emotion_cgi_publish_v6"
)


def generate_gtk(skey: str) -> str:
    """Generate gtk"""
    hash_val = 5381
    for i in range(len(skey)):
        hash_val += (hash_val << 5) + ord(skey[i])
    return str(hash_val & 2147483647)


def get_picbo_and_richval(upload_result):
    json_data = upload_result

    if "ret" not in json_data:
        raise Exception("Failed to get picbo and richval")

    if json_data["ret"] != 0:
        raise Exception("Image upload failed")
    picbo_spt = json_data["data"]["url"].split("&bo=")
    if len(picbo_spt) < 2:
        raise Exception("Image upload failed")
    picbo = picbo_spt[1]

    richval = ",{}, {},{},{},{},{},,{},{}".format(
        json_data["data"]["albumid"],
        json_data["data"]["lloc"],
        json_data["data"]["sloc"],
        json_data["data"]["type"],
        json_data["data"]["height"],
        json_data["data"]["width"],
        json_data["data"]["height"],
        json_data["data"]["width"],
    )

    return picbo, richval


class QzoneAPI:
    def __init__(self, cookies_dict: dict = {}):
        self.cookies = cookies_dict
        self.gtk2 = ""
        self.uin = 0
        self.session = requests.Session()
        logger.debug(f"Init QzoneAPI with cookies keys={list(self.cookies.keys())}")

        if "p_skey" in self.cookies:
            self.gtk2 = generate_gtk(self.cookies["p_skey"])

        if "uin" in self.cookies:
            try:
                self.uin = int(self.cookies["uin"][1:])
            except Exception:
                # 若不是o12345形式，尝试直接int
                try:
                    self.uin = int(self.cookies["uin"])  # 兜底
                except Exception:
                    self.uin = 0

    def do(
        self,
        method: str,
        url: str,
        params: dict = {},
        data: dict = {},
        headers: dict = {},
        cookies: dict = None,
        timeout: int = 10,
    ) -> requests.Response:
        if cookies is None:
            cookies = self.cookies

        t0 = time.time()
        try:
            if DEBUG:
                logger.debug(
                    f"HTTP {method} {url} params={scrub_dict(params)} "
                    f"data_keys={list(data.keys()) if isinstance(data, dict) else type(data)} "
                    f"headers={headers} cookies={scrub_dict(cookies)} timeout={timeout}"
                )
            res = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
            )
            dt = (time.time() - t0) * 1000
            body_path = None
            body_preview = ""
            if DEBUG:
                content = res.content or b""
                body_path = save_response_body("http_body", content)
                body_preview = content[:2048].decode(errors="ignore")
            logger.info(f"HTTP {method} {url} -> {res.status_code} in {dt:.1f}ms")
            if DEBUG:
                logger.debug(
                    f"Resp headers: {{'Content-Type': {res.headers.get('Content-Type')}, 'Content-Length': {res.headers.get('Content-Length')}}}"
                )
                logger.debug(f"Resp preview (first 2KB): {body_preview!r}, saved={body_path}")
            return res
        except Exception as e:
            logger.error(f"HTTP {method} {url} failed: {e}")
            logger.debug("Traceback:\n" + traceback.format_exc())
            raise

    def __del__(self):
        try:
            self.session.close()
        except Exception:
            pass

    def token_valid(self, retry: int = 3) -> bool:
        for i in range(retry):
            try:
                res = self.do(
                    method="GET",
                    url=GET_VISITOR_AMOUNT_URL.format(self.uin, self.gtk2),
                    headers={
                        "referer": "https://user.qzone.qq.com/" + str(self.uin),
                        "origin": "https://user.qzone.qq.com",
                    },
                )
                logger.debug(f"token_valid attempt={i+1} status={res.status_code}")
                if res.status_code == 200:
                    return True
            except Exception:
                logger.debug("token_valid exception:\n" + traceback.format_exc())
                if i == retry - 1:
                    logger.warning("token_valid exhausted retries, treat as invalid.")
                    return False
        return False

    def image_to_base64(self, image: bytes) -> str:
        pic_base64 = base64.b64encode(image)
        return pic_base64.decode("utf-8")

    def upload_image(self, image: bytes) -> dict:
        if DEBUG:
            logger.debug(
                f"upload_image size={len(image) if image else 0} bytes, uin={self.uin}, gtk2={_mask(self.gtk2)}"
            )

        res = self.do(
            method="POST",
            url=UPLOAD_IMAGE_URL,
            data={
                "filename": "filename",
                "zzpanelkey": "",
                "uploadtype": "1",
                "albumtype": "7",
                "exttype": "0",
                "skey": self.cookies["skey"],
                "zzpaneluin": self.uin,
                "p_uin": self.uin,
                "uin": self.uin,
                "p_skey": self.cookies["p_skey"],
                "output_type": "json",
                "qzonetoken": "",
                "refer": "shuoshuo",
                "charset": "utf-8",
                "output_charset": "utf-8",
                "upload_hd": "1",
                "hd_width": "2048",
                "hd_height": "10000",
                "hd_quality": "96",
                "backUrls": "http://upbak.photo.qzone.qq.com/cgi-bin/upload/cgi_upload_image,http://119.147.64.75/cgi-bin/upload/cgi_upload_image",
                "url": "https://up.qzone.qq.com/cgi-bin/upload/cgi_upload_image?g_tk=" + self.gtk2,
                "base64": "1",
                "picfile": self.image_to_base64(image),
            },
            headers={
                "referer": "https://user.qzone.qq.com/" + str(self.uin),
                "origin": "https://user.qzone.qq.com",
            },
            timeout=60,
        )
        if res.status_code == 200:
            text = res.text
            l = text.find("{")
            r = text.rfind("}")
            if l != -1 and r != -1 and r > l:
                json_text = text[l : r + 1]
            else:
                json_text = text
            try:
                data = json.loads(json_text)
                if DEBUG:
                    logger.debug(f"upload_image resp json keys={list(data.keys())}")
                return data
            except Exception as ex:
                body_path = save_response_body("upload_image_bad_json", res.content or b"")
                logger.error(f"Image upload JSON parse error: {ex}, saved_body={body_path}")
                raise Exception("Image upload failed (bad json)")
        else:
            raise Exception("Image upload failed")

    def publish_emotion(self, content: str, images: List[bytes] = []) -> str:
        if images is None:
            images = []

        post_data = {
            "syn_tweet_verson": "1",
            "paramstr": "1",
            "who": "1",
            "con": content,
            "feedversion": "1",
            "ver": "1",
            "ugc_right": "1",
            "to_sign": "0",
            "hostuin": self.uin,
            "code_version": "1",
            "format": "json",
            "qzreferrer": "https://user.qzone.qq.com/" + str(self.uin),
        }

        if len(images) > 0:
            pic_bos = []
            richvals = []
            for img in images:
                uploadresult = self.upload_image(img)
                picbo, richval = get_picbo_and_richval(uploadresult)
                pic_bos.append(picbo)
                richvals.append(richval)

            post_data["pic_bo"] = ",".join(pic_bos)
            post_data["richtype"] = "1"
            post_data["richval"] = "\t".join(richvals)

        res = self.do(
            method="POST",
            url=EMOTION_PUBLISH_URL,
            params={"g_tk": self.gtk2, "uin": self.uin},
            data=post_data,
            headers={
                "referer": "https://user.qzone.qq.com/" + str(self.uin),
                "origin": "https://user.qzone.qq.com",
            },
        )
        if res.status_code == 200:
            try:
                j = res.json()
            except Exception as ex:
                body_path = save_response_body("publish_emotion_bad_json", res.content or b"")
                logger.error(f"publish_emotion JSON decode error: {ex}, saved_body={body_path}")
                raise Exception("Failed to publish (bad json)")

            tid = j.get("tid")
            if tid:
                return tid
            code = j.get("code")
            msg = j.get("message") or j.get("msg")
            raise Exception(f"Publish failed code={code} msg={msg}")
        else:
            raise Exception("Failed to publish emotion: " + res.text)


def process_image(image_str: str) -> Optional[bytes]:
    """支持 http(s)://, file://, data:image;base64, 原始base64, 以及文件路径。"""
    if not image_str:
        return None
    image_str = image_str.strip()
    if image_str.startswith("http://") or image_str.startswith("https://"):
        resp = requests.get(image_str, timeout=20)
        resp.raise_for_status()
        return resp.content
    if image_str.startswith("file://"):
        file_path = image_str[7:]
        with open(file_path, "rb") as f:
            return f.read()
    if image_str.startswith("data:image"):
        m = re.match(r"data:image/[^;]+;base64,(.*)", image_str)
        if m:
            return base64.b64decode(m.group(1))
        raise ValueError("Invalid data URI format")
    # 尝试base64
    try:
        return base64.b64decode(image_str)
    except Exception:
        # 当作文件路径
        if os.path.isfile(image_str):
            with open(image_str, "rb") as f:
                return f.read()
        raise ValueError("Invalid image format: not a valid base64 string or file path")


class Submission(BaseModel):
    text: str
    image: Optional[List[str]] = []
    cookies: dict


def handle_submission(submission: Submission) -> str:
    """处理提交并返回结果字符串：success/failed/错误描述"""
    message = submission.text
    image_list = submission.image or []
    cookies = submission.cookies or {}
    if DEBUG:
        logger.debug(
            f"process_submission text_len={len(message) if message else 0}, images={len(image_list)}, cookies_keys={list(cookies.keys())}"
        )

    if not message:
        return "文本处理错误"

    if not cookies:
        return "failed"

    # 处理图片
    images: List[bytes] = []
    for image_str in image_list:
        try:
            data = process_image(image_str)
            if data:
                images.append(data)
        except Exception as e:
            logger.error(f"Image processing failed: {e}, src={image_str}")
            return "图像处理错误"

    qzone = QzoneAPI(cookies)
    if not qzone.token_valid():
        logger.warning(f"token_valid=False uin={qzone.uin} gtk2={_mask(qzone.gtk2)}")
        return "failed"

    try:
        tid = qzone.publish_emotion(message, images)
        logger.info(f"Publish OK tid={tid} uin={qzone.uin}")
        return "success"
    except Exception as e:
        logger.error(f"Failed to publish: {e}")
        return "failed"


class UDSServer:
    """Unix Domain Socket server with internal serial queue."""

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self.server_sock: Optional[socket.socket] = None
        self.task_queue: "queue.Queue[tuple[str, socket.socket]]" = queue.Queue()
        self._stop = threading.Event()
        self.worker = threading.Thread(target=self._worker_loop, name="qzone-uds-worker", daemon=True)

    def start(self):
        # 清理旧socket文件
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except Exception as e:
            logger.warning(f"移除旧socket失败: {e}")

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # 让 socket 文件权限遵从 umask，默认仅当前用户可读写
        self.server_sock.bind(self.sock_path)
        # 限制backlog
        self.server_sock.listen(16)
        logger.info(f"UDS listening at {self.sock_path}")

        self.worker.start()

        try:
            while not self._stop.is_set():
                try:
                    conn, _ = self.server_sock.accept()
                except OSError as e:
                    if self._stop.is_set():
                        break
                    logger.error(f"accept error: {e}")
                    continue

                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
        finally:
            self.stop()

    def stop(self):
        self._stop.set()
        try:
            if self.server_sock:
                try:
                    self.server_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.server_sock.close()
        finally:
            self.server_sock = None
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except Exception:
            pass
        logger.info("UDS server stopped")

    def _handle_client(self, conn: socket.socket):
        # 读取完整payload（客户端关闭连接作为结束）
        try:
            chunks = []
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
            raw = b"".join(chunks).decode("utf-8", errors="ignore").strip()
            if DEBUG:
                logger.debug(
                    f"recv bytes={sum(map(len, chunks))}, preview={raw[:512]!r}{'...(truncated)' if len(raw)>512 else ''}"
                )
            if not raw:
                try:
                    conn.sendall("空间发送解析提交数据失败".encode("utf-8"))
                finally:
                    conn.close()
                return

            # 投递到串行队列，由worker处理并回写
            self.task_queue.put((raw, conn))
        except Exception as e:
            logger.error(f"client handling error: {e}")
            logger.debug("Traceback:\n" + traceback.format_exc())
            try:
                conn.sendall("空间发送解析提交数据失败".encode("utf-8"))
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def _worker_loop(self):
        while not self._stop.is_set():
            try:
                raw, conn = self.task_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                # 解析JSON
                try:
                    payload = json.loads(raw)
                    submission = Submission(**payload)
                except Exception as e:
                    logger.error(f"解析提交数据失败: {e}")
                    logger.debug("Traceback:\n" + traceback.format_exc())
                    try:
                        conn.sendall("空间发送解析提交数据失败".encode("utf-8"))
                    finally:
                        conn.close()
                    continue

                # 串行处理
                result = handle_submission(submission)
                try:
                    conn.sendall(result.encode("utf-8"))
                finally:
                    conn.close()

            except Exception as e:
                logger.error(f"worker error: {e}")
                logger.debug("Traceback:\n" + traceback.format_exc())
                try:
                    conn.sendall("failed".encode("utf-8"))
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
            finally:
                # 显式回收，避免长时间堆积
                gc.collect()


def main():
    sock_path = os.getenv("QZONE_UDS_PATH", "./qzone_uds.sock")
    server = UDSServer(sock_path)
    try:
        logger.info("启动 qzone-serv-UDS (串行队列模式)...")
        server.start()
    except KeyboardInterrupt:
        logger.info("收到中断信号，准备退出...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
