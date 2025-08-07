import os
import json
import traceback
from typing import List, Optional, Tuple
import base64
import requests
import re
from pydantic import BaseModel
import gc
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# =========================
# Debug / Logging Settings
# =========================
# 优先读取环境变量，其次使用代码内缺省值
DEBUG = os.getenv("QZONE_DEBUG", "0").lower() in ("1", "true", "yes", "y")
LOG_DIR = os.getenv("QZONE_LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("qzone")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
_fmt = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
_fh = RotatingFileHandler(os.path.join(LOG_DIR, "qzone.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8")
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
    """将响应体保存为文件，返回文件路径（仅 DEBUG 时启用）"""
    fname = f"{prefix}_{int(time.time()*1000)}.resp"
    fpath = os.path.join(LOG_DIR, fname)
    try:
        with open(fpath, "wb") as f:
            f.write(content)
    except Exception as e:
        logger.warning(f"保存响应体失败: {e}")
    return fpath

# URL definitions
qrcode_url = "https://ssl.ptlogin2.qq.com/ptqrshow?appid=549000912&e=2&l=M&s=3&d=72&v=4&t=0.31232733520361844&daid=5&pt_3rd_aid=0"
login_check_url = "https://xui.ptlogin2.qq.com/ssl/ptqrlogin?u1=https://qzs.qq.com/qzone/v5/loginsucc.html?para=izone&ptqrtoken={}&ptredirect=0&h=1&t=1&g=1&from_ui=1&ptlang=2052&action=0-0-1656992258324&js_ver=22070111&js_type=1&login_sig=&pt_uistyle=40&aid=549000912&daid=5&has_onekey=1&&o1vId=1e61428d61cb5015701ad73d5fb59f73"
check_sig_url = "https://ptlogin2.qzone.qq.com/check_sig?pttype=1&uin={}&service=ptqrlogin&nodirect=1&ptsigx={}&s_url=https://qzs.qq.com/qzone/v5/loginsucc.html?para=izone&f_url=&ptlang=2052&ptredirect=100&aid=549000912&daid=5&j_later=0&low_login_hour=0&regmaster=0&pt_login_type=3&pt_aid=0&pt_aaid=16&pt_light=0&pt_3rd_aid=0"

GET_VISITOR_AMOUNT_URL = "https://h5.qzone.qq.com/proxy/domain/g.qzone.qq.com/cgi-bin/friendshow/cgi_get_visitor_more?uin={}&mask=7&g_tk={}&page=1&fupdate=1&clear=1"
UPLOAD_IMAGE_URL = "https://up.qzone.qq.com/cgi-bin/upload/cgi_upload_image"
EMOTION_PUBLISH_URL = "https://user.qzone.qq.com/proxy/domain/taotao.qzone.qq.com/cgi-bin/emotion_cgi_publish_v6"

def generate_gtk(skey: str) -> str:
    """Generate gtk"""
    hash_val = 5381
    for i in range(len(skey)):
        hash_val += (hash_val << 5) + ord(skey[i])
    return str(hash_val & 2147483647)

def get_picbo_and_richval(upload_result):
    json_data = upload_result

    if 'ret' not in json_data:
        raise Exception("Failed to get picbo and richval")

    if json_data['ret'] != 0:
        raise Exception("Image upload failed")
    picbo_spt = json_data['data']['url'].split('&bo=')
    if len(picbo_spt) < 2:
        raise Exception("Image upload failed")
    picbo = picbo_spt[1]

    richval = ",{},{},{},{},{},{},,{},{}".format(
        json_data['data']['albumid'], json_data['data']['lloc'],
        json_data['data']['sloc'], json_data['data']['type'],
        json_data['data']['height'], json_data['data']['width'],
        json_data['data']['height'], json_data['data']['width']
    )

    return picbo, richval

class QzoneAPI:

    def __init__(self, cookies_dict: dict = {}):
        self.cookies = cookies_dict
        self.gtk2 = ''
        self.uin = 0
        self.session = requests.Session()  # 使用 Session
        logger.debug(f"Init QzoneAPI with cookies keys={list(self.cookies.keys())}")

        if 'p_skey' in self.cookies:
            self.gtk2 = generate_gtk(self.cookies['p_skey'])

        if 'uin' in self.cookies:
            self.uin = int(self.cookies['uin'][1:])

    def do(
        self,
        method: str,
        url: str,
        params: dict = {},
        data: dict = {},
        headers: dict = {},
        cookies: dict = None,
        timeout: int = 10
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
                timeout=timeout
            )
            dt = (time.time() - t0) * 1000
            body_path = None
            body_preview = ""
            if DEBUG:
                # 保存响应体文件，日志仅预览前2KB
                content = res.content or b""
                body_path = save_response_body("http_body", content)
                body_preview = content[:2048].decode(errors="ignore")
            logger.info(f"HTTP {method} {url} -> {res.status_code} in {dt:.1f}ms")
            if DEBUG:
                logger.debug(f"Resp headers: {{'Content-Type': {res.headers.get('Content-Type')}, 'Content-Length': {res.headers.get('Content-Length')}}}")
                logger.debug(f"Resp preview (first 2KB): {body_preview!r}, saved={body_path}")
            return res
        except Exception as e:
            logger.error(f"HTTP {method} {url} failed: {e}")
            logger.debug("Traceback:\n" + traceback.format_exc())
            raise

    def __del__(self):
        self.session.close()  # 确保 Session 被关闭

    def token_valid(self, retry=3) -> bool:
        for i in range(retry):
            try:
                res = self.do(
                    method="GET",
                    url=GET_VISITOR_AMOUNT_URL.format(self.uin, self.gtk2),
                    headers={
                        'referer': 'https://user.qzone.qq.com/' + str(self.uin),
                        'origin': 'https://user.qzone.qq.com'
                    }
                )
                logger.debug(f"token_valid attempt={i+1} status={res.status_code}")
                if res.status_code == 200:
                    return True
            except Exception as e:
                traceback.print_exc()
                if i == retry - 1:
                    logger.warning("token_valid exhausted retries, treat as invalid.")
                    return False

    def image_to_base64(self, image: bytes) -> str:
        pic_base64 = base64.b64encode(image)
        return pic_base64.decode('utf-8')

    def upload_image(self, image: bytes) -> dict:
        """Upload image"""
        if DEBUG:
            logger.debug(f"upload_image size={len(image) if image else 0} bytes, uin={self.uin}, gtk2={_mask(self.gtk2)}")

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
                "p_skey": self.cookies['p_skey'],
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
                'referer': 'https://user.qzone.qq.com/' + str(self.uin),
                'origin': 'https://user.qzone.qq.com'
            },
            timeout=60
        )
        if res.status_code == 200:
            # QZone常见返回是jsonp/文本包裹json，做安全裁剪
            text = res.text
            l = text.find('{')
            r = text.rfind('}')
            if l != -1 and r != -1 and r > l:
                json_text = text[l:r + 1]
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
        """Publish emotion
        :return: tid
        :except: Publish failed
        """

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
            "qzreferrer": "https://user.qzone.qq.com/" + str(self.uin)
        }

        if len(images) > 0:

            # Upload images one by one
            pic_bos = []
            richvals = []
            for img in images:
                uploadresult = self.upload_image(img)
                picbo, richval = get_picbo_and_richval(uploadresult)
                pic_bos.append(picbo)
                richvals.append(richval)

            post_data['pic_bo'] = ','.join(pic_bos)
            post_data['richtype'] = '1'
            post_data['richval'] = '\t'.join(richvals)
        if DEBUG:
            logger.debug(f"publish_emotion content_len={len(content)} images={len(images)} uin={self.uin} gtk2={_mask(self.gtk2)} "
                         f"has_pic_bo={'pic_bo' in post_data} has_richval={'richval' in post_data}")

        res = self.do(
            method="POST",
            url=EMOTION_PUBLISH_URL,
            params={
                'g_tk': self.gtk2,
                'uin': self.uin,
            },
            data=post_data,
            headers={
                'referer': 'https://user.qzone.qq.com/' + str(self.uin),
                'origin': 'https://user.qzone.qq.com'
            }
        )
        if res.status_code == 200:
            try:
                j = res.json()
            except Exception as ex:
                body_path = save_response_body("publish_emotion_bad_json", res.content or b"")
                logger.error(f"publish_emotion JSON decode error: {ex}, saved_body={body_path}")
                raise Exception("Failed to publish (bad json)")

            if DEBUG:
                logger.debug(f"publish_emotion resp keys={list(j.keys())}, code={j.get('code')}, message={j.get('message') or j.get('msg')}")

            tid = j.get('tid')
            if tid:
                return tid
            # 当tid缺失时，保留更多上下文
            raise Exception(f"Failed to publish: no 'tid' in response, code={j.get('code')}, message={j.get('message') or j.get('msg')}, raw={j}")
        else:
            raise Exception("Failed to publish emotion: " + res.text)

def process_image(image_str: str, pipe_out: str) -> bytes:
    try:
        if image_str.startswith('http://') or image_str.startswith('https://'):
            # It's a URL, download it
            response = requests.get(image_str)
            response.raise_for_status()
            content = response.content
            if DEBUG:
                logger.debug(f"process_image url ok size={len(content)} url={image_str[:128]}")
            return content
        elif image_str.startswith('file://'):
            # It's a file path
            file_path = image_str[7:]  # Remove 'file://'
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    b = f.read()
                if DEBUG:
                    logger.debug(f"process_image file ok size={len(b)} path={file_path}")
                return b
            else:
                print(f"File not found: {file_path}")
                logger.warning(f"process_image file not found: {file_path}")
        elif image_str.startswith('data:image'):
            # It's base64 data with data URI scheme
            # Format: data:image/png;base64,xxx
            match = re.match(r'data:image/[^;]+;base64,(.*)', image_str)
            if match:
                base64_data = match.group(1)
                b = base64.b64decode(base64_data)
                if DEBUG:
                    logger.debug(f"process_image data-uri ok size={len(b)}")
                return b
            else:
                print("Invalid data URI format")
        else:
            # Try to treat it as base64 string
            try:
                b = base64.b64decode(image_str)
                if DEBUG:
                    logger.debug(f"process_image base64 ok size={len(b)}")
                return b
            except Exception:
                # Try to treat it as a file path
                if os.path.isfile(image_str):
                    with open(image_str, 'rb') as f:
                        b = f.read()
                    if DEBUG:
                        logger.debug(f"process_image bare-file ok size={len(b)} path={image_str}")
                    return b
                else:
                    print(f"Invalid image format or file not found: {image_str}")
                    logger.warning(f"process_image invalid input: {image_str}")
    except Exception as e:
        with open(pipe_out, 'w') as pipe:
            pipe.write('空间发送图片处理失败')
            pipe.flush()
        logger.error(f"process_image error: {e}")
        logger.debug("Traceback:\n" + traceback.format_exc())
    return None

class Submission(BaseModel):
    text: str
    image: Optional[List[str]] = []
    cookies: dict

def process_submission(submission: Submission, pipe_out: str):
    message = submission.text
    image_list = submission.image
    cookies = submission.cookies
    if DEBUG:
        logger.debug(f"process_submission text_len={len(message) if message else 0}, images={len(image_list) if image_list else 0}, "
                     f"cookies_keys={list(cookies.keys())}")

    if not message:
        print("No message text provided.")
        with open(pipe_out, 'w') as pipe:
            pipe.write('文本处理错误')
            pipe.flush()  
        return

    if not cookies:
        print("No cookies provided.")
        with open(pipe_out, 'w') as pipe:
            pipe.write('failed')
            pipe.flush()  
        return

    # Process images
    images = []
    for image_str in image_list:
        try:
            image_data = process_image(image_str, pipe_out)
            if image_data:
                images.append(image_data)
            else:
                raise Exception(f"Image data is None for {image_str}")
        except Exception as e:
            with open(pipe_out, 'w') as pipe:
                pipe.write('图像处理错误')
                pipe.flush()  
            traceback.print_exc()
            logger.error(f"Image processing failed: {e}, src={image_str}")
            return

    # Create QzoneAPI object
    qzone = QzoneAPI(cookies)

    # Validate token
    if not qzone.token_valid():
        print("Cookies expired or invalid.")
        logger.warning(f"token_valid=False uin={qzone.uin} gtk2={_mask(qzone.gtk2)}")
        with open(pipe_out, 'w') as pipe:
            pipe.write('failed')
            pipe.flush()  
        return

    # Publish emotion
    try:
        tid = qzone.publish_emotion(message, images)
        print(f"Successfully published. TID: {tid}")
        logger.info(f"Publish OK tid={tid} uin={qzone.uin}")
        # 向管道文件写入数据
        with open(pipe_out, 'w') as pipe:
            pipe.write('success')
            pipe.flush()  
    except Exception as e:
        error_msg = f"Failed to publish: {e}"
        traceback.print_exc()
        logger.error(error_msg)
        with open(pipe_out, 'w') as pipe:
            pipe.write('failed')
            pipe.flush()  

def main():
    FIFO_PATH = './qzone_in_fifo'  
    pipe_out = './qzone_out_fifo'
    if not os.path.exists(FIFO_PATH):
        os.mkfifo(FIFO_PATH)
    if not os.path.exists(pipe_out):
        os.mkfifo(pipe_out)
    while True:
        print("等待从管道读取数据...")
        logger.info("等待从管道读取数据...")
        with open(FIFO_PATH, 'r') as fifo:
            print("读取到了数据")
            logger.info("读取到了数据")
            data = ''
            while True:
                line = fifo.readline()
                if not line:
                    break  # EOF
                data += line
        if DEBUG:
            logger.debug(f"raw_pipe_data: {data[:2048]!r}{'...(truncated)' if len(data)>2048 else ''}")
        print(data)
        if not data:
            continue
        try:
            submission_data = json.loads(data)
            submission = Submission(**submission_data)
        except Exception as e:
            print(f"解析提交数据失败: {e}")
            traceback.print_exc()
            logger.error(f"解析提交数据失败: {e}")
            logger.debug("Traceback:\n" + traceback.format_exc())
            with open(pipe_out, 'w') as pipe:
                pipe.write('空间发送解析提交数据失败')
                pipe.flush()
            continue

        # 处理提交的数据
        process_submission(submission, pipe_out)
        print("数据处理完毕，等待下一次输入...")
        logger.info("数据处理完毕，等待下一次输入...")
        # 显式调用垃圾回收
        gc.collect()

if __name__ == "__main__":
    main()
