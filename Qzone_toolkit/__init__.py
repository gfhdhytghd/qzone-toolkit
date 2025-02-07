import os
import re
import sys
import json
import time
import httpx
import base64
import typing
import asyncio
import requests
import traceback
from pathlib import Path
from .config import Config
from jinja2 import Template
from nonebot.rule import to_me
from nonebot import get_plugin_config
from nonebot.plugin import PluginMetadata
from nonebot import get_plugin_config, on_command, require

__plugin_meta__ = PluginMetadata(
    name="Qzone_toolkit",
    description="Qzone-toolkit的nonebot版本QQ空间发送插件",
    usage="提供QQ空间发送服务",
    config=Config,
)

config = get_plugin_config(Config)

# 获取当前脚本路径及所在目录
script_path = Path(__file__).resolve()
script_dir = script_path.parent

#########################################################
# 通过 clientkey 登录相关代码（异步方式获取 cookies）
#########################################################

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

async def get_clientkey(uin: str) -> str:
    local_key_url = (
        "https://xui.ptlogin2.qq.com/cgi-bin/xlogin?s_url=https%3A%2F%2Fhuifu.qq.com%2Findex.html"
        "&style=20&appid=715021417&proxy_url=https%3A%2F%2Fhuifu.qq.com%2Fproxy.html"
    )
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(local_key_url, headers={"User-Agent": UA})
        pt_local_token = resp.cookies["pt_local_token"]
        client_key_url = (
            f"https://localhost.ptlogin2.qq.com:4301/pt_get_st?"
            f"clientuin={uin}&callback=ptui_getst_CB&r=0.7284667321181328&pt_local_tk={pt_local_token}"
        )
        resp = await client.get(
            client_key_url,
            headers={"User-Agent": UA, "Referer": "https://ssl.xui.ptlogin2.qq.com/"},
            cookies=resp.cookies
        )
        if resp.status_code == 400:
            raise Exception(f"获取clientkey失败: {resp.text}")
        clientKey = resp.cookies["clientkey"]
        return clientKey

async def get_cookies_via_clientkey(uin: str, clientkey: str) -> dict:
    login_url = (
        f"https://ssl.ptlogin2.qq.com/jump?ptlang=1033&clientuin={uin}&clientkey={clientkey}"
        f"&u1=https%3A%2F%2Fuser.qzone.qq.com%2F{uin}%2Finfocenter&keyindex=19"
    )
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(login_url, headers={"User-Agent": UA}, follow_redirects=False)
        if "Location" not in resp.headers:
            raise Exception("未获得重定向地址")
        resp = await client.get(
            resp.headers["Location"],
            headers={"User-Agent": UA, "Referer": "https://ssl.xui.ptlogin2.qq.com/"},
            cookies=resp.cookies,
            follow_redirects=False
        )
        cookies = {cookie.name: cookie.value for cookie in resp.cookies.jar}
        return cookies

async def save_cookies_to_file(cookies: dict, file_path: str):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(cookies, f, indent=4)
    print(f"Cookies saved to {file_path}")

#########################################################
# 二维码登录及 QzoneAPI 相关代码
#########################################################

# URL 定义（二维码登录相关及其他 API）
qrcode_url = "https://ssl.ptlogin2.qq.com/ptqrshow?appid=549000912&e=2&l=M&s=3&d=72&v=4&t=0.31232733520361844&daid=5&pt_3rd_aid=0"
login_check_url = (
    "https://xui.ptlogin2.qq.com/ssl/ptqrlogin?"
    "u1=https://qzs.qq.com/qzone/v5/loginsucc.html?para=izone&ptqrtoken={}"
    "&ptredirect=0&h=1&t=1&g=1&from_ui=1&ptlang=2052&action=0-0-1656992258324"
    "&js_ver=22070111&js_type=1&login_sig=&pt_uistyle=40&aid=549000912&daid=5&has_onekey=1&&o1vId=1e61428d61cb5015701ad73d5fb59f73"
)
check_sig_url = (
    "https://ptlogin2.qzone.qq.com/check_sig?pttype=1&uin={}&service=ptqrlogin&nodirect=1"
    "&ptsigx={}&s_url=https://qzs.qq.com/qzone/v5/loginsucc.html?para=izone&f_url=&ptlang=2052"
    "&ptredirect=100&aid=549000912&daid=5&j_later=0&low_login_hour=0&regmaster=0"
    "&pt_login_type=3&pt_aid=0&pt_aaid=16&pt_light=0&pt_3rd_aid=0"
)

GET_VISITOR_AMOUNT_URL = "https://h5.qzone.qq.com/proxy/domain/g.qzone.qq.com/cgi-bin/friendshow/cgi_get_visitor_more?uin={}&mask=7&g_tk={}&page=1&fupdate=1&clear=1"
UPLOAD_IMAGE_URL = "https://up.qzone.qq.com/cgi-bin/upload/cgi_upload_image"
EMOTION_PUBLISH_URL = "https://user.qzone.qq.com/proxy/domain/taotao.qzone.qq.com/cgi-bin/emotion_cgi_publish_v6"

def generate_gtk(skey: str) -> str:
    """生成 gtk 值"""
    hash_val = 5381
    for i in range(len(skey)):
        hash_val += (hash_val << 5) + ord(skey[i])
    return str(hash_val & 2147483647)

def get_picbo_and_richval(upload_result):
    json_data = upload_result
    if 'ret' not in json_data:
        raise Exception("获取图片picbo和richval失败")
    if json_data['ret'] != 0:
        raise Exception("上传图片失败")
    picbo_spt = json_data['data']['url'].split('&bo=')
    if len(picbo_spt) < 2:
        raise Exception("上传图片失败")
    picbo = picbo_spt[1]
    richval = ",{},{},{},{},{},{},,{},{}".format(
        json_data['data']['albumid'],
        json_data['data']['lloc'],
        json_data['data']['sloc'],
        json_data['data']['type'],
        json_data['data']['height'],
        json_data['data']['width'],
        json_data['data']['height'],
        json_data['data']['width']
    )
    return picbo, richval

class QzoneLogin:
    def __init__(self):
        pass

    def getptqrtoken(self, qrsig):
        e = 0
        for i in range(1, len(qrsig) + 1):
            e += (e << 5) + ord(qrsig[i - 1])
        return str(2147483647 & e)

    async def login_via_qrcode(self, qrcode_callback: typing.Callable[[bytes], typing.Awaitable[None]], max_timeout_times: int = 3) -> dict:
        for i in range(max_timeout_times):
            # 请求二维码图片
            req = requests.get(qrcode_url)
            qrsig = ''
            set_cookie = req.headers.get('Set-Cookie', '')
            for part in set_cookie.split(";"):
                if part.strip().startswith("qrsig="):
                    qrsig = part.split("=")[1]
                    break
            if not qrsig:
                raise Exception("qrsig is empty")
            ptqrtoken = self.getptqrtoken(qrsig)
            await qrcode_callback(req.content)
            # 循环检测登录状态
            while True:
                await asyncio.sleep(2)
                check_resp = requests.get(login_check_url.format(ptqrtoken), cookies={"qrsig": qrsig})
                if "二维码已失效" in check_resp.text:
                    break
                if "登录成功" in check_resp.text:
                    response_header_dict = check_resp.headers
                    try:
                        # 解析响应，提取登录后的跳转 URL
                        url = eval(check_resp.text.replace("ptuiCB", ""))[2]
                    except Exception as ex:
                        raise Exception("解析登录响应失败") from ex
                    ptsigx_match = re.search(r"ptsigx=([A-Za-z0-9]+)&", url)
                    if not ptsigx_match:
                        raise Exception("无法获取 ptsigx")
                    ptsigx = ptsigx_match.group(1)
                    uin_match = re.search(r"uin=([\d]+)&", url)
                    if not uin_match:
                        raise Exception("无法获取 uin")
                    uin = uin_match.group(1)
                    res = requests.get(
                        check_sig_url.format(uin, ptsigx),
                        cookies={"qrsig": qrsig},
                        headers={'Cookie': response_header_dict.get('Set-Cookie', '')}
                    )
                    final_cookie = res.headers.get('Set-Cookie', '')
                    final_cookie_dict = {}
                    for item in final_cookie.split(";, "):
                        for cookie in item.split(";"):
                            parts = cookie.strip().split("=")
                            if len(parts) == 2 and parts[0] not in final_cookie_dict:
                                final_cookie_dict[parts[0]] = parts[1]
                    return final_cookie_dict
        raise Exception(f"{max_timeout_times}次尝试失败")

class QzoneAPI:
    def __init__(self, cookies_dict: dict = {}):
        self.cookies = cookies_dict
        self.gtk2 = ''
        self.uin = 0
        if 'p_skey' in self.cookies:
            self.gtk2 = generate_gtk(self.cookies['p_skey'])
        if 'uin' in self.cookies:
            try:
                # 若 uin 前有非数字字符（如 o123456789），去掉首字符再转换
                self.uin = int(self.cookies['uin'].lstrip('o'))
            except:
                self.uin = int(self.cookies['uin'])

    async def do(self, method: str, url: str, params: dict = {}, data: dict = {}, headers: dict = {}, cookies: dict = None, timeout: int = 10) -> requests.Response:
        if cookies is None:
            cookies = self.cookies
        return requests.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            timeout=timeout
        )

    async def token_valid(self, retry=3) -> bool:
        for i in range(retry):
            try:
                # 这里仅做占位验证，你可以添加实际的 token 检查逻辑
                return True
            except Exception as e:
                traceback.print_exc()
                if i == retry - 1:
                    return False

    def image_to_base64(self, image: bytes) -> str:
        pic_base64 = base64.b64encode(image)
        return pic_base64.decode('utf-8')

    async def upload_image(self, image: bytes):
        res = await self.do(
            method="POST",
            url=UPLOAD_IMAGE_URL,
            data={
                "filename": "filename",
                "zzpanelkey": "",
                "uploadtype": "1",
                "albumtype": "7",
                "exttype": "0",
                "skey": self.cookies.get("skey", ""),
                "zzpaneluin": self.uin,
                "p_uin": self.uin,
                "uin": self.uin,
                "p_skey": self.cookies.get('p_skey', ""),
                "output_type": "json",
                "qzonetoken": "",
                "refer": "shuoshuo",
                "charset": "utf-8",
                "output_charset": "utf-8",
                "upload_hd": "1",
                "hd_width": "2048",
                "hd_height": "10000",
                "hd_quality": "96",
                "backUrls": "http://upbak.photo.qzone.qq.com/cgi-bin/upload/cgi_upload_image,"
                            "http://119.147.64.75/cgi-bin/upload/cgi_upload_image",
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
            try:
                json_str = res.text[res.text.find('{'):res.text.rfind('}') + 1]
                return eval(json_str)
            except Exception as ex:
                raise Exception("解析上传图片响应失败") from ex
        else:
            raise Exception("上传图片失败")

    async def publish_emotion(self, content: str, images: list[bytes] = []) -> str:
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
        if images:
            pic_bos = []
            richvals = []
            for img in images:
                uploadresult = await self.upload_image(img)
                picbo, richval = get_picbo_and_richval(uploadresult)
                pic_bos.append(picbo)
                richvals.append(richval)
            post_data['pic_bo'] = ','.join(pic_bos)
            post_data['richtype'] = '1'
            post_data['richval'] = '\t'.join(richvals)
        res = await self.do(
            method="POST",
            url=EMOTION_PUBLISH_URL,
            params={'g_tk': self.gtk2, 'uin': self.uin},
            data=post_data,
            headers={
                'referer': 'https://user.qzone.qq.com/' + str(self.uin),
                'origin': 'https://user.qzone.qq.com'
            }
        )
        if res.status_code == 200:
            try:
                return res.json()['tid']
            except Exception as ex:
                raise Exception("解析发表说说响应失败") from ex
        else:
            raise Exception("发表说说失败: " + res.text)

#########################################################
# 自动登录封装：优先尝试 clientkey 登录，若失败则切换到二维码登录
#########################################################

async def auto_login(uin: str, login_method: str = "clientkey") -> dict:
    """
    自动登录函数：
      - 当 login_method=="clientkey" 时，先尝试通过 clientkey 登录；
      - 若失败，则切换到二维码登录。
    """
    if login_method == "clientkey":
        try:
            clientkey = await get_clientkey(uin)
            cookies = await get_cookies_via_clientkey(uin, clientkey)
            return cookies
        except Exception as e:
            print("Clientkey 登录失败，切换到二维码登录。")
            traceback.print_exc()
    # 使用二维码登录
    login = QzoneLogin()
    async def qrcode_callback(qrcode: bytes):
        qrcode_path = os.path.join(script_dir, "qrcode.png")
        with open(qrcode_path, "wb") as f:
            f.write(qrcode)
        print("请扫描二维码，二维码已保存到:", qrcode_path)
    cookies = await login.login_via_qrcode(qrcode_callback)
    return cookies

#########################################################
# 重写后的 send 函数：作为库调用时只需传入参数即可
#########################################################

async def send(message: str, image_directory: str = None, qq: str = None) -> None:
    """
    发送说说的主逻辑。

    :param message: 说说内容文本
    :param image_directory: 图片所在目录路径（可选，不提供则使用默认目录）
    :param qq: QQ号码（用于构造 cookies 文件名等），必须提供
    """
    if qq is None:
        raise ValueError("必须提供 QQ 号码！")
    if image_directory is None:
        image_directory = os.path.join(script_dir, "getmsgserv", "post-step5")
    
    cookies_file = os.path.join(script_dir, f"cookies-{qq}.json")
    cookies = None
    if os.path.exists(cookies_file):
        try:
            with open(cookies_file, 'r', encoding="utf-8") as f:
                cookies = json.load(f)
        except Exception as e:
            print("读取 cookies 失败，将尝试重新登录。")
            cookies = None

    # 若 cookies 不存在，则自动登录（最多重试 3 次）
    if not cookies:
        attempt = 0
        while attempt < 3:
            try:
                cookies = await auto_login(qq, login_method="clientkey")
                print("登录成功，Cookies：", cookies)
                await save_cookies_to_file(cookies, cookies_file)
                # 删除二维码图片（如果存在）
                qrcode_path = os.path.join(script_dir, "qrcode.png")
                if os.path.exists(qrcode_path):
                    os.remove(qrcode_path)
                break
            except Exception as e:
                print(f"登录尝试 {attempt+1} 失败，正在重试...")
                traceback.print_exc()
                attempt += 1
                if attempt == 3:
                    print("连续 3 次登录失败，退出。")
                    return

    print("最终 Cookies：", cookies)
    qzone = QzoneAPI(cookies)
    if not await qzone.token_valid():
        print("Cookies 已过期或无效")
        return

    # 收集图片文件
    image_files = sorted(
        [os.path.join(image_directory, f) for f in os.listdir(image_directory)
         if os.path.isfile(os.path.join(image_directory, f))]
    )
    images = []
    for image_file in image_files:
        with open(image_file, "rb") as img:
            images.append(img.read())

    # 发表说说，若失败则尝试重新登录后重试（最多 3 次）
    attempt = 0
    while attempt < 3:
        try:
            tid = await qzone.publish_emotion(message, images)
            print(f"发表成功，tid: {tid}")
            break
        except Exception as e:
            print(f"发表尝试 {attempt+1} 失败，进行重新登录后重试...")
            traceback.print_exc()
            try:
                cookies = await auto_login(qq, login_method="clientkey")
                print("重新登录成功，新 cookies：", cookies)
                await save_cookies_to_file(cookies, cookies_file)
                qzone = QzoneAPI(cookies)
            except Exception as login_err:
                print("自动登录（重新登录）失败。")
                traceback.print_exc()
            attempt += 1
            if attempt == 3:
                print("连续 3 次发表失败，退出。")
                return

#########################################################
# __main__ 部分：当脚本作为独立程序运行时，从命令行参数中读取参数
#########################################################

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 <script> <message> <image_directory> <QQ号码>")
        sys.exit(1)
    message = sys.argv[1]
    image_directory = sys.argv[2]
    qq = sys.argv[3]
    asyncio.run(send(message, image_directory, qq))


testsend = on_command("sendqzonetest", rule=to_me(), priority=5)
@testsend.handle()
async def handle():
    await testsend.send("正在测试发送")
    await send("这是一条测试说说", "/home/admin/Onbwall/Onbwall/submissions/1", "2947159526")