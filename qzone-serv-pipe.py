import os
import json
import traceback
from typing import List, Optional
import base64
import requests
import re

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

        return requests.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            timeout=timeout
        )

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
                if res.status_code == 200:
                    return True
            except Exception as e:
                traceback.print_exc()
                if i == retry - 1:
                    return False
    def image_to_base64(self, image: bytes) -> str:
        pic_base64 = base64.b64encode(image)
        return pic_base64.decode('utf-8')

    def upload_image(self, image: bytes) -> dict:
        """Upload image"""

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
            return eval(res.text[res.text.find('{'):res.text.rfind('}') + 1])
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
            return res.json()['tid']
        else:
            raise Exception("Failed to publish emotion: " + res.text)

import requests
import re
import base64
import os

def process_image(image_str: str) -> bytes:
    try:
        if image_str.startswith('http://') or image_str.startswith('https://'):
            # It's a URL, download it
            response = requests.get(image_str)
            response.raise_for_status()
            return response.content
        elif image_str.startswith('file://'):
            # It's a file path
            file_path = image_str[7:]  # Remove 'file://'
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    return f.read()
            else:
                print(f"File not found: {file_path}")
        elif image_str.startswith('data:image'):
            # It's base64 data with data URI scheme
            # Format: data:image/png;base64,xxx
            match = re.match(r'data:image/[^;]+;base64,(.*)', image_str)
            if match:
                base64_data = match.group(1)
                return base64.b64decode(base64_data)
            else:
                print("Invalid data URI format")
        else:
            # Try to treat it as base64 string
            try:
                return base64.b64decode(image_str)
            except Exception:
                # Try to treat it as a file path
                if os.path.isfile(image_str):
                    with open(image_str, 'rb') as f:
                        return f.read()
                else:
                    print(f"Invalid image format or file not found: {image_str}")
    except Exception as e:
        with open(f"{pipe_out}", 'w') as pipe:
                    pipe.write('空间发送图片处理失败')
                    pipe.flush()
        continue
    return None



# Define the data models using Pydantic
from pydantic import BaseModel

class Submission(BaseModel):
    text: str
    image: Optional[List[str]] = []
    cookies: dict


def process_submission(submission: Submission):
    message = submission.text
    image_list = submission.image
    cookies = submission.cookies

    if not message:
        print("No message text provided.")
        return

    if not cookies:
        print("No cookies provided.")
        return

    # Process images
    images = []
    for image_str in image_list:
        try:
            image_data = process_image(image_str)
            images.append(image_data)
        except Exception as e:
            error_msg = f"Failed to process image {image_str}: {e}"
            traceback.print_exc()
            return

    # Create QzoneAPI object
    qzone = QzoneAPI(cookies)

    # Validate token
    if not qzone.token_valid():
        print("Cookies expired or invalid.")
        return

    # Publish emotion
    try:
        tid = qzone.publish_emotion(message, images)
        print(f"Successfully published. TID: {tid}")
        # 向管道文件写入数据
        pipe_out = './qzone_out_fifo'
        with open(f"{pipe_out}", 'w') as pipe:
            pipe.write('success')
            pipe.flush()  
            
    except Exception as e:
        error_msg = f"Failed to publish: {e}"
        traceback.print_exc()
        pipe_out = './qzone_out_fifo'
        with open(f"{pipe_out}", 'w') as pipe:
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
        with open(FIFO_PATH, 'r') as fifo:
            data = ''
            while True:
                line = fifo.readline()
                if not line:
                    break  # EOF
                data += line
            print(data)
            if not data:
                continue
            try:
                submission_data = json.loads(data)
                submission = Submission(**submission_data)
            except Exception as e:
                print(f"解析提交数据失败: {e}")
                traceback.print_exc()
                pipe_out = './qzone_out_fifo'
                with open(f"{pipe_out}", 'w') as pipe:
                    pipe.write('空间发送解析提交数据失败')
                    pipe.flush()
                continue

            # 处理提交的数据
            process_submission(submission)
        print("数据处理完毕，等待下一次输入...")


if __name__ == "__main__":
    main()