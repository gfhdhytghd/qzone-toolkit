import os
import json
import socket
import traceback
from importlib.machinery import SourceFileLoader


def load_api_module():
    here = os.path.dirname(__file__)
    api_path = os.path.join(here, 'qzone-serv-api.py')
    # 回退到 pipe 版本（仅提取 API）
    if not os.path.exists(api_path):
        api_path = os.path.join(here, 'qzone-serv-pipe.py')
    return SourceFileLoader('qzone_api_dyn', api_path).load_module()


def handle_one(req_obj: dict, api):
    # 解析字段
    text = req_obj.get('text') or ''
    images = req_obj.get('image') or []
    cookies = req_obj.get('cookies') or {}

    if not text:
        return '文本处理错误'
    if not cookies:
        return 'failed'

    # 处理图片
    img_bytes = []
    try:
        for item in images:
            b = api.process_image(item)
            img_bytes.append(b)
    except Exception:
        traceback.print_exc()
        return '图像处理错误'

    # 发送
    try:
        qzone = api.QzoneAPI(cookies)
        if not qzone.token_valid():
            return 'failed'
        qzone.publish_emotion(text, img_bytes)
        return 'success'
    except Exception:
        traceback.print_exc()
        return 'failed'


def serve(sock_path: str):
    os.makedirs(os.path.dirname(sock_path) or '.', exist_ok=True)
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    api = load_api_module()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(sock_path)
        os.chmod(sock_path, 0o660)
        srv.listen(16)
        print(f"[uds] listening at {sock_path}")
        while True:
            conn, _ = srv.accept()
            with conn:
                try:
                    f = conn.makefile('rwb')
                    line = f.readline()
                    if not line:
                        continue
                    data = line.decode('utf-8', errors='ignore')
                    try:
                        obj = json.loads(data)
                    except Exception as e:
                        f.write('空间发送解析提交数据失败\n'.encode())
                        f.flush()
                        continue
                    resp = handle_one(obj, api)
                    f.write((resp + '\n').encode())
                    f.flush()
                except Exception:
                    traceback.print_exc()
                    try:
                        conn.close()
                    except Exception:
                        pass


def main():
    sock_path = os.getenv('QZONE_SOCK_PATH', './cache/qzone.sock')
    serve(sock_path)


if __name__ == '__main__':
    main()

