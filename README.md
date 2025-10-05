# qzone-toolkit | QQ空间工具箱
## 简介
本仓库包含一些发送qq空间用的脚本和服务，目前仅支持发送文本和图片，暂时不支持视频
## 使用方法
### 获取cookies的工具：
自动获取cookies（要求qq在同一台机器上启动（可以是napcat或者LLOB））

```
python3 qzonerenewcookies.py qq号
或者
python3 qzonerenewcookies-napcat.py napcat的http服务器端口号
```
手动重新登陆：会下载一个qrcode.png到当前目录，你需要扫他
```
python3 send.py relogin “” qq号
```
selenium的那几个已弃用，想用的自己研究，我不提供技术支持

### 发送工具
send.py:
```
python3 send.py 文本 图片所在目录路径 qq号
```
注，你需要先执行renewcookies,否则他会下个qrcode让你扫描手动登陆

qzone-serv-api.py:
```
python3 qzone-serv-api.py
```
然后
```
curl -X POST "http://localhost:8000/publish" \
-H "Content-Type: application/json" \
-d '{
  "text": "Your message here",
  "image": ["image1", "image2"],
  "cookies": {
    "qzone_check": "",
    "skey": "",
    "uin": "",
    "p_skey": "",
    "p_uin": "",
    "pt4_token": ""
  }
}'

```
qzone-serv-UDS.py（推荐，IPC 使用 Unix Domain Socket）:
```
python3 qzone-serv-UDS.py
```
发送一条请求（socat）：
```
printf '%s' '{
  "text": "Your message here",
  "image": ["file:///path/to/img1.jpg", "https://example.com/2.png"],
  "cookies": {
    "qzone_check": "",
    "skey": "",
    "uin": "o12345678",
    "p_skey": "",
    "p_uin": "",
    "pt4_token": ""
  }
}' | socat - UNIX-CONNECT:"${QZONE_UDS_PATH:-./qzone_uds.sock}"
```
返回：
- success：成功
- failed：cookies 失效或下游失败
- 其他中文错误串：图像/解析错误等

环境变量：
- `QZONE_UDS_PATH` 指定 socket 路径（默认 `./qzone_uds.sock`）
<br/>说明：服务内部维护串行队列，按接入顺序依次处理，避免并发干扰。

cookies不全是必要的（建议包含 `uin`/`skey`/`p_skey`）。
image 支持：http://、https://、file://、data:image;base64,...、原始base64、以及本地文件路径。

Qzone_toolkit文件夹：
这是一个nonebot插件，拷贝到您的plugin目录后调用send函数即可
```
require("Qzone_toolkit")
import onbwall.plugins.Qzone_toolkit as Qzone_toolkit
testsender = on_command("sendtest", rule=to_me(), priority=5)
@testsender.handle()
async def handle():
    await testsender.send("正在测试发送")
    await Qzone_toolkit.send("这是一条nonebot插件测试说说", "/home/admin/Onbwall/Onbwall/submissions/1", "2947159526")
```
