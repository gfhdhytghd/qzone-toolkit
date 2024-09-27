# qzone-toolkit | QQ空间工具箱
## 简介
本仓库包含一些发送qq空间用的脚本和服务，目前仅支持发送文本和图片，暂时不支持视频
## 使用方法
### 获取cookies的工具：
自动获取cookies（要求qq在同一台机器上启动（可以是napcat或者LLOB））
```
python3 qzonerenewcookies.py qq号
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
qzone-serv-pipe.py:
```
python3 qzone-serv-pipe.py
```
然后
```
echo '{
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
}' > ./qzone_in_fifo

```
注意，这个执行完之后必须再执行
```
cat qzone_out_fifo
```
输出：success：成功 failed：cookies造成的失败 其他：其他失败原因
这项设计是为了信息发送队列的正确处理

cookies不全是必要的，但我也不知道哪些是必要的，反正你获取到多少填多少
image可以是http://,https://,file://,base64://.(只测试过file://，其他的理论上能用)


