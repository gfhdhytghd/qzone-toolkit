# qzone-toolkit
QQ空间工具箱
<br/>使用方法
<br/>获取cookies的工具：
```
python3 qzonerenewcookies.py qq号
```
```
python3 send.py relogin “” qq号
```
发送工具
```
python3 send.py 文本 图片所在目录路径 qq号
```
```
python3 qzone-serv-test.py
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
cookies不全是必要的，但我也不知道哪些是必要的，反正你获取到多少填多少
image可以是http://,https://,file://,base64://.(只测试过file://，其他的理论上能用)


