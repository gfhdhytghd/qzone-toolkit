import httpx
import json
import sys
import os

def get_cookie_file_path(uin: str) -> str:
    return os.path.join(os.getcwd(), f"cookies-{uin}.json")


def parse_cookie_string(cookie_str: str) -> dict:
    return {pair.split("=", 1)[0]: pair.split("=", 1)[1] for pair in cookie_str.split("; ")}

def extract_uin_from_cookie(cookie_str: str) -> str:
    for item in cookie_str.split("; "):
        if item.startswith("uin=") or item.startswith("o_uin="):
            return item.split("=")[1].lstrip("o")
    raise ValueError("无法从 Cookie 字符串中提取 uin")

async def fetch_cookies(domain: str, port: str) -> dict:
    url = f"http://127.0.0.1:{port}/get_cookies?domain={domain}"
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "ok" or "cookies" not in data.get("data", {}):
            raise RuntimeError(f"获取 cookie 失败: {data}")
        return data["data"]

async def main():
    if len(sys.argv) < 2:
        print("用法: python renewcookies_v2.py <port>")
        sys.exit(1)

    port = sys.argv[1]
    domain = "user.qzone.qq.com"
    cookie_data = await fetch_cookies(domain, port)
    cookie_str = cookie_data["cookies"]
    parsed_cookies = parse_cookie_string(cookie_str)
    uin = extract_uin_from_cookie(cookie_str)
    file_path = get_cookie_file_path(uin)
    with open(file_path, "w") as f:
        json.dump(parsed_cookies, f, indent=4, ensure_ascii=False)
    print(f"[OK] cookies saved to: {file_path}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
