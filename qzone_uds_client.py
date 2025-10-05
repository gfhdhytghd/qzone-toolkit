import os
import socket
import sys


def main():
    sock_path = os.getenv('QZONE_SOCK_PATH', './cache/qzone.sock')
    data = sys.stdin.read()
    if not data:
        return 1
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
        cli.connect(sock_path)
        f = cli.makefile('rwb')
        f.write((data.rstrip('\n') + '\n').encode())
        f.flush()
        line = f.readline()
        if not line:
            return 1
        sys.stdout.write(line.decode().strip())
        sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

