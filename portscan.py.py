#!/usr/bin/env python
#Made By LiGhT

import socket, sys, os, threading

# 这个脚本用于扫描指定IP范围内开放的特定端口，并将结果保存到一个文件中

# 该Python脚本要四个参数: start-range()、end-range()、port(端口号)、output-file(输出文件名)
if len(sys.argv) < 5:
	sys.exit("Usage: python "+sys.argv[0]+" [start-range] [end-range] [port] [output-file]")
	sys.exit()

port = int(sys.argv[3])
outputF = sys.argv[4]


def ipRange(start_ip, end_ip):
	'''返回起始IP和结束IP之间的所有IP地址'''
	start = list(map(int, start_ip.split("."))) # 将IP地址拆成四部分进行操作
	end = list(map(int, end_ip.split(".")))
	temp = start
	ip_range = []

	ip_range.append(start_ip)
	while temp != end:
		start[3] += 1
		for i in (3, 2, 1):
			if temp[i] == 256:
				temp[i] = 0
				temp[i-1] += 1
		ip_range.append(".".join(map(str, temp)))    

	return ip_range

class p0r75c4n(threading.Thread):
	def __init__ (self, ip):
		threading.Thread.__init__(self)
	def run(self):
		x = 1
		while x != 0:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((ip, port))	# 创建一个新的socket并连接到指定的IP和端口
				if result == 0:		# 连接成功
					os.system("echo "+ip+" >> "+outputF+"")		
					print "\033[32mGood:\033[37m "+ip
				elif result != 0:	# 连接失败
					print "\033[31mBad:\033[37m "+ip
				sock.close()
			except:
				pass
			x = 0
ip_range = ipRange("" +sys.argv[1], "" +sys.argv[2])
for ip in ip_range:
	try:
		t = p0r75c4n(ip)	# 为每个IP创建一个p0r75c4n线程
		t.start()
	except:
		pass #MAY CRASH SERVER LMFAOOO DRUNK AF WHEN MADE THS