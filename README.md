# DDoS-Scripts
[Random Collection of DoS Scripts, includes AMP, Dos and DDOS Scripts all the same shit lulz]





LIST of Attacks {Currently Collecting}
----------------------------------------------------------------------------------------------------------------------------------------
Name	                            Utilisation	Ports	Type
XML-RPC	                         Site web	80	LAYER 7 - VIP
JOOMLA	                         Site web	80	LAYER 7 - VIP
Js-ByPass	                       Site web	80	LAYER 7 - VIP
BoostHTTP	                       Site web	80	LAYER 7 - BASIC
BasicDNS	    Servers or home connections	80, 3724	LAYER 4
ESSYN	Basic |                    Servers	80, 3724	LAYER 4
SSYN	Basic |                    Servers	UDP Game Servers	LAYER 4
STORM	                           Servers	80, 443, 8080	LAYER 4
SSDP	        Servers or home connections	UDP Game Servers	LAYER 4
CHARGEN	      Servers or home connections	80, 443, 8080	LAYER 4
NTP	          Servers or home connections	TCP Services	LAYER 4
DOMINATE	                       TCP based servers	9987	LAYER 4
ACK	                             TCP based servers	9987	LAYER 4
SNMP	                           Servers	80	LAYER 4
TELNET	                         Servers	80	LAYER 4
BasicTS3	   Application layer flood for teamspeak	80	LAYER 4
SynACK	                         Advanced	80, 443, 8080	LAYER 4
xACK	                           Advanced	UDP Game Servers	LAYER 4
xSYN	                           Advanced	UDP Game Servers	LAYER 4
ZAP	                             Servers	80	LAYER 4
sUDP	                           Servers	80	LAYER 4
sTCP	                           Servers	80	LAYER 4
UDP-BYPASS	Home connections bypass and basic servers	80	LAYER 4
Home	                           Home connections	80	LAYER 4
TFTP	                           Servers	80	LAYER 4 
PORTMAP	                         Servers	80	LAYER 4
FRAGMENTATION	                   Servers	80	LAYER 4
BasicVSE	Basic Valve Source Engine servers	80	LAYER 4
HAVEN	                           Servers	80	LAYER 4
LDAP	                           Servers	80	LAYER 4 -VIP
OVX-DROP	                       Servers OVH	80	LAYER 4 -VIP
OVH-DROP	                       Servers OVH	80	LAYER 4 -VIP
NFO-LAGGER	                     Servers NFO Nuclear	80	LAYER 4 -VIP
PRO-UDP	                         Servers	80	LAYER 4 -VIP
VSE	                             Valve Source Engine servers	80	LAYER 4 -VIP
VSA	                             Valve Source Engine servers	80	LAYER 4 -VIP
XMAS	                           Servers	80	LAYER 4 -VIP
WIZARD	                         Servers	80	LAYER 4 -VIP
YUBINA9	                         Servers	80	LAYER 4 -VIP
EBOLA	                           Servers	80	LAYER 4 -VIP
GreenSYN	                       Servers	80	LAYER 4 -VIP
OVH-Tempest	                     Servers OVH-GAME	80	LAYER 4 -VIP
GRENADE	                         Servers	80	LAYER 4 -VIP
SENTINEL	                       Servers	80	LAYER 4 -VIP
FIN	                             Servers	80	LAYER 4 -VIP
ABUSE	                           Servers	80	LAYER 4 -VIP
XTS3	                           Servers	80	LAYER 4 -VIP
GTAFUCK	                         GTA SERVERS	80	LAYER 4 -VIP
MCBOT	                           MC SERVERS	80	LAYER 4 -VIP
HomeV2	                         Home connections	80	LAYER 4 -VIP
nOk	ABUSE                        Servers	80	LAYER 4 -VIP
SourceOVH	Basic 2015 |           OVH	80	LAYER 4 -VIP
OVZ	                             Servers OVH	80	LAYER 4 -VIP
OVR	                             Servers OVH	80	LAYER 4 -VIP
TCP-SE	                         SERVERS	80	LAYER 4 -VIP
TCP-RST	                         SERVERS	80	LAYER 4 -VIP
TCP-PSH	                         SERVERS	80	LAYER 4 -VIP
TCP-FIN	                         SERVERS	80	LAYER 4 -VIP
TCP-XMAS	                       SERVERS	80	LAYER 4 -VIP
ZSYN	Advanced |                 Servers	80	LAYER 4 -VIP
CSYN	Advanced |                 Servers	80	LAYER 4 -VIP
ISSYN	Advanced |                 Servers	80	LAYER 4 -VIP
XTSX	                           Application layer flood for teamspeak	80	LAYER 4 -VIP
A2S	                             Player Query Spam | CSS,CSGO,Arma3 etc	80	LAYER 4 -VIP
TS3FUCK	                         Application layer flood for teamspeak	80	LAYER 4 -VIP
TS3DROP	                         Application layer flood for teamspeak	80	LAYER 4 -VIP
Security	Basic 2016 |           OVH,NFO, & CloudFlare	80	LAYER 4 -VIP

##  Flood.c
用于模拟TCP、UDP和ICMP数据包发送的程序，它可以通过不同的参数配置来模拟网络攻击

##  ack.c
TCP DDoS攻击，模拟多个客户端发送大量TCP数据包，TCP ACK Flood。主要通过发送大量伪造的TCP ACK数据包来耗尽目标系统的资源

##  dns_scanner.c
DNS扫描和放大攻击：扫描指定IP范围内的DNS服务器，并发送伪造的DNS查询请求，利用这些服务器进行放大攻击。

##  dns.c
通过发送大量伪造的DNS查询请求，利用开放的DNS服务器将小请求放大为大响应，从而放大攻击流量

##  dominate.c
构造并发送TCP数据包来模拟DoS攻击， 通过SYN Flood

##  essyn.c
TCP SYN flood 类似dominate

##  god-flood.py 
UDP flood

##  god-flood.py
TCP flood， TCP SYN flood，UDP flood 混合 

##  ntp.c
基于NTP反射的DDoS攻击，通过发送大量伪造的NTP请求数据包来耗尽目标系统的资源
NTP（Network Time Protocol）服务器是一种用于同步计算机系统时间的服务器。它使用 NTP 协议，通过网络将时间信息传递给客户端，使客户端的系统时间与服务器的时间保持一致。

##  kaitenstd.c
实现了一个IRC（Internet Relay Chat）机器人，能够执行多种DDoS攻击（如STD攻击和未知攻击），将感染的设备变成攻击者控制的肉鸡，并利用其资源执行远程命令和发动网络攻击。并通过IRC命令控制这些攻击。