# ntp_scanner解析
## NTP概念
网络时间协议NTP（Network Time Protocol）是TCP/IP协议族里面的一个**应用层**协议，用来使客户端和服务器之间进行时钟同步，提供高精准度的时间校正。NTP服务器从权威时钟源（例如原子钟、GPS）接收精确的协调世界时UTC，客户端再从服务器请求和接收时间。

NTP**基于UDP报文**进行传输，使用的UDP端口号为123。

## NTP结构(时钟层级)
NTP以**层级**来组织模型结构，层级中的每层被称为Stratum。通常将从权威时钟获得时钟同步的NTP服务器的层数设置为Stratum 1，并将其作为主时间服务器，为网络中其他的设备提供时钟同步。而Stratum 2则从Stratum 1获取时间，Stratum 3从Stratum 2获取时间，以此类推(有点像DNS)。时钟层数的取值范围为1～16，取值越小，时钟准确度越高。

![NTP 时钟层级](https://i-blog.csdnimg.cn/direct/66ec61baf2f0436392cd7b09b2b0ab13.png)

由于 NTP 时间服务器采用类似阶层架构 (stratum) 来处理时间的同步化， 所以他使用的是类似一般 **server/client** 的主从架构。


## NTP同步原理
以C/S方式为例：

![NTP时间同步](https://i-blog.csdnimg.cn/direct/f84c057708fa46d693c996b6e15e9332.png)

1. 客户端首先向服务端发送一个NTP请求报文，其中包含了该报文离开客户端的时间戳t1;
2. NTP请求报文到达NTP服务器，此时NTP服务器的时刻为t2。当服务端接收到该报文时，NTP服务器处理之后，于t3时刻发出NTP应答报文。该应答报文中携带报文离开NTP客户端时的时间戳t1、到达NTP服务器时的时间戳t2、离开NTP服务器时的时间戳t3；
3. 客户端在接收到响应报文时，记录报文返回的时间戳t4。

然后客户端根据t1、t2、t3、t4计算时间差来调整自己的时钟，实现与服务器时钟同步

## ntp_scanner代码
代码的两个主要函数:
- void *flood(void *par1) : 用于发送NTP请求
- void *recievethread() : 用于监听网络NTP响应并处理
具体可以看ntp_scannner.c中的注释

UDP头部报文格式如下：
![UDP 头部报文格式](https://i-blog.csdnimg.cn/blog_migrate/dff29768c58f6aacc49b010827586435.png)


## 应用
这个我觉得只是作为一个前置工具，**获取NTP服务器的IP地址和响应时间**，NTP漏洞只搜到了mod-6漏洞。