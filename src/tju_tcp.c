#include "tju_tcp.h"
#include <errno.h>
#include <time.h>

/*
 * 三次握手所需的控制信息统一保存在本文件的私有结构中。
 * 这样既能为每个 socket 独立维护序列号、RTO 和 accept 排队状态，又无需修改
 * global.h 中由课程框架定义的 tju_tcp_t，从而严格遵守框架文件的修改限制。
 */
typedef struct handshake_ctx {
    tju_tcp_t* sock;                 // 本上下文对应的连接 socket
    tju_tcp_t* listener;             // 服务端子连接所属的监听 socket；客户端为 NULL
    uint32_t iss;                    // 本端初始发送序列号（Initial Send Sequence）
    uint32_t irs;                    // 对端初始发送序列号（Initial Receive Sequence）
    uint32_t snd_nxt;                // 本端下一个发送序列号；SYN 会占用一个序列号
    uint32_t rcv_nxt;                // 期望从对端收到的下一个序列号
    unsigned int current_rto_ms;     // 当前握手重传超时，单位为毫秒
    int syn_was_retransmitted;       // 握手阶段是否重传过 SYN 或 SYN-ACK
    int queued_for_accept;           // 是否已完成握手并等待 accept 取出
    struct handshake_ctx* next;      // 全局握手上下文链表的下一项
} handshake_ctx_t;

/*
 * 接收线程和调用 connect/accept 的应用线程会并发访问握手状态。
 * 统一用 handshake_lock 保护上下文及状态转换，并用条件变量唤醒等待线程。
 */
static pthread_mutex_t handshake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t handshake_cond = PTHREAD_COND_INITIALIZER;
static handshake_ctx_t* handshake_list = NULL;
static uint32_t isn_counter = 0;

/* RFC 6298 规定无 RTT 样本时初始 RTO 为 1 秒。 */
#define INITIAL_HANDSHAKE_RTO_MS 1000U
/* 对重传次数设置上限，避免对端不可达时永久阻塞。 */
#define MAX_HANDSHAKE_RETRIES 5

/* 调用者必须持有 handshake_lock，防止遍历时链表被并发修改。 */
static handshake_ctx_t* find_handshake(tju_tcp_t* sock){
    handshake_ctx_t* ctx;
    for(ctx = handshake_list; ctx != NULL; ctx = ctx->next){
        if(ctx->sock == sock){
            return ctx;
        }
    }
    return NULL;
}

/* 获取已有上下文，或为新的 socket 创建上下文；调用者必须持有握手锁。 */
static handshake_ctx_t* get_handshake(tju_tcp_t* sock){
    handshake_ctx_t* ctx = find_handshake(sock);
    if(ctx != NULL){
        return ctx;
    }
    ctx = (handshake_ctx_t*)calloc(1, sizeof(handshake_ctx_t));
    if(ctx == NULL){
        return NULL;
    }
    ctx->sock = sock;
    ctx->next = handshake_list;
    handshake_list = ctx;
    return ctx;
}

static uint32_t generate_isn(tju_tcp_t* sock){
    struct timespec now;
    uint32_t value;

    /*
     * 将单调时钟、持续变化的计数器和本地地址混合生成 32 位 ISN。
     * 计数器在锁内更新，确保并发建立连接时不会为所有连接返回固定序列号。
     */
    clock_gettime(CLOCK_MONOTONIC, &now);
    pthread_mutex_lock(&handshake_lock);
    isn_counter += 0x9e3779b9U;
    value = (uint32_t)now.tv_sec ^ (uint32_t)now.tv_nsec ^ isn_counter;
    /*
     * 主动连接的 socket 不一定调用过 tju_bind，因此不能读取可能未初始化的
     * bind_addr。建立连接时使用的本地、远端四元组已经确定，直接将其混入 ISN。
     */
    value ^= sock->established_local_addr.ip;
    value ^= ((uint32_t)sock->established_local_addr.port << 16);
    value ^= sock->established_remote_addr.ip;
    value ^= (uint32_t)sock->established_remote_addr.port;
    pthread_mutex_unlock(&handshake_lock);
    return value;
}

static void send_control(tju_tcp_t* sock, uint32_t seq, uint32_t ack,
                         uint8_t flags){
    uint16_t advertised_window;

    /*
     * 握手控制报文不带数据，所以报文头长度和报文总长度均为固定的 20 字节。
     * advertised_window 必须反映本端接收能力，不能用原先的占位值 1；当前课程
     * 缓冲区小于 16 位窗口上限，可直接通告 TCP_RECVWN_SIZE。
     */
    advertised_window = TCP_RECVWN_SIZE > 65535U
        ? 65535U : (uint16_t)TCP_RECVWN_SIZE;
    char* packet = create_packet_buf(sock->established_local_addr.port,
        sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN, flags, advertised_window, 0, NULL, 0);
    if(packet != NULL){
        sendToLayer3(packet, DEFAULT_HEADER_LEN);
        free(packet);
    }
}

static void add_milliseconds(struct timespec* deadline, unsigned int ms){
    /* timedwait 接收绝对时间；累加毫秒后需显式处理纳秒向秒的进位。 */
    deadline->tv_sec += ms / 1000U;
    deadline->tv_nsec += (long)(ms % 1000U) * 1000000L;
    if(deadline->tv_nsec >= 1000000000L){
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

static tju_tcp_t* pop_established_connection(tju_tcp_t* listener){
    /*
     * 从指定监听 socket 的完成队列中取出一个连接。
     * queued_for_accept 清零保证同一子连接只会被 accept 返回一次。
     */
    handshake_ctx_t* ctx;
    for(ctx = handshake_list; ctx != NULL; ctx = ctx->next){
        if(ctx->listener == listener && ctx->queued_for_accept){
            ctx->queued_for_accept = 0;
            return ctx->sock;
        }
    }
    return NULL;
}

static void* synack_retransmission_worker(void* arg){
    handshake_ctx_t* ctx = (handshake_ctx_t*)arg;
    unsigned int rto_ms = INITIAL_HANDSHAKE_RTO_MS;
    int retries;

    /*
     * 服务端发送 SYN-ACK 后独立等待最终 ACK。每次超时重发同一份逻辑报文，
     * 并按 1、2、4……秒进行指数退避；状态离开 SYN_RECV 后立即结束线程。
     */
    for(retries = 0; retries < MAX_HANDSHAKE_RETRIES; retries++){
        struct timespec deadline;
        int wait_result = 0;

        clock_gettime(CLOCK_REALTIME, &deadline);
        add_milliseconds(&deadline, rto_ms);

        pthread_mutex_lock(&handshake_lock);
        while(ctx->sock->state == SYN_RECV && wait_result != ETIMEDOUT){
            wait_result = pthread_cond_timedwait(&handshake_cond,
                &handshake_lock, &deadline);
        }
        if(ctx->sock->state != SYN_RECV){
            /* 已收到有效 ACK，或连接状态已由其他路径推进，无需继续重传。 */
            pthread_mutex_unlock(&handshake_lock);
            return NULL;
        }
        pthread_mutex_unlock(&handshake_lock);

        send_control(ctx->sock, ctx->iss, ctx->rcv_nxt,
            SYN_FLAG_MASK | ACK_FLAG_MASK);
        pthread_mutex_lock(&handshake_lock);
        ctx->syn_was_retransmitted = 1;
        pthread_mutex_unlock(&handshake_lock);
        rto_ms *= 2U;
    }
    return NULL;
}

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    /*
     * socket 内包含地址、缓冲区指针和窗口指针等成员。使用 calloc 统一清零，
     * 防止尚未显式赋值的字段携带堆内存残值并影响握手哈希或 ISN 计算。
     */
    tju_tcp_t* sock = (tju_tcp_t*)calloc(1, sizeof(tju_tcp_t));
    if(sock == NULL){
        return NULL;
    }
    sock->state = CLOSED;
    
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    tju_tcp_t* new_conn;

    /*
     * accept 只能返回完成三次握手的子连接。若完成队列为空，则睡眠等待接收线程
     * 处理最终 ACK 后发出通知，避免原框架中未经握手便直接返回连接的问题。
     */
    pthread_mutex_lock(&handshake_lock);
    while((new_conn = pop_established_connection(listen_sock)) == NULL){
        pthread_cond_wait(&handshake_cond, &handshake_lock);
    }
    pthread_mutex_unlock(&handshake_lock);
    return new_conn;
}


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){
    handshake_ctx_t* ctx;
    uint32_t iss;
    unsigned int rto_ms = INITIAL_HANDSHAKE_RTO_MS;
    int retries;

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    /*
     * SYN-ACK 到达时，内核需要按连接四元组找到仍处于 SYN_SENT 的 socket，
     * 因此发送首个 SYN 前就必须把它登记到已连接 socket 哈希表中。
     */
    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;

    iss = generate_isn(sock);
    pthread_mutex_lock(&handshake_lock);
    ctx = get_handshake(sock);
    if(ctx == NULL){
        pthread_mutex_unlock(&handshake_lock);
        return -1;
    }
    ctx->iss = iss;
    ctx->snd_nxt = ctx->iss + 1U;
    ctx->current_rto_ms = INITIAL_HANDSHAKE_RTO_MS;
    ctx->syn_was_retransmitted = 0;
    /* connect 仅进入 SYN_SENT，绝不能在三次握手完成前提前标记 ESTABLISHED。 */
    sock->state = SYN_SENT;
    pthread_mutex_unlock(&handshake_lock);

    /*
     * 发送 SYN 后阻塞等待接收线程处理 SYN-ACK。若一个 RTO 内没有状态推进，
     * 则重传相同序列号的 SYN 并将 RTO 加倍，符合握手丢包时的退避要求。
     */
    for(retries = 0; retries <= MAX_HANDSHAKE_RETRIES; retries++){
        struct timespec deadline;
        int wait_result = 0;

        send_control(sock, ctx->iss, 0, SYN_FLAG_MASK);
        clock_gettime(CLOCK_REALTIME, &deadline);
        add_milliseconds(&deadline, rto_ms);

        pthread_mutex_lock(&handshake_lock);
        while(sock->state == SYN_SENT && wait_result != ETIMEDOUT){
            wait_result = pthread_cond_timedwait(&handshake_cond,
                &handshake_lock, &deadline);
        }
        if(sock->state == ESTABLISHED){
            /* 接收线程已校验 SYN-ACK、发送最终 ACK 并推进状态，connect 方可返回。 */
            pthread_mutex_unlock(&handshake_lock);
            return 0;
        }
        ctx->syn_was_retransmitted = 1;
        ctx->current_rto_ms = rto_ms * 2U;
        pthread_mutex_unlock(&handshake_lock);
        rto_ms *= 2U;
    }
    /* 达到重传上限仍未完成握手，向调用者明确返回失败。 */
    return -1;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    // 这里当然不能直接简单地调用sendToLayer3
    char* data = malloc(len);
    memcpy(data, buffer, len);

    char* msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    sendToLayer3(msg, plen);
    
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len<=0){
        // 阻塞
    }

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    /* 先解析握手判断所需的公共字段，后续分支再依据 socket 状态处理。 */
    uint8_t flags = get_flags(pkt);
    uint32_t seq = get_seq(pkt);
    uint32_t ack = get_ack(pkt);
    handshake_ctx_t* ctx;

    if(sock->state == LISTEN && (flags & SYN_FLAG_MASK)){
        /*
         * 监听 socket 收到 SYN：为该四元组创建独立子连接。
         * 子连接先进入 SYN_RECV 并登记到哈希表，再发送 SYN-ACK；这样后续 ACK
         * 以及重复 SYN 都会被内核分派到子连接，而不会污染监听 socket 的状态。
         */
        tju_tcp_t* new_conn = tju_socket();
        pthread_t retransmit_thread;
        char hostname[8] = {0};

        if(new_conn == NULL){
            return -1;
        }
        new_conn->established_local_addr = sock->bind_addr;
        new_conn->established_remote_addr.port = get_src(pkt);
        gethostname(hostname, sizeof(hostname));
        new_conn->established_remote_addr.ip = strcmp(hostname, "server") == 0
            ? inet_network("172.17.0.2") : inet_network("172.17.0.3");

        pthread_mutex_lock(&handshake_lock);
        ctx = get_handshake(new_conn);
        if(ctx == NULL){
            pthread_mutex_unlock(&handshake_lock);
            free(new_conn);
            return -1;
        }
        ctx->listener = sock;
        ctx->irs = seq;
        /* SYN 占用一个序列号，所以确认号必须指向对端 ISN 的下一位。 */
        ctx->rcv_nxt = seq + 1U;
        ctx->current_rto_ms = INITIAL_HANDSHAKE_RTO_MS;
        ctx->syn_was_retransmitted = 0;
        pthread_mutex_unlock(&handshake_lock);

        ctx->iss = generate_isn(new_conn);
        ctx->snd_nxt = ctx->iss + 1U;
        new_conn->state = SYN_RECV;
        established_socks[cal_hash(new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port)] = new_conn;
        send_control(new_conn, ctx->iss, ctx->rcv_nxt,
            SYN_FLAG_MASK | ACK_FLAG_MASK);
        /* 后台线程负责最终 ACK 丢失时的 SYN-ACK 超时重传。 */
        if(pthread_create(&retransmit_thread, NULL,
                synack_retransmission_worker, ctx) == 0){
            pthread_detach(retransmit_thread);
        }
        return 0;
    }

    pthread_mutex_lock(&handshake_lock);
    ctx = find_handshake(sock);

    if(sock->state == SYN_SENT && ctx != NULL &&
       (flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) ==
           (SYN_FLAG_MASK | ACK_FLAG_MASK) && ack == ctx->snd_nxt){
        /*
         * 客户端只接受同时带 SYN、ACK 且确认号等于本端 snd_nxt 的报文，
         * 防止无效确认提前完成连接；随后记录服务端 ISN 并发送第三次握手 ACK。
         */
        ctx->irs = seq;
        ctx->rcv_nxt = seq + 1U;
        /*
         * 若采用小于 3 秒的初始 RTO 且 SYN 曾重传，RFC 6298 要求连接建立后
         * 将数据阶段 RTO 重新初始化为 3 秒。此值保存在上下文中供后续传输使用。
         */
        if(ctx->syn_was_retransmitted &&
           ctx->current_rto_ms < 3000U){
            ctx->current_rto_ms = 3000U;
        }
        /*
         * 必须先将第三次握手 ACK 交给下层，再发布 ESTABLISHED 并唤醒 connect。
         * 否则应用可能在 connect 返回后立即退出，终止尚未发送 ACK 的接收线程。
         * sendToLayer3 只发送 UDP 报文，不回调本状态机，因此此处可持握手锁发送，
         * 同时阻止等待线程在 ACK 发送前观察到连接已建立。
         */
        send_control(sock, ctx->snd_nxt, ctx->rcv_nxt, ACK_FLAG_MASK);
        sock->state = ESTABLISHED;
        pthread_cond_broadcast(&handshake_cond);
        pthread_mutex_unlock(&handshake_lock);
        return 0;
    }

    if(sock->state == SYN_RECV && ctx != NULL){
        if((flags & SYN_FLAG_MASK) && seq == ctx->irs){
            /* 首个 SYN-ACK 可能丢失；收到同一 SYN 时立即重发有效 SYN-ACK。 */
            ctx->syn_was_retransmitted = 1;
            pthread_mutex_unlock(&handshake_lock);
            send_control(sock, ctx->iss, ctx->rcv_nxt,
                SYN_FLAG_MASK | ACK_FLAG_MASK);
            return 0;
        }
        if((flags & ACK_FLAG_MASK) && ack == ctx->snd_nxt){
            /*
             * 最终 ACK 必须确认服务端 SYN 所占用的序列号。校验通过后才进入
             * ESTABLISHED，并加入监听 socket 的完成队列以唤醒 accept。
             */
            if(ctx->syn_was_retransmitted &&
               ctx->current_rto_ms < 3000U){
                ctx->current_rto_ms = 3000U;
            }
            sock->state = ESTABLISHED;
            ctx->queued_for_accept = 1;
            pthread_cond_broadcast(&handshake_cond);
            pthread_mutex_unlock(&handshake_lock);
            return 0;
        }
    }

    if(sock->state == ESTABLISHED && ctx != NULL &&
       (flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) ==
           (SYN_FLAG_MASK | ACK_FLAG_MASK) && ack == ctx->snd_nxt){
        /*
         * 第三次握手 ACK 可能丢失：服务端会重发 SYN-ACK。客户端即使已经进入
         * ESTABLISHED，也必须对重复 SYN-ACK 再次发送相同语义的 ACK。
         */
        uint32_t final_seq = ctx->snd_nxt;
        uint32_t final_ack = seq + 1U;
        pthread_mutex_unlock(&handshake_lock);
        send_control(sock, final_seq, final_ack, ACK_FLAG_MASK);
        return 0;
    }
    pthread_mutex_unlock(&handshake_lock);

    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

    /* 纯 ACK 等无负载控制报文不应被错误写入应用接收缓冲区。 */
    if(data_len == 0){
        return 0;
    }

    // 把收到的数据放到接受缓冲区
    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    if(sock->received_buf == NULL){
        sock->received_buf = malloc(data_len);
    }else {
        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    }
    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    sock->received_len += data_len;

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁


    return 0;
}

int tju_close (tju_tcp_t* sock){
    return 0;
}
