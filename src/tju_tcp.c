#include "tju_tcp.h"
#include <errno.h>
#include <time.h>
#include <limits.h>

/* 课程参数尚未随框架发布，可用编译器 -D 覆盖；默认采用保守的 MSL。
 * 独立测试可缩短等待，但正式验收必须采用课程平台给出的值。 */
#ifndef TJU_MSL
#define TJU_MSL 120
#endif
#ifndef TJU_CLOSE_RETRIES
#define TJU_CLOSE_RETRIES 5
#endif
#ifndef TJU_CLOSE_TIMEOUT
#define TJU_CLOSE_TIMEOUT 120
#endif

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
    int close_requested;             // close 一进入即置位，禁止接纳新的发送请求
    int failed;                      // 超时异常终止；保留未确认数据并报告失败
    int peer_fin;                    // 已按序收到对端 FIN，接收方向到达 EOF
    int fin_sent;
    int fin_acked;
    uint32_t fin_seq;                // FIN 的固定序列号；重传不能再次消耗序列号
    uint32_t data_end;               // 当前待确认数据段的右边界
    int data_pending;               // 简化停等发送：同一连接至多一个未确认数据段
    struct timespec time_wait_until; // 单调时钟上的 TIME-WAIT 截止时刻
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

/* 以下连接状态辅助函数均要求持有 handshake_lock。
 * 不释放 socket 或锁本身：应用及内核接收线程可能仍持有指针。
 * 已确认发送缓存由发送线程释放，未读接收数据保留给 recv。 */
static void finish_connection(handshake_ctx_t* ctx, int failed){
    tju_tcp_t* sock = ctx->sock;
    int slot = cal_hash(sock->established_local_addr.ip,
        sock->established_local_addr.port, sock->established_remote_addr.ip,
        sock->established_remote_addr.port);
    if(established_socks[slot] == sock) established_socks[slot] = NULL;
    ctx->failed = failed;
    sock->state = CLOSED;
    pthread_cond_broadcast(&handshake_cond);
}

static void enter_time_wait(handshake_ctx_t* ctx){
    ctx->sock->state = TIME_WAIT;
    clock_gettime(CLOCK_MONOTONIC, &ctx->time_wait_until);
    ctx->time_wait_until.tv_sec += 2 * TJU_MSL;
}

static int deadline_reached(struct timespec deadline){
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec > deadline.tv_sec ||
        (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
}

/* 条件变量使用默认实时时钟；短周期等待后用单调时钟核验协议期限，
 * 避免把无关 ACK 的唤醒当作超时，也不因重复报文无限延长 FIN 重传期限。 */
static void wait_connection_event(void){
    struct timespec tick;
    clock_gettime(CLOCK_REALTIME, &tick);
    add_milliseconds(&tick, 50);
    pthread_cond_timedwait(&handshake_cond, &handshake_lock, &tick);
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
 * tju_close 发出首个 FIN 后由该线程继续维护关闭定时器。应用线程无需阻塞完整
 * 的四次挥手和 2MSL，但 socket 状态仍会按 FIN_WAIT/CLOSING/TIME_WAIT 推进。
 * close_requested 已经封闭发送入口，因此后台线程不需要占用 send_lock。
 */
static void* close_retransmission_worker(void* arg){
    handshake_ctx_t* ctx = (handshake_ctx_t*)arg;
    unsigned int rto;
    int retries = 0;
    struct timespec retry_at, terminate_at;

    pthread_mutex_lock(&handshake_lock);
    rto = ctx->current_rto_ms ? ctx->current_rto_ms : 1000;
    clock_gettime(CLOCK_MONOTONIC, &retry_at);
    terminate_at = retry_at;
    terminate_at.tv_sec += TJU_CLOSE_TIMEOUT;
    add_milliseconds(&retry_at, rto);

    while(ctx->sock->state != CLOSED){
        if(ctx->sock->state == TIME_WAIT){
            if(deadline_reached(ctx->time_wait_until)){
                finish_connection(ctx, 0);
                break;
            }
        }else if(deadline_reached(terminate_at)){
            finish_connection(ctx, 1);
            break;
        }else if(!ctx->fin_acked && deadline_reached(retry_at)){
            if(retries++ >= TJU_CLOSE_RETRIES){
                finish_connection(ctx, 1);
                break;
            }
            /* FIN 重传必须复用首次 FIN 的序列号，不能重复消耗序列空间。 */
            send_control(ctx->sock, ctx->fin_seq, ctx->rcv_nxt,
                FIN_FLAG_MASK | ACK_FLAG_MASK);
            if(rto <= UINT_MAX / 2) rto *= 2;
            clock_gettime(CLOCK_MONOTONIC, &retry_at);
            add_milliseconds(&retry_at, rto);
        }
        wait_connection_event();
    }
    pthread_mutex_unlock(&handshake_lock);
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
    handshake_ctx_t* ctx;
    int offset = 0;
    if(!sock || len < 0 || (len && !buffer)) { errno = EINVAL; return -1; }
    /* send_lock 串行化应用发送；close 先禁止新发送，再等待当前已接纳请求。
     * 锁顺序统一为 send_lock -> handshake_lock，接收线程只取后者。 */
    pthread_mutex_lock(&sock->send_lock);
    pthread_mutex_lock(&handshake_lock);
    ctx = find_handshake(sock);
    if(!ctx || ctx->close_requested || ctx->failed ||
       (sock->state != ESTABLISHED && sock->state != CLOSE_WAIT)){
        pthread_mutex_unlock(&handshake_lock);
        pthread_mutex_unlock(&sock->send_lock);
        errno = EPIPE;
        return -1;
    }
    /* 先保存整个请求，直到累计确认后才释放；失败时也不默默丢弃缓存。
     * 这是关闭的数据排空前提，尚不是第 5.3 节完整滑动窗口实现。 */
    if(len){
        sock->sending_buf = malloc(len);
        if(!sock->sending_buf){
            pthread_mutex_unlock(&handshake_lock);
            pthread_mutex_unlock(&sock->send_lock);
            errno = ENOMEM;
            return -1;
        }
        memcpy(sock->sending_buf, buffer, len);
    }
    sock->sending_len = len;
    while(offset < len && !ctx->failed){
        int chunk = len - offset;
        unsigned int rto = ctx->current_rto_ms ? ctx->current_rto_ms : 1000;
        int retries = 0;
        uint32_t seq = ctx->snd_nxt;
        struct timespec deadline;
        if(chunk > MAX_LEN - DEFAULT_HEADER_LEN) chunk = MAX_LEN - DEFAULT_HEADER_LEN;
        ctx->snd_nxt += (uint32_t)chunk;
        ctx->data_end = ctx->snd_nxt;
        ctx->data_pending = 1;
        while(ctx->data_pending && !ctx->failed){
            char* msg = create_packet_buf(sock->established_local_addr.port,
                sock->established_remote_addr.port, seq, ctx->rcv_nxt,
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + chunk, ACK_FLAG_MASK,
                TCP_RECVWN_SIZE, 0, sock->sending_buf + offset, chunk);
            sendToLayer3(msg, DEFAULT_HEADER_LEN + chunk);
            free(msg);
            clock_gettime(CLOCK_MONOTONIC, &deadline);
            add_milliseconds(&deadline, rto);
            while(ctx->data_pending && !ctx->failed && !deadline_reached(deadline))
                wait_connection_event();
            if(!ctx->data_pending || ctx->failed) break;
            if(retries++ >= TJU_CLOSE_RETRIES){ finish_connection(ctx, 1); break; }
            if(rto <= UINT_MAX / 2) rto *= 2;
        }
        if(!ctx->failed){ offset += chunk; sock->sending_len = len - offset; }
    }
    if(!ctx->failed){ free(sock->sending_buf); sock->sending_buf = NULL; }
    int result = ctx->failed ? -1 : 0;
    pthread_mutex_unlock(&handshake_lock);
    pthread_mutex_unlock(&sock->send_lock);
    if(result < 0) errno = ETIMEDOUT;
    return result;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    if(!sock || len < 0 || (len && !buffer)){ errno = EINVAL; return -1; }
    if(len == 0) return 0;
    /* 收包、EOF 和应用读取共用握手锁，消除忙等和 received_len 数据竞争。
     * FIN 之前的已接收数据必须先交付；仅缓存排空后才向应用报告 EOF。 */
    pthread_mutex_lock(&handshake_lock);
    handshake_ctx_t* ctx = find_handshake(sock);
    while(sock->received_len == 0 && ctx && !ctx->peer_fin &&
          !ctx->failed && sock->state != CLOSED)
        pthread_cond_wait(&handshake_cond, &handshake_lock);
    if(sock->received_len == 0){
        int failed = ctx && ctx->failed;
        pthread_mutex_unlock(&handshake_lock);
        if(failed) errno = ECONNRESET;
        return failed ? -1 : 0;
    }

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        memmove(sock->received_buf, sock->received_buf + read_len, sock->received_len - read_len);
        sock->received_len -= read_len;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&handshake_lock);

    return 0;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    if(!sock || !pkt || get_hlen(pkt) != DEFAULT_HEADER_LEN ||
       get_plen(pkt) < DEFAULT_HEADER_LEN || get_plen(pkt) > MAX_LEN) return -1;
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
    /* 握手以外只处理本连接的合法端口和已同步状态；控制报文不得落入数据缓存。 */
    if(!ctx || sock->state == CLOSED || sock->state == LISTEN ||
       sock->state == SYN_SENT || sock->state == SYN_RECV ||
       get_src(pkt) != sock->established_remote_addr.port ||
       get_dst(pkt) != sock->established_local_addr.port || (flags & SYN_FLAG_MASK)){
        pthread_mutex_unlock(&handshake_lock);
        return 0;
    }
    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
    /* 停等发送只有一个确认边界；不接受确认尚未发出数据的未来 ACK。 */
    if((flags & ACK_FLAG_MASK) && ctx->data_pending && ack == ctx->data_end)
        ctx->data_pending = 0;
    if((flags & ACK_FLAG_MASK) && ctx->fin_sent && ack == ctx->fin_seq + 1U){
        ctx->fin_acked = 1;
        if(sock->state == FIN_WAIT_1) sock->state = FIN_WAIT_2;
        else if(sock->state == CLOSING) enter_time_wait(ctx);
        else if(sock->state == LAST_ACK) finish_connection(ctx, 0);
    }
    /* FIN 可以紧跟报文负载。先按序接收负载，再判断 FIN 所在序列号。
     * 失序数据和失序 FIN 不推进确认点，发送端后续重传时再接收。
     * 已交付的重复数据不再次交付，保证关闭期间重传不会破坏接收内容。 */
    if(data_len && !ctx->peer_fin && seq == ctx->rcv_nxt &&
       sock->state != CLOSED && data_len <= (uint32_t)(INT_MAX - sock->received_len)){
        char* next = realloc(sock->received_buf, sock->received_len + data_len);
        if(next){
            sock->received_buf = next;
            memcpy(next + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
            sock->received_len += data_len;
            ctx->rcv_nxt += data_len;
        }
    }
    if(flags & FIN_FLAG_MASK){
        uint32_t fin = seq + data_len;
        if(!ctx->peer_fin && fin == ctx->rcv_nxt && sock->state != CLOSED){
            ctx->peer_fin = 1;
            ctx->rcv_nxt++; // FIN 只在首次按序接收时占用一个序列号
            if(sock->state == ESTABLISHED) sock->state = CLOSE_WAIT;
            else if(sock->state == FIN_WAIT_1) sock->state = CLOSING;
            else if(sock->state == FIN_WAIT_2) enter_time_wait(ctx);
        }else if(ctx->peer_fin && fin == ctx->rcv_nxt - 1U && sock->state == TIME_WAIT){
            // 最终 ACK 丢失时，对端会重发 FIN；重新开始完整的 2MSL 等待。
            enter_time_wait(ctx);
        }
    }
    if((data_len || (flags & FIN_FLAG_MASK)) && sock->state != CLOSED)
        send_control(sock, ctx->snd_nxt, ctx->rcv_nxt, ACK_FLAG_MASK);
    pthread_cond_broadcast(&handshake_cond);
    pthread_mutex_unlock(&handshake_lock);
    return 0;
}

int tju_close (tju_tcp_t* sock){
    handshake_ctx_t* ctx;
    pthread_t close_thread;
    if(!sock){ errno = EINVAL; return -1; }
    pthread_mutex_lock(&handshake_lock);
    ctx = find_handshake(sock);
    if(!ctx || ctx->close_requested ||
       (sock->state != ESTABLISHED && sock->state != CLOSE_WAIT)){
        pthread_mutex_unlock(&handshake_lock);
        errno = ENOTCONN;
        return -1;
    }
    /* 先封闭发送入口，再等待已接纳的 send 完成确认；这里不能持握手锁等
     * send_lock，否则接收线程无法处理 ACK，正在进行的 send 将无法结束。 */
    ctx->close_requested = 1;
    pthread_mutex_unlock(&handshake_lock);
    pthread_mutex_lock(&sock->send_lock);
    pthread_mutex_lock(&handshake_lock);
    if(ctx->failed){
        pthread_mutex_unlock(&handshake_lock);
        pthread_mutex_unlock(&sock->send_lock);
        errno = ETIMEDOUT;
        return -1;
    }
    ctx->fin_sent = 1;
    ctx->fin_seq = ctx->snd_nxt++;
    sock->state = ctx->peer_fin ? LAST_ACK : FIN_WAIT_1;
    send_control(sock, ctx->fin_seq, ctx->rcv_nxt, FIN_FLAG_MASK | ACK_FLAG_MASK);
    /* 首个 FIN 发送成功后启动后台状态机。若线程无法创建，就明确返回失败，
     * 不能让连接停留在无人维护的 FIN_WAIT/LAST_ACK 状态。 */
    if(pthread_create(&close_thread, NULL, close_retransmission_worker, ctx) != 0){
        finish_connection(ctx, 1);
        pthread_mutex_unlock(&handshake_lock);
        pthread_mutex_unlock(&sock->send_lock);
        errno = EAGAIN;
        return -1;
    }
    pthread_detach(close_thread);
    pthread_mutex_unlock(&handshake_lock);
    pthread_mutex_unlock(&sock->send_lock);
    return 0;
}
