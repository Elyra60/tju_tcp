#include "tju_tcp.h"
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>

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

/* 保持课程框架原有的 MAX_DLEN 作为实际分段长度；发送上限与报文中
 * 16 位通告窗口的最大值一致，最终可用窗口还会取对端 rwnd 的较小值。 */
#define RDT_SMSS MAX_DLEN
#define RDT_SEND_WINDOW 65535U
#define RDT_MIN_RTO_MS 1000U
#define RDT_MAX_RTO_MS 60000U

typedef struct send_segment {
    uint32_t seq;                    // 本段第一个数据字节的序列号
    uint32_t end_seq;                // 本段末尾之后的序列号
    int len;
    char* data;
    int sent;
    int retransmitted;               // Karn：重传过的段不再提供 RTT 样本
    struct timespec sent_at;
    struct send_segment* next;
} send_segment_t;

typedef struct recv_segment {
    uint32_t seq;
    int len;
    char* data;
    struct recv_segment* next;
} recv_segment_t;

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
    uint32_t snd_max;                // 已真正交给下层的最高数据字节边界，用于拒绝未来 ACK
    uint32_t rcv_nxt;                // 期望从对端收到的下一个序列号
    unsigned int current_rto_ms;     // 当前握手重传超时，单位为毫秒
    int syn_was_retransmitted;       // 握手阶段是否重传过 SYN 或 SYN-ACK
    int queued_for_accept;           // 是否已完成握手并等待 accept 取出
    int close_requested;             // close 一进入即置位，禁止接纳新的发送请求
    int failed;                      // 超时异常终止；保留未确认数据并报告失败
    int peer_fin;                    // 已按序收到对端 FIN，接收方向到达 EOF
    int pending_fin;                 // FIN 失序到达时等待前方数据补齐
    uint32_t pending_fin_seq;        // 失序 FIN 在字节序列空间中的位置
    int fin_sent;
    int fin_acked;
    uint32_t fin_seq;                // FIN 的固定序列号；重传不能再次消耗序列号
    uint32_t snd_una;                // 最早尚未确认的字节序列号
    send_segment_t* send_head;
    send_segment_t* send_tail;
    uint64_t queued_bytes;           // 尚未累计确认的数据总量
    int sender_started;
    int sender_stop;
    uint32_t duplicate_ack;
    int duplicate_ack_count;
    int fast_recovery;               // 三次重复 ACK 后是否正在修复同一发送窗口
    uint32_t recovery_seq;            // 进入快速恢复时已经发送到的最高字节边界
    int have_rtt_sample;
    double srtt_ms;
    double rttvar_ms;
    double rto_ms;
    int retransmission_timer_running;
    struct timespec retransmission_timer_at;
    size_t recv_buffer_capacity;     // received_buf 当前已分配的容量
    size_t recv_buffer_offset;       // 缓冲区中第一个尚未交付字节的偏移
    recv_segment_t* recv_ooo;        // 按序列号排序的失序数据段链表
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

/*
 * Trace 使用独立互斥锁和大块 stdio 缓冲，避免把磁盘写入放大为每个报文一次
 * 系统调用。每 256 条主动刷新一次，在吞吐开销和进程异常结束时的日志完整性
 * 之间取得平衡；该锁不参与 TCP 状态机，因此不会改变握手、挥手和 RDT 时序。
 */
static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE* trace_file = NULL;
static int trace_initialized = 0;
static unsigned int trace_pending_lines = 0;

static char* build_packet(handshake_ctx_t* ctx, uint32_t seq, uint32_t ack,
                          uint8_t flags, char* data, int len);

/* RFC 6298 规定无 RTT 样本时初始 RTO 为 1 秒。 */
#define INITIAL_HANDSHAKE_RTO_MS 1000U
/* 对重传次数设置上限，避免对端不可达时永久阻塞。 */
#define MAX_HANDSHAKE_RETRIES 5

/* 返回 UTC Unix 时间戳，单位为毫秒。秒乘 1000 后加微秒的千分之一，保证
 * 常规日期下恰好是说明书要求的 13 位整数，而不是示例代码中误写的微秒值。 */
static long long trace_utc_milliseconds(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

/* 调用者必须持有 trace_lock。仅在进程内第一次使用时以 "w" 覆盖旧日志。 */
static void trace_initialize_locked(void){
    if(trace_initialized) return;
    trace_initialized = 1;

    char hostname[64] = {0};
    const char* role = NULL;
    char path[160] = {0};
    if(gethostname(hostname, sizeof(hostname) - 1U) != 0) return;
    if(strcmp(hostname, "server") == 0) role = "server";
    else if(strcmp(hostname, "client") == 0) role = "client";
    else return;

    snprintf(path, sizeof(path),
        "/vagrant/tju_tcp/test/%s.event.trace", role);
    trace_file = fopen(path, "w");
    /* 非 Vagrant 环境下从 test 目录直接运行程序时使用当前目录作为回退；
     * 自动测评环境始终会命中上面的规范绝对路径。 */
    if(!trace_file){
        snprintf(path, sizeof(path), "%s.event.trace", role);
        trace_file = fopen(path, "w");
    }
    if(!trace_file) return;
    setvbuf(trace_file, NULL, _IOFBF, 1024U * 1024U);

    /* 当前版本尚未实现拥塞/流量控制，三个窗口均为固定初值。仍记录初始状态，
     * 使 Trace 消费程序能够得到完整的窗口基线；窗口单位严格使用 byte。 */
    long long now = trace_utc_milliseconds();
    fprintf(trace_file, "[CWND] [%lld] [type:0 size:%u]\n",
        now, RDT_SEND_WINDOW);
    fprintf(trace_file, "[RWND] [%lld] [size:%u]\n",
        now, (unsigned int)TCP_RECVWN_SIZE);
    fprintf(trace_file, "[SWND] [%lld] [size:%u]\n",
        now, RDT_SEND_WINDOW);
    /* 初始窗口事件数量很少，立即落盘，确保仅运行连接测试时文件也非空。 */
    fflush(trace_file);
    trace_pending_lines = 0U;
}

/* 按说明书统一输出 [event] [utctimestamp] [info]。info 的具体键值格式由
 * 各事件调用者提供，集中封装可以避免不同路径产生空格或括号差异。 */
static void trace_event(const char* event, const char* info_format, ...){
    pthread_mutex_lock(&trace_lock);
    trace_initialize_locked();
    if(trace_file){
        fprintf(trace_file, "[%s] [%lld] [", event,
            trace_utc_milliseconds());
        va_list args;
        va_start(args, info_format);
        vfprintf(trace_file, info_format, args);
        va_end(args);
        fputs("]\n", trace_file);
        if(++trace_pending_lines >= 256U){
            fflush(trace_file);
            trace_pending_lines = 0U;
        }
    }
    pthread_mutex_unlock(&trace_lock);
}

/* SEND/RECV 的 length 只记录 payload 长度，不包含 20 字节首部。 */
static void trace_packet(const char* event, char* packet){
    uint16_t header_len = get_hlen(packet);
    uint16_t packet_len = get_plen(packet);
    unsigned int payload_len = packet_len >= header_len ?
        (unsigned int)(packet_len - header_len) : 0U;
    trace_event(event, "seq:%u ack:%u flag:%u length:%u",
        get_seq(packet), get_ack(packet), (unsigned int)get_flags(packet),
        payload_len);
}

/* 首个 socket 创建发生在 startSimulation 之后，可作为本进程 Trace 生命周期
 * 的起点；此调用保证即使暂时没有报文，也会覆盖旧日志并写入窗口初值。 */
static void trace_start_process(void){
    pthread_mutex_lock(&trace_lock);
    trace_initialize_locked();
    pthread_mutex_unlock(&trace_lock);
}

/* 在关键控制报文或应用主动关闭时刷新尚未落盘的少量日志。数据传输热路径
 * 不调用本函数，仍由 trace_event 每 256 行批量刷新。 */
static void trace_flush_pending(void){
    pthread_mutex_lock(&trace_lock);
    if(trace_file && trace_pending_lines){
        fflush(trace_file);
        trace_pending_lines = 0U;
    }
    pthread_mutex_unlock(&trace_lock);
}

/* 所有 TJU TCP 发包都经过本函数，先按最终报文头记录 SEND，再交给仿真网络。
 * 记录动作不修改报文内容，因此不会影响连接状态与可靠传输语义。 */
static void send_packet_traced(char* packet, int packet_len){
    trace_packet("SEND", packet);
    sendToLayer3(packet, packet_len);
    if(get_flags(packet) & (SYN_FLAG_MASK | FIN_FLAG_MASK))
        trace_flush_pending();
}

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

static void send_control(handshake_ctx_t* ctx, uint32_t seq, uint32_t ack,
                         uint8_t flags){
    /*
     * 握手控制报文不带数据，所以报文头长度和报文总长度均为固定的 20 字节。
     * build_packet 会填写当前接收窗口和 ext 校验值。
     */
    char* packet = build_packet(ctx, seq, ack, flags, NULL, 0);
    if(packet != NULL){
        send_packet_traced(packet, DEFAULT_HEADER_LEN);
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
    /* 连接一旦结束，立即唤醒并终止可靠发送线程，防止其继续重传。 */
    ctx->sender_stop = 1;
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

/* 32 位序列号比较只在窗口小于 2^31 时使用；有符号差值可自然处理回绕。 */
static int seq_before(uint32_t a, uint32_t b){ return (int32_t)(a - b) < 0; }
static int seq_after(uint32_t a, uint32_t b){ return seq_before(b, a); }
static int seq_before_or_equal(uint32_t a, uint32_t b){ return !seq_after(a, b); }

static double elapsed_ms(struct timespec start, struct timespec end){
    return (end.tv_sec - start.tv_sec) * 1000.0 +
        (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

static char* build_packet(handshake_ctx_t* ctx, uint32_t seq, uint32_t ack,
                          uint8_t flags, char* data, int len){
    tju_tcp_t* sock = ctx->sock;
    /* 当前工作只保留可靠传输，发送端不再依据 rwnd 限速。首部中的窗口字段
     * 填写框架默认接收窗口，保持报文格式合法，但不参与本地发送判定。 */
    uint16_t window = TCP_RECVWN_SIZE;
    char* packet = create_packet_buf(sock->established_local_addr.port,
        sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN + len, flags, window, 0, data, len);
    /* 课程报文格式规定 ext 只是把首部补齐到 20 字节的保留字段，没有校验和
     * 语义，必须保持 create_packet_buf 参数中给出的 0。不得私自复用该字段，
     * 否则严格检查首部的平台会把 SYN、ACK 或数据报文判为格式错误。 */
    return packet;
}

static void update_rto(handshake_ctx_t* ctx, double sample_ms){
    if(!ctx->have_rtt_sample){
        ctx->srtt_ms = sample_ms;
        ctx->rttvar_ms = sample_ms / 2.0;
        ctx->have_rtt_sample = 1;
    }else{
        double error = ctx->srtt_ms - sample_ms;
        if(error < 0) error = -error;
        ctx->rttvar_ms = 0.75 * ctx->rttvar_ms + 0.25 * error;
        ctx->srtt_ms = 0.875 * ctx->srtt_ms + 0.125 * sample_ms;
    }
    ctx->rto_ms = ctx->srtt_ms + 4.0 * ctx->rttvar_ms;
    if(ctx->rto_ms < RDT_MIN_RTO_MS) ctx->rto_ms = RDT_MIN_RTO_MS;
    if(ctx->rto_ms > RDT_MAX_RTO_MS) ctx->rto_ms = RDT_MAX_RTO_MS;
    ctx->current_rto_ms = (unsigned int)ctx->rto_ms;
    /* 四个 RTT 指标任一更新时记录同一组新值，单位均为毫秒。 */
    trace_event("RTTS",
        "SampleRTT:%f EstimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f",
        sample_ms, ctx->srtt_ms, ctx->rttvar_ms, ctx->rto_ms);
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

        send_control(ctx, ctx->iss, ctx->rcv_nxt,
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
            send_control(ctx, ctx->fin_seq, ctx->rcv_nxt,
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

/* 计算当前已发送但尚未累计确认的数据量。调用者持有 handshake_lock。 */
static uint32_t flight_size(handshake_ctx_t* ctx){
    uint32_t bytes = 0;
    for(send_segment_t* seg = ctx->send_head; seg && seg->sent; seg = seg->next)
        bytes += (uint32_t)seg->len;
    return bytes;
}

static void transmit_segment(handshake_ctx_t* ctx, send_segment_t* seg,
                             int retransmission){
    char* packet = build_packet(ctx, seg->seq, ctx->rcv_nxt,
        ACK_FLAG_MASK, seg->data, seg->len);
    if(!packet) return;
    send_packet_traced(packet, DEFAULT_HEADER_LEN + seg->len);
    free(packet);
    clock_gettime(CLOCK_MONOTONIC, &seg->sent_at);
    seg->sent = 1;
    if(seq_after(seg->end_seq, ctx->snd_max)) ctx->snd_max = seg->end_seq;
    if(retransmission) seg->retransmitted = 1;
}

/*
 * 每条连接只有一个发送线程。它将应用入队的数据按发送窗口流水线发出，
 * 最早未确认段的计时器到期时执行超时重传；ACK 处理负责释放队首并唤醒它。
 */
static void* reliable_sender_worker(void* arg){
    handshake_ctx_t* ctx = (handshake_ctx_t*)arg;
    pthread_mutex_lock(&handshake_lock);
    while(!ctx->sender_stop && !ctx->failed){
        while(!ctx->send_head && !ctx->sender_stop && !ctx->failed)
            pthread_cond_wait(&handshake_cond, &handshake_lock);
        if(ctx->sender_stop || ctx->failed) break;

        uint32_t in_flight = flight_size(ctx);
        for(send_segment_t* seg = ctx->send_head; seg; seg = seg->next){
            if(seg->sent) continue;
            /* RDT 只按固定的本地发送窗口限制在途字节数，不再等待对端 rwnd。
             * 使用剩余空间判断，避免窗口边界计算发生无符号溢出。 */
            if((uint32_t)seg->len > RDT_SEND_WINDOW - in_flight) break;
            if(in_flight == 0){
                ctx->retransmission_timer_running = 1;
                clock_gettime(CLOCK_MONOTONIC, &ctx->retransmission_timer_at);
            }
            transmit_segment(ctx, seg, 0);
            in_flight += (uint32_t)seg->len;
        }

        if(ctx->send_head && ctx->send_head->sent &&
           ctx->retransmission_timer_running){
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double rto = ctx->rto_ms > 0 ? ctx->rto_ms : RDT_MIN_RTO_MS;
            if(elapsed_ms(ctx->retransmission_timer_at, now) >= rto){
                transmit_segment(ctx, ctx->send_head, 1);
                ctx->rto_ms = rto * 2.0;
                if(ctx->rto_ms > RDT_MAX_RTO_MS) ctx->rto_ms = RDT_MAX_RTO_MS;
                ctx->current_rto_ms = (unsigned int)ctx->rto_ms;
                ctx->retransmission_timer_at = now;
            }
        }
        wait_connection_event();
    }
    pthread_mutex_unlock(&handshake_lock);
    return NULL;
}

/*
 * 将连续到达的数据追加到动态接收缓存。读取端仅推进 recv_buffer_offset，
 * 不再为每个 tju_recv 调用移动全部剩余数据；只有尾部空间不足时才偶尔压紧，
 * 从而把 100MB 大文件接收从二次方复制降为近似线性开销。
 */
static int append_received(handshake_ctx_t* ctx, const char* data, int len){
    if(len <= 0) return 1;
    size_t used = (size_t)ctx->sock->received_len;
    size_t required = used + (size_t)len;

    if(ctx->recv_buffer_offset + required > ctx->recv_buffer_capacity &&
       ctx->recv_buffer_offset > 0U){
        memmove(ctx->sock->received_buf,
            ctx->sock->received_buf + ctx->recv_buffer_offset, used);
        ctx->recv_buffer_offset = 0U;
    }
    if(required > ctx->recv_buffer_capacity){
        size_t capacity = ctx->recv_buffer_capacity ?
            ctx->recv_buffer_capacity : (size_t)(32U * RDT_SMSS);
        while(capacity < required){
            if(capacity > SIZE_MAX / 2U){ capacity = required; break; }
            capacity *= 2U;
        }
        char* next = realloc(ctx->sock->received_buf, capacity);
        if(!next) return 0;
        ctx->sock->received_buf = next;
        ctx->recv_buffer_capacity = capacity;
    }
    memcpy(ctx->sock->received_buf + ctx->recv_buffer_offset + used, data, len);
    ctx->sock->received_len += len;
    ctx->rcv_nxt += (uint32_t)len;
    return 1;
}

/*
 * 插入失序段后合并重叠区间，再把从 rcv_nxt 开始连续的数据移入应用缓存。
 * 所有比较均在小于 2^31 的接收窗口内进行，因此支持 32 位序列号回绕。
 */
static void receive_data_locked(handshake_ctx_t* ctx, uint32_t seq,
                                const char* data, int len){
    if(len <= 0 || ctx->peer_fin) return;
    if(seq_before(seq, ctx->rcv_nxt)){
        uint32_t overlap = ctx->rcv_nxt - seq;
        if(overlap >= (uint32_t)len) return;
        seq += overlap;
        data += overlap;
        len -= (int)overlap;
    }
    /* 删除 rwnd 流量控制后，接收端仍只缓存固定发送窗口范围内的失序数据，
     * 防止损坏或恶意报文用极远的序列号无界占用内存。 */
    uint32_t ahead = seq - ctx->rcv_nxt;
    if(ahead >= RDT_SEND_WINDOW) return;
    /* 包括恰好从 rcv_nxt 开始的段也先进入排序链表。这样新段
     * 与早到的失序段有交叠时，仍能统一去重合并，不会卡住队首。 */
    recv_segment_t* node = calloc(1, sizeof(*node));
    if(!node) return;
    node->data = malloc(len);
    if(!node->data){ free(node); return; }
    memcpy(node->data, data, len);
    node->seq = seq;
    node->len = len;
    recv_segment_t** pos = &ctx->recv_ooo;
    while(*pos && seq_before((*pos)->seq, seq)) pos = &(*pos)->next;
    node->next = *pos;
    *pos = node;

    /* 合并相邻或重叠区间。交叠字节只保留一份，因此重复报文
     * 不会被二次交付；每次合并后重算缓存量，避免重叠长度误差。 */
    for(recv_segment_t* cur = ctx->recv_ooo; cur && cur->next; ){
        recv_segment_t* next = cur->next;
        uint32_t cur_end = cur->seq + (uint32_t)cur->len;
        if(seq_before(cur_end, next->seq)){ cur = next; continue; }
        uint32_t next_end = next->seq + (uint32_t)next->len;
        if(seq_after(next_end, cur_end)){
            uint32_t offset = next->seq - cur->seq;
            int merged_len = (int)(next_end - cur->seq);
            char* merged = realloc(cur->data, merged_len);
            if(!merged) break;
            cur->data = merged;
            memcpy(cur->data + offset, next->data, next->len);
            cur->len = merged_len;
        }
        cur->next = next->next;
        free(next->data);
        free(next);
    }
    while(ctx->recv_ooo && ctx->recv_ooo->seq == ctx->rcv_nxt){
        recv_segment_t* node = ctx->recv_ooo;
        if(!append_received(ctx, node->data, node->len)) break;
        ctx->recv_ooo = node->next;
        /* 仅在连续数据成功进入应用接收缓存后记录 DELV；失序暂存和重复包
         * 不记录，确保 Trace 中的交付字节与应用实际可读字节完全一致。 */
        trace_event("DELV", "seq:%u size:%d", node->seq, node->len);
        free(node->data);
        free(node);
    }
}

/*
 * 处理累计确认并滑动发送窗口。ACK 只能落在 [snd_una, snd_nxt] 内；未来 ACK
 * 会被忽略。连续三个相同 ACK 立即重传队首，超时计时器则在有效新 ACK 后
 * 针对新的最早未确认段重新启动。
 */
static void process_ack_locked(handshake_ctx_t* ctx, uint32_t ack){
    /* snd_nxt 还包含已经入队但尚未发出的字节，只有不超过 snd_max 的 ACK 才有效。 */
    if(seq_after(ack, ctx->snd_max)) return;
    if(seq_after(ack, ctx->snd_una)){
        struct timespec now;
        int was_fast_recovery = ctx->fast_recovery;
        uint32_t recovery_seq = ctx->recovery_seq;
        int rtt_ambiguous = 0;
        int have_candidate = 0;
        double candidate_ms = 0.0;
        clock_gettime(CLOCK_MONOTONIC, &now);
        while(ctx->send_head &&
              seq_before_or_equal(ctx->send_head->end_seq, ack)){
            send_segment_t* done = ctx->send_head;
            /* 累计 ACK 覆盖任何重传段时，无法判断它确认的是原报文还是副本；
             * Karn 算法要求整次确认都不采样。否则至多保留一个候选 RTT。 */
            if(done->retransmitted) rtt_ambiguous = 1;
            else if(!have_candidate && done->sent){
                candidate_ms = elapsed_ms(done->sent_at, now);
                have_candidate = 1;
            }
            ctx->send_head = done->next;
            ctx->queued_bytes -= (uint32_t)done->len;
            free(done->data);
            free(done);
        }
        if(have_candidate && !rtt_ambiguous) update_rto(ctx, candidate_ms);
        if(!ctx->send_head) ctx->send_tail = NULL;
        ctx->snd_una = ack;
        ctx->duplicate_ack = ack;
        ctx->duplicate_ack_count = 0;
        ctx->sock->sending_len = ctx->queued_bytes > INT_MAX ?
            INT_MAX : (int)ctx->queued_bytes;
        if(ctx->send_head && ctx->send_head->sent){
            ctx->retransmission_timer_running = 1;
            ctx->retransmission_timer_at = now;
        }else{
            ctx->retransmission_timer_running = 0;
        }
        /*
         * 一个窗口内可能同时丢失多个段。三次重复 ACK 修复第一个缺口后，
         * 若新 ACK 仍未越过进入快速恢复时的发送边界，它就是“部分 ACK”，
         * 说明接收方失序缓存之后仍有缺口。立即重传新的队首，避免每个缺口
         * 都额外等待至少 1 秒 RTO；确认越过 recovery_seq 后退出快速恢复。
         */
        if(was_fast_recovery && seq_before(ack, recovery_seq) &&
           ctx->send_head && ctx->send_head->sent){
            transmit_segment(ctx, ctx->send_head, 1);
            ctx->retransmission_timer_running = 1;
            ctx->retransmission_timer_at = now;
        }else if(was_fast_recovery && !seq_before(ack, recovery_seq)){
            ctx->fast_recovery = 0;
        }
        pthread_cond_broadcast(&handshake_cond);
    }else if(ack == ctx->snd_una && ctx->send_head && ctx->send_head->sent){
        /* 流量控制相关的窗口更新 ACK 已被删除，因此相同确认号表示接收端仍在
         * 等待同一个缺失分段，可以直接用于三次重复 ACK 快速重传。 */
        if(ctx->duplicate_ack == ack) ctx->duplicate_ack_count++;
        else{
            ctx->duplicate_ack = ack;
            ctx->duplicate_ack_count = 1;
        }
        if(ctx->duplicate_ack_count >= 3){
            if(!ctx->fast_recovery){
                ctx->fast_recovery = 1;
                ctx->recovery_seq = ctx->snd_max;
            }
            transmit_segment(ctx, ctx->send_head, 1);
            clock_gettime(CLOCK_MONOTONIC, &ctx->retransmission_timer_at);
            ctx->retransmission_timer_running = 1;
            ctx->duplicate_ack_count = 0;
        }
    }
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
    trace_start_process();
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
    /* 实验网络的服务端地址已更正为 172.17.0.6。测试应用可能仍传入旧模板
     * 地址，因此在协议实现入口统一规范化，确保监听哈希与内核收包地址一致。 */
    bind_addr.ip = inet_network("172.17.0.6");
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

    /* 主动连接的目标固定为更正后的服务端地址。入口处覆盖旧模板传入的地址，
     * 避免连接表登记使用旧 IP，而底层实际向 172.17.0.6 发送数据包。 */
    target_addr.ip = inet_network("172.17.0.6");
    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    // 主动连接方是客户端，其本地地址使用实验网络中更正后的客户端 IP。
    local_addr.ip = inet_network("172.17.0.5");
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
    ctx->snd_una = ctx->snd_nxt;
    ctx->snd_max = ctx->snd_nxt;
    ctx->current_rto_ms = INITIAL_HANDSHAKE_RTO_MS;
    ctx->rto_ms = INITIAL_HANDSHAKE_RTO_MS;
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

        send_control(ctx, ctx->iss, 0, SYN_FLAG_MASK);
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
    send_segment_t* first = NULL;
    send_segment_t* last = NULL;
    int offset = 0;
    if(!sock || len < 0 || (len && !buffer)) { errno = EINVAL; return -1; }
    if(len == 0) return 0;
    /* send_lock 串行化应用发送；close 先禁止新发送，再等待当前已接纳请求。
     * 锁顺序统一为 send_lock -> handshake_lock，接收线程只取后者。 */
    pthread_mutex_lock(&sock->send_lock);

    /* 先在私有链表中完成复制，任何分配失败都不会向连接队列提交半个请求。 */
    while(offset < len){
        int chunk = len - offset;
        if(chunk > RDT_SMSS) chunk = RDT_SMSS;
        send_segment_t* seg = calloc(1, sizeof(*seg));
        if(seg) seg->data = malloc(chunk);
        if(!seg || !seg->data){
            free(seg);
            while(first){ send_segment_t* next = first->next; free(first->data); free(first); first = next; }
            pthread_mutex_unlock(&sock->send_lock);
            errno = ENOMEM;
            return -1;
        }
        memcpy(seg->data, (const char*)buffer + offset, chunk);
        seg->len = chunk;
        if(last) last->next = seg; else first = seg;
        last = seg;
        offset += chunk;
    }

    pthread_mutex_lock(&handshake_lock);
    ctx = find_handshake(sock);
    if(!ctx || ctx->close_requested || ctx->failed ||
       (sock->state != ESTABLISHED && sock->state != CLOSE_WAIT)){
        /* 私有链表尚未提交给连接，失败路径必须完整释放。 */
        while(first){
            send_segment_t* next = first->next;
            free(first->data);
            free(first);
            first = next;
        }
        pthread_mutex_unlock(&handshake_lock);
        pthread_mutex_unlock(&sock->send_lock);
        errno = EPIPE;
        return -1;
    }

    /* 在锁内连续分配字节序列号，保证多个应用发送请求在字节流中不交叉。 */
    for(send_segment_t* seg = first; seg; seg = seg->next){
        seg->seq = ctx->snd_nxt;
        ctx->snd_nxt += (uint32_t)seg->len;
        seg->end_seq = ctx->snd_nxt;
    }
    if(ctx->send_tail) ctx->send_tail->next = first; else ctx->send_head = first;
    ctx->send_tail = last;
    ctx->queued_bytes += (uint32_t)len;
    sock->sending_len = ctx->queued_bytes > INT_MAX ? INT_MAX : (int)ctx->queued_bytes;
    if(!ctx->sender_started){
        pthread_t sender;
        if(pthread_create(&sender, NULL, reliable_sender_worker, ctx) != 0){
            /* 已入队数据不能假装发送成功；标记连接失败，由 close 明确报告。 */
            finish_connection(ctx, 1);
            pthread_mutex_unlock(&handshake_lock);
            pthread_mutex_unlock(&sock->send_lock);
            errno = EAGAIN;
            return -1;
        }
        pthread_detach(sender);
        ctx->sender_started = 1;
    }
    pthread_cond_broadcast(&handshake_cond);
    pthread_mutex_unlock(&handshake_lock);
    pthread_mutex_unlock(&sock->send_lock);
    /* 与课程框架原有约定保持一致：数据成功接纳进发送缓存返回 0。 */
    return 0;
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

    /* received_buf 保持指向分配块起点，未读数据由私有偏移定位。读取时只推进
     * 偏移而不移动剩余内容，后续追加空间不足时再由 append_received 压紧。 */
    size_t offset = ctx ? ctx->recv_buffer_offset : 0U;
    memcpy(buffer, sock->received_buf + offset, read_len);
    sock->received_len -= read_len;
    if(ctx){
        ctx->recv_buffer_offset += (size_t)read_len;
        if(sock->received_len == 0) ctx->recv_buffer_offset = 0U;
    }else if(sock->received_len > 0){
        memmove(sock->received_buf, sock->received_buf + read_len,
            (size_t)sock->received_len);
    }
    pthread_cond_broadcast(&handshake_cond);
    pthread_mutex_unlock(&handshake_lock);

    /* 返回实际交付的字节数，上层依此拼接完整字节流。 */
    return read_len;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    if(!sock || !pkt || get_hlen(pkt) != DEFAULT_HEADER_LEN ||
       get_plen(pkt) < DEFAULT_HEADER_LEN || get_plen(pkt) > MAX_LEN) return -1;
    /* 报文公共字段通过基本边界检查后立即记录 RECV，包含握手、数据、ACK 和
     * 挥手报文；这样日志中的接收事件与状态机是否接受该报文相互独立。 */
    trace_packet("RECV", pkt);
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
        /* 根据本机角色填写子连接的对端地址：服务端接收到的连接来自客户端
         * 172.17.0.5；反向角色下则将对端记录为服务端 172.17.0.6。 */
        new_conn->established_remote_addr.ip = strcmp(hostname, "server") == 0
            ? inet_network("172.17.0.5") : inet_network("172.17.0.6");

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
        ctx->snd_una = ctx->snd_nxt;
        ctx->snd_max = ctx->snd_nxt;
        ctx->rto_ms = INITIAL_HANDSHAKE_RTO_MS;
        new_conn->state = SYN_RECV;
        established_socks[cal_hash(new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port)] = new_conn;
        send_control(ctx, ctx->iss, ctx->rcv_nxt,
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
            ctx->rto_ms = 3000.0;
        }
        /*
         * 必须先将第三次握手 ACK 交给下层，再发布 ESTABLISHED 并唤醒 connect。
         * 否则应用可能在 connect 返回后立即退出，终止尚未发送 ACK 的接收线程。
         * sendToLayer3 只发送 UDP 报文，不回调本状态机，因此此处可持握手锁发送，
         * 同时阻止等待线程在 ACK 发送前观察到连接已建立。
         */
        send_control(ctx, ctx->snd_nxt, ctx->rcv_nxt, ACK_FLAG_MASK);
        /* 第三次握手 ACK 数量不足以触发批量阈值，主动刷新以完整保留握手。 */
        trace_flush_pending();
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
            send_control(ctx, ctx->iss, ctx->rcv_nxt,
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
                ctx->rto_ms = 3000.0;
            }
            sock->state = ESTABLISHED;
            ctx->queued_for_accept = 1;
            /* 服务端已记录最终 ACK，建立完成时立即落盘。 */
            trace_flush_pending();
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
        send_control(ctx, final_seq, final_ack, ACK_FLAG_MASK);
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
    /* RDT 阶段只使用累计 ACK 推进发送队列；通告窗口字段不参与发送限制。 */
    if(flags & ACK_FLAG_MASK){
        process_ack_locked(ctx, ack);
    }
    if((flags & ACK_FLAG_MASK) && ctx->fin_sent && ack == ctx->fin_seq + 1U){
        ctx->fin_acked = 1;
        if(sock->state == FIN_WAIT_1) sock->state = FIN_WAIT_2;
        else if(sock->state == CLOSING) enter_time_wait(ctx);
        else if(sock->state == LAST_ACK) finish_connection(ctx, 0);
    }
    /* 数据可失序、重复或部分重叠；receive_data_locked 先去重重组，
     * 只把从 rcv_nxt 开始的连续字节一次、按序交付给应用缓存。 */
    if(data_len && sock->state != CLOSED)
        receive_data_locked(ctx, seq, pkt + DEFAULT_HEADER_LEN, (int)data_len);
    if(flags & FIN_FLAG_MASK){
        uint32_t fin = seq + data_len;
        if(!ctx->peer_fin && !seq_before(fin, ctx->rcv_nxt)){
            /* FIN 也可先于前方数据到达；记住其序列位置，但不提前报 EOF。 */
            ctx->pending_fin = 1;
            ctx->pending_fin_seq = fin;
        }else if(ctx->peer_fin && fin == ctx->rcv_nxt - 1U && sock->state == TIME_WAIT){
            // 最终 ACK 丢失时，对端会重发 FIN；重新开始完整的 2MSL 等待。
            enter_time_wait(ctx);
        }
    }
    if(ctx->pending_fin && ctx->pending_fin_seq == ctx->rcv_nxt &&
       !ctx->peer_fin && sock->state != CLOSED){
        ctx->pending_fin = 0;
        ctx->peer_fin = 1;
        ctx->rcv_nxt++;              // FIN 仅在首次按序接收时占用一个序列号
        if(sock->state == ESTABLISHED) sock->state = CLOSE_WAIT;
        else if(sock->state == FIN_WAIT_1) sock->state = CLOSING;
        else if(sock->state == FIN_WAIT_2) enter_time_wait(ctx);
    }
    if((data_len || (flags & FIN_FLAG_MASK)) && sock->state != CLOSED)
        send_control(ctx, ctx->snd_nxt, ctx->rcv_nxt, ACK_FLAG_MASK);
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
    /* tju_send 只负责将字节接纳到发送队列，因此 close 必须等待
     * 累计 ACK 将数据全部移出队列，才能让 FIN 紧跟最后一个数据字节。
     * 排空等待也有总时限，对端不可达时向应用明确报告失败。 */
    struct timespec drain_deadline;
    clock_gettime(CLOCK_REALTIME, &drain_deadline);
    drain_deadline.tv_sec += TJU_CLOSE_TIMEOUT;
    int drain_wait = 0;
    while(ctx->send_head && !ctx->failed && drain_wait != ETIMEDOUT)
        drain_wait = pthread_cond_timedwait(&handshake_cond,
            &handshake_lock, &drain_deadline);
    if(ctx->failed || ctx->send_head){
        if(!ctx->failed) finish_connection(ctx, 1);
        pthread_mutex_unlock(&handshake_lock);
        pthread_mutex_unlock(&sock->send_lock);
        errno = ETIMEDOUT;
        return -1;
    }
    ctx->fin_sent = 1;
    ctx->fin_seq = ctx->snd_nxt++;
    sock->state = ctx->peer_fin ? LAST_ACK : FIN_WAIT_1;
    send_control(ctx, ctx->fin_seq, ctx->rcv_nxt, FIN_FLAG_MASK | ACK_FLAG_MASK);
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
