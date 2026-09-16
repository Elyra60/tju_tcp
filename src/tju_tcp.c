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

/* 保持当前工程 MAX_DLEN=1375。未知对端窗口时的回退上限为 16 位最大值，
 * 实际新数据发送始终还要受动态 cwnd 限制。 */
#define RDT_SMSS MAX_DLEN
#define RDT_SEND_WINDOW 65535U
/* 挑战任务默认启用完整 Reno；编译 -DTJU_FULL_RENO=0 可复现基础实现，
 * 两种模式共用握手、关闭、RDT 和流控代码，不按测试名称选择行为。 */
#ifndef TJU_FULL_RENO
#define TJU_FULL_RENO 1
#endif
#if TJU_FULL_RENO != 0 && TJU_FULL_RENO != 1
#error "TJU_FULL_RENO must be 0 or 1"
#endif
/* 平台配置尚未出现在本地文件中：允许通过 -D 指定字节值。
 * 默认 IW 使用 RFC 5681 对当前 SMSS 的上限，不能误用现代 TCP 的 IW10。 */
#define RENO_IW_LIMIT ((RDT_SMSS > 2190U ? 2U : (RDT_SMSS > 1095U ? 3U : 4U)) * RDT_SMSS)
#ifndef TJU_INITIAL_CWND
#define TJU_INITIAL_CWND RENO_IW_LIMIT
#endif
#ifndef TJU_INITIAL_SSTHRESH
#define TJU_INITIAL_SSTHRESH 65535U
#endif
#if TJU_INITIAL_CWND < RDT_SMSS || TJU_INITIAL_CWND > RENO_IW_LIMIT
#error "TJU_INITIAL_CWND must satisfy RFC 5681 IW bounds"
#endif
#if TJU_INITIAL_SSTHRESH < 2 * RDT_SMSS || TJU_INITIAL_SSTHRESH > 65535U
#error "TJU_INITIAL_SSTHRESH must fit the course advertised window"
#endif
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
    uint32_t cwnd;                    // 字节单位，每连接独立，受 handshake_lock 保护
    uint32_t ssthresh;                // 慢启动阈值；丢包时根据真实 FlightSize 更新
    int congestion_state;            // 复用框架状态常量，不修改 global.h
    uint64_t ca_acked_bytes;          // 拥塞避免累计确认字节，避免整数截断和 ACK 拆分加速
    int reno_wait_ack;               // 快速重传后等待首次新 ACK；完整模式期间允许膨胀
    uint32_t traced_cwnd, traced_ssthresh;
    int traced_congestion_type;
    int have_congestion_trace;       // CWND/SSTHRESH 仅变化时输出，CC 保留每个原因快照
    int have_rtt_sample;
    double srtt_ms;
    double rttvar_ms;
    double rto_ms;
    int retransmission_timer_running;
    struct timespec retransmission_timer_at;
    uint16_t peer_rwnd;              // 对端最近一次通告的 16 位接收窗口
    uint32_t peer_window_right;      // 对端窗口绝对右边界：SEG.ACK + SEG.WND
    int peer_window_initialized;     // 是否已经从握手或 ACK 中取得有效窗口
    uint32_t advertised_right_edge;  // 本端已经通告且不得主动左移的窗口右边界
    int advertised_window_initialized;
    uint16_t last_traced_rwnd;       // 上次记录的本端实际空闲缓存，包含失序缓存占用
    int have_last_traced_rwnd;
    uint32_t last_traced_swnd;       // 上次写入 Trace 的实际有效发送窗口
    int have_last_traced_swnd;
    int persist_timer_running;       // 零/小窗口探测计时器是否正在运行
    double persist_interval_ms;      // 当前探测间隔，失败后按指数退避
    struct timespec persist_timer_at;
    size_t recv_buffer_capacity;     // received_buf 当前已分配的容量
    size_t recv_buffer_offset;       // 缓冲区中第一个尚未交付字节的偏移
    recv_segment_t* recv_ooo;        // 按序列号排序的失序数据段链表
    uint32_t recv_ooo_bytes;         // 失序链表去重后的实际占用字节数
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

/* 返回 UTC Unix 时间戳，单位为微秒。现有 gen_graph_win.py 会用时间差除以
 * 1000000 换算为秒，因此必须保留完整微秒精度，才能得到正确的横轴比例。 */
static long long trace_utc_microseconds(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000LL + (long long)tv.tv_usec;
}

/* 调用者必须持有 trace_lock。仅在进程内第一次使用时以 "w" 覆盖旧日志。 */
static void trace_initialize_locked(void){
    if(trace_initialized) return;
    trace_initialized = 1;

    char hostname[64] = {0};
    const char* role = NULL;
    char path[160] = {0};
    const char* override_path = getenv("TJU_TRACE_PATH");
    if(gethostname(hostname, sizeof(hostname) - 1U) != 0) return;
    if(strcmp(hostname, "server") == 0) role = "server";
    else if(strcmp(hostname, "client") == 0) role = "client";
    else if(!override_path || !override_path[0]) return;

    /* 隔离实验可明确指定输出文件，避免覆盖课程 test 目录中的既有证据。 */
    if(override_path && override_path[0]){
        trace_file = fopen(override_path, "w");
    }else{
        snprintf(path, sizeof(path),
            "/vagrant/tju_tcp/test/%s.event.trace", role);
        trace_file = fopen(path, "w");
        /* 非 Vagrant 环境使用当前工作目录作为回退。隔离验证必须显式指定
         * TJU_TRACE_PATH，不能依赖默认路径恰好不存在。 */
        if(!trace_file){
            snprintf(path, sizeof(path), "%s.event.trace", role);
            trace_file = fopen(path, "w");
        }
    }
    if(!trace_file){
        /* 日志失败应可见，但不能因此中断网络协议或向报文中添加诊断数据。 */
        perror("TJU TCP trace fopen");
        return;
    }
    setvbuf(trace_file, NULL, _IOFBF, 1024U * 1024U);

    /* 初值由各连接创建路径记录，不再伪造固定 CWND/SWND。 */
    /* 初始窗口事件数量很少，立即落盘，确保仅运行连接测试时文件也非空。 */
    fflush(trace_file);
    trace_pending_lines = 0U;
}

/* 按说明正文及 gen_graph_win.py 的解析顺序输出
 * [utctimestamp] [event] [info]。集中封装可避免不同路径产生格式差异。 */
static void trace_event(const char* event, const char* info_format, ...){
    pthread_mutex_lock(&trace_lock);
    trace_initialize_locked();
    if(trace_file){
        fprintf(trace_file, "[%lld] [%s] [",
            trace_utc_microseconds(), event);
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
    ctx->cwnd = TJU_INITIAL_CWND;
    ctx->ssthresh = TJU_INITIAL_SSTHRESH;
    ctx->congestion_state = ctx->cwnd < ctx->ssthresh ?
        SLOW_START : CONGESTION_AVOIDANCE;
    trace_event("CWND", "type:%d size:%u", ctx->congestion_state, ctx->cwnd);
    trace_event("SSTHRESH", "size:%u", ctx->ssthresh);
    /* 握手完成前不会发送应用数据。先采用 16 位窗口上限，收到 SYN/SYN-ACK
     * 中的真实通告值后再更新绝对右边界。 */
    ctx->peer_rwnd = UINT16_MAX;
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

/*
 * 计算并维护本端要写入报文首部的 Advertised Window。
 *
 * 接收缓存占用包括已经按序到达但尚未被应用读取的字节，以及仍在等待缺口的
 * 失序字节。advertised_right_edge 保存“曾经承诺可接收”的绝对右边界：新计算
 * 的边界较小时保持原值，避免接收端主动收缩已通告窗口；只有应用释放了至少
 * 一个 SMSS 的空间时才向右推进，以实现接收端基本 SWS 避免。
 * 调用者必须持有 handshake_lock。
 */
static uint16_t receive_window_locked(handshake_ctx_t* ctx){
    uint64_t used = (uint64_t)ctx->sock->received_len + ctx->recv_ooo_bytes;
    uint32_t available = used >= TCP_RECVWN_SIZE ? 0U :
        (uint32_t)(TCP_RECVWN_SIZE - used);
    /* Trace 说明的 RWND 是本端接收方的实际可用缓存。它与经过 SWS 避免和
     * 右边界保持处理的首部通告值并非总是相等，也不是本端收到的对端窗口。
     * 只记录真实变化；固定窗口的时间延展由绘图端处理，不伪造变化事件。 */
    if(!ctx->have_last_traced_rwnd || ctx->last_traced_rwnd != available){
        trace_event("RWND", "size:%u", available);
        ctx->last_traced_rwnd = (uint16_t)available;
        ctx->have_last_traced_rwnd = 1;
    }
    uint32_t candidate_right = ctx->rcv_nxt + available;

    if(!ctx->advertised_window_initialized){
        ctx->advertised_right_edge = candidate_right;
        ctx->advertised_window_initialized = 1;
    }else if(seq_after(candidate_right, ctx->advertised_right_edge)){
        uint32_t growth = candidate_right - ctx->advertised_right_edge;
        uint32_t sws_threshold = RDT_SMSS;
        if(sws_threshold > TCP_RECVWN_SIZE / 2U)
            sws_threshold = TCP_RECVWN_SIZE / 2U;
        if(growth >= sws_threshold)
            ctx->advertised_right_edge = candidate_right;
    }

    uint32_t window = seq_after(ctx->advertised_right_edge, ctx->rcv_nxt) ?
        ctx->advertised_right_edge - ctx->rcv_nxt : 0U;
    if(window > UINT16_MAX) window = UINT16_MAX;
    return (uint16_t)window;
}

/* 新数据同时受拥塞窗口与对端绝对窗口右边界约束。缩窗不会撤回已发数据。 */
static uint32_t sender_effective_window_locked(handshake_ctx_t* ctx){
    uint32_t rwnd = RDT_SEND_WINDOW;
    if(ctx->peer_window_initialized){
        rwnd = seq_after(ctx->peer_window_right, ctx->snd_una) ?
            ctx->peer_window_right - ctx->snd_una : 0U;
    }
    return rwnd < ctx->cwnd ? rwnd : ctx->cwnd;
}

/* 仅在实际有效发送窗口改变时记录 SWND，避免为每个 ACK 重复写磁盘。 */
static void trace_sender_window_locked(handshake_ctx_t* ctx){
    uint32_t swnd = sender_effective_window_locked(ctx);
    if(!ctx->have_last_traced_swnd || ctx->last_traced_swnd != swnd){
        trace_event("SWND", "size:%u", swnd);
        ctx->last_traced_swnd = swnd;
        ctx->have_last_traced_swnd = 1;
    }
}

/*
 * 用 ACK 与 Advertised Window 形成对端窗口的绝对右边界。绝对边界而不是单独
 * 保存窗口大小，可以正确处理 ACK 前移和对端窗口缩小。窗口重新打开时取消
 * persist 退避，使发送线程立即恢复正常发送。
 */
static void update_peer_window_locked(handshake_ctx_t* ctx, uint32_t ack,
                                      uint16_t advertised_window){
    if(ctx->peer_window_initialized &&
       (seq_before(ack, ctx->snd_una) || seq_after(ack, ctx->snd_max))) return;

    if(!ctx->peer_window_initialized || ctx->peer_rwnd != advertised_window ||
       ctx->peer_window_right != ack + (uint32_t)advertised_window)
        trace_event("PEER_WINDOW", "conn:%p ack:%u size:%u right:%u",
            (void*)ctx->sock, ack, (unsigned int)advertised_window,
            ack + (uint32_t)advertised_window);
    ctx->peer_rwnd = advertised_window;
    ctx->peer_window_right = ack + (uint32_t)advertised_window;
    ctx->peer_window_initialized = 1;
    if(advertised_window > 0U){
        ctx->persist_timer_running = 0;
        ctx->persist_interval_ms = 0.0;
    }
    pthread_cond_broadcast(&handshake_cond);
}

static char* build_packet(handshake_ctx_t* ctx, uint32_t seq, uint32_t ack,
                          uint8_t flags, char* data, int len){
    tju_tcp_t* sock = ctx->sock;
    /* 每一种 TJU TCP 报文（包括 SYN、纯 ACK、数据和 FIN）都携带当前可用接收
     * 窗口；未实现窗口扩展，因此 receive_window_locked 将值限制在 65535。 */
    uint16_t window = receive_window_locked(ctx);
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
        /* 窗口字段也属于连接状态，重传 SYN-ACK 时在同一锁内取快照。 */
        send_control(ctx, ctx->iss, ctx->rcv_nxt,
            SYN_FLAG_MASK | ACK_FLAG_MASK);
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

/* CC 快照绑定连接和触发原因；RWND 原事件仍表示本地接收缓存，peer 字段
 * 才是本连接发送方向收到的窗口。所有数值均来自锁内真实状态。 */
static void trace_congestion(handshake_ctx_t* ctx, const char* reason, int type){
    if(!ctx->have_congestion_trace || ctx->traced_cwnd != ctx->cwnd ||
       ctx->traced_congestion_type != type)
        trace_event("CWND", "type:%d size:%u", type, ctx->cwnd);
    if(!ctx->have_congestion_trace || ctx->traced_ssthresh != ctx->ssthresh)
        trace_event("SSTHRESH", "size:%u", ctx->ssthresh);
    ctx->traced_cwnd = ctx->cwnd;
    ctx->traced_ssthresh = ctx->ssthresh;
    ctx->traced_congestion_type = type;
    ctx->have_congestion_trace = 1;
    trace_event("CC", "conn:%p reason:%s state:%d cwnd:%u ssthresh:%u peer:%u flight:%u ack:%u",
        (void*)ctx->sock, reason, ctx->congestion_state, ctx->cwnd,
        ctx->ssthresh, (unsigned int)ctx->peer_rwnd, flight_size(ctx), ctx->snd_una);
    trace_sender_window_locked(ctx);
}

/* 丢包响应必须使用尚未累计确认的数据量，而不是排队长度或 cwnd。
 * RFC 5681 第3.2节：完整模式为三个已离开网络的段增加3*SMSS窗口额度；
 * 基础模式维持原来的无膨胀行为。超时一律回到一个SMSS并清除恢复状态。 */
static void reno_loss(handshake_ctx_t* ctx, int timeout){
    uint32_t half = flight_size(ctx) / 2U;
    ctx->ssthresh = half > 2U * RDT_SMSS ? half : 2U * RDT_SMSS;
    ctx->cwnd = timeout ? RDT_SMSS : ctx->ssthresh;
    if(TJU_FULL_RENO && !timeout) ctx->cwnd += 3U * RDT_SMSS;
    ctx->ca_acked_bytes = 0;
    ctx->reno_wait_ack = !timeout;
    ctx->congestion_state = timeout ? SLOW_START : FAST_RECOVERY;
    if(timeout){
        ctx->fast_recovery = 0;
        ctx->duplicate_ack_count = 0;
    }
    trace_congestion(ctx, timeout ? "RTO" : "FAST_RETRANSMIT", timeout ? 3 : 2);
}

/* 仅确认新数据时调用。按字节计数防止把一个 ACK 拆成多个小 ACK 加速增长。
 * CA 每累计确认当前 cwnd 字节增加一个 SMSS，一次 ACK 最多增长一次。
 * 饱和到序号安全范围，绝不让 uint32_t 回绕造成窗口突然归零。 */
static void reno_new_ack(handshake_ctx_t* ctx, uint32_t bytes){
    uint32_t increment = 0;
    int recovery_ack = ctx->reno_wait_ack;
    if(ctx->reno_wait_ack){
        ctx->reno_wait_ack = 0;
        ctx->cwnd = ctx->ssthresh;
        ctx->ca_acked_bytes = 0;
        /* 经典Reno遇到首个新ACK即退出，包括只修复部分缺口的ACK。
         * 不能继续保留NewReno式部分ACK恢复，也不能给此ACK再加一次CA窗口。 */
        if(TJU_FULL_RENO) ctx->fast_recovery = 0;
    }else if(ctx->cwnd < ctx->ssthresh){
        increment = bytes < RDT_SMSS ? bytes : RDT_SMSS;
    }else{
        ctx->ca_acked_bytes += bytes;
        if(ctx->ca_acked_bytes >= ctx->cwnd){
            ctx->ca_acked_bytes -= ctx->cwnd;
            increment = RDT_SMSS;
        }
    }
    if(increment > (uint32_t)INT_MAX - ctx->cwnd) ctx->cwnd = INT_MAX;
    else ctx->cwnd += increment;
    ctx->congestion_state = ctx->cwnd < ctx->ssthresh ? SLOW_START : CONGESTION_AVOIDANCE;
    trace_congestion(ctx, TJU_FULL_RENO && recovery_ack ? "RECOVERY_ACK" : "NEW_ACK", ctx->congestion_state);
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
    trace_event(retransmission ? "RETRANSMIT" : "FLIGHT",
        "conn:%p seq:%u length:%d flight:%u cwnd:%u peer:%u",
        (void*)ctx->sock, seg->seq, seg->len, flight_size(ctx), ctx->cwnd,
        (unsigned int)ctx->peer_rwnd);
}

/*
 * 零窗口探测不属于正常在途数据，不能把待发段标记为已发送。这里发送一个位于
 * SND.UNA 前一字节的单字节重复段：接收端会把它视为旧数据并立即返回包含当前
 * ACK 与窗口的确认，从而既查询窗口又不会越过对端已通告的零窗口右边界。
 */
static void transmit_window_probe(handshake_ctx_t* ctx){
    send_segment_t* pending = ctx->send_head;
    while(pending && pending->sent) pending = pending->next;
    if(!pending || pending->len <= 0) return;
    char probe_byte = pending->data[0];
    char* packet = build_packet(ctx, ctx->snd_una - 1U, ctx->rcv_nxt,
        ACK_FLAG_MASK, &probe_byte, 1);
    if(!packet) return;
    trace_event("PROBE", "conn:%p ack:%u peer:%u", (void*)ctx->sock,
        ctx->snd_una, (unsigned int)ctx->peer_rwnd);
    send_packet_traced(packet, DEFAULT_HEADER_LEN + 1);
    free(packet);
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
        uint32_t effective_window = sender_effective_window_locked(ctx);
        for(send_segment_t* seg = ctx->send_head; seg; seg = seg->next){
            if(seg->sent) continue;
            /* 新数据必须同时受本地发送上限和对端通告窗口约束。对端缩窗后旧的
             * 在途段仍照常确认/重传，但 effective_window <= in_flight 时不再
             * 发送任何新段，避免无符号减法下溢反而放大窗口。 */
            uint32_t remaining = effective_window > in_flight ?
                effective_window - in_flight : 0U;
            if((uint32_t)seg->len > remaining) break;
            /* 发送端基本 SWS 避免：队尾不足一个 SMSS 的最终碎片在仍有数据
             * 在途时暂缓；若后面已经排入更多数据则继续流水发送。这样不会在
             * 测试程序多次调用 tju_send 时为每个调用额外引入一个 RTT。 */
            if((uint32_t)seg->len < RDT_SMSS && in_flight != 0U &&
               seg->next == NULL) break;
            if(in_flight == 0){
                ctx->retransmission_timer_running = 1;
                clock_gettime(CLOCK_MONOTONIC, &ctx->retransmission_timer_at);
            }
            transmit_segment(ctx, seg, 0);
            in_flight += (uint32_t)seg->len;
        }

        /* 对端通告零窗口且仍有新数据等待时启动 persist 计时器。首次间隔为
         * 一个当前 RTO，之后指数增长并限制在最大 RTO；收到持续的零窗口响应
         * 只更新状态而不关闭连接，因而不会把“应用暂未读取”误判为故障。 */
        send_segment_t* unsent = ctx->send_head;
        while(unsent && unsent->sent) unsent = unsent->next;
        if(unsent && ctx->peer_window_initialized && ctx->peer_rwnd == 0U){
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if(!ctx->persist_timer_running){
                ctx->persist_timer_running = 1;
                ctx->persist_interval_ms = ctx->rto_ms > 0.0 ?
                    ctx->rto_ms : RDT_MIN_RTO_MS;
                ctx->persist_timer_at = now;
            }else if(elapsed_ms(ctx->persist_timer_at, now) >=
                     ctx->persist_interval_ms){
                transmit_window_probe(ctx);
                ctx->persist_timer_at = now;
                ctx->persist_interval_ms *= 2.0;
                if(ctx->persist_interval_ms > RDT_MAX_RTO_MS)
                    ctx->persist_interval_ms = RDT_MAX_RTO_MS;
            }
        }else{
            ctx->persist_timer_running = 0;
            ctx->persist_interval_ms = 0.0;
        }

        if(ctx->send_head && ctx->send_head->sent &&
           ctx->retransmission_timer_running){
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double rto = ctx->rto_ms > 0 ? ctx->rto_ms : RDT_MIN_RTO_MS;
            if(elapsed_ms(ctx->retransmission_timer_at, now) >= rto){
                trace_event("RTO", "conn:%p seq:%u rto_ms:%.3f flight:%u",
                    (void*)ctx->sock, ctx->send_head->seq, rto, flight_size(ctx));
                reno_loss(ctx, 1);
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
 * 将连续到达的数据追加到有界接收缓存。读取端仅推进 recv_buffer_offset，
 * 不再为每个 tju_recv 调用移动全部剩余数据；只有尾部空间不足时才偶尔压紧。
 * 缓冲容量严格限制为 TCP_RECVWN_SIZE，防止内部动态扩容绕过已通告窗口。
 */
static int append_received(handshake_ctx_t* ctx, const char* data, int len){
    if(len <= 0) return 1;
    size_t used = (size_t)ctx->sock->received_len;
    size_t required = used + (size_t)len;
    if(required > TCP_RECVWN_SIZE) return 0;

    if(ctx->recv_buffer_offset + required > ctx->recv_buffer_capacity &&
       ctx->recv_buffer_offset > 0U){
        memmove(ctx->sock->received_buf,
            ctx->sock->received_buf + ctx->recv_buffer_offset, used);
        ctx->recv_buffer_offset = 0U;
    }
    if(required > ctx->recv_buffer_capacity){
        size_t capacity = TCP_RECVWN_SIZE;
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
    /* 只接纳已经通告窗口右边界之前的数据；跨越右边界的尾部被裁掉。这样
     * received_len 与失序缓存之和不会超过接收容量，也能安全处理恶意远端序号。 */
    receive_window_locked(ctx);
    if(!seq_before(seq, ctx->advertised_right_edge)) return;
    uint32_t allowed = ctx->advertised_right_edge - seq;
    if((uint32_t)len > allowed) len = (int)allowed;
    if(len <= 0) return;
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
    /* 合并完成后按唯一字节重算失序占用，避免重复/重叠报文把可用窗口错误减小。 */
    ctx->recv_ooo_bytes = 0U;
    for(recv_segment_t* cur = ctx->recv_ooo; cur; cur = cur->next)
        ctx->recv_ooo_bytes += (uint32_t)cur->len;
    while(ctx->recv_ooo && ctx->recv_ooo->seq == ctx->rcv_nxt){
        recv_segment_t* node = ctx->recv_ooo;
        if(!append_received(ctx, node->data, node->len)) break;
        ctx->recv_ooo = node->next;
        ctx->recv_ooo_bytes -= (uint32_t)node->len;
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
static void process_ack_locked(handshake_ctx_t* ctx, uint32_t ack,
                               int advertised_window_unchanged){
    /* snd_nxt 还包含已经入队但尚未发出的字节，只有不超过 snd_max 的 ACK 才有效。 */
    if(seq_after(ack, ctx->snd_max)) return;
    if(seq_after(ack, ctx->snd_una)){
        uint32_t newly_acked = ack - ctx->snd_una;
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
        /* ACK 可以落在段内部：裁去已确认前缀，FlightSize 和重传都只包含余量。
         * 未完整确认段不采 RTT，避免把同一发送实例多次用于估计。 */
        if(ctx->send_head && ctx->send_head->sent &&
           seq_after(ack, ctx->send_head->seq)){
            send_segment_t* partial = ctx->send_head;
            uint32_t prefix = ack - partial->seq;
            if(partial->retransmitted) rtt_ambiguous = 1;
            memmove(partial->data, partial->data + prefix, partial->len - prefix);
            partial->len -= (int)prefix;
            partial->seq = ack;
            ctx->queued_bytes -= prefix;
        }
        if(have_candidate && !rtt_ambiguous) update_rto(ctx, candidate_ms);
        if(!ctx->send_head) ctx->send_tail = NULL;
        ctx->snd_una = ack;
        trace_event("ACK", "conn:%p ack:%u new:%u", (void*)ctx->sock, ack, newly_acked);
        reno_new_ack(ctx, newly_acked);
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
        if(!TJU_FULL_RENO && was_fast_recovery && seq_before(ack, recovery_seq) &&
           ctx->send_head && ctx->send_head->sent){
            transmit_segment(ctx, ctx->send_head, 1);
            ctx->retransmission_timer_running = 1;
            ctx->retransmission_timer_at = now;
        }else if(was_fast_recovery && !seq_before(ack, recovery_seq)){
            ctx->fast_recovery = 0;
        }
        pthread_cond_broadcast(&handshake_cond);
    }else if(ack == ctx->snd_una && ctx->send_head && ctx->send_head->sent &&
             advertised_window_unchanged){
        /* 只有确认号与通告窗口都未变化时才是重复 ACK。窗口更新 ACK 不代表
         * 丢包，若错误计入三次重复确认会触发无意义的快速重传并破坏吞吐。 */
        if(ctx->duplicate_ack == ack){
            if(ctx->duplicate_ack_count < INT_MAX) ctx->duplicate_ack_count++;
        }
        else{
            ctx->duplicate_ack = ack;
            ctx->duplicate_ack_count = 1;
        }
        trace_event("DUPACK", "conn:%p ack:%u count:%d", (void*)ctx->sock,
            ack, ctx->duplicate_ack_count);
        if(TJU_FULL_RENO && ctx->reno_wait_ack){
            /* 已经处于恢复期的每个有效重复ACK都增加一个SMSS，窗口更新ACK
             * 不进入此分支。饱和运算避免整数回绕；发送仍受rwnd共同约束。
             * 即使重复计数被窗口更新清零，恢复状态也不会因此丢失或再次减半。 */
            if(ctx->cwnd > (uint32_t)INT_MAX - RDT_SMSS) ctx->cwnd = INT_MAX;
            else ctx->cwnd += RDT_SMSS;
            trace_congestion(ctx, "DUPACK_INFLATE", FAST_RECOVERY);
            pthread_cond_broadcast(&handshake_cond);
        }else if(ctx->duplicate_ack_count == 3 && !ctx->fast_recovery){
            reno_loss(ctx, 0);
            ctx->fast_recovery = 1;
            ctx->recovery_seq = ctx->snd_max;
            transmit_segment(ctx, ctx->send_head, 1);
            clock_gettime(CLOCK_MONOTONIC, &ctx->retransmission_timer_at);
            ctx->retransmission_timer_running = 1;
            pthread_cond_broadcast(&handshake_cond);
            /* 同一恢复窗口不因后续每组三个重复 ACK 再次减半或重传。 */
        }
    }else if(ack == ctx->snd_una && !advertised_window_unchanged){
        trace_event("ACK", "conn:%p reason:NON_DUPLICATE ack:%u peer:%u",
            (void*)ctx->sock, ack, (unsigned int)ctx->peer_rwnd);
        ctx->duplicate_ack = ack;
        ctx->duplicate_ack_count = 0;
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
    /* 本地测试服务端固定使用 172.17.0.3。在协议入口统一地址，确保监听表
     * 登记所用的四元组与 kernel.c 收包时构造的本地地址完全一致。 */
    bind_addr.ip = inet_network("172.17.0.3");
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

    /* 本地测试时主动连接目标固定为服务端 172.17.0.3，确保连接表登记地址
     * 与底层 UDP 报文的实际目的地址一致。 */
    target_addr.ip = inet_network("172.17.0.3");
    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    // 主动连接方是客户端，本地测试环境中的客户端地址为 172.17.0.2。
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

        pthread_mutex_lock(&handshake_lock);
        send_control(ctx, ctx->iss, 0, SYN_FLAG_MASK);
        pthread_mutex_unlock(&handshake_lock);
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

    /* 先保存应用读取前真正通告的窗口。读取释放空间后，仅当接收端 SWS
     * 规则允许右边界推进时才发送窗口更新 ACK。 */
    uint16_t window_before = ctx ? receive_window_locked(ctx) : 0U;
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
        uint16_t window_after = receive_window_locked(ctx);
        if(window_after != window_before && !ctx->failed && sock->state != CLOSED)
            send_control(ctx, ctx->snd_nxt, ctx->rcv_nxt, ACK_FLAG_MASK);
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
    uint16_t advertised_window = get_advertised_window(pkt);
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
        /* 根据本机角色填写子连接的对端地址：本地测试服务端收到的连接来自
         * 客户端 172.17.0.2；反向角色下将对端记录为服务端 172.17.0.3。 */
        new_conn->established_remote_addr.ip = strcmp(hostname, "server") == 0
            ? inet_network("172.17.0.2") : inet_network("172.17.0.3");
        /* generate_isn 内部会取得 handshake_lock，因此必须在进入下面的原子
         * 初始化区之前生成，避免同一线程重复加锁。 */
        uint32_t child_iss = generate_isn(new_conn);

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
        ctx->iss = child_iss;
        ctx->snd_nxt = ctx->iss + 1U;
        ctx->snd_una = ctx->snd_nxt;
        ctx->snd_max = ctx->snd_nxt;
        ctx->rto_ms = INITIAL_HANDSHAKE_RTO_MS;
        /* SYN 尚不知道服务端序号，故其 ACK 字段不能直接形成窗口右边界；
         * 服务端以自己的首个可发送序号为左边界应用客户端在 SYN 中的窗口。 */
        update_peer_window_locked(ctx, ctx->snd_una, advertised_window);
        trace_sender_window_locked(ctx);
        new_conn->state = SYN_RECV;
        established_socks[cal_hash(new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port)] = new_conn;
        send_control(ctx, ctx->iss, ctx->rcv_nxt,
            SYN_FLAG_MASK | ACK_FLAG_MASK);
        pthread_mutex_unlock(&handshake_lock);
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
        /* 客户端发送 SYN 时尚未知服务端 ISN，曾以 rcv_nxt=0 计算过本端窗口。
         * 学到 IRS 后必须重建绝对右边界，再在第三次握手中通告正确窗口。 */
        ctx->advertised_window_initialized = 0;
        update_peer_window_locked(ctx, ack, advertised_window);
        trace_sender_window_locked(ctx);
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
        if(ctx->syn_was_retransmitted) ctx->cwnd = RDT_SMSS;
        ctx->congestion_state = ctx->cwnd < ctx->ssthresh ? SLOW_START : CONGESTION_AVOIDANCE;
        trace_congestion(ctx, "HANDSHAKE", ctx->congestion_state);
        sock->state = ESTABLISHED;
        pthread_cond_broadcast(&handshake_cond);
        pthread_mutex_unlock(&handshake_lock);
        return 0;
    }

    if(sock->state == SYN_RECV && ctx != NULL){
        if((flags & SYN_FLAG_MASK) && seq == ctx->irs){
            /* 首个 SYN-ACK 可能丢失；收到同一 SYN 时立即重发有效 SYN-ACK。 */
            ctx->syn_was_retransmitted = 1;
            send_control(ctx, ctx->iss, ctx->rcv_nxt,
                SYN_FLAG_MASK | ACK_FLAG_MASK);
            pthread_mutex_unlock(&handshake_lock);
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
            update_peer_window_locked(ctx, ack, advertised_window);
            if(ctx->syn_was_retransmitted) ctx->cwnd = RDT_SMSS;
            ctx->congestion_state = ctx->cwnd < ctx->ssthresh ? SLOW_START : CONGESTION_AVOIDANCE;
            trace_congestion(ctx, "HANDSHAKE", ctx->congestion_state);
            trace_sender_window_locked(ctx);
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
        send_control(ctx, final_seq, final_ack, ACK_FLAG_MASK);
        pthread_mutex_unlock(&handshake_lock);
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
    /* 先用 ACK 与首部窗口形成对端绝对窗口右边界，再推进 snd_una。窗口字段
     * 发生变化的纯 ACK 不能计作重复 ACK，否则会误触发快速重传。 */
    if(flags & ACK_FLAG_MASK){
        int window_unchanged = ctx->peer_window_initialized &&
            ctx->peer_rwnd == advertised_window &&
            ctx->peer_window_right == ack + (uint32_t)advertised_window;
        update_peer_window_locked(ctx, ack, advertised_window);
        /* 带数据或 FIN 的 ACK 不满足 RFC 5681 重复 ACK 定义；新累计 ACK
         * 仍正常处理，仅禁止其进入重复 ACK 计数分支。 */
        process_ack_locked(ctx, ack, window_unchanged && data_len == 0 &&
            !(flags & FIN_FLAG_MASK));
        trace_sender_window_locked(ctx);
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
