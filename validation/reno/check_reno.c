/* 新增隔离验证：直接编译真实协议实现，替换的只有下层网络传输。
 * 不读取或改写 test 产物；本文件不是课程平台测试，也不模拟平台评分。 */
#include <assert.h>
#include <unistd.h>
static int test_hostname(char* name, size_t length){
    const char role[] = "server";
    if(length < sizeof(role)) return -1;
    for(size_t i = 0; i < sizeof(role); ++i) name[i] = role[i];
    return 0;
}
#define gethostname test_hostname
#include "../../src/tju_tcp.c"
#undef gethostname

static unsigned transmissions;
static int network_enabled;
static int drop_syn, drop_synack, drop_data, data_number, dropped;
typedef struct wire_packet { char* data; struct wire_packet* next; } wire_packet;
static wire_packet *wire_head, *wire_tail;
static pthread_mutex_t wire_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wire_cond = PTHREAD_COND_INITIALIZER;

int cal_hash(uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port){
    (void)local_ip; (void)remote_ip; (void)remote_port;
    return local_port % MAX_SOCK;
}
void sendToLayer3(char* packet, int length){
    transmissions++;
    if(!network_enabled) return;
    uint16_t payload = get_plen(packet) - get_hlen(packet);
    /* 在真正发送新数据前检查窗口，重传不重复计入 FlightSize。 */
    for(handshake_ctx_t* ctx = handshake_list; ctx; ctx = ctx->next){
        if(ctx->sock->established_local_addr.port == get_src(packet) && payload &&
           !seq_before(get_seq(packet), ctx->snd_max)){
            assert(flight_size(ctx) + payload <= sender_effective_window_locked(ctx));
        }
    }
    if(drop_syn && get_flags(packet) == SYN_FLAG_MASK){ drop_syn = 0; dropped++; return; }
    if(drop_synack && get_flags(packet) == (SYN_FLAG_MASK | ACK_FLAG_MASK)){
        drop_synack = 0; dropped++; return;
    }
    if(payload && get_src(packet) == 5678){
        data_number++;
        if(data_number == drop_data || (drop_data == 12 && data_number == 14)){
            dropped++; return;
        }
    }
    wire_packet* item = calloc(1, sizeof(*item));
    assert(item);
    item->data = malloc(length);
    assert(item->data);
    memcpy(item->data, packet, length);
    pthread_mutex_lock(&wire_lock);
    if(wire_tail) wire_tail->next = item; else wire_head = item;
    wire_tail = item;
    pthread_cond_signal(&wire_cond);
    pthread_mutex_unlock(&wire_lock);
}
static void* network_worker(void* unused){
    (void)unused;
    for(;;){
        pthread_mutex_lock(&wire_lock);
        while(!wire_head) pthread_cond_wait(&wire_cond, &wire_lock);
        wire_packet* item = wire_head;
        wire_head = item->next;
        if(!wire_head) wire_tail = NULL;
        pthread_mutex_unlock(&wire_lock);
        usleep(500); /* 可复现的排队延迟，让真实 ACK/定时线程交互。 */
        tju_tcp_t* target = NULL;
        pthread_mutex_lock(&handshake_lock);
        for(handshake_ctx_t* ctx = handshake_list; ctx; ctx = ctx->next){
            if(ctx->sock->state != CLOSED && ctx->sock->state != LISTEN &&
               ctx->sock->established_local_addr.port == get_dst(item->data)){
                target = ctx->sock; break;
            }
        }
        if(!target) target = listen_socks[get_dst(item->data) % MAX_SOCK];
        pthread_mutex_unlock(&handshake_lock);
        if(target) tju_handle_packet(target, item->data);
        free(item->data); free(item);
    }
    return NULL;
}

static handshake_ctx_t* fixture(unsigned segments){
    tju_tcp_t* sock = tju_socket();
    handshake_ctx_t* ctx = get_handshake(sock);
    sock->state = ESTABLISHED;
    ctx->snd_una = UINT32_MAX - 5000U; /* 包含序号回绕的确认测试。 */
    ctx->snd_max = ctx->snd_nxt = ctx->snd_una;
    for(unsigned i = 0; i < segments; i++){
        send_segment_t* seg = calloc(1, sizeof(*seg));
        seg->data = calloc(RDT_SMSS, 1);
        seg->len = RDT_SMSS;
        seg->seq = ctx->snd_nxt;
        seg->end_seq = seg->seq + RDT_SMSS;
        seg->sent = 1;
        clock_gettime(CLOCK_MONOTONIC, &seg->sent_at);
        if(ctx->send_tail) ctx->send_tail->next = seg; else ctx->send_head = seg;
        ctx->send_tail = seg;
        ctx->snd_max = ctx->snd_nxt = seg->end_seq;
        ctx->queued_bytes += RDT_SMSS;
    }
    return ctx;
}
static void unit_checks(void){
    handshake_ctx_t* ctx = fixture(20);
    assert(ctx->cwnd == TJU_INITIAL_CWND && ctx->ssthresh == TJU_INITIAL_SSTHRESH);
    update_peer_window_locked(ctx, ctx->snd_una, 2000);
    assert(sender_effective_window_locked(ctx) == 2000);
    update_peer_window_locked(ctx, ctx->snd_una, 65535);
    assert(sender_effective_window_locked(ctx) == ctx->cwnd);
    uint32_t before = ctx->cwnd;
    process_ack_locked(ctx, ctx->snd_una + 100, 1);
    assert(ctx->cwnd == before + 100 && ctx->send_head->len == RDT_SMSS - 100);
    assert(flight_size(ctx) == 20 * RDT_SMSS - 100);
    before = ctx->cwnd;
    process_ack_locked(ctx, ctx->snd_una + 2 * RDT_SMSS, 1);
    assert(ctx->cwnd == before + RDT_SMSS);
    before = ctx->cwnd;
    process_ack_locked(ctx, ctx->snd_max + 1, 1);
    process_ack_locked(ctx, ctx->snd_una - 1, 1);
    process_ack_locked(ctx, ctx->snd_una, 0);
    assert(ctx->cwnd == before && ctx->duplicate_ack_count == 0);
    puts("PASS initialization, rwnd/cwnd, partial ACK, wraparound, stale/future/window ACK");

    ctx->cwnd = ctx->ssthresh = 10 * RDT_SMSS;
    ctx->ca_acked_bytes = 0;
    for(int i = 0; i < 10 * RDT_SMSS - 1; i++) reno_new_ack(ctx, 1);
    assert(ctx->cwnd == 10 * RDT_SMSS);
    reno_new_ack(ctx, 1);
    assert(ctx->cwnd == 11 * RDT_SMSS);
    puts("PASS congestion avoidance: one SMSS per acknowledged cwnd, ACK splitting");

    uint32_t half = flight_size(ctx) / 2;
    unsigned sent = transmissions;
    for(int i = 0; i < 3; i++) process_ack_locked(ctx, ctx->snd_una, 1);
    assert(ctx->ssthresh == half && ctx->cwnd == half && ctx->reno_wait_ack);
    for(int i = 0; i < 12; i++) process_ack_locked(ctx, ctx->snd_una, 1);
    assert(transmissions == sent + 1 && ctx->ssthresh == half);
    process_ack_locked(ctx, ctx->send_head->end_seq, 1);
    assert(ctx->cwnd == half && ctx->congestion_state == CONGESTION_AVOIDANCE);
    assert(transmissions == sent + 2); /* 保留原有部分 ACK 多丢包修复。 */
    reno_loss(ctx, 1);
    assert(ctx->cwnd == RDT_SMSS && !ctx->fast_recovery && !ctx->reno_wait_ack);
    assert(ctx->congestion_state == SLOW_START && ctx->duplicate_ack_count == 0);
    ctx = fixture(1);
    reno_loss(ctx, 1);
    assert(ctx->ssthresh == 2 * RDT_SMSS);
    puts("PASS fast retransmit once, partial recovery, RTO reset, threshold floor");
    trace_flush_pending();
}

static void* close_socket(void* sock){
    assert(tju_close(sock) == 0);
    return NULL;
}
static void integration(const char* mode){
    drop_syn = strcmp(mode, "syn_loss") == 0;
    drop_synack = strcmp(mode, "synack_loss") == 0;
    drop_data = strcmp(mode, "rto") == 0 ? 1 : (strcmp(mode, "multi_loss") == 0 ? 12 : 0);
    int handshake_loss = drop_syn || drop_synack;
    int server_handshake_loss = drop_synack;
    int simultaneous = strcmp(mode, "simultaneous") == 0;
    network_enabled = 1;
    pthread_t net;
    pthread_create(&net, NULL, network_worker, NULL);
    tju_tcp_t* listener = tju_socket();
    tju_sock_addr address = { inet_network("172.17.0.3"), 1234 };
    assert(tju_bind(listener, address) == 0);
    assert(tju_listen(listener) == 0);
    tju_tcp_t* client = tju_socket();
    assert(tju_connect(client, address) == 0);
    tju_tcp_t* server = tju_accept(listener);
    assert(server);
    pthread_mutex_lock(&handshake_lock);
    assert(find_handshake(client)->cwnd == (handshake_loss ? RDT_SMSS : TJU_INITIAL_CWND));
    assert(find_handshake(server)->cwnd == (server_handshake_loss ? RDT_SMSS : TJU_INITIAL_CWND));
    pthread_mutex_unlock(&handshake_lock);
    size_t total = 200000;
    char* data = malloc(total);
    char* received = malloc(total);
    for(size_t i = 0; i < total; i++) data[i] = (char)((i * 37 + i / 101) & 255);
    assert(tju_send(client, data, total) == 0);
    /* close 与数据交付并行，验证 FIN 等待可靠发送完成。 */
    pthread_t closer;
    if(!simultaneous) pthread_create(&closer, NULL, close_socket, client);
    if(strcmp(mode, "zero_window") == 0){
        sleep(3);
        pthread_mutex_lock(&handshake_lock);
        assert(find_handshake(client)->peer_rwnd == 0);
        pthread_mutex_unlock(&handshake_lock);
    }
    size_t offset = 0;
    while(offset < total){
        int got = tju_recv(server, received + offset, (int)(total - offset));
        assert(got > 0);
        offset += got;
    }
    assert(memcmp(data, received, total) == 0);
    if(simultaneous){
        /* 已完成正向传输后反向传一段，检查双方 Reno 计数相互独立。 */
        assert(tju_send(server, data, 4096) == 0);
        size_t reverse = 0;
        while(reverse < 4096){
            int got = tju_recv(client, received + reverse, 4096 - reverse);
            assert(got > 0); reverse += got;
        }
        assert(memcmp(data, received, 4096) == 0);
        pthread_t server_closer;
        pthread_create(&closer, NULL, close_socket, client);
        pthread_create(&server_closer, NULL, close_socket, server);
        pthread_join(server_closer, NULL);
        pthread_join(closer, NULL);
    }else{
        pthread_join(closer, NULL);
        assert(tju_recv(server, received, 1) == 0);
        assert(tju_close(server) == 0);
    }
    sleep(3);
    pthread_mutex_lock(&handshake_lock);
    assert(client->state == CLOSED && server->state == CLOSED);
    assert(!find_handshake(client)->failed && !find_handshake(server)->failed);
    pthread_mutex_unlock(&handshake_lock);
    printf("PASS integration %s: %zu bytes identical, handshake, window bounds, draining close; dropped=%d\n", mode, total, dropped);
    trace_flush_pending();
    free(data); free(received);
}
int main(int argc, char** argv){
    alarm(30);
    if(argc > 1) integration(argv[1]); else unit_checks();
    return 0;
}
