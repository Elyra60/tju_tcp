/* 使用真实发送线程检查小窗口前进、字节顺序、逐段超时与退避。 */
#define main previous_main
#include "../reno/check_reno.c"
#undef main

static void small_window(void){
    handshake_ctx_t* c = fixture(1);
    send_segment_t* head = c->send_head;
    for(int i=0; i<head->len; i++) head->data[i]=(char)(i&255);
    head->sent=0;
    c->snd_max=c->snd_una;
    update_peer_window_locked(c,c->snd_una,32);
    pthread_t worker;
    assert(!pthread_create(&worker,NULL,reliable_sender_worker,c));
    for(int i=0;i<500;i++){
        pthread_mutex_lock(&handshake_lock);
        int ready=flight_size(c)==32;
        pthread_mutex_unlock(&handshake_lock);
        if(ready) break;
        usleep(1000);
    }
    pthread_mutex_lock(&handshake_lock);
    assert(flight_size(c)==32 && head->len==32 && head->sent);
    assert(head->next && !head->next->sent && head->next==c->send_tail);
    assert(c->queued_bytes==RDT_SMSS && head->end_seq==head->next->seq);
    for(int i=0;i<head->next->len;i++) assert((unsigned char)head->next->data[i]==((i+32)&255));
    c->sender_stop=1;
    pthread_cond_broadcast(&handshake_cond);
    pthread_mutex_unlock(&handshake_lock);
    pthread_join(worker,NULL);
    puts("PASS 32-byte peer window progresses without exceeding rwnd or losing queued bytes");
}

static void rdt_timers(void){
    handshake_ctx_t* c=fixture(3);
    c->cwnd=TCP_RECVWN_SIZE;
    c->rto_ms=30;
    c->have_rtt_sample=1;
    update_peer_window_locked(c,c->snd_una,65535);
    pthread_t worker;
    pthread_mutex_lock(&handshake_lock);
    /* 三个不同段都过期；第二轮应退避至60ms而非立即再次发出。 */
    for(send_segment_t* p=c->send_head;p;p=p->next) p->sent_at.tv_sec-=1;
    assert(!pthread_create(&worker,NULL,reliable_sender_worker,c));
    pthread_mutex_unlock(&handshake_lock);
    for(int i=0;i<500;i++){
        pthread_mutex_lock(&handshake_lock);
        int done=c->send_tail->retransmitted;
        pthread_mutex_unlock(&handshake_lock);
        if(done) break;
        usleep(1000);
    }
    pthread_mutex_lock(&handshake_lock);
    for(send_segment_t* p=c->send_head;p;p=p->next) assert(p->retransmitted==1);
    assert(c->cwnd==TCP_RECVWN_SIZE && flight_size(c)==3*RDT_SMSS);
    unsigned before=transmissions;
    pthread_mutex_unlock(&handshake_lock);
    usleep(15000);
    pthread_mutex_lock(&handshake_lock);
    assert(transmissions==before);
    process_ack_locked(c,c->snd_max,1);
    assert(!c->send_head && !c->queued_bytes);
    c->sender_stop=1;
    pthread_cond_broadcast(&handshake_cond);
    pthread_mutex_unlock(&handshake_lock);
    pthread_join(worker,NULL);
    puts("PASS per-segment timeout, backoff, unchanged flow cap and cumulative release");
}

int main(int argc,char**argv){
    alarm(40);
    if(argc>1){integration(argv[1]);return 0;}
    small_window();
    if(TJU_RDT_PROFILE) rdt_timers();
    trace_flush_pending();
    return 0;
}
