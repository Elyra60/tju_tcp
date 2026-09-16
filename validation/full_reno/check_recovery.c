/* 复用已有夹具但执行独立专项断言；真实发送线程负责窗口允许的新数据发送。 */
#define main regression_main
#include "../reno/check_reno.c"
#undef main
static void await_flight(handshake_ctx_t* c, uint32_t expected){
 for(int i=0;i<200;i++){
  pthread_mutex_lock(&handshake_lock); uint32_t f=flight_size(c); pthread_mutex_unlock(&handshake_lock);
  if(f==expected) return;
  usleep(1000);
 }
 assert(!"发送线程未按窗口发送");
}
int main(void){
 assert(TJU_FULL_RENO); alarm(10);
 handshake_ctx_t*c=fixture(12); send_segment_t*p=c->send_head;
 for(int i=0;p;p=p->next,i++)if(i>=8)p->sent=0;
 c->snd_max=c->snd_una+8*RDT_SMSS; c->cwnd=8*RDT_SMSS;
 update_peer_window_locked(c,c->snd_una,65535);
 pthread_mutex_lock(&handshake_lock);
 for(int i=0;i<3;i++)process_ack_locked(c,c->snd_una,1);
 assert(c->ssthresh==4*RDT_SMSS && c->cwnd==7*RDT_SMSS);
 pthread_mutex_unlock(&handshake_lock);
 pthread_t sender; pthread_create(&sender,NULL,reliable_sender_worker,c);
 pthread_mutex_lock(&handshake_lock);
 process_ack_locked(c,c->snd_una,1); assert(c->cwnd==8*RDT_SMSS);
 process_ack_locked(c,c->snd_una,1); assert(c->cwnd==9*RDT_SMSS);
 pthread_mutex_unlock(&handshake_lock);
 await_flight(c,9*RDT_SMSS);
 puts("PASS third ACK inflation and fifth ACK sends new data in recovery");
 pthread_mutex_lock(&handshake_lock);
 update_peer_window_locked(c,c->snd_una,9*RDT_SMSS);
 uint32_t before=c->cwnd; process_ack_locked(c,c->snd_una,0); assert(c->cwnd==before && c->reno_wait_ack);
 process_ack_locked(c,c->snd_una,1); assert(c->cwnd==10*RDT_SMSS);
 pthread_mutex_unlock(&handshake_lock);
 usleep(20000); await_flight(c,9*RDT_SMSS);
 puts("PASS rwnd blocks inflated cwnd; window update does not inflate or exit");
 pthread_mutex_lock(&handshake_lock);
 unsigned sent=transmissions; process_ack_locked(c,c->send_head->end_seq,1);
 assert(c->cwnd==4*RDT_SMSS && !c->reno_wait_ack && !c->fast_recovery);
 assert(c->congestion_state==CONGESTION_AVOIDANCE && transmissions==sent);
 puts("PASS partial recovery ACK deflates and exits without NewReno repair");
 reno_loss(c,0); c->fast_recovery=1; reno_loss(c,1);
 assert(c->cwnd==RDT_SMSS && !c->fast_recovery && !c->reno_wait_ack);
 assert(c->congestion_state==SLOW_START);
 c->sender_stop=1; pthread_cond_broadcast(&handshake_cond); pthread_mutex_unlock(&handshake_lock);
 pthread_join(sender,NULL);
 puts("PASS RTO during recovery resets all recovery state"); trace_flush_pending(); return 0;
}
