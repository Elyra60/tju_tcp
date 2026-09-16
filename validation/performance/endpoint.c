/* 性能实验端点：真实协议传输固定数据；接收耗时从首个字节返回到最后字节返回。
 * 文件写盘和连接关闭放在计时之后，避免把 TIME_WAIT 计入有效吞吐率。 */
#include "tju_tcp.h"
#include <assert.h>
#include <time.h>
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
int main(int argc,char**argv){
 assert(argc==3); alarm(180); int server=!strcmp(argv[1],"server");
 const int total=2000000; char*buf=malloc(total); assert(buf);
 startSimulation(); tju_tcp_t*s=tju_socket(); tju_sock_addr a={inet_network("172.17.0.3"),1234};
 if(server){
  assert(!tju_bind(s,a)); assert(!tju_listen(s)); s=tju_accept(s); assert(s);
  int n=tju_recv(s,buf,1); assert(n==1); double begin=now(); int off=1;
  while(off<total){n=tju_recv(s,buf+off,total-off); assert(n>0); off+=n;}
  double elapsed=now()-begin;
  printf("METRIC bytes=%d elapsed=%.9f mbps=%.9f\n",total-1,elapsed,8.0*(total-1)/elapsed/1e6); fflush(stdout);
  assert(tju_recv(s,buf,1)==0);
 }else{
  for(int i=0;i<total;i++)buf[i]=(char)((i*37+i/101)&255);
  assert(!tju_connect(s,a)); assert(!tju_send(s,buf,total));
 }
 FILE*f=fopen(argv[2],"wb"); assert(f); assert(fwrite(buf,1,total,f)==(size_t)total); fclose(f);
 assert(!tju_close(s)); sleep(3); free(buf); return 0;
}
