/* 独立实验端点：调用真实 TJU API，输出全量收发文件用于比对。 */
#include "tju_tcp.h"
#include <assert.h>
#include <time.h>
int main(int argc, char** argv){
    assert(argc == 3);
    alarm(30);
    int server = strcmp(argv[1], "server") == 0;
    startSimulation();
    tju_tcp_t* sock = tju_socket();
    tju_sock_addr addr = {inet_network("172.17.0.3"), 1234};
    const int total = getenv("TEST_BYTES") ? atoi(getenv("TEST_BYTES")) : 300000;
    assert(total > 0 && total <= 300000);
    char* buf = malloc(total);
    assert(buf);
    if(server){
        assert(tju_bind(sock, addr) == 0);
        assert(tju_listen(sock) == 0);
        sock = tju_accept(sock);
        assert(sock);
        int offset = 0;
        while(offset < total){
            int n = tju_recv(sock, buf + offset, total - offset);
            assert(n > 0); offset += n;
        }
        assert(tju_recv(sock, buf, 1) == 0);
    }else{
        for(int i = 0; i < total; i++) buf[i] = (char)((i * 37 + i / 101) & 255);
        assert(tju_connect(sock, addr) == 0);
        assert(tju_send(sock, buf, total) == 0);
    }
    FILE* file = fopen(argv[2], "wb");
    assert(file && fwrite(buf, 1, total, file) == (size_t)total);
    fclose(file);
    assert(tju_close(sock) == 0);
    sleep(3); /* 实验构建的 MSL=1，让 FIN 和 TIME_WAIT 日志完整保存。 */
    printf("PASS %s bytes=%d\n", argv[1], total);
    free(buf);
    return 0;
}
