/* 仅测试进程加载的链路注入器，不修改协议代码、课程文件或 Trace。
 * DROP_DATA=N 丢弃客户端第 N 次有载荷发送，返回成功模拟网络丢包。
 * CAP_WINDOW=N 将测试接收端真实通告限制到 N 字节，制造受控小窗口对端。
 * 只收紧有效通告，不扩大缓冲区；发送方实际收到的字段由抓包独立核对。 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
ssize_t sendto(int fd, const void* data, size_t len, int flags,
               const struct sockaddr* address, socklen_t addrlen){
    static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
    static unsigned data_count;
    if(!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    const unsigned char* p = data;
    const char* drop = getenv("DROP_DATA");
    if(len > 20 && drop && ++data_count == (unsigned)atoi(drop)){
        uint32_t seq = ((uint32_t)p[4]<<24) | ((uint32_t)p[5]<<16) | ((uint32_t)p[6]<<8) | p[7];
        fprintf(stderr, "INJECT_DROP packet=%u seq=%u length=%zu\n", data_count, seq, len - 20);
        return (ssize_t)len;
    }
    const char* cap_text = getenv("CAP_WINDOW");
    if(len >= 20 && len <= 1400 && cap_text){
        unsigned cap = (unsigned)atoi(cap_text);
        unsigned window = ((unsigned)p[17]<<8) | p[18];
        if(window > cap){
            unsigned char copy[1400];
            memcpy(copy, data, len);
            copy[17] = cap >> 8; copy[18] = cap & 255;
            return real_sendto(fd, copy, len, flags, address, addrlen);
        }
    }
    return real_sendto(fd, data, len, flags, address, addrlen);
}
