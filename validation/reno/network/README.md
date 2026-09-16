# 基础 Reno 定向实验与图像核验

## 结论

第七部分五组真实网络实验完成，发送文件与接收文件逐字节一致；共核算 737 次拥塞控制快照，未发现窗口计算不一致。逐组检查了 7 张课程脚本图像和额外的 Reno 核验图。该结论只适用于这里保存的定向实验，不代表课程平台满分、完整回归测试或零窗口覆盖。

| 场景 | 实验设计 | 实际证据（窗口单位：字节） | 核算次数 |
|---|---|---|---|
| slow_start | 无丢包，传输 20000 字节，阈值65535 | cwnd从4125增至24125，无RTO或重传 | 16 |
| congestion_avoidance | 无丢包，传输 100000 字节 | cwnd 从 4125 慢启动到阈值 22000，再以拥塞避免增长到 26125；没有接收窗口限制快照 | 74 |
| rto | 丢弃第 1 个数据包，传输 300000 字节 | 1 次 RTO、1 次重传；FlightSize=4125，ssthresh=max(4125/2,2750)=2750，cwnd=1375 | 219 |
| triple_ack | 丢弃第 12 个数据包，传输 300000 字节 | 3 次重复 ACK 触发快速重传；FlightSize=19250，ssthresh=cwnd=9625；新 ACK 后进入拥塞避免；没有 RTO | 208 |
| small_rwnd | 通告窗口上限 5500，传输 300000 字节 | cwnd 最大 35750，实际 FlightSize 最大 5500；没有 RTO 或重传 | 220 |

RTO关键快照位于rto/test/client.event.trace第25行，距首次数据发送1.051427秒；快速重传位于triple_ack/test/client.event.trace第156行，0.134916秒。以上均对应output/report7_20260915_153313。全部窗口更新的原始行号、数值和核算公式保存在各组window_updates.md / window_updates.json。

## 环境与隔离

- 使用 WSL Ubuntu 20.04、独立客户端/服务端网络命名空间、veth、tc/netem 和 tcpdump，运行真实 tju API 与项目 TCP/UDP 实现。
- 根据当前源码匹配地址 172.17.0.2 / 172.17.0.3、UDP 端口 20218；不是未经检查沿用历史环境。
- 每方向延迟 20 ms、速率 100 Mbit/s、无随机丢包。用确定性丢包区分 RTO 与快速重传，未照搬说明文档的高丢包默认参数。
- SMSS 保持 1375；实验 IW=4125，专用编译阈值 ssthresh=22000（16 SMSS），TJU_MSL=1 用于缩短等待。这些实验覆盖值不是课程平台发布配置的确认结论，也没有改写生产默认配置。
- impairment.c 仅在实验进程中通过 LD_PRELOAD 拦截 sendto：丢弃指定数据包或将实际报文的通告窗口保守限制为 5500。小窗口实验不是把生产接收缓冲区改小，报文中的窗口值另由抓包核对。
- 原项目 test 目录只读，本轮未覆盖其中代码、日志、Trace 或图像。已有 Git 差异予以保留。新实验及输出全部放在 validation/reno/network 下。

## 核验方法

analyze.py 根据实际 SEND 序号和累计 ACK 独立重建 FlightSize，再与日志快照比较；依据新确认字节数逐步重算慢启动、拥塞避免的字节累计、RTO 及快速重传响应。每次新发送检查 cwnd 与对端窗口的共同限制。握手快照不增长窗口。

此外检查 tcpdump 保存的报文：数据包数与注入丢包对应，对端窗口更新有实际报文来源。收发文件执行 cmp 并记录 SHA-256；不是只看曲线形状判断成功。

图像使用原 test/gen_graph_win.py 与 test/gen_graph_seq.py 的当前内容生成，未修改脚本。通过运行时重定向 savefig，将输出写入隔离目录；脚本打印的 /vagrant/tju_tcp/test 路径不是实际保存位置。窗口图配对使用服务端 Trace 和客户端 --sender Trace；序号图来自服务端抓包。额外核验图只绘制真实事件与重建数据，不补造期望曲线。

## 图像判读与限制

- 无丢包图可见先慢启动、后较缓的拥塞避免阶梯；RTO 图下降到 1 SMSS；快速重传图下降到 7 SMSS；小窗口图中 SWND 保持 4 SMSS，即使 CWND 继续增长。
- 课程窗口图使用 segment 单位，当前脚本已按 1375 换算，单位正确；额外 Reno 核验图使用字节。
- ReceiveWindowSize 图展示接收端空闲缓冲区，不等于小窗口实验人为限制后的线上的通告窗口。检查 FlightSize 是否受 5500 限制，应看 Reno核验.png、PEER_WINDOW 和抓包，不能直接拿绿色空闲缓冲区曲线代替。
- 短实验的吞吐量图只有少数时间桶，呈水平线或少量阶梯并不表示数据造假，也不适合用来评价长期吞吐量。序号图的科学计数偏移来自真实 ISN。RTT 图中的超时阈值与 RTT 不是同一指标。
- 课程组合图有自身的展示粒度；关键瞬间的精确数值以逐事件核验图和核算表为准。
- 原项目 client.event.trace 最后一行被截断。其可解析前缀的 95 次快照核算一致，包含 20 次 RTO、2 次快速重传及 26 次重传，因此原图反复下降有日志依据；但不能据此声明原测试完整成功。
- output 下早期非 report7 实验曾因路径空格造成预加载失败，不计为有效丢包覆盖；主结论采用随后独立运行的五组 report7 结果。

## 产物与复现

第七部分的有效结果在 output/report7_20260915_153313：audit_summary.json 为机器可读汇总；各组包含 config.txt、实际收发文件、日志、server.pcap、窗口核算表以及 test 子目录中的双端 Trace 和图像。source_snapshot 与 build_sources.sha256 保存并核对构建输入。旧的重复网络结果不作为当前结论保留。

在已安装 gcc、iproute2、tcpdump 的 Linux/WSL 中，从项目根目录以具备网络命名空间权限的身份运行：

```bash
bash validation/reno/network/run_report.sh
```

该命令每次生成新的时间戳目录，不覆盖历史证据，不调用会写原test的课程驱动。当前脚本显式设置-DTJU_FULL_RENO=0，防止生产默认完整Reno改变基础模式口径。analyze_report.py仍绑定历史目录，分析新运行须将root改为新目录。历史git_head.txt仅为工作区基线，实际输入以source_snapshot和build_sources.sha256为准。分析需要matplotlib、numpy、scapy和可用中文字体：

```text
python validation/reno/network/analyze.py --deps <已安装依赖的目录>
python validation/reno/network/review_figures.py <已安装依赖的目录>
```

本轮没有为通过测试而修改生产 TCP 代码，也没有修改受限制的协议头或 SMSS。
