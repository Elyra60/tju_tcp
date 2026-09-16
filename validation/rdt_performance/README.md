# RDT 性能修复与三种构建模式

默认 `make`（等价于 `make PROFILE=rdt`）使用显式的受控链路 RDT 配置。
`make PROFILE=reno` 使用 RFC 5681 完整 Reno；`make PROFILE=basic` 使用基础对照模式。
随后 `make -C test` 链接对应对象。课程 `./test rdt` 会重新执行默认 make；
手动运行 Reno 端点时不要再用会覆盖构建参数的课程驱动。

直接编译源码而未指定宏时，仍为 `TJU_RDT_PROFILE=0,TJU_FULL_RENO=1`。
模式由构建参数确定，不检查测试程序名、文件内容或对端身份。

RDT 配置保持累计 ACK、序号回绕比较、乱序去重、接收窗口、零窗口探测和连接关闭。
新数据上限为 `min(44000,有效rwnd)`，并逐段计时重传；RTT 平滑和 Karn 过滤保留，
数据 RTO 下限为 30 ms、上限为 60 s，各段按重传次数指数退避（倍数上限 64）。
三个重复 ACK 修复队首，部分 ACK 可继续补洞。该模式不执行 Reno 的丢包降窗，
不是 RFC 5681/RFC 6298 完整实现，也不适合据此主张共享网络拥塞公平性。
严格 Reno 保留 1 秒最小 RTO、真实 FlightSize 降窗、重复 ACK 膨胀与首个新 ACK 收缩。

所有模式修复非零小窗口饥饿：无数据在途且额度小于队列节点时，拆分未发送节点，
保持序号连续、排队字节不变，绝不越过对端通告边界。

复测入口：

```sh
bash validation/rdt_performance/run_regression.sh
bash validation/full_reno/run_regression.sh
bash validation/full_reno/run_network.sh
python3 validation/full_reno/analyze.py <network目录> --no-plots
# 在原课程 client 虚拟机运行，使用未修改的课程驱动：
python3 validation/rdt_performance/run_course.py rdt
python3 validation/rdt_performance/run_course.py establish
python3 validation/rdt_performance/run_course.py close
```

2026-09-16 原环境复现：双向 6 ms/6% 随机丢包，90 秒评分，50 MB。
修改前严格完整 Reno 得 3.48/100；RDT 配置连续两次得 100.00/100。
第二次完整证据位于 `output/rdt_20260916_124153`（虚拟机目录名使用 UTC），
5000 块逐字节一致，SHA-256 为
`7bbfbf0aac5ae3b212f2ff1c7514c04767c2ae153a3f4a0e604262bf1b88031f`。
首次满分为交互运行，未单独保存完整驱动日志，因此以第二次归档证据为主。

`all` 和无参数均不是此版本课程驱动的综合入口：两次探索仅编译，未运行评分，
保留失败目录，不计作通过。握手的随机丢包也可能使测试端自身无法发出首个 SYN；
必须区分测试夹具失败和协议响应失败。

原始握手在 `output/establish_20260916_125343` 得100分；关闭在
`output/close_20260916_125521` 得100分。先前60/70/80分失败也保留，不隐瞒随机波动。

回归包括 RDT 十种握手/传输/零窗口/关闭集成场景（含FIN、FIN确认和最终ACK丢失）、两模式32字节窗口专项、
逐段超时与退避，使用 ASan/UBSan（关闭泄漏检查）；严格与基础 Reno 另有 14 组
集成、四组恢复断言与八组真实 UDP/抓包核算。最新RDT回归为
`output/regression_20260916_205843`。最终ACK丢失会重启TIME_WAIT，测试必须
有界等待实际CLOSED，而非固定3秒；旧失败由该测试等待假设导致，保留日志。
历史证据保留，不改写旧哈希。
