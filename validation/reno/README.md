# 基础 Reno 实现与隔离验证

协议改动集中在 `src/tju_tcp.c`，保持 `MAX_DLEN=1375`，未修改 `test`、
`global.h`、`kernel.h/.c` 或 `tju_packet.h/.c`。新增的验证程序仅用于本地诊断，
不是课程提供的测试或平台评分程序。

## 实现规则

- 每连接维护字节单位的 `cwnd`、`ssthresh` 和拥塞状态，统一由现有锁保护。
- 新数据上限取 `min(cwnd, 对端窗口相对 snd_una 的有效宽度)`。
  缩窗后已发数据仍可确认和重传，不通过无符号减法制造额外额度。
- 慢启动每个新累计 ACK 增加 `min(新确认字节数, SMSS)`。
- 拥塞避免累计确认当前 `cwnd` 字节后增长一个 SMSS；一次 ACK 至多增长一次。
- RTO 按实际 `FlightSize` 更新阈值，令 `cwnd=SMSS`，清除快速重传恢复状态，
  沿用原有 RTO 指数退避。
- 第三个有效重复 ACK 触发一次快速重传，
  `ssthresh=max(FlightSize/2, 2*SMSS)`，`cwnd=ssthresh`。
  首个新 ACK 后进入拥塞避免；同一恢复窗口不反复降窗。
- 保留原 RDT 的部分 ACK 后续缺口修复，不实现窗口膨胀型完整快速恢复。
- 握手 ACK 不增长 cwnd；SYN/SYN-ACK 重传后 IW 降为一个 SMSS。
- 累计 ACK 落在段内部时裁掉已确认前缀，使 FlightSize、排队长度和重传内容一致。

## 初始参数待平台核对

本地未找到课程平台发布的具体初值。目前默认 `TJU_INITIAL_CWND=4125`、
`TJU_INITIAL_SSTHRESH=65535`，前者为当前 SMSS 对应的 RFC 5681 兼容上限。
编译 `src/tju_tcp.c` 时可以用 `-DTJU_INITIAL_CWND=...`
和 `-DTJU_INITIAL_SSTHRESH=...` 覆盖；单位均为字节。
配置检查要求 IW 至少一个 SMSS 且不超过 RFC 上限，阈值在 2750 至 65535 之间。
正式提交前需要对照平台发布值，不能把上述默认值称为已核实的平台配置。

标准依据：https://www.rfc-editor.org/rfc/rfc5681.html
课程基础任务允许省略完整快速恢复，具体实现遵循说明书 5.5 的简化范围。

## Trace

设置 `TJU_TRACE_PATH` 指向隔离输出文件。未设置时沿用原有输出路径，
因此不要在保护的原仓库中直接运行会覆盖 test 的课程脚本。

原 SEND、RECV、DELV、RTTS、RWND、SWND 格式保留；CWND 保持
`type:... size:...` 格式，只在数值或类型改变时记录。类型 0 为慢启动、
1 为拥塞避免、2 为基本快速重传、3 为超时；超时后的协议状态仍是慢启动。

新增事件：

| 事件 | 含义 |
| --- | --- |
| SSTHRESH | 实际阈值变化 |
| CC | 连接标识、触发原因、拥塞状态、cwnd、ssthresh、peer、flight、ack |
| ACK / DUPACK | 有效累计确认及新增字节，或重复 ACK 计数 |
| RTO | 数据重传定时器到期、序号、超时值和在途量 |
| RETRANSMIT / FLIGHT | 重传或正常发送后的实际在途量 |
| PEER_WINDOW | 对端通告窗口和绝对右边界变化 |
| PROBE | 实际零窗口探测 |

`RWND` 仍表示本地接收缓存；`CC.peer` 表示发送方向收到的对端窗口。
`CC.conn` 用于区分同进程连接，不是稳定跨进程 ID。
CC 快照覆盖握手、每个新 ACK 和两种丢包原因；无需通过曲线形状猜测丢包。

## 复现

在 Linux 或 WSL 中从任意目录调用本文件同目录下的 `run.sh`：

```sh
bash validation/reno/run.sh
```

需要 GCC、pthread 和 Python 3 标准库。所有二进制、日志和 Trace 写入
`validation/reno/output`，不调用 `test/Makefile`，不执行会写 test 的测试程序。
原有五个课程测试仅做源码兼容性编译；它们的输出二进制也放在隔离目录。

新增单元验证覆盖初值、双窗口限制、段内 ACK、序号回绕、无效 ACK、
窗口更新 ACK、ACK 拆分、拥塞避免增长、单次快速重传、部分 ACK 修复、
RTO 复位和阈值下限。AddressSanitizer/UBSan 运行同一单元验证；
因原有 socket 生命周期保留用户持有对象，关闭泄漏检测，不宣称对象释放已全面验证。

七组集成验证编译真实协议实现和报文编解码，使用独立线程的内存报文队列
代替 UDP 下层，并注入可复现丢包。真实定时器、ACK、发送/接收线程均参与运行。
测试将 `TJU_MSL` 缩短为 1 秒，生产代码的默认值不变。

已保存的本轮结果：

| 场景 | 结果 |
| --- | --- |
| baseline | 200000 字节一致，无重传 |
| syn_loss | 丢弃一个 SYN 后握手及传输成功 |
| synack_loss | 丢弃一个 SYN-ACK 后握手及传输成功 |
| rto | 一次真实数据 RTO、一次重传，200000 字节一致 |
| multi_loss | 丢两个数据段，一次快速重传触发、两次重传，200000 字节一致 |
| zero_window | 一次零窗口通告和一次实际探测，恢复后 200000 字节一致 |
| simultaneous | 正向 200000 字节、反向 4096 字节一致，两端并发关闭完成 |

逐场日志为 `output/<场景>.log`，原始事件为 `output/<场景>.trace`。
`summarize.py` 校验原始 Trace 中的阈值公式、发送窗口限制、交付量和必要事件，
输出汇总到 `output/trace_summary.log`（由 run.sh 保存）。
五个课程程序均完成链接；RDT 客户端的 fstat 声明警告保留在 course_compile.log。

这些结果不代表已完成真实双主机 UDP/netem 测试、100 MB 性能测试或平台满分验收。

## 当前目录整理

当前 `output` 目录仅保留单元/集成验证的日志、原始 Trace 和汇总结果；运行脚本产生的
可执行文件、目标文件和临时缓存不作为结果提交。`network/output/report7_20260915_153313`
保留第七部分 R7-01～R7-05 五组实验的完整证据；两次启动失败目录保留用于报告中的失败记录。
