# 完整 Reno 快速恢复

依据说明书5.6及RFC 5681 §3.2。默认`TJU_FULL_RENO=1`，`-DTJU_FULL_RENO=0`编译基础模式作对照。SMSS保持1375字节。

第三个有效重复ACK：阈值按FlightSize减半（不低于2 SMSS），重传队首，cwnd=ssthresh+3 SMSS。后续有效重复ACK每个增加SMSS并唤醒发送线程；新数据仍受rwnd限制。首个确认新数据的ACK（包含部分ACK）收缩窗口、退出恢复。RTO清除恢复状态并回到一个SMSS。

本任务未实现RFC 3042 Limited Transmit（第1/2个重复ACK不额外发送），也未选做NewReno/SACK。基础模式保留历史RDT部分ACK缺口修复；完整模式以经典Reno退出规则为准。

## 复测

在具备网络命名空间权限的Linux/WSL，项目根目录运行：

```sh
bash validation/full_reno/run_regression.sh
bash validation/full_reno/run_network.sh
python validation/full_reno/analyze.py validation/full_reno/output/<network时间戳目录>
# 仅核算trace/pcap、输出CSV和JSON（无需matplotlib）：
python validation/full_reno/analyze.py validation/full_reno/output/<network时间戳目录> --no-plots
```

依赖gcc、pthread、iproute2、tcpdump、Python3与matplotlib。所有测试独立输出，不运行会写原test路径的课程驱动。回归包括两模式单元/内存检查与14组集成实验、5个课程程序兼容编译；网络包括两模式各4场景，每次300000字节。专项测试check_recovery.c使用真实发送线程验证恢复期间新发送、小窗口、部分ACK和RTO重置。

每个网络实验保存双端trace、pcap、收发文件、日志、配置和逐事件window_updates.csv。analyze.py从SEND/ACK序号重建FlightSize，重算窗口公式，核对pcap实际数据包与注入丢包，并生成windows.png及summary.json。

网络测试每场景一次，只能解释该次定向行为与耗时，不作为统计性能优势证据。MSL=1和网络专用ssthresh=22000为实验编译配置。既有七组内存报文队列回归包含多丢包和真实零窗口探测；与UDP小rwnd测试区分。

网络脚本需要root或对应的网络命名空间权限，例如WSL中使用 `wsl -u root -- bash validation/full_reno/run_network.sh`。ASan/UBSan测试程序使用`-no-pie`避开当前WSL/GCC 9的PIE启动故障，并设置硬超时；生产编译参数不受影响。快速恢复真实发送线程专项也纳入ASan/UBSan检查，保持`detect_leaks=0`，不声称验证连接对象最终释放。

最终复核：`regression_20260915_232959`通过两模式14组集成回归、两模式ASan/UBSan单元、ASan/UBSan恢复专项和5个课程程序兼容编译；`network_20260915_233439`的8组UDP实验与独立trace/pcap核算通过。单丢包完整模式恢复期发送6个新段，重传1次、RTO为0；历史报告图对应`network_20260915_204329`（恢复期5个新段），两轮数据分别保存，不混用。
