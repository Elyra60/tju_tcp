# 第八部分性能测试

依据说明书10.7：时延5/20/50 ms（每方向100 Mbit/s），带宽1/5/20 Mbit/s（每方向20 ms）。每档三次，每次2000000字节。原始结果在 `output/20260915_200849`。

运行：在有网络命名空间权限的Linux/WSL执行 `bash validation/performance/run.sh`。
分析：`python validation/performance/analyze.py validation/performance/output/20260915_200849`（需要matplotlib）。

每组保存配置、接收计时、双端trace、pcap、完整收发文件和SHA-256。统计图来自原始日志，均值±样本标准差，未剔除样本。计时分子为1999999字节；首字节读出后开始计时，末字节读出后结束。

`output/20260915_200849/source/`与`build.sha256`保留当时的基础Reno构建源码快照和哈希。历史实验使用MSL=1缩短关闭等待；当前`run.sh`还显式编译`-DTJU_FULL_RENO=0`，使复测口径固定为基础模式。当前协议默认完整Reno，不能省略模式参数后把新结果直接当作原历史实验。

目录仅保留运行脚本`run.sh`、端点代码`endpoint.c`、统计绘图脚本`analyze.py`、本复现说明和`output/`实验结果。可执行文件由运行脚本重新编译。
