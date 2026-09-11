#encoding: utf-8
import matplotlib.pyplot as plt
import sys
import numpy as np
import argparse

font_size = 15
trace_end_time = 0.0
window_source = 'local'


def plot_window_state(time_list, win_list, **style):
    """窗口是离散状态：保留每次变化，并保持最后的值到日志结束。

    即使只有一个初值，也显示标记；延展仅用于绘图，不修改原始 trace，
    更不把固定值误记成新的拥塞控制事件。
    """
    if len(time_list) == 0:
        return
    times = list(time_list)
    sizes = list(win_list)
    if trace_end_time > times[-1]:
        times.append(trace_end_time)
        sizes.append(sizes[-1])
    if len(time_list) == 1:
        style.update(marker='o', markersize=4)
    plt.step(times, sizes, where='post', **style)

def plot_win(time_list, win_list, win_type, type=[]):
    # plt.rcParams['figure.figsize'] = (10.0, 5.0)
    plot_window_state(time_list, win_list, color='black')
    plt.xlabel('Time since first trace event (s)', fontdict={'size':font_size})
    plt.ylabel('%s Window Size (segment)'%win_type, fontdict={'size':font_size})

    if win_type=='Congestion':
        map_color = {0: 'red', 1: 'green', 2:'blue', 3:'cyan'}
        map_label = {0: 'slow start', 1: 'congestion avoidance', 2:'fast retransmit', 3:  'timeout'}
        # 仅有固定初值时，不能由 type:0 推断整个实验处于慢启动。
        if len(win_list) and np.all(np.asarray(win_list) == win_list[0]):
            plt.scatter([time_list[0]], [win_list[0]], c='red', label='constant CWND / send cap')
        else:
            for item in range(4):
                idx = np.flatnonzero(np.asarray(type) == item)
                if len(idx):
                    plt.scatter(np.asarray(time_list)[idx], np.asarray(win_list)[idx], c=map_color[item], label=map_label[item])
        plt.legend()
    plt.title('receiver free buffer' if win_type == 'Receive' else window_source + ' ' + win_type)

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig('/vagrant/tju_tcp/test/%sWindowSize_VS_Time.png'%win_type, dpi=600)
    print("绘制成功, 图像位于/vagrant/tju_tcp/test/%sWindowSize_VS_Time.png"%win_type)
    plt.cla()

def plot_all(cwnd_list, rwnd_list, swnd_list):
    plot_window_state(cwnd_list[0], cwnd_list[1], color='red', label=window_source + ' CWND / send cap')
    plot_window_state(rwnd_list[0], rwnd_list[1], color='green', label='receiver free buffer')
    # 重合时采用虚线，仍能看见下方的接收窗口曲线。
    plot_window_state(swnd_list[0], swnd_list[1], color='blue', label=window_source + ' SWND', linestyle='--')
    plt.legend()                                                    
    plt.legend(loc=0, numpoints=1)
    plt.xlabel('Time since first trace event (s)', fontdict={'size':font_size})
    plt.title('Free buffer differs from peer-advertised window')
    plt.ylabel('Window Size (segment)', fontdict={'size':font_size})
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig('/vagrant/tju_tcp/test/AllWindowSize_VS_Time.png', dpi=600)
    print("绘制成功, 图像位于/vagrant/tju_tcp/test/AllWindowSize_VS_Time.png")
    plt.cla()

def plot_rtt(time_list, SampleRTT, EstimatedRTT, DeviationRTT, TimeoutInterval):
    plt.plot(time_list, SampleRTT, color='red', label='SampleRTT')
    plt.plot(time_list, EstimatedRTT, color='green', label='EstimatedRTT')
    plt.plot(time_list, DeviationRTT, color='blue', label='DeviationRTT')
    plt.plot(time_list, TimeoutInterval, color='black', label='TimeoutInterval')
    plt.legend()
    plt.xlabel('Time (s)', fontdict={'size':font_size})
    plt.ylabel('Time (ms)', fontdict={'size':font_size})
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig('/vagrant/tju_tcp/test/RTT.png', dpi=600)
    print("绘制成功, 图像位于/vagrant/tju_tcp/test/RTT_VS_Time.png")
    plt.cla()

def throughput_bins(times, sizes, duration):
    """按日志统一零点分箱，最后不足一秒按实际时长计算；不遗漏末端字节。

    histogram 的最后一个区间包含右端点，因此结束时恰好到达的数据只计算一次。
    返回边界和速率，可用 sum(速率 * 区间长度) 核对交付总比特数。
    """
    if not len(times) or duration <= 0:
        return np.array([]), np.array([])
    edges = np.append(np.arange(0.0, duration, 1.0), duration)
    amounts, _ = np.histogram(times, bins=edges, weights=np.asarray(sizes, dtype=np.int64))
    return edges, amounts * 8.0 / np.diff(edges)


def plot_throughput(time_list, throuput_list, thrp_intv):
    if len(throuput_list):
        # 保持区间平均值，末尾只延伸到日志终点，不外推虚假的零吞吐区间。
        plt.step(time_list, np.append(throuput_list, throuput_list[-1]), where='post', color='black')
    else:
        plt.text(.5, .5, 'No timed DELV data available', ha='center', transform=plt.gca().transAxes)
    plt.xlabel('Time since first trace event (s)', fontdict={'size':font_size})
    plt.ylabel('Delivered payload (bps)', fontdict={'size':font_size})
    plt.xlim(0, max(trace_end_time, .001))
    plt.ylim(ymin=0, ymax=max(float(np.max(throuput_list))*1.05, 1) if len(throuput_list) else 1)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig('/vagrant/tju_tcp/test/Throuput.png', dpi=600)
    print("绘制成功, 图像位于/vagrant/tju_tcp/test/Throuput.png [注: 每%.3fs计算一次瞬时吞吐率]"%thrp_intv)
    plt.cla()

def read_trace(file):
    SEND_dic = {'utctime':[], 'seq':[], 'ack':[], 'flag':[], 'length':[]}
    RECV_dic = {'utctime':[], 'seq':[], 'ack':[], 'flag':[], 'length':[]}
    CWND_dic = {'utctime':[], 'type':[], 'size':[]}
    RWND_dic = {'utctime':[], 'size':[]}
    SWND_dic = {'utctime':[], 'size':[]}
    RTTS_dic = {'utctime':[], 'SampleRTT':[], 'EstimatedRTT':[], 'DeviationRTT':[], 'TimeoutInterval':[]}
    DELV_dic = {'utctime':[], 'seq':[], 'size':[], 'throughput':[]}

    start_time = 0
    with open(file, 'r', encoding='utf-8') as f:
        for num, line in enumerate(f):
            if(line=='\n'): continue # 跳过空行
            if('SEND' not in line and 'RECV' not in line and 'CWND' not in line and 'RWND' not in line 
            and 'SWND' not in line and 'RTTS' not in line and 'DELV' not in line): continue # 跳过非事件行
            line = line.strip('\n')
            line = line.replace('[', '')
            line = line.replace(']', '')
            line_list = line.split(' ')
            info_list = line_list[2:]
            info_list = [item.split(':')[1] for item in info_list]
            
            if line_list[1] == 'SEND':
                SEND_dic['utctime'].append(int(line_list[0]))
                SEND_dic['seq'].append(int(info_list[0]))
                SEND_dic['ack'].append(int(info_list[1]))
                SEND_dic['flag'].append(info_list[2])
                SEND_dic['length'].append(int(info_list[3]))
            elif line_list[1] == 'RECV':
                RECV_dic['utctime'].append(int(line_list[0]))
                RECV_dic['seq'].append(int(info_list[0]))
                RECV_dic['ack'].append(int(info_list[1]))
                RECV_dic['flag'].append(info_list[2])
                RECV_dic['length'].append(int(info_list[3]))
            elif line_list[1] == 'CWND':
                CWND_dic['utctime'].append(int(line_list[0]))
                CWND_dic['type'].append(int(info_list[0]))
                CWND_dic['size'].append(int(info_list[1])/1375)
            elif line_list[1] == 'RWND':
                RWND_dic['utctime'].append(int(line_list[0]))
                RWND_dic['size'].append(int(info_list[0])/1375)
            elif line_list[1] == 'SWND':
                SWND_dic['utctime'].append(int(line_list[0]))
                SWND_dic['size'].append(int(info_list[0])/1375)
            elif line_list[1] == 'RTTS':
                if line_list[0] not in RTTS_dic['utctime']: 
                    RTTS_dic['utctime'].append(int(line_list[0]))
                    RTTS_dic['SampleRTT'].append(float(info_list[0]))
                    RTTS_dic['EstimatedRTT'].append(float(info_list[1]))
                    RTTS_dic['DeviationRTT'].append(float(info_list[2]))
                    RTTS_dic['TimeoutInterval'].append(float(info_list[3]))
            elif line_list[1] == 'DELV':
                DELV_dic['utctime'].append(int(line_list[0]))
                DELV_dic['seq'].append(int(info_list[0]))
                DELV_dic['size'].append(int(info_list[1])) 

            if start_time==0:
                start_time = int(line_list[0])

    SEND_dic['time'] = [item - start_time for item in SEND_dic['utctime']]
    RECV_dic['time'] = [item - start_time for item in RECV_dic['utctime']]
    CWND_dic['time'] = [item - start_time for item in CWND_dic['utctime']]
    RWND_dic['time'] = [item - start_time for item in RWND_dic['utctime']]
    SWND_dic['time'] = [item - start_time for item in SWND_dic['utctime']]
    RTTS_dic['time'] = [item - start_time for item in RTTS_dic['utctime']]
    DELV_dic['time'] = [item - start_time for item in DELV_dic['utctime']]
    SEND_dic['time'] = np.divide(SEND_dic['time'], 1000000) # 单位: s
    RECV_dic['time'] = np.divide(RECV_dic['time'], 1000000)
    CWND_dic['time'] = np.divide(CWND_dic['time'], 1000000)
    RWND_dic['time'] = np.divide(RWND_dic['time'], 1000000)
    SWND_dic['time'] = np.divide(SWND_dic['time'], 1000000)
    RTTS_dic['time'] = np.divide(RTTS_dic['time'], 1000000)
    DELV_dic['time'] = np.divide(DELV_dic['time'], 1000000)

    return SEND_dic, RECV_dic, CWND_dic, RWND_dic, SWND_dic, RTTS_dic, DELV_dic


parser = argparse.ArgumentParser(description='Plot local trace or matched receiver/sender traces')
parser.add_argument('trace', nargs='?', default='/vagrant/tju_tcp/test/client.event.trace')
parser.add_argument('--sender', help='same connection sender trace; uses sender CWND/SWND')
args = parser.parse_args()
FILE_TO_READ = args.trace
print("正在使用 %s Trace文件绘图"%FILE_TO_READ)
SEND_dic, RECV_dic, CWND_dic, RWND_dic, SWND_dic, RTTS_dic, DELV_dic = read_trace(FILE_TO_READ)

if args.sender:
    sender = read_trace(args.sender)
    # 同时匹配两个方向的握手及绝对时间，拒绝被后续测试覆盖的日志。
    def handshake_packets(events, flags):
        return {(seq, ack): timestamp for timestamp, seq, ack, flag in zip(
            events['utctime'], events['seq'], events['ack'], events['flag']) if int(flag) == flags}
    for outgoing, incoming, flag in ((sender[0], RECV_dic, 8), (SEND_dic, sender[1], 12)):
        sent, received = handshake_packets(outgoing, flag), handshake_packets(incoming, flag)
        if not any(abs(sent[key] - received[key]) < 60000000 for key in sent.keys() & received.keys()):
            parser.error('Sender/receiver traces do not have a matching handshake')
        if any(received[key] < sent[key] for key in sent.keys() & received.keys()):
            print('警告：握手接收时间早于发送时间，两端时钟未同步；联合曲线不能用于精确时序比较。', file=sys.stderr)
    receiver = (SEND_dic, RECV_dic, CWND_dic, RWND_dic, SWND_dic, RTTS_dic, DELV_dic)
    origin = min(min(item['utctime']) for item in receiver + sender if item['utctime'])
    # 先在整数微秒中作差，避免浮点大时间戳损失精度；两端共享相同零点。
    for item in receiver + sender:
        item['time'] = np.asarray([value - origin for value in item['utctime']]) / 1000000
    CWND_dic, SWND_dic, RTTS_dic = sender[2], sender[4], sender[5]
    window_source = 'sender'
    sender_end = max(float(np.max(item['time'])) for item in sender if len(item['time']))

# 使用所有事件的最后时刻作为状态曲线终点，固定窗口也覆盖完整传输时间。
trace_end_time = max((float(np.max(item['time'])) for item in
    (SEND_dic, RECV_dic, CWND_dic, RWND_dic, SWND_dic, RTTS_dic, DELV_dic)
    if len(item['time'])), default=0.0)
if args.sender:
    trace_end_time = max(trace_end_time, sender_end)

# 绘图时是否需要间隔 间隔的大小 绘制的数据区间 需要大家根据自己的数据以及绘图效果自行调整, 可参考
# 每条记录均保留，避免不足 101 条时只剩一个点，并避免漏掉短暂零窗口。
intv = 1
if len(CWND_dic['utctime']):
    plot_win(CWND_dic['time'], np.array(CWND_dic['size']), 'Congestion', CWND_dic['type']) # 用全部数据绘图
    # plot_win(CWND_dic['time'][::intv], np.array(CWND_dic['size'][::intv]), 'Congestion', CWND_dic['type'][::intv]) # 间隔100个数据进行绘制
    # plot_win(CWND_dic['time'][:100], np.array(CWND_dic['size'][:100]), 'Congestion', CWND_dic['type'][:100]) # 仅绘制前100个数据点
    # plot_win(CWND_dic['time'][100:201], np.array(CWND_dic['size'][100:201]), 'Congestion', CWND_dic['type'][100:201]) # 仅绘制第100到第200的数据点

if len(RWND_dic['utctime']):
    plot_win(RWND_dic['time'][::intv], RWND_dic['size'][::intv], 'Receive')

if len(SWND_dic['utctime']):
    plot_win(SWND_dic['time'][::intv], SWND_dic['size'][::intv], 'Send')

plot_all([CWND_dic['time'][::intv], CWND_dic['size'][::intv]], [RWND_dic['time'][::intv], RWND_dic['size'][::intv]], [SWND_dic['time'][::intv], SWND_dic['size'][::intv]])

if len(RTTS_dic['utctime']): 
    plot_rtt(RTTS_dic['time'][::intv], RTTS_dic['SampleRTT'][::intv], RTTS_dic['EstimatedRTT'][::intv], RTTS_dic['DeviationRTT'][::intv], RTTS_dic['TimeoutInterval'][::intv])

# 吞吐量与窗口曲线使用同一零点，保留初始等待时间及末尾不足一秒的区间。
throughput_edges, throughput_rates = throughput_bins(DELV_dic['time'], DELV_dic['size'], trace_end_time)
plot_throughput(throughput_edges, throughput_rates, 1)
