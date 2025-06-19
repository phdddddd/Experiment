import time
import os
import subprocess  # 用于调用流量监测工具（如 tcpdump）

# 硬件计数器文件路径列表
COUNTER_FILES = {
    'rx_read_requests': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/rx_read_requests',
    'rx_write_requests': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/rx_write_requests',
    'duplicate_request': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/duplicate_request',
    'out_of_sequence': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/out_of_sequence',
    'req_remote_access_errors': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/req_remote_access_errors',
    'np_eecn_marked_roce_packets': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/np_eecn_marked_roce_packets',
    'rp_cnp_ignored': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/rp_cnp_ignored',
    'rp_cnp_handled': '/sys/class/infiniband/rxe_0/ports/1/hw_counters/rp_cnp_handled',
    'cm_rx_msgs_req': '/sys/class/infiniband/rxe_0/ports/1/cm_rx_msgs/req',
    'cm_tx_msgs_rtu': '/sys/class/infiniband/rxe_0/ports/1/cm_tx_msgs/rtu',
    'cm_rx_duplicates_req': '/sys/class/infiniband/rxe_0/ports/1/cm_rx_duplicates/req',
    'cm_tx_msgs_req': '/sys/class/infiniband/rxe_0/ports/1/cm_tx_msgs/req'
}

# 上次记录的计数值字典
last_counts = {counter: 0 for counter in COUNTER_FILES}
first_run = True  # 标记是否是第一次运行

def read_counter_from_file(file_path):
    """从硬件计数器文件中读取当前值"""
    try:
        with open(file_path, 'r') as f:
            value = f.read().strip()
            return int(value)
    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
        exit(1)
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return None

def trigger_deep_flow_monitoring():
    """触发深度流量监控"""
    print("[流量监控] 条件满足，开始深度流量监测...")
    # 在这里调用 tcpdump 或类似工具进行流量监控
    try:
        # 运行 tcpdump 进行流量监控，并保存到文件中
        subprocess.run(['tcpdump', '-i', 'eth0', '-w', 'flow_capture.pcap', '-c', '1000'], check=True)
        print("[流量监控] 流量监测完成，已保存为 'flow_capture.pcap'")
    except subprocess.CalledProcessError as e:
        print(f"[流量监控] 流量监控失败: {e}")

def monitor_counters(interval=0.5):
    global last_counts, first_run

    print(f"开始监控多个计数器（间隔 {interval} 秒）...")

    while True:
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        current_counts = {}

        for counter_name, file_path in COUNTER_FILES.items():
            current_value = read_counter_from_file(file_path)

            if current_value is None:
                continue  # 如果读取失败则跳过本次循环

            current_counts[counter_name] = current_value

            if not first_run:
                delta = current_value - last_counts[counter_name]
                if delta > 0:
                    print(f"[{current_time}] 计数器 {counter_name}: 新增 {delta}")
                else:
                    print(f"[{current_time}] 计数器 {counter_name}: 无新增")

                # 基于论文中的规则检测是否触发深度流量监测
                if counter_name == "duplicate_request" and delta > 10:
                    print(f"[{current_time}] 计数器 {counter_name} 大幅增加，疑似重放攻击（A4）。触发流量监控。")
                    trigger_deep_flow_monitoring()

                elif counter_name == "out_of_sequence" and delta > 5:
                    print(f"[{current_time}] 计数器 {counter_name} 大幅增加，疑似包序错乱攻击（A5）。触发流量监控。")
                    trigger_deep_flow_monitoring()

                elif counter_name == "req_remote_access_errors" and delta > 3:
                    print(f"[{current_time}] 计数器 {counter_name} 大幅增加，疑似未授权内存访问攻击（A7）。触发流量监控。")
                    trigger_deep_flow_monitoring()

            else:
                print(f"[{current_time}] 初始计数值 {counter_name}: {current_value}")

        # 更新上次值
        last_counts.update(current_counts)
        first_run = False

        # 等待指定间隔
        time.sleep(interval)

if __name__ == "__main__":
    monitor_counters(interval=0.5)  # 每500毫秒检查一次
