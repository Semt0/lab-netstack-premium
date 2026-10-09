# 计算机网络实验：用户态协议栈

基于 **C 和 libpcap** 实现用户态网络协议栈，依次完成链路层、网络层和传输层实验。实验要求见 [原始实验说明](README.pdf)。

当前已完成 **Lab1：Ethernet II 帧收发**，并在 Linux veth 网络中验证了自编程序之间的实际收发。

## 实验进度

| 实验 | 内容 | 状态 |
| --- | --- | --- |
| Lab1：链路层 | 设备管理、MAC 地址获取与缓存、以太网帧封装与注入、捕获与回调 | 已完成，附 CP1 / CP2 记录 |
| Lab2：网络层 | IPv4、地址解析与路由 | 待实现 |
| Lab3：传输层 | TCP 与兼容 socket 的应用接口 | 待实现 |

## 目录结构

```text
.
├── src/                    # 协议栈实现与接口
│   ├── device.c / device.h
│   └── packetio.c / packetio.h
├── test/                   # 自编测试及演示程序
├── evidence/               # CP1、CP2 原始终端会话记录
├── reports/lab1/           # Lab1 报告 PDF 及可编辑 Markdown
├── pcap-trace/             # 写作题使用的抓包文件
├── vnetUtils/              # Linux 虚拟网络辅助脚本
├── checkpoints/            # 实验提供的后续 echo / perf 测试源码
├── mperf/                  # 实验提供的性能测试工具
├── Makefile
├── answer.md               # WT1 作答
└── tmp/                    # 构建时生成的可执行文件，不纳入 Git
```

## 构建与测试

运行环境为 Linux，需要 C 编译器、make 和 libpcap 开发库。例如，在 Ubuntu / Debian 上安装：

```bash
sudo apt update
sudo apt install build-essential libpcap-dev iproute2 tcpdump
```

在仓库根目录构建：

```bash
make
```

所有可执行文件输出到 **`./tmp/`**。运行不访问真实网卡的发送、接收测试：

```bash
make check
```

该测试使用 libpcap / 设备接口替身，覆盖 **19 项发送检查**和 **24 项接收与回调检查**，包括参数错误、帧字段、字节序、填充、捕获超时、截断帧及失败路径。

设备管理及 MAC 测试需要实际 Ethernet 接口和捕获权限。先查看接口名称，再运行：

```bash
ip -brief link
make check-device DEVICE=enp3s0
```

将 `enp3s0` 换成当前主机的 Ethernet 接口。设备测试会检查注册、查找、重复注册、MAC 副本、清理和重新注册。清理构建产物使用 `make clean`。

## Lab1 收发演示

使用一对直连 veth 接口，无需配置 IP 地址：

```text
send_demo → lab1tx ══ lab1rx → receive_demo
```

先创建并启用接口；若名称已存在，先确认它们属于当前实验再继续：

```bash
sudo ip link add lab1tx type veth peer name lab1rx
sudo ip link set lab1tx up
sudo ip link set lab1rx up
```

**终端 A：先启动接收。**

```bash
sudo ./tmp/lab-netstack-receive-demo lab1rx
```

看到等待提示后，在**终端 B**获取当前目的 MAC 并发送：

```bash
peer_mac=$(cat /sys/class/net/lab1rx/address)
sudo ./tmp/lab-netstack-send-demo lab1tx "$peer_mac"
```

发送程序注入 EtherType 为 `0x88b5`、载荷为 `lab1-test` 的帧。接收程序只捕获该 EtherType，打印 MAC、帧长和十六进制内容，处理一个帧后退出。

预期帧长为 **60 字节，不含 FCS**：14 字节头部、9 字节载荷、37 字节零填充。接收端最后显示：

```text
Reception completed.
```

如需独立检查，可在发送前另开终端启动 tcpdump：

```bash
sudo tcpdump -i lab1rx -nn -e -XX -c 1 'ether proto 0x88b5'
```

完成后清理接口，删除一端会同时删除另一端：

```bash
sudo ip link delete lab1tx
```

## Lab1 接口与设计

| 接口 | 用途 |
| --- | --- |
| `addDevice` / `findDevice` | 注册 Ethernet 设备、按名称查找设备 ID |
| `getDeviceHandle` / `getDeviceMAC` | 取得借用的 pcap 句柄、复制缓存 MAC |
| `clearDevices` | 关闭设备句柄并清空注册状态 |
| `sendFrame` | 构造、填充并注入 Ethernet II 帧 |
| `setFrameReceiveCallback` | 注册回调，传入 `NULL` 取消注册 |
| `receiveFrames` | 同步接收指定数量的完整帧并调用回调 |

当前实现支持最多 16 个设备、0–1500 字节载荷和普通无 VLAN 的 Ethernet II 帧。设备注册时获取并缓存 MAC；接收时检查链路类型，跳过短帧和截断帧。帧数据由 libpcap 管理，需要保留时由回调复制。

接收接口使用单个回调注册，并在每次调用开始时固定该回调。`count` 表示成功处理的帧数，不是等待时间；没有匹配流量时会持续等待。当前接口按单线程使用设计。Lab1 按实验说明不计算 FCS。

## 报告与检查点证据

- [Lab1 报告 PDF](reports/lab1/README.pdf)：WT1、实现说明、检查点解释和复现步骤。
- [Lab1 报告 Markdown](reports/lab1/README.md)：可编辑的报告内容。
- [CP1 终端记录](evidence/cp1.typescript)：接口检测结果。
- [CP2 发送端记录](evidence/cp2-send.typescript)：自编程序注入帧。
- [CP2 接收端记录](evidence/cp2-receive.typescript)：自编程序捕获并通过回调处理帧。

`.typescript` 是由 Linux `script` 命令保存的原始终端会话记录，包含命令和输出。
