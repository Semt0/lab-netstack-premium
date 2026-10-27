# 计算机网络实验：用户态协议栈

基于 **C 和 libpcap** 实现用户态网络协议栈。实验要求见[原始实验说明](README.pdf)。

已完成 **Lab1 链路层**和 **Lab2 网络层**。Lab2 支持 IPv4 收发、多跳转发、最长前缀匹配，以及带毒性逆转和超时失效的距离向量路由；CP3–CP6 的终端录制、抓包和实验说明保存在仓库中。

## 实验进度

| 实验 | 内容 | 状态 |
| --- | --- | --- |
| Lab1：链路层 | 设备管理、MAC 缓存、Ethernet II 帧收发与回调 | 已完成，保留 CP1 / CP2 记录 |
| Lab2：网络层 | IPv4、下一跳 MAC、动态路由、超时与多跳转发 | 已完成，附 WT2–WT4、CP3–CP6 和报告 |
| Lab3：传输层 | TCP 与兼容 socket 的应用接口 | 待实现 |

## 目录结构

~~~text
.
├── src/                    # device、packetio、smtarp、ip、smtroute 和 main
├── test/
│   ├── cp3/                # IPv4 发送演示
│   ├── cp4/                # 可交互查询和发送的路由测试程序
│   ├── cp5/                # 六节点距离矩阵与断开/恢复实验
│   ├── cp6/                # 最长前缀匹配及双出口抓包实验
│   └── checkpoint_common.py
├── checkpoints/
│   ├── cp3/ ... cp6/       # README.md、原始 typescript 和 pcap
│   └── *.c / Makefile      # 实验原附 echo / perf 程序
├── evidence/               # Lab1 的 CP1、CP2 原始录制
├── reports/
│   ├── lab1/               # Lab1 报告
│   └── lab2/               # Lab2 报告 PDF、Markdown、LaTeX 和空的未实现项文件
├── lab1-answer.md
├── lab2-answer.md
├── pcap-trace/             # 写作题使用的原始 trace.pcap
├── vnetUtils/              # 虚拟网络 helper
├── Makefile
├── tmp/                    # 构建产物和辅助验证数据，不纳入 Git
└── submission/             # 本地提交目录及压缩包，不纳入 Git
~~~

开发树的测试位于 `test/`。正式提交副本按照实验文档整理到 `lab2/src/test/`，对应的 Makefile、运行脚本和报告路径已调整；使用同一套协议栈实现。

## 环境与构建

需要 Linux、C 编译器、make、libpcap 开发库；网络实验还使用 Python 3、iproute2、iptables、tcpdump 和 Linux `script`。

~~~bash
sudo apt update
sudo apt install build-essential libpcap-dev iproute2 iptables tcpdump python3

make
make cp3 cp4 cp5 cp6
~~~

构建启用 `-O2 -Wall -Wextra -Wpedantic -Werror -pthread`，链接 `-lpcap`。所有可执行文件位于 `tmp/`。

| 命令 | 输出 |
| --- | --- |
| `make` / `make main` | `tmp/lab-main` |
| `make cp3` | `tmp/send-ipv4-demo` |
| `make cp4` / `make cp5` | `tmp/cp4-router` |
| `make cp6` | `tmp/cp6-lpm` |
| `make clean` | 删除上述可执行文件 |

旧的 Lab1 独立演示和 mock 测试已清理。Lab1 的实现保留在设备与帧收发模块中，历史实验见 [Lab1 报告](reports/lab1/README.pdf)。

## Lab2 实现

| 模块 | 职责 |
| --- | --- |
| `device` | 注册接口，缓存 MAC 和首个 IPv4 地址，分别管理 RX / TX pcap 句柄 |
| `packetio` | 以太网封装、捕获、回调分发，以及互斥保护的帧注入 |
| `ip` | 构造 IPv4 首部、校验输入、本机交付和多跳转发 |
| `smtroute` | 手工路由、最长前缀查询、距离向量收发、失效和清理 |
| `smtarp` | ARP 请求、应答及受锁保护的缓存 |
| `main` | 注册接口和本地路由、启动接收线程、周期维护和广播 DV |

距离向量使用 **自定义以太网协议**，EtherType 为 `0x88B6`，不使用 RIP 的 UDP 报文格式。每个接口初始化一条代价为 0 的本机 `/32` 路由，随后约每秒按接口广播。跳数 16 表示不可达；动态路由 5 秒未收到采纳的可达更新后失效，再保留 5 秒清理。发送通告时按出口执行毒性逆转。

收到 DV 时先验证完整报文，再处理路由更新。动态下一跳由接收接口和报文源 MAC 标识；当前下一跳的坏消息也会被接受。转发按最长前缀选择有效路由，递减 TTL 并重算校验和。目的地址匹配任意已注册接口时交付本机。

手工路由直接提供下一跳 MAC，动态路由从邻居的以太网通告中学习 MAC，因此 CP3–CP6 无需先进行 ARP 问答。代码另有零 MAC 路由的 ARP 查询分支，详见 [WT3 与完整实现说明](reports/lab2/README.md)。

初始化接口和回调后再启动线程；路由表、ARP 缓存和发送路径分别同步，路由查询返回线程局部副本。分片直接丢弃，TOS 使用默认值，IP 选项不作解释，符合 Lab2 允许的简化。

## 运行和交互

在已创建的 CP4 拓扑中，可以为 ns1 启动路由程序：

~~~bash
sudo ip netns exec cp4ns1 ./tmp/lab-main cp4veth1-2
~~~

需要交互查询时，使用 `cp4-router` 作为该节点的启动入口：

~~~bash
sudo ip netns exec cp4ns1 ./tmp/cp4-router cp4veth1-2
~~~

随后在程序内部输入：

~~~text
route 10.34.3.2
send 10.34.3.2 example-payload
quit
~~~

`route` 打印有效路由的前缀、掩码、距离、出口、下一跳 MAC 和学习来源；无有效路由时打印 `UNREACHABLE`。`send` 使用同一进程的路由表发送协议号 253 的 IPv4 测试载荷。

## 自动复现实验

CP5 和 CP6 的脚本使用 vnetUtils helper 创建专用 namespace，调用真实 C 实现，并通过 tcpdump 独立核对报文。自动运行需要能够非交互执行所需的 `sudo -n` 命令。运行前对应的 `cp5ns*` 或 `cp6ns*` 名称应未被占用，结果目录使用新名字。

~~~bash
make cp5 cp6

mkdir -p tmp/cp5-run
PYTHONDONTWRITEBYTECODE=1 script -q -f -e \
  -c 'python3 -u test/cp5/run.py tmp/cp5-run' \
  tmp/cp5-run/control.typescript

mkdir -p tmp/cp6-run
PYTHONDONTWRITEBYTECODE=1 script -q -f -e \
  -c 'python3 -u test/cp6/run.py tmp/cp6-run' \
  tmp/cp6-run/control.typescript
~~~

CP5 复用 CP4 的路由测试入口。两个脚本结束时清理本次创建的进程和 namespace；辅助 CSV / JSON 及 capture 日志写入 `tmp/`。helper 依赖相对路径，手动调用时进入 `vnetUtils/helper/`。

## 已保存的实验结果

| 检查点 | 内容 | 实际结果 |
| --- | --- | --- |
| [CP3](checkpoints/cp3/README.md) | IPv4 发送、抓包及逐字节解析 | 28 字节 IP 数据报，8 字节载荷，首部校验和正确 |
| [CP4](checkpoints/cp4/README.md) | 四节点链式发现、隔离 ns2 和恢复 | 距离 3 → 不可达 → 3；断开前及恢复后报文 TTL 均为 62 |
| [CP5](checkpoints/cp5/README.md) | 六节点初始、隔离 ns5、恢复三阶段 | 108 个距离条目正确；80 次成功到达、10 次无路由发送被拒绝 |
| [CP6](checkpoints/cp6/README.md) | `/32`、`/24`、`/16`、`/0` 重叠前缀及两个物理出口 | 四个报文均使用预期前缀、出口和下一跳 MAC |

[检查点总览](checkpoints/README-lab2.md)列出了各项证据。CP3 / CP4 为手动录制；CP5 / CP6 为自动运行的真实网络实验。每个正式结果目录只保留 `README.md`、`.typescript` 和 `.pcap`。

所有 CP5 / CP6 报文逐包核对载荷、目的 IP、TTL 和 IPv4 首部校验和。测试建立的是对应拓扑与稳定状态下的行为，不将轮询观察时间当作精确收敛时延。

## 报告与提交

- [Lab2 报告 PDF](reports/lab2/README.pdf)：8 页 A4，包含代码组织、PT3、WT2–WT4 和 CP3–CP6。
- [Lab2 报告 Markdown](reports/lab2/README.md) / [LaTeX](reports/lab2/README.tex)：可编辑源文件。
- [Writing task 答案](lab2-answer.md)。
- [未实现项文件](reports/lab2/not-implemented.pdf)：按全部完成 Lab2 必做要求的规定，保留为空文件。
- [Lab1 报告](reports/lab1/README.pdf)及 [CP1](evidence/cp1.typescript)、[CP2 发送](evidence/cp2-send.typescript)、[CP2 接收](evidence/cp2-receive.typescript)原始录制。

正式提交目录按文档组织为：

~~~text
lab2/
├── src/                    # 协议源码、src/test/ 及必要 helper
├── Makefile
├── README.pdf
├── not-implemented.pdf     # 空文件
└── checkpoints/            # CP3–CP6 原始证据和简要说明
~~~

本地 `submission/` 保存已组织的目录和压缩包。该提交副本已在全新解压目录通过默认 `make`，并成功运行 CP5 / CP6。临时数据、重复结果包和生成的 submission 不纳入 Git。
