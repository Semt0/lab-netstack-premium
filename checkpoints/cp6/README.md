# CP6: 最长前缀匹配

## 实验设计

~~~text
cp6ns2 (出口 A 对端) -- cp6ns1 (发送端) -- cp6ns3 (出口 B 对端)
10.36.1.2/24            10.36.1.1/24
                       10.36.2.1/24       10.36.2.2/24
~~~

使用 vnetUtils 创建两条独立链路；三个节点均屏蔽内核 IP 处理并关闭内核转发。
test/cp6/lpm.c 调用真实 setRoutingTable、findRouter 和 sendIPPacket。
按 /24、/0、/32、/16 的顺序插入路由，检查查询结果，并发送实际报文。
所有路由均已存在时执行四次匹配检查；选择结果不依赖插入顺序。

## 实际结果

| 目的地址 | 最长匹配 | 实际出口 | 载荷 | 结果 |
| --- | --- | --- | --- | --- |
| 10.60.1.42 | 10.60.1.42/32 | cp6veth1-2，A | cp6-host | PASS |
| 10.60.1.43 | 10.60.1.0/24 | cp6veth1-3，B | cp6-subnet | PASS |
| 10.60.2.42 | 10.60.0.0/16 | cp6veth1-2，A | cp6-network | PASS |
| 203.0.113.7 | 0.0.0.0/0 | cp6veth1-3，B | cp6-default | PASS |

另在空路由表时查询 203.0.113.7，正确返回无路由。
每次查询均比较目的前缀、掩码、设备及下一跳 MAC。
两端 tcpdump 分别捕获两个报文；独立核对了实际出口、目的 IP、源 IP、TTL=64、载荷及 IPv4 首部校验和。
以太网目的 MAC 也与对应出口的对端 MAC 一致。两个抓包进程均正常退出，内核丢包计数为 0。

## 证据与代码

- control.typescript：拓扑创建、内核隔离、编译后程序的运行输出与资源清理，退出码为 0。
- out-a.pcap、out-b.pcap：两个出口的真实抓包。
- test/cp6/lpm.c：C 测试入口；test/cp6/run.py：实验执行与结果核验。
- test/checkpoint_common.py：复用的拓扑、抓包和清理工具。

查询与发送输出均在 control.typescript 中。结果目录只保留 README.md、typescript 和 pcap；后续运行的辅助数据写入 tmp。

构建（仓库根目录）：

~~~bash
make cp6
~~~

复现实验时使用一个新的结果目录，保留本次记录：

~~~bash
mkdir -p checkpoints/cp6-rerun
PYTHONDONTWRITEBYTECODE=1 script -q -f -e   -c 'python3 -u test/cp6/run.py checkpoints/cp6-rerun'   checkpoints/cp6-rerun/control.typescript
~~~

实验结束后已停止本次进程并删除 cp6 专用命名空间；src 未改动。
