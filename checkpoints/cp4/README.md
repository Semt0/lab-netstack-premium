# CP4: 动态路由发现、断开与恢复

## 拓扑与运行方式

```text
cp4ns1 -- cp4ns2 -- cp4ns3 -- cp4ns4
```

| 链路 | 左端地址 | 右端地址 |
| --- | --- | --- |
| ns1-ns2 | 10.34.1.1/24 | 10.34.1.2/24 |
| ns2-ns3 | 10.34.2.1/24 | 10.34.2.2/24 |
| ns3-ns4 | 10.34.3.1/24 | 10.34.3.2/24 |

四个节点均设置 INPUT、OUTPUT、FORWARD DROP，关闭内核 IPv4 转发。
各节点运行 test/cp4/router.c 编译生成的 tmp/cp4-router，复用 src 中的 DV、路由超时和 IPv4 收发实现；不添加手工远端路由。
测试程序每秒检查超时并发送 DV；主线程接受 route、send、quit 命令。

## 实际结果

| 阶段 | ns1 查询 10.34.3.2 | ns4 查询 10.34.1.1 | ns1 到 ns4 的数据报 |
| --- | --- | --- | --- |
| 初始收敛 | metric=3，learned_from_dv=1 | metric=3，learned_from_dv=1 | cp4-before 到达，TTL=62 |
| ns2 两个接口 down 后 | UNREACHABLE | UNREACHABLE | send 命令查询无有效路由，输出 UNREACHABLE，未发包 |
| ns2 两个接口恢复 up 后 | metric=3，learned_from_dv=1 | metric=3，learned_from_dv=1 | cp4-after 到达，TTL=62 |

初始与恢复后，ns1 的出口均为 cp4veth1-2，下一跳 MAC 为 d2:53:38:07:e9:55，即 ns2 对应接口。
两个阶段均收到实际多跳报文；初始 TTL 为 64，经过 ns2、ns3 两次转发后为 62。
隔离期间 ns2 的接口发送失败被保留在 ns2.typescript 中；恢复时没有重启路由进程，各接收线程未记录退出。

本实验验证查询时的稳定状态变化，没有精确测量从链路变化到收敛的延迟。
UNREACHABLE 表示 findRouter 没有找到有效路由；本实验没有直接检查失效条目是否已从内部路由表删除。

## 证据

- control.typescript：拓扑创建、内核隔离、关闭及恢复 ns2 两个接口、抓包读取；正常结束。
- ns1.typescript：初始路由、断开后的查询与发送失败、恢复后的路由及发送；正常结束。
- ns2.typescript、ns3.typescript：中间路由进程的持续运行记录；正常结束。
- ns4.typescript：初始与恢复后的反向路由、隔离后的不可达、两次实际接收；正常结束。
- forward.pcap：cp4-before、cp4-after 两个数据报，TTL 均为 62；两个 IPv4 首部校验和均经独立计算验证。

从仓库根目录读取抓包：

```bash
sudo tcpdump -nn -e -vvv -X -r checkpoints/cp4/forward.pcap
```

结论：该四节点链式拓扑下，ns1 能动态发现 ns4；隔离 ns2 后路由失效；恢复连接后，原有进程重新学习路由并恢复实际多跳转发，满足 CP4 要求。
