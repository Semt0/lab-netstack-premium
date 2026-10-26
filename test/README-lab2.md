# Lab2：最小 IPv4 收发演示

在仓库根目录执行 `make lab2 check-lab2`。接收接口必须已配置 IPv4 地址；注册设备后保存该地址。

接收端：

```sh
sudo ./tmp/lab-netstack-main 接口名
```

发送端（对端 IP 和下一跳 MAC 按实验拓扑填写）：

```sh
sudo ./tmp/lab2-send-ipv4 接口名 对端IPv4 下一跳MAC hello-lab2
```

发送演示添加一条已知下一跳 MAC 的 /32 主机路由，调用自己的 `sendIPPacket`，使用实验协议号 253。接收回调打印源/目的 IP、IP 总长度、首部长度、载荷长度、协议号和 TTL。

目前只交付目的地址为接收接口本机地址、长度和首部校验和正确的完整 IPv4 数据报。以太网填充不传给 IP 回调；分片被丢弃。尚未实现转发和动态路由。`check-lab2` 使用替身检查接收边界、完整报文交付和发送字节，不访问网络。

## 本次实测

两个临时 namespace 通过 veth 直连，192.0.2.1 与 192.0.2.2 分别发送 `hello-from-A`、`hello-from-B`。两端用户态回调均打印 IP 长度 32、首部 20、载荷 12、协议号 253、TTL 64。独立 AF_PACKET 记录到的帧长 60，MAC、IP 地址、载荷和 IPv4 首部校验和均匹配。

本次内核 IPv4 没有屏蔽（clab 的 iptables 操作超时），验证范围是自编 `sendIPPacket` 到对端 `handleIPPacket`/打印回调的直连收发，不代表转发或动态路由已完成。证据保存在 `tmp/lab2-ipv4-smoke-35c22d/`，包含日志、PCAP 和 `result.json`；临时 namespace 与接口已清理。
