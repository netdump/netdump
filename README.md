
## 项目名称
**network packet capture and dump (netdump)**

## 项目简介
目前是基于 libpcap 的网络抓包工具，相较于 tcpdump 提供了 TUI 界面，有更好的人机交互。
可支持手动控制来查看协议相应字段对应的值。


## 技术架构
目前采用了多进程的架构来实现，分别是抓包进程、帧解析进程、TUI 展示进程。


## 项目特性
1. 基于 libpcap 的单次数据拷贝
2. 基于共享内存的、原子操作的多进程间传递数据
3. 自定义协议解析框架（模块化）
4. 预分配、无 malloc 路径


## 编译与依赖
### 安装编译工具
* **ubuntu** 

    `apt update`

    `apt install -y build-essential autoconf automake libtool pkg-config flex bison`
* **centos**

    `yum update -y`

    `yum install -y autoconf automake libtool pkgconfig flex bison`

    `yum groupinstall -y "Development Tools"`

### 编译
在 **netdump** 目录中直接执行 **make** 命令即可


## 快速开始



## 测试方案

### 功能测试方案



### 性能测试方案



## 性能数据


## 未来计划
1. 支持 DPDK、XDP
