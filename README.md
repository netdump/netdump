
## 项目名称
**network packet capture and dump (netdump)**

## 项目简介
目前是基于 libpcap 的网络抓包工具，相较于 tcpdump 提供了 TUI 界面，有更好的人机交互。

## 技术架构
目前采用了多进程的架构来实现，分别是抓包进程、帧解析进程、TUI 展示进程。


## 项目特性

### TUI 特性
1. 终端实时刷新
2. HexDump + 协议字段对应映射（字段选中高亮 + HexDump 高亮对应位置）
3. 状态栏，显示过滤条件、网卡名
4. 包视图，每一行显示：时间戳、长度、协议、源/目的 IP
5. 键盘交互（切换主题框、选包、选字段、协议折叠、暂停、继续）

### 技术特性
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
在 **netdump** 目录中直接执行 **make** 命令即可获得可执行程序 **"netdump"**


## 快速开始
### 注意事项

* Linux shell 终端执行 **netdump** 需要 **root** 权限
* Linux shell 终端执行 **netdump** 对屏幕尺寸有一定要求，当提示屏幕尺寸不够时请修改终端的字体大小
* Linux shell 终端执行 **netdump** 时，由于对资源的初始化，存在十秒左右的等待

### TUI 界面介绍与使用方法
#### TUI 指令输入界面
![TUI-1](docs/img/TUI-1.PNG)

#### TUI 网络帧显示界面


## 测试方案

### 功能测试方案
**暂未实现**


### 性能测试方案
**暂未实现**


## 性能数据
**暂未实现**

## 未来计划
### 第 1 阶段：libpcap 版本（基础版）
1. pcap 抓包、pcap 文件解析
2. 报文重组
3. TUI/交互
4. 协议解析
5. 插件系统
6. pcapng 保存
7. 协议解析功能验证
8. 性能调优文档
9. 性能数据
### 第 2 阶段：加入高性能输入（DPDK / XDP）
1. 创建统一的“Packet Source API”
2. 添加 AF_XDP
3. 添加 DPDK
4. 性能调优文档
5. 性能数据
### 第 3 阶段：协议解析 pipeline
1. 解析器和抓包输入完全解耦。
2. 性能调优文档
3. 性能数据


