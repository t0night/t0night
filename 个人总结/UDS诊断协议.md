## 基本介绍

UDS（Unified Diagnostic Services）统一诊断服务是在汽车上与ECU之间通信的一种协议。UDS服务使用OSI模型的第五层（会话层）和第七层（应用层），诊断工具可以与开启UDS服务的ECU进行连接。UDS包含26中服务，每种服务有唯一的ID（SID诊断服务ID）。

UDS诊断作为汽车ECU里的一个服务功能，位于应用层，它的实现需要有网络的支撑，我们把基于CAN总线实现的UDS诊断称为DoCAN，

# 一、DoCAN

## 0x01

基于CAN总线实现的UDS诊断称为DoCAN

## 0x02 交互方式

UDS是一种交互式的协议（Request/Response）

肯定响应的请求数据：

请求ID是0x10，响应0x50（[0x10+0x40]）即[SID+0x40]

```
Request : 02 10 01 00 00 00 00 00
Response: 06 50 01 00 32 00 C8 AA
```



否定响应的请求数据：

请求ID是0x10，响应[0x7F, 0x10, 0x7E]，即[0x7F, SID, 否定响应码]

```
Request : 02 10 02 00 00 00 00 00
Response: 03 7F 10 7E AA AA AA AA
```



否定响应码是代表否定请求的依据，如下所示：

![image-20220922101320217](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220922101320217.png)



## 0x03 寻址方式

每个在请求包和响应包中包含源地址和目标地址，类似与TCP协议。

UDS有两种寻址方式，物理寻址和功能寻址

物理寻址是根据物理地址不同进行访问，只能单个与ECU进行通信，Tester为SA源地址，ECU作为TA目标地址。每一个ECU都有2个CAN的诊断帧ID，分别对应物理寻址的收与发，比如0x701对应接收Tester的消息，0x709对应发给Tester的消息。

功能寻址是根据不同的功能进行访问，可以一对多的形式进行访问。

## 0x04 服务类型

共有26中服务类型，每个类型对应唯一的SID

![image-20220922103859333](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220922103859333.png)

## 0x05 会话模式

会话模式相当于对UDS服务进行权限分类，对于某些服务类型，必须在特定会话模式下才能进行，类似于linux的不用用户。

UDS提供三种会话模式，分别是

- Default默认会话：ECU启动后默认进入此会话。只提供基本的诊断服务。
- Programming编程会话：ECU更新应用程序或标定数据时进入此会话。支持与程序更新相关的诊断服务。
- Extended扩展会话：除支持默认会话下的诊断服务和功能外，还支持额外的诊断服务。

> 同一时刻只有一个诊断会话处于激活状态，激活新的诊断会话会关闭上一个诊断会话。



https://blog.csdn.net/weixin_47890316/article/details/121665919





## 0x06 请求命令



- SID
- SID+SF（Sub-function）
- SID+DID（Data Identifier）
- SID+SF+DID



## 参考

https://blog.ffxiv.cat/174/

# 二、DoIP

## 0x01

基于Ethernet实现的UDS诊断称为DoIP

相比DoCAN中CAN网络的封闭性，DoIP由于Ethernet的互联互通，可以实现车与车、车与人的远距离诊断通信

![image-20220929133009225](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220929133009225.png)



TCP连接：

- 支持DoIP的ECU的诊断服务创建的socket必须监听在端口号13400上，外部测试设备通过连接此端口建立连接
- 每个支持DoIP的ECU必须支持n+1个并发的TCP socket连接，这是为了防止有多个外部测试设备同时和ECU进行诊断通信
- 外部测试设备创建的socket应选择本地端口，本地端口即系统随机的端口



TCP连接的过程:

![image-20220929133133513](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220929133133513.png)

UDP连接：

![image-20220929134104994](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220929134104994.png)



发现DoIP设备（ECU）的两种方式：

- DoIP设备启动后，通过UDP向13400端口广播发送vehicle announcement message，源端口号为13400或随机，里面包含此DoIP设备的基本信息，外部测试设备需要监听13400来接收这些信息
- 外部测试设备通过UDP广播发送request消息，目标端口号是13400，DoIP设备监听在13400端口，接收此request并响应

