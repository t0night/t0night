Service ID 0x10是用于切换会话模式， `10 02`用于把会话切换到编程模式。

```bash
9.498709 1  7DF             Tx   d 8 02 10 02 AA AA AA AA AA  Length = 0 BitCount = 116 ID = 2015
```

正响应:

```
9.499693 1  7B0             Rx   d 8 06 50 02 00 32 01 F4 00  Length = 235910 BitCount = 122 ID = 1968
```



Service ID 0x27是用于解锁安全模式。第一个参数05用于请求seed

```bash
9.740585 1  730             Tx   d 8 02 27 05 AA AA AA AA AA  Length = 222015 BitCount = 114 ID = 1840
```

正响应，第二个参数之后的为seed内容`11 22 33 44`

```
9.741697 1  7B0             Rx   d 8 06 67 05 11 22 33 44 00  Length = 223910 BitCount = 116 ID = 1968
```

第一个参数06用于发送key值`EE DD CC BB`

```
9.782739 1  730             Tx   d 8 06 27 06 EE DD CC BB AA  Length = 226244 BitCount = 116 ID = 1840
```

正响应，key验证通过，成功解锁安全模式。

```bash
9.783703 1  7B0             Rx   d 8 02 67 06 00 00 00 00 00  Length = 235910 BitCount = 122 ID = 1968
```



接下来是一个多帧的CAN-TP帧，前四个bit固定为1，4-16bit表示有效字节数据长度为0xD，后续为数据部分。

```
9.788131 1  730             Tx   d 8 10 0D 31 01 FF 00 44 08  Length = 232000 BitCount = 119 ID = 1840
```

响应包为流控帧，前四个bit固定为3，4-8bit表示流状态，当前为0（继续发送），8-16bit表示允许一次连续发送的CF数量，当前为8，告知发送端，其在没有接收到接收端的流控帧期间；最多能发送的连续帧数量是8。

```
9.788431 1  7B0             Rx   d 8 30 08 00 00 00 00 00 00  Length = 239910 BitCount = 124 ID = 1968
```

连续帧,前四个bit固定为2,4-8个bit为SN，值为0x00-0x0F，**首帧开始1-F，第二次循环0-F**。其余为data,

```
9.788947 1  730             Tx   d 8 21 00 00 00 00 00 20 00  Length = 244244 BitCount = 125 ID = 1840
```

综上所述，当前多帧传送的数据为：`31 01 FF 00 44 08 00 00 00 00 00 20 00`

Service ID 0x31是用于启动、停止、查询RID，第一个参数01表示启动RID例程，第二个参数`FF 00`表示eraseMemory（擦除内存的 RID）

44表示之后的两个数据分别以4字节、4字节为单位，也就是0x08000000、0x00002000



正响应包，

```
9.789707 1  7B0             Rx   d 8 05 71 01 FF 00 00 00 00  Length = 233910 BitCount = 121 ID = 1968
```



接下来又是一个连续帧

```bash
9.791765 1  730             Tx   d 8 10 0B 34 00 44 08 00 00  Length = 236244 BitCount = 121 ID = 1840
9.792061 1  7B0             Rx   d 8 30 08 00 00 00 00 00 00  Length = 239910 BitCount = 124 ID = 1968
9.792625 1  730             Tx   d 8 21 00 00 00 20 00 AA AA  Length = 234244 BitCount = 120 ID = 1840
9.793715 1  7B0             Rx   d 8 04 74 20 01 02 00 00 00  Length = 233910 BitCount = 121 ID = 1968
```

当前多帧发送的数据为：`34 00 44 08 00 00 00 00 00 20 00`

Service ID为34用于请求从客户端到服务器的数据传输，第一个参数00表示不使用 CompressionMethod 或 cryptoningMethod。第二个参数44分别表示memoryAddress和memorySize的字节数，接下来的数据根据第二个参数分成memoryAddress和memorySize，当前memoryAddress是0x08000000，memorySize是0x00002000。

正响应的第一个参数20表示后面数据的字节数分别是2和0，第三个参数为2字节，代表maxNumberOfBlockLength，数据为0x0102，此参数来通知客户端每个 TransferData 请求消息中应包含多少个数据字节。



接下来是一个多帧

```bash
   9.795696 1  730             Tx   d 8 10 82 36 01 28 04 00 20  Length = 232244 BitCount = 119 ID = 1840
   9.795987 1  7B0             Rx   d 8 30 08 00 00 00 00 00 00  Length = 239910 BitCount = 124 ID = 1968
   9.796548 1  730             Tx   d 8 21 45 01 00 08 21 03 00  Length = 236244 BitCount = 121 ID = 1840
   9.796790 1  730             Tx   d 8 22 08 23 03 00 08 27 03  Length = 236244 BitCount = 121 ID = 1840
   9.797030 1  730             Tx   d 8 23 00 08 2B 03 00 08 2F  Length = 234000 BitCount = 120 ID = 1840
   9.797278 1  730             Tx   d 8 24 03 00 08 00 00 00 00  Length = 242000 BitCount = 124 ID = 1840
   9.797526 1  730             Tx   d 8 25 00 00 00 00 00 00 00  Length = 242000 BitCount = 124 ID = 1840
   9.797770 1  730             Tx   d 8 26 00 00 00 00 00 33 03  Length = 238000 BitCount = 122 ID = 1840
   9.798012 1  730             Tx   d 8 27 00 08 35 03 00 08 00  Length = 236000 BitCount = 121 ID = 1840
   9.798256 1  730             Tx   d 8 28 00 00 00 37 03 00 08  Length = 238000 BitCount = 122 ID = 1840
   9.798556 1  7B0             Rx   d 8 30 08 00 00 00 00 00 00  Length = 239910 BitCount = 124 ID = 1968
   9.799088 1  730             Tx   d 8 29 39 03 00 08 5F 01 00  Length = 232259 BitCount = 119 ID = 1840
   9.799329 1  730             Tx   d 8 2A 08 5F 01 00 08 5F 01  Length = 234259 BitCount = 120 ID = 1840
   9.799569 1  730             Tx   d 8 2B 00 08 5F 01 00 08 5F  Length = 234015 BitCount = 120 ID = 1840
   9.799809 1  730             Tx   d 8 2C 01 00 08 5F 01 00 08  Length = 234015 BitCount = 120 ID = 1840
   9.800049 1  730             Tx   d 8 2D 5F 01 00 08 5F 01 00  Length = 234015 BitCount = 120 ID = 1840
   9.800291 1  730             Tx   d 8 2E 08 5F 01 00 08 5F 01  Length = 236015 BitCount = 121 ID = 1840
   9.800531 1  730             Tx   d 8 2F 00 08 5F 01 00 08 5F  Length = 234015 BitCount = 120 ID = 1840
   9.800773 1  730             Tx   d 8 20 01 00 08 5F 01 00 08  Length = 236015 BitCount = 121 ID = 1840
   9.801077 1  7B0             Rx   d 8 30 08 00 00 00 00 00 00  Length = 239910 BitCount = 124 ID = 1968
   9.801509 1  730             Tx   d 8 21 5F 01 00 08 5F 01 00  Length = 234244 BitCount = 120 ID = 1840
   9.801745 1  730             Tx   d 8 22 08 5F 01 00 08 AA AA  Length = 230244 BitCount = 118 ID = 1840
   9.802687 1  7B0             Rx   d 8 03 7F 36 78 00 00 00 00  Length = 233910 BitCount = 121 ID = 1968
   9.802931 1  7B0             Rx   d 8 02 76 01 00 00 00 00 00  Length = 235910 BitCount = 122 ID = 1968
```

82 表示数据的长度，Service ID 36 表示客户端将数据传输到服务器，01表示blockSequenceCounter，数据是分块传输的，该字段一次递增，之后的为数据段。去除有含义的字段，每块中数据段的长度为0x82-2=0x80，在整个文件最后一次传输的块ID为0x40，0x40*0x80=0x2000。



提取数据：

```python
import os
data_len = 0x80
filecnt = ""
tmp_len = 0
with open("./data.txt") as file:
    for item in file:
        if "Rx" not in item:
            cnt = item[item.index("Tx   d 8 ")+9:item.index("  Length =")]
            if cnt.startswith("10 82 36"):
                # filecnt += cnt.strip()
                filecnt += cnt.replace(" ","").decode("hex")[4:]
                tmp_len += 4
            if cnt.startswith("2"):
                if tmp_len+7>0x80:
                    filecnt += cnt.replace(" ","").decode("hex")[1:6]
                    print cnt.replace(" ","")
                    tmp_len = 0
                else:
                    filecnt += cnt.replace(" ","").decode("hex")[1:]
                    tmp_len += 7

r = open("./ext_bin","wb+")
r.write(filecnt)
r.close()
```

导入ghidra

![image-20221103112749757](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20221103112749757.png)

在options中调整加载内存地址

![image-20221103112836897](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20221103112836897.png)



从中找到关键函数：

![image-20221103112916819](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20221103112916819.png)

把flag字符串进行转变：

```python
data = "flag{canoecr7-zd9h-1emi-or8m-f8vm2od81nfk}"
def aaa(idx,num):
    return chr(ord(data[idx])+num)
rule = {
    7:-0xd,
    0x10:-5,
    0x14:-0x2c,
    8:-0xb,
    10:-0x30,
    0xc:0x2b,
    0x21:0x32,
    0x24:0x2e,
    0x18:-0xd,
    0x19:-0x42,
    6:0x3,
    0x22:-0x37,
    0x1d:-0x33,
    0xe:-0x17,
    0x1e:-6,
    0x20:-0x3c,
    9:-0x34,
    0xb:-0xe,
    0x23:-0x34,
    0x1b:-0x3a,
    0x11:-0x30,
    0x15:-0x38,
    0x27:-0x35,
    5:-0x30,
    0x13:0x3,
    0x16:-5,
    0x26:-0x37,
    0x28:-0x38,
    0xf:-2,
    0x1f:-0x43,
    0x1a:-6
}

flag = ""
for x in range(0,42):
    if x not in rule.keys():
        flag += data[x]
    else:
        flag += aaa(x,rule[x])

print flag#flag{3dad13db-cb48-495d-b023-3231d80f1713}
```





相关附件：https://github.com/t0night/t0night/blob/main/AllFiles/2020%E7%BD%91%E9%BC%8E%E6%9D%AF-tesla.zip