# Enumeration

I gaze across all four seas, every detail stands clear, My heart hides in the dark, traces reveal themselves in the faint.

<br>

目穷四海，纤毫毕现，心隐于暗，迹显于微。

[TOC]

## windows枚举（服务器信息，网络信息，用户信息，防护软件，密码搜索）

#### 服务器信息枚举（版本，架构，服务，进程，驱动，磁盘，补丁，系统，应用程序，计划任务，开机启动，环境变量）

###### 版本

```
ver #显示当前windows系统的版本号

powershell Get-ComputerInfo -Property "OsVersion"
```

###### 架构

```
echo %processor_architecture% #架构信息

powershell Get-ComputerInfo -Property "OsArchitecture"
```

###### 服务

```
sc query state= all #服务信息
net start #已启动服务

powershell Get-Service
```

###### 进程

```
tasklist #列举进程信息
tasklist /svc #显示每个进程中主持的服务

powershell Get-Process
```

###### 驱动

```
driverquery #驱动信息

powershell Get-CimInstance Win32_SystemDriver
```

###### 磁盘

```
mountvol #查看磁盘序列

powershell Get-Volume
```

###### 补丁

```
systeminfo | findstr KB #查看补丁

powershell Get-HotFix
```

###### 系统

```
systeminfo #系统信息
hostname #显示当前机器名

powershell Get-ComputerInfo
```

###### 应用程序

```
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" && reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" && reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" #应用程序

powershell Get-Package
```

###### 计划任务

```
schtasks /query /fo list /v #计划任务信息
schtasks /query /fo CSV | find /v "\Microsoft" | sort /unique #去除默认计划任务

powershell Get-ScheduledTask
powershell Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }
```

###### 开机启动

```
echo === 所有用户的个人启动文件夹 === & for /d %i in (C:\Users\*) do @(if exist "%i\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" dir "%i\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") & echo === 所有用户的公共启动文件夹 === & dir "c:\programdata\microsoft\windows\start menu\programs\startup" & echo === HKCU Run === & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" & echo === HKCU Runonce === & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce" & echo === HKLM Run === & reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" & echo === HKLM Runonce === & reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" & echo === HKLM WOW6432Node Run === & reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" & echo === HKLM WOW6432Node Runonce === & reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Runonce" #查看开机启动项

powershell Get-CimInstance Win32_StartupCommand | Format-List Name, Command, Location, User
```

###### 环境变量

```
set #环境变量

powershell Get-ChildItem env:
```

#### 网络信息枚举（ip，端口，网络接口，路由，共享，连接）

###### ip

```
ipconfig #获取ip地址
ipconfig /all #获取本地ip地址，dns，网关等配置信息

powershell Get-NetIPAddress
powershell Get-NetIPConfiguration | Format-List *
```

###### 端口

```
netstat -ano #获取端口信息
netstat -ano | findstr LISTENING #正在监听端口

powershell Get-NetTCPConnection ; Get-NetUDPEndpoint
powershell Get-NetTCPConnection -State Listen
```

###### 网络接口

```
netsh interface ip show config #获取网络接口

powershell get-netipconfiguration | ft interfacealias,interfacedescription,ipv4address
```

###### 路由

```
route print #获取路由表信息

powershell Get-NetRoute
```

###### 共享

```
net share #共享信息

powershell Get-SmbShare
```

###### 连接

```
for /L %i in (1,1,255) do @(ping -n 1 -w 1 192.168.12.%i | findstr TTL)
arp -a #查看局域网活跃设备

powershell for ($i=1;$i -lt 255;$i++){ping -w 1 -n 1 192.168.12.$i | findstr TTL }
powershell Get-NetNeighbor
```

#### 用户信息枚举（当前用户，所有用户/组，在线用户，用户策略）

###### 当前用户

```
whoami /all
whoami /user #查看当前账户sid
whoami /priv #查看当前账户权限
whoami /groups #查看当前账户所属组

powershell [System.Security.Principal.WindowsIdentity]::GetCurrent()
```

###### 所有用户/组

```
net user #查看所有账户
net user administrator #查看具体账户
net localgroup #查看所有组
net localgroup administrators #查看具体组

powershell Get-LocalUser
powershell Get-LocalUser -Name "administrator" | Format-List *
powershell Get-LocalGroup
powershell Get-LocalGroupMember -Group "administrators" | Format-List *
```

###### 在线用户(windows server)

```
query user #获取当前在线账户
qwinsta
```

###### 用户策略

```
net accounts #查看账户策略信息
```

#### 防护软件枚举（防火墙，windows defender，常见防护软件）

###### 防火墙

```
netsh advfirewall show allprofiles #查看防火墙状态
netsh advfirewall firewall show rule name=all #查看特定防火墙规则

netsh advfirewall set allprofiles state on #开启防火墙
netsh advfirewall set allprofiles state off #关闭防火墙（需高权限）



powershell Get-NetFirewallProfile
powershell Get-NetFirewallRule -DisplayName "*"

powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

###### windows defender

```
powershell Get-MpComputerStatus #查看windows defender状态
powershell Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected

#AntivirusEnabled 病毒防护
#RealTimeProtectionEnabled 实时保护
#OnAccessProtectionEnabled 访问时保护
#BehaviorMonitorEnabled 行为监控
#IsTamperProtected 篡改防护

powershell Set-MpPreference -DisableRealtimeMonitoring $false #开启实时保护
powershell Set-MpPreference -DisableRealtimeMonitoring $true #关闭实时保护（需高权限，未开启篡改防护）
```

###### 常见防护软件

```
360tray.exe/360safe.exe/ZhuDongFangYu.exe/360sd.exe #360系列防护软件
QQPCRTP.exe #QQ电脑管家
avcenter.exe/avguard.exe/avgnt.exe/sched.exe #Avira(小红伞)
SafeDogGuardCenter.exe #安全狗和其他带有safedog字符的进程
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
dir /S *passw* #目录/文件搜索
findstr /SI "passw" *.txt *.ini *.config 2>nul #文本搜索 /M 只列出文件绝对路径

powershell Get-ChildItem -Recurse -Force -Filter "*passw*" -ErrorAction SilentlyContinue
powershell Get-ChildItem -Recurse -Force -Include "*.txt", "*.ini", "*.config" -File -ErrorAction SilentlyContinue | Select-String -Pattern "passw" -CaseSensitive:$false
```

###### 注册表

```
reg query "hkcu" /f "*passw*" /t reg_sz /s #注册表目录/键名/键值搜索

#hkcr hkcu hklm hku hkcc
```

###### 无人值守文件

```
dir /S *sysprep*.txt *sysprep*.xml *sysprep*.inf *unattend*.txt *unattend*.xml *unattend*.inf

powershell Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_ -like "*sysprep*.txt" -or $_ -like "*sysprep*.xml" -or $_ -like "*sysprep*.inf" -or $_ -like "*unattend*.txt" -or $_ -like "*unattend*.xml" -or $_ -like "*unattend*.inf" }

#无人值守文件
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
dir c:\windows\repair #查询是否有安全账户数据库备份文件
copy c:\windows\repair\sam c:\temp\sam
copy c:\windows\repair\system c:\temp\system

powershell Get-ChildItem -Path "c:\windows\repair"
powershell Copy-Item -Path "c:\windows\repair\sam" -Destination "c:\temp\sam"
powershell Copy-Item -Path "c:\windows\repair\system" -Destination "c:\temp\system"

#利用creddump7提取hash
python pwdump.py system sam
```

###### 便笺信息

```
copy %localappdata%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite c:\temp\plum.sqlite #便笺内容

powershell Copy-Item -Path "$env:localappdata\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite" -Destination "c:\temp\plum.sqlite"

#利用
sqlite3 plum.sqlite
sqlite>SELECT * FROM ".note";
```

###### 应用中的密码

```
#SessionGopher 查找常见应用中的密码
powershell -ep bypass -c ". .\SessionGopher.ps1 ; Invoke-SessionGopher -Thorough" 

#LaZagne
lazagne.exe all

#Seatbelt
seatbelt.exe -group=all -full
```

###### powershell历史命令记录

```
for /d %i in (C:\Users\*) do @(if exist "%i\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" type "%i\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul) #查看所有账户历史命令记录

powershell Get-Content -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
```

###### wifi密码

```
netsh wlan show profiles * key=clear #wifi密码
```

###### 凭据管理器

```
cmdkey /list #列出保存的凭据

#Invoke-WCMDump
powershell -ep bypass -c ". .\Invoke-WCMDump.ps1 ; invoke-wcmdump"
```

###### wsl子系统

```
where /R "c:\windows" "bash.exe"

powershell Get-ChildItem -Recurse -Force -Path "c:\windows" -Filter "bash.exe" -ErrorAction SilentlyContinue
```

#### 自动枚举

```
peas : winpeas

metasploit : search enum ; search suggester

PowerUp : Invoke-PrivescAudit

PrivescCheck : Invoke-PrivescCheck
```

## linux枚举（服务器信息，网络信息，用户信息，软件和文件）

#### 服务器信息枚举（虚拟化，系统基本信息，内核版本，系统架构，发行版本，系统主机名，系统环境，进程，corn自动任务，磁盘配置）

###### 虚拟化

```
systemd-detect-virt #查看是否位于虚拟机

grep 'docker' /proc/1/cgroup #查看是否位于docker容器
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
uname -m #系统架构信息
```

###### 发行版本

```
cat /etc/*-release #查看发行版信息
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
echo $PATH #查看系统路径
cat /etc/profile #查看账户变量及配置文件
cat /etc/shells #查看系统可用shell
```

###### 服务

```
systemctl list-units --type=service --all #查看所有服务
systemctl list-units --type=service --state=running #查看正在运行的服务
systemctl list-unit-files --type=service | awk '$2 == "enabled" {print $0}' #查看开机启动服务
```

###### 进程

```
ps aux 2>/dev/null #查看系统进程，包括进程pid，所属账户，cpu占用率，内存占用等
ps aux 2>/dev/null | grep 'root' #筛选root权限运行的进程
ls -liah -- $(ps aux 2>/dev/null | awk '{print $11}') 2>/dev/null | sort | uniq #查看进程对应的文件位置

ps -ef #显示所有运行进程，详细输出
ps aux #显示所有账户进程，显示启动进程的账户，显示未连接到终端的进程

ps axjf #显示所有账户进程，显示未连接到终端的进程，显示进程树，详细输出

top -n 1 #查看当前运行的进程机器资源使用情况，输出一次
```

###### corn自动任务

```
cat /etc/crontab #查看系统cron自动任务

ls -liah /etc/cron* 2>/dev/null #查看所有cron自动任务列表

for i in $(cat /etc/passwd | cut -d: -f1) ;do echo "#crontabs for $i #" ; crontab -u $i -l 2>/dev/null ; done #查看所有账户的cron自动任务

crontab -l #查看当前账户cron自动任务
crontab -u xxx -l #查看其他账户cron自动任务
```

###### 磁盘配置

```
cat /etc/fstab #查看挂载信息

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
netstat -antlp #显示所有套接字，不解析名称，tcp，列出监听端口，pid信息
ss -tulnp

netstat -ano #显示所有套接字，不解析名称，显示计时器
```

###### dns

```
cat /etc/resolv.conf #查看dns配置文件

cat /etc/hosts
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
id $(cat /etc/passwd | cut -d":" -f1) #查看所有用户及其对应id和组
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
cat /etc/passwd | awk -F: '$3 == 0 {print $0}' #查看超管用户
```

###### 特权访问

```
sudo -l #sudo特权访问

getcap -r / 2>/dev/null #capabilites权限
```

#### 软件和文件（软件信息，常用工具，敏感文件，特殊权限文件，可读可写可执行文件，特殊拓展名文件&关键字文件，历史命令记录，隐藏文件，配置文件，ssh私钥）

###### 软件信息

```
yum list #查看软件安装信息
apt list
dpkg -l
```

###### 常用工具

```
which sh bash rbash dash pwsh zsh gcc cc python python2 python3 c c++ c# java ruby go golang nc netcat curl wget ftp iftp tmux screen vi vim find 2>/dev/null
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
find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/var/lib/*" ! -path "/usr/lib/*" 2>/dev/null #查看可写文件

#-readable 可读
#-writable 可写
#-executable 可执行
```

###### 特殊拓展名文件&关键字文件

```
find / -name *.bak -type f 2>/dev/null #查看特殊后缀文件

find / -name *passw* -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/var/lib/*" ! -path "/usr/lib/*" 2>/dev/null #查看特殊关键字文件

find / -type f -exec grep -in "passw" {} \; 2>/dev/null #查找文件内关键字
```

###### 历史命令记录

```
ls -liah /root/.*_history /home/*/.*_history 2>/dev/null #历史命令记录

history
```

###### 隐藏文件

```
ls -liah -- $(find /home -name ".*" 2>/dev/null) #查看隐藏文件
```

###### 配置文件

```
find /home -name "*.ovpn" -type f -exec ls -liah -- {} \; 2>/dev/null #查看配置文件
```

###### ssh私钥

```
find / -name "*id_rsa*" -exec ls -liah -- {} \; 2>/dev/null #查看ssh私钥文件
```

#### 自动枚举

```
peas : linpeas

metasploit : search enum ; search suggester

pspy64 : pspy64 #进程监控

linux_exploit_suggester : linux_exploit_suggester

linEnum : linEnum

unix-privesc-check : unix-privesc-check
```

## 域枚举

#### 域内信息枚举(powerview-python)

###### 安装&连接

```
python -m venv pwview
source pwview/bin/activate

cd pwview

proxychains git clone https://github.com/aniqfakhrul/powerview.py.git #下载powerview项目

cd powerview.py 

proxychains ../bin/pip3 install "git+https://github.com/aniqfakhrul/powerview.py" #使用pwview/bin/pip3

#使用
powerview two/win2019:root@192.168.12.5 #连接
```

###### 域名，域控制器，域sid，域策略

```
Get-Domain #获取到域名，域控制器，域sid，域策略
Get-DomainController #域控制器信息
```

###### 域用户，用户策略，用户属性

```
Get-DomainUser -Identity "win2019"
```

###### 域主机，主机策略，主机属性

```
Get-DomainComputer  -Identity "DC"
```

###### 域组

```
Get-DomainGroup -Identity "Administrators" #域组，组内成员
```

###### 域组内成员

```
Get-DomainGroupMember -Identity "Administrators"
```

###### 域GPO

```
Get-DomainGPO
```

###### 域OU

```
Get-DomainOU
```

###### 域信任

```
Get-DomainTrust
```

###### 域object

```
Get-DomainObject -Identity "win2019" #获取域对象
```

###### 域ACL

```
Get-DomainObjectAcl -Identity "CN=win2019,CN=Users,DC=two,DC=com" #查看其他安全主体对域对象win2019的权限

Get-DomainObjectAcl -SecurityIdentifier "S-1-5-21-873118422-227618334-1429070027-1000" #获取域对象win2019对其他安全主体的权限

[-Select "SecurityIdentifier,ObjectDN,ActiveDirectoryRights,AccessMask,ObjectAceType" -TableView]
```

###### 登录用户

```
Get-NetLoggedOn -Computer 192.168.12.5 #目标主机登录信息，当前登录用户
```

###### 主机共享

```
Get-NetShare -Computer 192.168.12.5 #目标主机共享
```

#### 自动枚举(bloodhound)

```
bloodhound-python : bloodhound-python -d one.com -u cook -p '1qaz@WSX' -dc DC.one.com -c all -ns 192.168.10.5 --zip #bloodhound-python收集域信息

bloodhound-python : proxychains bloodhound-python -d one.com -u cook -p '1qaz@WSX' -dc DC.one.com -c all  --dns-tcp -ns 192.168.10.5 --zip --dns-timeout 60 #跨代理访问

nxc : nxc ldap one.com -u cook -p '1qaz@WSX' --bloodhound -c all --dns-server 192.168.10.5 #nxc收集域信息
```

# TOOLS_LINK

```
metasploit:
https://www.metasploit.com

peas:
https://github.com/peass-ng/PEASS-ng

PowerUp:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

PrivescCheck:
https://github.com/itm4n/PrivescCheck

pspy64:
https://github.com/DominicBreuker/pspy

linux-exploit-suggester:
https://github.com/The-Z-Labs/linux-exploit-suggester

LinEnum:
https://github.com/rebootuser/LinEnum

unix-privesc-check:
https://pentestmonkey.net/tools/audit/unix-privesc-check

creddump7:
https://github.com/CiscoCXSecurity/creddump7

sqlite3：
https://www.sqlite.org/download.html

SessionGopher:
https://github.com/Arvanaghi/SessionGopher

LaZagne:
https://github.com/AlessandroZ/LaZagne

Seatbelt:
https://github.com/GhostPack/Seatbelt

Invoke-WCMDump:
https://github.com/peewpw/Invoke-WCMDump

powerview-python:
https://github.com/aniqfakhrul/powerview.py

powerview:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

proxychains:
https://github.com/rofl0r/proxychains-ng

bloodhound:
https://github.com/SpecterOps/BloodHound

bloodhound-python:
https://github.com/dirkjanm/BloodHound.py

NetExec:
https://github.com/Pennyw0rth/NetExec
```

# DOC_LINK

```
Auto_Wordlists: #敏感文件/目录
https://github.com/carlospolop/Auto_Wordlists
```
