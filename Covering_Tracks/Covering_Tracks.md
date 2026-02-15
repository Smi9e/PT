# Covering_Tracks

日志，文件，命令记录。

没有完美的痕迹清理，专业取证人员仍可能发现痕迹，只能尽可能的少留下痕迹。

[TOC]

## Windows 痕迹清理

系统日志，启动服务日志，文件时间和所有者。

#### 日志操作

windows 系统日志主要包括system,application,security以及各种应用服务日志。

###### 导出

```
copy/cp c:\windows\system32\winevt\logs\system32.evtx system32.evtx

wevtutil epl security security.evtx #evtx格式

wevtutil qe security /f:text > secruity.txt #txt格式

wevtutil qe security /f:xml > secruity.xml #xml格式

get-winevent -logname "security" | export-csv security.csv #csv格式(时间长)

get-winevent -logname "security" > security.txt #txt格式(时间长)
```

###### 清理

```
wevtutil cl system

clear-eventlog -logname application,system,security

minikatz event::clear

run event_manager -c [system]

foreach ( $i in `get-winevent -listlog "*"` ) { wevtutil cl $i.logname }\#清除所有系统日志（危险操作）
```

###### 伪造

```
eventcreate /id 1000 /t warning /d "this is the massage" /l system
```

###### 挂起和恢复

```
Stop-Service/Start-Service EventLog -Force 停止日志记录
```

#### 文件操作

###### 删除

```
del example.txt / rd example_folder / rm example.txt / remove-item example.txt

cipher /w:"example.txt"  #覆写(通过2次覆写0x00,0xFF,1次随机数)
```

###### 时间修改

```
windows 文件时间一般会有三项，即CreationTime,LastWriteTime,LastAccessTime

(Get-Item "C:\path\to\test.txt").CreationTime = "2023-10-01 12:00:00" #修改为指定时间 gi或者gci #Get-Date 是当前时间

foreach ( $i in `gci .` ) {$i.lastwritetime=get-date}  #将本目录下所有文件创建时间修改为当前时间
```

###### 所有者修改

```
get-acl example.txt #获取所有者

icacls "C:\example\file.txt" /setowner "qwe"
```

###### 文件

```
%localappdata%\Microsoft\Windows\History #近期访问记录

%AppData%\Microsoft\Windows\PowerShell #powershell命令记录文件

%AppData%\Microsoft\Windows\Recent\ #recent文件（最近打开的文件）

%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\ #清除跳表（记录文件跳转）

%AppData%\Microsoft\Windows\Recent\CustomDestinations\ #清除跳表（记录文件跳转）

%temp% #用户临时文件

C:\Windows\Prefetch #预读文件，可能包含执行过的程序痕迹#

C:\Windows\System32\LogFiles\Firewall\pfirewall.log 防火墙日志（需启动）windows definder 日志'

C:\Windows\System32\Winevt\logs\ #大部分系统日志
```

###### 注册表

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU #运行记录

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs #删除最近打开文件记录
```

###### 远程连接日志（进攻手段决定）

```
rdp:

HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers

%USERPROFILE%\Documents\Default.rdp

smb\wmi:

Microsoft-Windows-WMI-Activity/Operational 日志

net session \\computername /delete # 清除net sessions（需要管理员权限）

win-RM:

Microsoft-Windows-WinRM/Operational 日志

windows PowerShell 日志
```

###### 服务日志清除（部分，实战中随机应变）

```
IIS:

%SystemDrive%\inetpub\logs\LogFiles\

Apache:

Apache安装目录\logs\

Nginx:

Nginx安装目录\logs\

Tomcat:

Tomcat安装目录\logs\

MSSql:

%ProgramFiles%\Microsoft SQL Server\MSSQL<版本>.<实例名>\MSSQL\Log

MySQL:

MySQL安装目录\data\

PostgreSQL:

PostgreSQL安装目录\data\

Oracle:

$ORACLE_BASE/diag/rdbms/<数据库名>/<实例名>/trace/

MongoDB:

MongoDB安装目录\bin\mongod.log
```

## linux

#### 日志

###### 系统日志

```
/var/log/utmp #记录当前已经登录的用户信息 w,who,users

/var/log/wtmp #显示所有成功登录登出的记录 last

/var/log/btmp #记录登录失败信息 lastb

/var/log/lastlog #记录所有用户最后一次登录时间的日志 lastlog

/var/log/secure #安全日志

/var/log/messages #系统启动后的信息和错误日志

/var/log/syslog

/var/log/cron #计划任务
```

###### 服务日志

```
/var/log/httpd #apache日志

/var/log/nginx #nginx日志

/var/log/cron #定时任务记录



sed -i '/192.168.1.100/d' /var/log/messages #删除匹配行日志

sed -i 's/12:20:11/12:20:99/g' /var/log/messages #替换匹配行内容

sed -i '/Qsa3.*su.*root/d' /var/log/auth.log  #删除提权痕迹
```

#### 文件时间

linux 文件时间属性分为4种，分别为访问时间atime，修改时间mtime，变更时间ctime，创建时间btime

###### 修改时间和访问时间:

```
touch -r A B 使得B文件的时间变得和A文件相同

touch -d "2018-04-18 08:00:00" test.txt 修改为指定时间
```

###### 创建时间:(修改系统时间是非常危险的操作)

```
date -s "2018-04-18 08:00:00"

move 旧文件 新文件名

cp 旧文件名 新文件

sudo timedatectl set-timezone Asia/Shanghai

sudo timedatectl set-ntp true

sudo timedatectl set-ntp false
```

###### 变更时间:(修改系统时间是非常危险的操作)

```
date -s "2018-04-18 08:00:00"

chmod u+x file_name

chmod u-x file_name

debugfs -w /dev/sda1

set_inode_field /home/qwe3/main/main.sh ctime 946656000
```

###### 命令记录

```
在命令行前加空格（有的发行版不支持）

unset HISTSIZE #清空历史保存命令记录

history -c                   #bash 防止命令被写入.bash_history   zsh是fc -p

echo > ~/.*_history
```

###### vim操作记录

```
echo > ~/.viminfo
```

###### mysql历史

```
~/.mysql_history
```

###### 文件覆写

```
shred -f -u -z -v -n 8 1.txt

wipe -r /tmp/test
```

###### 文件加锁

```
lsattr +i shell.php #查看文件加锁情况

chattr +i shell.php #加锁 无法修改，删除，重命名，不能创建链接，不能写入数据

chattr -i shell.php #解锁

chattr +a /ver/log/messages #只能追加不能删除
```