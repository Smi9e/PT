# Covering_Tracks

It is like the plight of the fire-stealer: to cover your tracks, you must touch the flame, yet the act of touching leaves its mark.

<br>

这就像一个“盗火者”的困境：为了掩盖行踪，你不得不触碰火种，而触碰本身就会留下印记。

[TOC]

## Windows 痕迹清理（日志操作，文件操作，敏感日志&文件，命令记录，用户&组）

#### 日志操作

###### 导出

```
copy c:\windows\System32\winevt\Logs\System.evtx .\System.evtx #evtx格式
powershell cp c:\windows\System32\winevt\Logs\System.evtx .\System.evtx
wevtutil epl system system.evtx

powershell Get-WinEvent -LogName 'System' | Export-Clixml -Path '.\System.xml' #xml格式

powershell Get-WinEvent -LogName 'System' | Export-Csv -Path '.\System.csv' #csv格式

wevtutil qe system /f:text > system.txt #txt格式
powershell Get-WinEvent -LogName 'System' | Out-File -FilePath '.\System.txt'
```

###### 清理

```
主要日志:
system #系统日志
security #安全日志
application #应用日志
"windows powershell" #powershell日志

wevtutil cl [system,security,application,"windows powershell"]
powershell clear-eventlog -logname application,system,security

minikatz event::clear

run event_manager -c [system,application,security]
clearev

#清除所有日志记录(所有日志位置:C:\Windows\System32\winevt\Logs)
for /f "delims=" %i in ('wevtutil el') do wevtutil cl "%i"
powershell foreach ( $i in `get-winevent -listlog "*"` ) { wevtutil cl $i.logname }

#清除指定条目日志
EventCleaner closehandle
EventCleaner 100 #删除 event record id 为 100 的日志
```

###### 伪造

```
eventcreate /id 1000 /t warning [/so administrator] /d "this is the test" /l system
```

###### 查看

```
wevtutil qe system #查看日志
powershell Get-WinEvent -LogName System

run event_manager -l system

wevtutil el #列出日志
powershell Get-WinEvent -ListLog *
run event_manager -i
```

###### 挂起和恢复

```
net stop eventlog #挂起
powershell Stop-Service EventLog -Force
EventCleaner suspend

net start eventlog #恢复
powershell Start-Service EventLog
EventCleaner normal

sc query eventlog #确定状态
powershell Get-Service EventLog
```

#### 文件操作

###### 覆写

```
cipher /w:"test.exe"
```

###### 时间修改(CreationTime,LastWriteTime,LastAccessTime)

```
powershell (gci test.txt).CreationTime="2023-10-01 12:00:00"
powershell foreach ( $i in `gci .` ) {$i.CreationTime=get-date} #将本目录下所有文件创建时间修改为当前时间

#时间查看
dir /T:C test.txt && dir /T:W test.txt && dir /T:A test.txt
powershell gci test.txt | Format-List CreationTime,LastWriteTime,LastAccessTime
```

###### 所有者修改

```
icacls test.txt /setowner "administrator"

#所有者查看
powershell Get-Acl test.txt
```

#### 敏感日志&文件

```
%localappdata%\Microsoft\Windows\History #近期访问记录
%AppData%\Microsoft\Windows\Recent #recent文件（最近打开的文件）
%temp% #用户临时文件
C:\Windows\Prefetch #预读文件，可能包含执行过的程序痕迹

%AppData%\Microsoft\Windows\Recent\AutomaticDestinations #清除跳表（记录文件跳转）
%AppData%\Microsoft\Windows\Recent\CustomDestinations #清除跳表（记录文件跳转）

C:\Windows\System32\LogFiles\Firewall\pfirewall.log #防火墙日志（需启动）windows definder日志

C:\Windows\System32\Winevt\logs #系统日志

#注册表
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU #运行记录
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs #删除最近打开文件记录

#远程连接日志
rdp:
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers
%USERPROFILE%\Documents\Default.rdp

smb\wmi:
Microsoft-Windows-WMI-Activity/Operational #默认日志位置
net session \\computername /delete #清除net sessions（需要管理员权限）

win-RM:
Microsoft-Windows-WinRM/Operational #默认日志位置
windows PowerShell #默认日志位置

#服务日志
%SystemRoot%\WindowsUpdate.log #Windows Update

%SystemRoot%\System32\DNS #DNS

%SystemRoot%\System32\DHCP #DHCP

%SystemDrive%\inetpub\logs\LogFiles\ #IIS
%SystemDrive%\inetpub\logs\LogFiles\FTPSVC #IIS_FTP

Apache安装目录\logs\ #Apache

Nginx安装目录\logs\ #Nginx

Tomcat安装目录\logs\ #Tomcat

%ProgramFiles%\Microsoft SQL Server\MSSQL<版本>.<实例名>\MSSQL\Log #MSSql

MySQL安装目录\data\ #MySQL

PostgreSQL安装目录\data\ #PostgreSQL

$ORACLE_BASE/diag/rdbms/<数据库名>/<实例名>/trace/ #Oracle

MongoDB安装目录\bin\mongod.log #MongoDB
```

#### 命令记录

```
Clear-History #清除当前界面的命令记录
powershell Clear-Content (Get-PSReadlineOption).HistorySavePath #清除历史命令记录文件
powershell clc (gci "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt").FullName #清除所有用户历史命令记录文件

Get-History #查看命令记录
powershell cat (Get-PSReadlineOption).HistorySavePath
```

#### 用户&组

```
net user 用户名 /del #删除用户
powershell Remove-LocalUser -Name "用户名"

net localgroup "组名" 用户名 /delete #移除组中用户
powershell Remove-LocalGroupMember -Group "组名" -Member "用户名"

net localgroup "测试组" /delete #删除组
powershell Remove-LocalGroup -Name "组名"
```

## linux 痕迹清理（日志操作，文件操作，敏感日志&文件，命令记录，用户&组）

#### 日志操作

###### 导出

```
cp /var/log/secure ./secure_backup
```

###### 清理

```
cat /dev/null > /var/log/secure #置空secure日志

sed -i '/Feb 22 21:39:57/d' /var/log/secure #删除匹配行日志
```

###### 伪造

```
echo "Feb 22 00:00:01 localhost polkitd[565]: Hello,User" >> /var/log/secure

sed -i 's/Feb 22 21:39:29/Feb 22 00:00:01/g' /var/log/secure #替换匹配行日志内容
```

###### 查看

```
cat /var/log/secure
```

###### 挂起和恢复

```
cp /var/log/secure ./secure_backup #挂起
rm -rf /var/log/secure
ln -s /dev/null /var/log/secure

rm -rf /var/log/secure #恢复
cp ./secure_backup /var/log/secure
chmod 600 /var/log/secure ; chown root:root /var/log/secure
```

#### 文件操作

###### 覆写

```
shred -vfzu -n 7 test.txt
```

###### 时间修改(btime,mtime,atime,ctime)

```
#mtime&atime
touch -m test.txt #将mtime设置为当前系统时间

touch -a test.txt #将atime设置为当前系统时间

touch test.txt #将mtime&atime设置为当前系统时间
touch -t 202503211430.45 test.txt #将mtime&atime设置为"2025年3月21日14:30:45"
touch -r /etc/passwd test.txt #将test.txt的mtime&atime设置为/etc/passwd的mtime&atime

#ctime 无法直接设置，跟随mtime/atime改变，更新为当前时间。但是可以通过修改系统时间到目标时间，然后重新创建文件。风险系数大。

#btime 默认无法改变，但是可以通过修改系统时间到目标时间，然后重新创建文件。风险系数大。

#时间查看[btime(创建时间),mtime(修改时间),atime(访问时间),ctime(变更时间)]
stat test.txt
```

###### 所有者修改

```
chown root:root test.txt
```

#### 敏感日志&文件

```
#系统日志
/var/log/utmp #记录当前已经登录的用户信息 w,who,users
/var/log/wtmp #显示所有成功登录登出的记录 last
/var/log/btmp #记录登录失败信息 lastb
/var/log/lastlog #记录所有用户最后一次登录时间的日志 lastlog
/var/log/secure #安全日志
/var/log/messages #系统启动后的信息和错误日志
/var/log/syslog
/var/log/cron #计划任务

#ssh
/var/log/secure #RHEL/CentOS
/var/log/auth.log #Debian/Ubuntu

#邮件服务
/var/log/maillog
/var/log/mail.log

#系统审计
/var/log/audit/audit.log

#计划任务
/var/log/cron

#内核与启动
/var/log/kern.log #Debian/Ubuntu
/var/log/dmesg

#防火墙
/var/log/ufw.log #ufw

#包管理器
/var/log/dpkg.log #Debian/Ubuntu
/var/log/yum.log #RHEL/CentOS

#系统性能
/var/log/sysstat

#服务日志
/var/log/httpd #apache日志
/var/log/nginx #nginx日志

/var/log/mysql #MySQL
/var/log/mariadb #MariaDB
/var/log/php-fpm #PHP-FPM
$CATALINA_HOME/logs #Tomcat
/var/log/vsftpd.log #FTP(vsftpd)

/var/lib/docker/containers/<container-id>/<container-id>-json.log #docker

~/.viminfo ; /root/.viminfo #vim操作记录
~/.mysql_history ; /root/.mysql_history ##mysql历史记录

#内核日志
dmesg -c
```

#### 命令记录

```
echo $SHELL #判断shell

#清除当前界面的命令记录
history -c #bash
fc -p #zsh

#bash 在命令之前增加空格（不将当前命令记录到当前界面的命令记录）
 echo "hello"

cat /dev/null > /root/.bash_history #清除历史命令记录文件

for f in /root/.*_history; do cat /dev/null > "$f"; done ; for f in /home/*/.*_history; do cat /dev/null > "$f"; done #清除所有用户历史命令记录文件
```

#### 用户&组

```
killall -u 用户名 #删除用户
userdel -r 用户名

gpasswd -d 用户名 组名 #移除组中用户

groupdel 组名 #删除组
```

## 域 痕迹清理（敏感日志&文件，用户&组）

#### 敏感日志&文件

```
%SystemRoot%\NTDS\NTDS.DIT #数据库文件

%SystemRoot%\NTDS\EDB.LOG #事务日志文件

%SystemRoot%\NTDS\EDB.CHK #检查点文件

%systemroot%\debug\dcpromo.log & dcpromoui.log #AD部署日志

%systemroot%\debug\adprep\<datetime>\adprep.log #AD准备日志

\\<domain>\SYSVOL\<domain>\Policies #SYSVOL(GPO模板和配置)

C:\Windows\System32\winevt\Logs #DC主要日志目录
```

#### 用户&组

```
net user 用户名 /domain /del #删除域用户
powershell Remove-ADUser -Identity "用户名"

net group "组名" 用户名 /delete /domain #移除域组中用户
powershell Remove-ADGroupMember -Identity "组名" -Members "用户名"

net group 组名 /delete /domain #删除域组
powershell Remove-ADGroup -Identity "组名"

Remove-ADComputer -Identity "计算机名" #删除域主机
```

# TOOLS_LINK

```
metasploit:
https://metasploit.com

mimikatz:
https://github.com/gentilkiwi/mimikatz

EventCleaner:
https://github.com/QAX-A-Team/EventCleaner/tree/master
```