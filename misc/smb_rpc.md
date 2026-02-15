smb,rpc(135,139,445)(*横向*)

开启smb服务

impacket-smbserver guest . -smb2support

impacket-smbserver guest . -username admin -password passwd -smb2support

列出共享(判断能否匿名登录)

nxc smb 192.168.12.130 -u '' -p '' --shares #空用户名，空密码

nxc smb 192.168.12.130 -u anonymous -p '' --shares #anonymous用户名，空密码

nxc smb 192.168.12.130 -u admin -p 'passwd' --shares #用户名，密码

smbclient -L 192.168.12.130 -U '' -N #空用户名，空密码

smbclient -L 192.168.12.130 -U anonymous -N #anonymous用户名，空密码

smbclient -L 192.168.12.130 -U admin%'passwd' #用户名，密码

smbmap -u '' -p '' -H 192.168.12.130 #空用户名，空密码

smbmap -u anonymous -p '' -H 192.168.12.130 #anonymous用户名，空密码

smbmap -u admin -p passwd -H 192.168.12.130 #用户名，密码

smb匿名登录(交互连接)

impacket-smbclient ''@192.168.12.130 -no-pass #空用户名，空密码

impacket-smbclient anonymous@192.168.12.130 -no-pass #anonymous用户名，空密码

: shares : use IPC$ : help

smbclient //192.168.12.130/GUEST -U '' -N #空用户名，空密码

smbclient //192.168.12.130/GUEST -U anonymous -N #anonymous用户名，空密码

: help : mget : mput

smb实名登录(交互连接)

impacket-smbclient admin:passwd@192.168.12.130 -no-pass

: shares : use IPC$ : help

smbclient //192.168.12.130/GUEST -U admin%'passwd'

: help : mget : mput

net use \\192.168.12.130\IPC$ passwd /user:admin

net use

net view \\192.168.12.130

net use \\192.168.12.130\GUEST

dir \\192.168.12.130\GUEST

copy : dir : type : schtasks

net use \\192.168.12.130\IPC$ /del

rpc匿名登录

rpcclient 192.168.12.5 -U '' -N

help : enumdomusers : enumdomgroups : enumdomains

rpc实名登录

rpcclient -U win2019%'root' 192.168.12.5

help : enumdomusers : enumdomgroups : enumdomains

impacket-rpcdump win2019:'root'@192.168.12.5

SID枚举/RID枚举

impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\samr]' samr操作数枚举

impacket-rpcmap -brute-opnums -opnum-max 64 -auth-level 1 'ncacn_np:192.168.12.5[\pipe\lsarpc]' lsarpc操作数枚举

impacket-samrdump two.com/win2019:'root'@192.168.12.5 #samr

impacket-lookupsid two.com/win2019:'root'@192.168.12.5 #lsarpc

nxc smb 192.168.12.5 192.168.12.5 -u win2019 -p root --rid-brute

enum4linux-ng -u win2019 -p root 192.168.12.5 -U -R

rpcclient $> enumdomains ; lookupdomain ; lookupsids ; lookupsids S-1-5-21-873118422-227618334-1429070027-1000/1001/1002 ; lookupnames win2019