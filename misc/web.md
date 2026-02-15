web(80,443,8080)

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