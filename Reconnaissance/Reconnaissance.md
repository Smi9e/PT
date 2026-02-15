# Reconnaissance

分为开源情报搜集(OSINT)和主动搜集(主动情报搜集与打点阶段密不可分)。

## OSINT(开源情报收集)

#### 情报周期 { 需求(plan)，收集(collect)，处理(process)，分析(analysis)，分发(dissemination) } 

开源情报（OSINT）：来自公开可获取的渠道，如新闻报道、政府公告、企业财报、社交媒体、学术论文、卫星影像等，特点是合法、成本低、覆盖面广，是现代情报收集的基础。

###### 调查目标：

人员，组织，事件。

###### 框架：

https://osintframework.com/

###### 综合工具网站：

https://www.raebaker.net/resources

https://start.me/p/7kYgk2/rae-baker-deep-dive-osint

https://spacekid.notion.site/osint

https://rr.reuser.biz/

###### 教程：

https://xz.aliyun.com/news/17607

<br>

###### 主要分类：

opsec

<br>

人员情报(&社交媒体情报&交通情报)，组织情报

<br>

搜索引擎(google dorking)，reverse images search(图寻/网络迷踪)，AI

<br>

dark website(暗网)，加密货币&稳定币&代币&web3

<br>

Other websites' collection(其他网站收集)

------

#### opsec(行动安全)

保持安全隐私：（主要分为两种方式，使用虚拟信息，创造真空通道）。

###### 虚拟信息，虚拟设备，虚拟通道

尽可能少的留下可能证明真实身份的攻击痕迹。

###### 真实机/虚拟机

专用设备，二手笔记本，vmware，virtualBox，Hyper-V，KVM，QEMU，移动设备模拟器

###### 虚拟通讯

vpn，vps，机场

(隐私浏览器)

tor，freenet，i2p，canvas defender(数字指纹)，AdBlock(数字指纹)，Disconnect Me(数字指纹)

###### 虚拟账户

(虚拟电话)

voip，mysudo

(加密邮箱/匿名邮箱)

protonmail，thexyz，startmail，tutanota，zoho Mail

###### 假身份生成

www.fakenamegenerator.com

###### 随机头像生成

www.thispersondoesnotexist.com

###### 虚拟支付卡

www.privacy.com/virtual-card

------

#### 人员情报

++++++++++++++++++++++++++++++

###### 核心身份

姓名(命名习惯[名，姓，族名..]，昵称(相似昵称)，用户名[各网络博客等]）

性别，年龄/出生日期，国籍/民族/籍贯，政府标识符(身份证，户籍证，护照，驾驶证，行驶证...)，生物特征(画像，指纹，声纹)

###### 联系方式与位置信息

移动/固定电话号码，电子邮箱，通讯账号(wechat，QQ，telegram)，固定地址/现居住地，IP/MAC地址，汽车/牌照/型号

###### 社会关系与背景

家庭成员/伴侣，朋友，教育背景，工作履历，同事/上下级，社团/组织/党派

###### 数字足迹与网络身份

社交媒体账号(微博，抖音，facebook，twitter，instagram)，个人网站/博客，网站发言/活跃内容，注册信息

###### 财务与资产状况

公司/法人/股东，房产，知识产权/专利，商标，法院判决/失信记录

###### 时间线与事件

爱好，旅行经历，生活模式（经常出现的时间/地点），报道

++++++++++++++++++++++++++++++

###### 用户名

namechk.com #查找用户名注册过的东西

whatsmyname.app #枚举多网站用户名

namecheckup.com #枚举多网站用户名

sherlock xxx

www.whitepages.com #查找人员(联系信息等)

www.truepeoplesearch.com #搜索姓名，电话，地址

webmii.com #搜索名字在互联网上留下的痕迹

peekyou.com #搜索名字在互联网上留下的痕迹

###### 电子邮箱

查找邮箱

hunter.io

phonebook.cz

www.voilanorbert.com

Clearbit Connect #谷歌邮箱插件

github.com/paulirish/github-email

www.spokeo.com

验证邮箱是否存在

tools.verifyemailaddress.io

email-checker.net/validate

邮箱反查

https://epieos.com/

查询邮箱是否被暴露

haveibeenpwned.com

###### 电话号码

fastpeoplesearch.io

truepeoplesearch.net

thatsthem.com

phoneinfoga.net

socialcatfish.com

www.truecaller.com

calleridtest.com

infobel.com

###### 生活模式 : 研究目标的生活模式，例如发朋友圈的时间间隔，长期规律等

#### 社交媒体情报

++++++++++++++++++++++++++++++

Facebook，Twitter(X)，Instagram，MeWe

Gab，WhatsApp，Telegram

Tumblr，Skype，Viber

Snapchat，YY，VK，Pinterest

LinkedIn，github

YouTube，Flickr，TikTok，Discord

Reddit，4chan，8chan

微信，QQ，支付宝

小红书，百度贴吧，CSDN，博客园，抖音，微博，bilibili，快手，陌陌，kook，知乎

++++++++++++++++++++++++++++++

###### twitter(X)

twitter.com/search-advanced #twitter高级搜索

socialbearing.com

www.twitonomy.com

spoonbill.io #查看目标账号之前的签名

tinfoleak.com #查找目标账户的敏感信息

###### facebook

www.sowsearch.info #搜索Facebook目标用户的一些信息

intelx.io/tools?tab=facebook #搜索Facebook目标用户的一些信息

###### instagram

tools.codeofaninja.com/find-instagram-user-id #查询Instagram的用户id

www.instadp.com #下载Instagram的用户的资料

imginn.com #匿名浏览 Instagram 快拍，直接搜索用户名即可

###### telegram

tgstat.com

#### 交通情报

地图

earth.google.com #谷歌地球

maps.google.com #谷歌地图

map.baidu.com #百度地图

map.qq.com #腾讯地图

ditu.amap.com #高德地图

公路运输

earth.google.com

https://www.icauto.com.cn/gonglu/ #车主指南

铁路运输

earth.google.com

https://www.openrailwaymap.org/ #OpenRailwayMap

https://qq.ip138.com/train/ #全球列车时刻表(zh-CN)

http://railmap.renchang.me/ #任畅铁路地图

航空运输

https://www.flightradar24.com/ #flightradar24

https://zh.flightaware.com/ #flightaware

水路运输

https://www.marinetraffic.com/ #marinetraffic

https://www.vesselfinder.com/ #vesselfinder

https://www.shipxy.com/ #shipxy

------

#### 组织情报(域名，ip，cdn，dns，ip反查，whois，whois反查，注册备案，SSL证书查询，子域名，旁站，c段，威胁情报，网络空间搜索引擎，app应用，cms识别，大型工具)

###### 域名，ip，cdn，dns

tools.ipip.net/cdn.php

get-site-ip.com

cert="24217219254604001662049442027" #16进制转10进制，序列号查找真实ip，fofa语法

ping.chinaz.com #超级ping

ping.aizhan.com #超级ping

ping / nslookup / dig #(--主动搜集)

###### ip反查

site.ip138.com #ip138反查

x.threatbook.cn #微步在线

dns.aizhan.com #爱站反查域名

fofa.info #fofa

###### whois，whois反查，注册备案，SSL证书查询

whois.aliyun.com

whois.chinaz.com

whois xxx.com

whois.icann.org（国际）/whois.cnnic.cn（国内）



whois.chinaz.com #whois反查

www.benmi.com/rwhois

icp.chinaz.com

icp.miit.gov.cn #工信部icp备案查询

beian.miit.gov.cn  #icp备案查询

beian.mps.gov.cn #公安备案查询

www.beianx.cn 

www.whoxy.com

www.qcc.com #qcc

www.tianyancha.com #天眼查



crt.sh #crtsh

censys.io/certificates #censys

sslmate.com/certspotter/api #certspotter



###### 子域名

site:xxx.com #google dorking

site.ip138.com ip138

tool.chinaz.com/subdomain 站长

tools.bugscaner.com/subdomain bugscan

dnsdumpster.com

hackertarget.com/find-dns-host-records



subfinder -d baidu.com -o subdomains.txt #(--主动搜集)

amass enum -d baidu.com -o subdomains.txt #(--主动搜集)

gobuster dns -d xxx.com -w /usr/share/dnsenum/dns.txt #(--主动搜集)

wfuzz -u "https://www.baidu.com" -H "Host: FUZZ.baidu.com" -w /usr/share/dnsenum/dns.txt --hh 227 #(--主动搜集)

github.com/shmilylty/OneForAll #OneForAll子域名查询工具 教程: blog.csdn.net/weixin_49769267/article/details/131464408 #(--主动搜集)

github.com/euphrat1ca/LayerDomainFinder/releases #layer子域名挖掘机 #(--主动搜集)

###### 旁站

stool.chinaz.com/same

chapangzhan.com

###### c段

c.webscan.cc #c段查询

ip="8.210.121.0/24" #fofa

net:"8.210.121.0/24" #shodan

nmap -sn 192.168.12.1/24 #nmap

###### 威胁情报收集

x.threatbook.cn #微步

ti.nsfocus.com #绿盟科技 威胁情报云

isecurity.huawei.com/sec #华为安全平台

###### 网络空间搜索引擎

fofa.info #FOFA

www.zoomeye.org #钟馗之眼

0.zone #零零信安

www.shodan.io #shodan

censys.com #censys

hunter.qianxin.com #鹰图

quake.360.net/quake/#/index #360quake

www.kamerka.io / lite.kamerka.io #kamerka(下载) / 轻量kamerka

###### app应用

www.qimai.cn #七麦

weixin.sogou.com #搜狗微信

###### cms识别

finger.tidesec.com #云悉指纹

fp.shuziguanxing.com #数字观心

github.com/TideSec/TideFinger #TideFinger (指纹识别工具) #(--主动搜集)

whatweb #(--主动搜集)

wappalyze #浏览器插件 #(--主动搜集)

###### 大型工具

www.maltego.com #maltego

github.com/ki9mu/ARL-plus-docker #arl灯塔系统

github.com/penson233/TailorFinder #Tailorfinder #教程 xz.aliyun.com/news/13179 

------

#### 搜索引擎(google，bing，yandex，duckduckgo，baidu，sogou)

google

www.google.com #google

google dorking

https://www.google.com/advanced_search #高级搜索

 \+ 强制搜索其后的一个单词

 \- 忽略剔除一项

 ~ 同义词

 . 单一通配符

 \* 通配符，可代表多个字母

 "" 精确查询

 | 或 OR 只要符合多个关键词中的任意一个结果予以显示

site: 搜素特定站点或域名

intitle: 网页标题包含关键词 (不能含有空格 使用OR AND连接关键词)

inurl: url地址中包含关键词(inurl:web inurl:gov) (不支持空格，区分大小写)

intext: 网页文本中包含关键词

filetype: 限定搜索结果的文件类型 (doc,docx,xls,xlsx,ppt,pptx,txt,htm,html,py,java,php)

info: 快速获取相似页

link: 查找指向该域名的外部链接

###### bing

www.bing.com #bing

learn.microsoft.com/zh-cn/microsoftsearch/overview-microsoft-search-bing #搜索指南

###### yandex

yandex.com #yandex

###### duckduckgo

duckduckgo.com #duckduckgo 

help.duckduckgo.com/duckduckgo-help-pages/results/syntax/ #搜索指南

###### baidu

www.baidu.com #baidu

###### sogou

sogou.com #sogou

------

#### reverse images search(图寻/网络迷踪)

###### exif数据

exiftool xxx.png

exif.tuchong.com

exifdata.com

###### 地图开放平台

https://lbsyun.baidu.com/ 百度地图开放平台

++++++++++++++++++++++++++++++

import requests

\# 服务地址

host = "https://api.map.baidu.com"

\# 接口地址

uri = "/place/v2/search"

\# 此处填写你在控制台-应用管理-创建应用后获取的AK

ak = "U3qWRpks1YCmohsoSarDc0uDeTC6eUfv"

params = {

​    "query":    "ATM机",

​    "tag":    "银行",

​    "region":    "北京",

​    "output":    "json",

​    "ak":       ak,

}

response = requests.get(url = host + uri, params = params)

if response:

​    print(response.json())

++++++++++++++++++++++++++++++

https://lbs.amap.com/ 高德地图开放平台

http://developers.google.com/maps google地图开放平台

https://www.openstreetmap.org/ OpenStreetMap

https://overpass-turbo.eu/ 

https://taginfo.openstreetmap.org/ tagsfinder

++++++++++++++++++++++++++++++

[timeout:20][bbox:{{bbox}}][out:json];

nwr["name"="河北科技工程职业技术大学"];

(._;>;);

out;

++++++++++++++++++++++++++++++

whatiswhere.com/

https://www.geolearnr.com/quiz-info/bollards #路杆

1.气候，2.山脉与水体，

植被

树木

https://thetreeographer.com/

，土壤，光影 https://www.suncalc.org/ ，

天气

天文气象图

https://earth.nullschool.net/zh-cn/ 

https://www.windy.com/

https://www.ventusky.com/

https://zoom.earth/

历史天气查询

https://www.wunderground.com/history

https://spacekid.notion.site/2345-09f15019fb4e4e8aaaa5bf961934253e?pvs=25

，星空，

星象 (高级)

https://stellarium-web.org/

https://theskylive.com/planetarium

人文信息{

国旗

https://www.fotw.info/flags/index.html

，

建筑

徽派、闽派、京派、苏派、晋派、川派

，语言，文字，

人种和肤色

黑白黄

，当地特色，商品

}

https://zh.flightaware.com/ 飞机

https://www.marinetraffic.com/ 船舶

https://www.openrailwaymap.org/ 铁路

http://cnrail.geogv.org/zhcn/ 中国铁路

识文

https://www.ip138.com/

https://qq.ip138.com/train/ 列车时刻表

https://www.ip138.com/jb.htm 飞机时刻表

https://www.ip138.com/sj/ 手机归属地

https://www.ip138.com/post/ 邮编和区号查询

https://qq.ip138.com/idsearch/ 身份证号码查询

https://www.ip138.com/carlist.htm 车牌查询

http://www.worldlicenseplates.com/ 世界各国车辆车牌样式

识图

https://lens.google/ 谷歌智能镜头（通过 Chrome 浏览器的右键菜单即可使用）

google.com

https://images.google.com/ 谷歌图片

bing.com

https://www.microsoft.com/zh-cn/bing/visual-search/ bings识图

baidu.com

https://graph.baidu.com/pcpage/index?tpl_from=pc 百度识图

https://pic.sogou.com/ 搜狗识图

yandex.com yandex识图

https://tineye.com/ tineye 反向识图

https://earth.google.com/ 谷歌地球（街景）

https://map.baidu.com 百度地图 (街景)

https://www.amap.com/ 高德地图

https://map.qq.com/ 腾讯地图

实景照片查询

大众点评，抖音，微博，小红书

https://720yun.com/ 720云

anjuke.com/ 安居客 (可能会有小区全景图)

https://www.skyscrapercity.com/ (城市天际线图库)

------

AI

claude，cheatgpt，gemini，Grok，cursor，Copilot，deepseek，豆包/Dola

------

### dark website(暗网)

dark.fail #dark fail

http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/ #Ahmia

thepiratebay.org #The Pirate Bay(海盗湾)

4chan.org #4chan

http://ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion/ #CIA(美国情报局)

https://www.facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion #facebook

http://xp44cagis447k3lpb4wwhcqukix6cgqokbuys24vmxmbzmaq2gjvc2yd.onion #theguardian(线人对接暗号)

http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/ #propublica(深层新闻信息)

http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/ #the hidden wiki

http://crqkllx7afomrokwx6f2sjcnl2do2i3i77hjjb4eqetlgq3cths3o6ad.onion/ #megaTor(匿名文件共享)

暗网域名生成工具:

v2 : https://github.com/lachesis/scallion

v3 : https://github.com/dr-bonez/tor-v3-vanity

------

### 加密货币&稳定币&代币&web3

交易所(违背区块链去中心化)

币安，火币，欧易

交易流程{

c2c交易(购入USDT)

资金账户->交易账户

交易货币

USDT->BTC

BTC->USDT

交易账户->资金账户

c2c交易(卖出USDT)

}

比特币

教程

bulianglin.com/archives/bitcoin.html

bulianglin.com/archives/miner.html

bulianglin.com/archives/mining-hijack.html

比特币钱包

https://bitcoin.org/zh_CN/download

比特币挖矿

solo独立挖矿(独自获得全部收益)

github.com/pooler/cpuminer #本地挖矿软件

minerd.exe -a sha256d -D -o http://127.0.0.1:18442 -u user1 -p pass1 --coinbase-addr [btc_address]

pool矿池挖矿(按比例获取收益)

www.antpool.com/home

www.f2pool.com

minerd.exe -a sha256d -D -o stratum+tcp://pool -u user.0 -p x

solo矿池挖矿(独自获得绝大多数收益(给pool少部分))

solo.ckpool.org

可视化区块链查看工具

mempool.space/zh

代币

NFT(非同质化代币)

https://opensea.io/

web1.0 读(早期雅虎等)

web2.0 读 & 写(facebook,tiktok等)

web3.0 读 & 写 & 拥有(类似比特币的持有，比如上传视频到区块链，拥有权，删除权为自己所有)

------

### Other websites' collection

世界上最受欢迎的网站排名 : www.similarweb.com/top-websites

数据库泄露

intelx.io

pipl.com

spiderfoot.xyz