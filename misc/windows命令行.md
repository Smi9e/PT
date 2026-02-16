## windows 命令行操作(bat+powershell)

[F3]/[ctrl]+[F] 快速调出搜索栏

[F5] 刷新当前页面

[F11] 全屏

[F12] 另存为

[F2]/ 重命名

[F6] 网页将光标定位到地址栏

[printScreen]/[shift]+[win]+[s] 截图

[insert] 覆盖模式

[delete] 删除光标后面的字

------

bat

control 控制面板

regedit 注册表

taskmgr 任务管理器

sysdm.cpl 系统属性

firewall.cpl 防火墙设置

compmgmt.msc 计算机管理

devmgmt.msc 硬件设备管理

eventvwr 事件查看器

gpedit.msc 组策略

mstsc 远程桌面连接

taskschd.msc 打开定时任务

lusrmgr.msc 本地用户和组

chap 65001 设置编码为utf-8

set           #查看环境变量

gci env:   #查看环境变量

cls 清除屏幕

logoff 注销当前用户

dir md rd ren move del copy 

tree 

replace D:\1.txt D:\Temp // 使用D盘下的1.txt强制替换D盘Temp目录中的1.txt 文件

type 查看文本文件内容

more 逐屏的显示文本文件内容

time date 设置时间日期 00:00:00 YYYY/MM/DD

start /B xxx #将命令放到后台执行

findstr /S /I "passw" *.php

if 1 EQU 1 @(echo 1)

EQU-eq NEQ-ne LSS-lt LEQ-le GTR-gt GEQ-ge

for /d %i in (*) do @(echo %i) 输出 本目录下所有文件

for /r asdf %i in (*.txt) do @(echo %i)

for /f %i in (1.txt) do @(echo %i:111)

for /f "tokens=1 delims= " %i in ('dir') do @(echo %i:111)

/r：递归遍历文件 / 目录（含子目录）

/l：数字序列循环（类似 for 循环的经典用法）

for /L %i in (1,1,30);do @ping -w 1 -n 1 10.10.220.%i | findstr TTL

for ($i=1;$i -lt 20;$i++){ping -w 1 -n 1 10.10.220.$i | findstr TTL }

timeout 5 延迟5s

exit pause 

runas /user:qwe2 cmd #切换用户

saps powershell -verb runas #切换用户

------

powershell

get-executionpolicy 获得当前执行权限

set-executionpolicy remotesigned 更改权限为本地文件可运行（需要管理员权限）

set-executionpolicy remotesigned -Scope CurrentUser 仅修改当前用户权限（不需要管理员权限）

powershell -executionpolicy bypass -file book.ps1 #bypass 绕过执行权限

get-command -commandtype cmdlet 查看所有的cmdlet  gcm

get-module -listavailable 查看系统中的所有模块 gmo

get-process | get-member 查看对象结构 gps | gm

get-help 

基础语法

注释 #    <#   #>

变量 $name  $age  输出变量$name $($name)

$env:computer 

gci env:

数据类型

字符串，整数，小数，布尔值，数组（$arr = @(1,2,3,4,5,6)）,哈希表 $hax = @{name="tom";age=12} ,对象 $name=get-process

使用$str.gettype().Name 来查看变量类型

$_ 管道中当前处理的对象

作用域

$global:name = "Tom"       # 全局变量

$name = "Alice"            # 本地变量

function Show-Name {

​    $name = "Bob"          # 函数内的局部变量

​    Write-Output "函数内部：$name"

} ; Show-Name

Write-Output "函数外部：$name"

Write-Output "全局变量：$global:name"

运算符

 \+ - * / % 

-eq -ne -lt -gt

-and -or -not

流程控制

if ($age -ge 80) {pass} elseif ($age -ne 80) {pass} else {pass}

switch ($value) { "start" { echo "begin" } "stop" { echo "stop" } default {echo "unknown" } }

for ($i = 1; $i -le 5; $i++) {pass}

$colors = @("red","green","blue") ; foreach ($color in $colors ) {pass}

$count = 0 ; while ($count -lt 3) { pass ; $count++}

$count = 0 ; do { pass ; $count++} while ($count -lt 3)

function say-hello { param([string]$name) ; write-output "hello,$name!" } ; say-hello -name powershell

function square($x) { return $x * $x} square 5

异常处理

try { } catch { } finally {} #catch块 只能捕获强制报错 

-ErrorAction Stop 跟在语句后面可将未停止报错，改变为强制报错 

文件操作

get-content xx #gc cat type

set-content xx xx #sc

add-content xx xx #ac

get-childitem -force/-recurse  #gci ls dir

new-item  [-ItemType Directory] 1.txt /dir_1 #mkdir ni

remove-item -path "c:\demo" [-recurse] [-force] #ri rm rmdir del erase rd

copy-item -path "c:\demo" -destination "d:\demo2" [-recurse] #cpi cp copy

move-item -path "c:\demo.txt" -destination "c:\demo" #mi mv move

rename-item -path "c:\demo\example.txt" -newname "renamed.txt" #rni ren

进程和服务管理

get-process -name chrome, notepad #gps ps

start-process notepad saps [-verb runas] #saps start

stop-process (-name notepad stps)(-id 1234) [-force] #spps kill

get-service #gsv 

start-service -name W32time #sasv

stop-service -name W32time #spsv

restart-service -name W32time 

set-service -name W32Time [-startuptype automatic/disabled ] 

new-Service -Name "服务名称" -BinaryPathName "可执行文件路径" -DisplayName "显示名称" -Description "描述" -StartupType <启动类型>

参数说明：

-Name：服务的名称（在服务管理器中使用的名称）。

-BinaryPathName：服务对应的可执行文件的路径。

-DisplayName：在服务管理器中显示的名称。

-Description：服务的描述。

-StartupType：服务的启动类型，可以是以下值之一：Automatic（自动）、Manual（手动）、Disabled（禁用）。

网络与系统管理

test-connection [-computername] www.baidu.com -count 4 #ping

get-netipaddress #ipconfig

get-nettcpconnection [-localport 80] #netstat

clear-dnsclientcache #清除DNS缓存

get-computerinfo #systeminfo gin

get-volume #获取磁盘信息

Get-CimInstance [-ClassName] Win32_BIOS #gcim

用户组管理

get-localuser #glu 获取当前用户列表 

disable-localuser [-name] "testuser" #dlu 禁用用户

enable-localuser [-name] "testuser" #elu 启用用户

get-localgroup #查看本地组

get-localgroupmember #查看组包含的成员

对象，管道和过滤

Where-Object #where ?

sort-object #sort

select-object #select

| #管道符传递对象而不是文本

Get-Service | ? {$_.Status -eq "Running"} | sort DisplayName #获取所有服务对象，筛选出状态为running的服务，根据服务名进行排序.

get-service | ? { $_.name -like[-eq/-ne/-lt/-le/-gt/-ge] "win*" }

Get-Service | Select-object Name,Status

(get-process)[0].Name 查看第一个对象进程的name属性

get-process | select-object name,@{name="nana";expression={$_.name}}   @{name="";expression={}} 起别名，name是名字，expression是计算逻辑

get-process | sort-object id         按照id排序

get-service | group-object status     按照服务状态分组

get-service | format-table -property name, status, displayname #ft 以表格形式显示服务信息

get-service | out-file 2.txt

字符串操作

子字符串提取

$string.substring(0,10) #提取1-10的字符串

$string.substring(10) #提取10之后的字符串

$string.substring($string.length - 3) #从末尾开始提取

$string[0..9] -join "" 

$string[-3..-1] -join ""

分割字符串

$csv.split(",") #以,分割

$data.split("|" , ";" , ",") #多分隔符

$data.split("\", 3) #分割2次

"name name" -split ","

正则表达式

匹配

-imatch #不区分大小写(默认)

-cmatch #区分大小写

-nomatch #取反

"powershell" -match ""

$text = "版本号: v1.2.3"

if ($text -match "v(\d+\.\d+\.\d+)") {

​    $matches[0]  # "v1.2.3" (完整匹配)

​    $matches[1]  # "1.2.3"  (第一个捕获组)

}

替换

"powershell" -replace "p", "8" #将p替换为8

"123-456-789" -replace "\D", "" #将非数字替换为空

"John Doe" -replace "(.*) (.*)", '$2, $1'  # "Doe, John" 捕获组

字符串模板格式化

"姓名: {0}, 年龄: {1}" -f "John", 30  # "姓名: John, 年龄: 30"

Get-Date -Format "yyyy-MM-dd HH:mm:ss"  # "2024-01-15 10:30:25" #格式化

多行字符串

$template = @"

姓名: {0}

年龄: {1}

邮箱: {2}

"@

$template -f "John", 30, "john@example.com"

select-string #grep sls

Select-String -Path "file.txt" -Pattern "searchTerm"

Select-String -Path "*" -Pattern "error" [-Recurse] [-CaseSensitive:$false]

Select-String -Path "file.log" -Pattern "\d{3}-\d{2}-\d{4}"

\# 只显示匹配到的部分（而不是整行）

Select-String -Path "file.txt" -Pattern "warning" -AllMatches | ForEach-Object { $_.Matches.Value }

\# 显示匹配行及其后2行（-A 2）

Select-String -Path "file.txt" -Pattern "error" -Context 0,2

\# 显示匹配行及其前2行（-B 2）

Select-String -Path "file.txt" -Pattern "error" -Context 2,0

\# 显示匹配行及其前后各2行（-C 2）

Select-String -Path "file.txt" -Pattern "error" -Context 2,2

get-service | Export-Csv 1.csv   导成CSV格式

get-service | convertto-json | out-file 1.json  转成json格式

脚本编写

param (

​    [string]$name,

​    [int]$age

)

Write-Output "你好，$name，你的年龄是 $age 岁。"

.\greet.ps1 -name "小明" -age 18

imoprt-module mymodule.psm1 使用import-module导入模块

get-module 查看已加载的模块

say-hello 调用模块的函数

Start-Job -ScriptBlock {ping 127.0.0.1} #启动后台jobs

cmd /c "command"

powershell "command"

. .\xxx.ps1

powershell -ep bypass ". .\PowerView.ps1 ; get-domainuser "