ftp(21),mstsc(3389),smtp(25),imap/imaps(143/993),rstp(554)

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