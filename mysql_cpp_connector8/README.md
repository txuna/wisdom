# MySQL Connector/C++ 8.0 사용법

## 개론 
C++에서 Mysql Database에 접근할 수 있는 방법은 여러가지가 있을 수 있지만 그 중 한가지의 방식인 `mysql connector/c++`을 사용하는 것이다.  

## Platform
- Ubuntu 22.04 LTS 

## Install 
설치는 [MySQL Connector/C++](https://github.com/mysql/mysql-connector-cpp)링크에서 자세히 나오지만 아래 따로 공시  
```shell
# Install mysql-server
sudo apt install mysql-server

# Install Mysql CPP Connector - header file 
wget https://dev.mysql.com/get/Downloads/Connector-C++/libmysqlcppconn-dev_8.1.0-1ubuntu22.04_amd64.deb
sudo dpkg -i libmysqlcppconn-dev_8.1.0-1ubuntu22.04_amd64.deb

# Install Mysql CPP Connector - library (link)
wget https://dev.mysql.com/get/Downloads/Connector-C++/libmysqlcppconn8-2_8.1.0-1ubuntu22.04_amd64.deb
sudo dpkg -i libmysqlcppconn8-2_8.1.0-1ubuntu22.04_amd64.deb

# mysql 의존성 문제 해결 패키지1
wget https://dev.mysql.com/get/Downloads/Connector-C++/libmysqlcppconn9_8.1.0-1ubuntu22.04_amd64.deb
sudo dpkg -i libmysqlcppconn9_8.1.0-1ubuntu22.04_amd64.deb

# mysql 의존성 문제 해결 패키지2
wget https://dev.mysql.com/get/Downloads/MySQL-8.1/mysql-community-client-plugins_8.1.0-1ubuntu22.04_amd64.deb
sudo dpkg -i mysql-community-client-plugins_8.1.0-1ubuntu22.04_amd64.deb
```

## Usage
mysql connector를 사용하기 위해서는 해당 헤더파일을 포함해야 한다.
```C
#include <mysqlx/xdevapi.h>
```


### Connect
connection시 사용포트는 33060올 X port가 활성화 되어있음 해당 포트가 아니면 연결이 성립이 안되는거 같음
```C++
bool Mysql::DB::Connect(std::string database)
{
    try
    {
        mysqlx::SessionSettings *from_options = new mysqlx::SessionSettings(host, stoi(port), user, password);
        mysqlx::Session *ess = new mysqlx::Session(*from_options);
        mysqlx::Schema *sch = new mysqlx::Schema(sess->getSchema(database));
        return true;
    }
    catch(const mysqlx::Error &err)
    {
        std::cout<<"DB Error : "<<err<<std::endl;
        return false;
    }
}
```

### Get Table
```C++
mysqlx::Table Mysql::DB::GetTable(std::string tname)
{
    return sch->getTable(tname);
}
```

### Select
```C++
mysqlx::Table table = db_connection.GetTable("accounts");
mysqlx::RowResult result = table.select("user_id", "email", "password", "salt", "name", "permission")
                                .where("email = :email")
                                .bind("email", req_email).execute();

mysqlx::Row row = result.fetchOne();

if(row.isNull())
{
    return;
}


uint32_t user_id = row[0];              /* 정수값의 경우 */
std::stringstream email << row[1];      /* 문자열의 경우 */
std::stringstream password << row[2];
std::stringstream salt << row[3];
std::stringstream name << row[4];
uint43_t permission = row[5];
```

### Delete
사용시 remove를 썼지만 delete가 따로있는거 같음  
아마 8.0으로 업데이트 되면서 relation table뿐만 아니라 Document형식까지 지원하다보니 remove는 Document로 사용하고 delete는 relation table에 해당하는 것으로 사료중  
```C++
mysqlx::Table table = db_connection.GetTable("accounts");
table.remove().where("user_id = :user_id").bind("user_id", user_id).execute();
```


### Insert
```C++
uuid_t user_id; 

mysqlx::Table table = db_connection.GetTable("accounts");
mysqlx::Result result = table.insert("email", "password", "salt", "name")
.values(email, password, salt, name)
.execute();

user_id = result.getAutoIncrementValue(); /* Auto Increasement한 옵션이 있을 때 몇으로 증가했는지 반환 */
```


### Update
```C++
mysqlx::Table table = db_connection.GetTable("players");
table.update()
.set("win", user->win)
.set("lose", user->lose)
.set("draw", user->draw)
.set("point", user->point)
.where("user_id = :user_id")
.bind("user_id", user->user_id)
.execute();
```
