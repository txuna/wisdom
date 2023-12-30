# Wordpress 도커로 관리하기 

### 개요
WordPress와 Apache, Mysql을 이용하여 웹사이트를 간단하게 만들일이 생겨 제작과정에 있었습니다.   
이를 호스트에서 작업해버리면 그 당시에는 편하겠지만 실제 배포단계에서는 서버 설정과 아이피설정등 굉장히 불편할것이기에 처음부터 도커로 관리하면 좋습니다.   
그리고 제작과정에서 컨테이너에 데이터를 저장하면 물론 또 편하겠지만 도커 컨테이너는 언제든지 지우고 설치하고 하는 것이 장점이기에 도커 볼륨이라는 것을 사용하여 데이터를 저장할 것입니다. 

그리고 도커 볼륨에 저장된 데이터를 다른 호스트로 전송하여 적용하여 배포까지 하는 것을 목표로 합니다. 

사실 배포 과정에서 도커 볼륨을 지워서 이틀동안 작업한 결과물을 날리고 배운경험입니다. 

### 본론 
wordpress와 mysql은 docker hub에 이미지로 올라온것이 있는데 이를 활용할것입니다. 

```yaml
version: '3.1'

services:

  wordpress:
    image: wordpress
    restart: always
    ports:
      - 8080:80
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: exampleuser
      WORDPRESS_DB_PASSWORD: examplepass
      WORDPRESS_DB_NAME: exampledb
    volumes:
      - wordpress:/var/www/html

  db:
    image: mysql:8.0
    restart: always
    environment:
      MYSQL_DATABASE: exampledb
      MYSQL_USER: exampleuser
      MYSQL_PASSWORD: examplepass
      MYSQL_RANDOM_ROOT_PASSWORD: '1'
    volumes:
      - db:/var/lib/mysql

volumes:
  wordpress:
  db:
```
위의 내용을 docker-compose.yaml에 저장하고 아래의 커맨드를 적용하면 워드프레스가 설치됩니다.
```BASH
docker-compose up -d
```
이제 자신의 컴퓨터에서 신나게 작업을 하고 다른 호스트에 배포를 해야 한다면 어떻게 해야할까요...  
컨테이너에서 작업을 했으니 작업한 컨테이너를 커밋해서 이미지로 만든다음 해당 이미지를 tar로 바꾸고 호스트에 업로드하면 될까요...  

만약 컨테이너에서 작업해서 컨테이너내부에 데이터를 남겼다면 맞습니다. 하지만 이전에 docker-compose를 구성할 때 docker volume을 사용하기로 적용했습니다.  
그렇다면 실제 작업물은 컨테이너에 저장되는 것이 아닌 도커 볼륨에 저장됩니다. 그렇기에 해당 이미지를 실행한다고 해도 데이터가 돌아오지않습니다.  
즉, 도커 볼륨까지 백업하고 덮어씌우는 과정또한 배포단계에 포함되어야 합니다.  

그럼 이제 다른 호스트로 배포하는 과정에 대해서 명시합니다.  
그전에 먼저 도커 볼륨을 백업해주는 툴을 설치하여야하는데 아래 링크에서 설치하시면 됩니다.   


https://github.com/junedkhatri31/docker-volume-snapshot

1. 자신의 호스트에서 백업툴로 wordpress 볼륨을 백업한다.
```bash
docker-volume-snapshot create [volume id] [file.tar]
```

2. mysql 컨테이너에 접속합니다.  
```bash
sudo docker exec -it [container id] bash
```

3. mysql 데이터베이스를 백업합니다. 
```bash
mysqldump -u [사용자명] -p [데이터베이스명] > [백업파일명].sql
```

4. mysql docker 내부에 있는 파일을 호스트로 가지고 옵니다. 
```bash
docker cp [container id]:/[file.sql] .
```

5. 다른 호스트로 wordpress 파일과 sql 파일을 전송합니다.
```bash
scp [file.tar] [user]@[ip]:[path]
scp [file.sql] [user]@[ip]:[path]
```

6. 다른 호스트에서 이전에 docker-compose 파일정의한것을 다시 쳐주고 기초 설정을 해줍니다. 
```bash
docker-compose up -d
```

***주의) 작업전 모든 컨테이너는 STOP 해야합니다.***    

7. wordpress 파일을 볼륨에 덮어줍니다. 
```bash
docker-volume-snapshot restore [file.tar] [volume id]
```

8. sql파일을 mysql docker에 전송합니다. 
```bash
docker cp [file.sql] [container id]:/file.sql
```

9. sql 파일을 백업합니다. 
```bash
mysql -u [사용자명] -p [데이터베이스명] < [백업파일명].sql
```

10. 다시 docker-compose를 통해 모든 컨테이너를 켜줍니다. 
```bash
docker-compose up -d
```

이제 이전에 작업한 테마와 포스트등이 백업되었을 겁니다...!

### 코멘트 

도커 볼륨이라는 개념없이 컨테이너에 데이터가 있을거니 하고 컨테이너 커밋하고 이미지화 한다음 볼륨지웠는데 데이터가 싹다 없어져서 글을 써보았습니다