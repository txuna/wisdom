# PHP-FPM Architecture

> !NOTICE  
> 본 글은 php의 opcache, zend, php 언어 처리 등의 부분에 관한 내용이 아닙니다.  
> 본 글은 php-fpm의 전반적인 아키텍처 프로세스 라이프 사이클, 클라이언트의 요청을 어떻게 처리하는지와 scoreboard의 역할이 무엇인지 분석하는데 중점을 두었습니다.

## 개요 
`php-fpm`의 동작과정, 전반적인 구조를 이해하기 위한 분석글입니다. 

## 본론
`php-fpm`을 분석하기 위해서는 `gdb`를 사용하여 동적디버깅이 필요합니다. `apt`로 설치하는 `php-fpm`은 디버깅 심볼이 없어 어셈블리코드만으로 분석을 해야하기에 힘듭니다. 그렇기에 `php` 소스코드를 `github`에서 `clone`하여 설치합니다. 그리고 `nginx`을 통해 데이터를 주고 받을 수 있는 기본적인 세팅을 진행하겠습니다. 그리고 설치가 끝나면 본격적인 디버깅을 해보겠습니다.

### Build
`php-fpm`을 분석하기 위해서는 정적분석과 동적분석이 존재합니다. `php-fpm` 소스코드만 보고 분석하면 쉽고 좋겠지만 방대한 양의 소스코드를 보면 어디가 엔드포인트인지 해당 함수는 언제 호출되는건지 알기 어렵습니다. 그렇기에 분석하기 위해 `gdb`를 사용하여 분석을 진행합니다. 물론 본 글에는 gdb내용은 없으며 gdb로 분석한 소스코드의 해설만 있습니다.   
`php-fpm`을 디버깅하기 위해서는 `nginx`와 `php-fpm`이 필요하며 이 때 `php-fpm`은 디버깅 심볼이 살아있어야 합니다. 소스코드 버전은 `8.1.29` 버전을 기준으로 진행합니다.

#### build php-fpm
```bash
git clone --depth 1 --branch php-8.1.29 https://github.com/php/php-src.git

cd php-src
./buildconf --force
./configure --enable-debug --enable-fpm --disable-cgi --with-openssl --enable-phpdbg --enable-phpdbg-debug
./config.nice 
make -j $(nproc)
make test
sudo make install

./sapi/fpm/php-fpm -v
```
에러가 발생하면 필요한 모듈 다운받으면 됩니다. 

#### php-fpm 설정
```bash 
php --ini
sudo cp php.ini-development /usr/local/php/php.ini
sudo cp php.ini-development /usr/local/lib
sudo cp /usr/local/etc/php-fpm.d/www.conf.default /usr/local/etc/php-fpm.d/www.conf
sudo cp sapi/fpm/php-fpm /usr/local/bin
sudo cp /sapi/fpm/php-fpm.con /usr/local/etc/php-fpm.conf
```
php-fpm.conf 마지막줄을 `include=/usr/local/etc/php-fpm.d/*.conf` 이걸로 수정하여 `www.conf` 파일의 위치를 가리킵니다.


```bash
vim /usr/local/php/php.ini

# cgi.fix_pathinfo=0 으로 설정
```

```bash
vim /usr/local/etc/php-fpm.d/www.conf

# nobody --> www-data로 수정
# user = www-data
# group = www-data
# access.log = var/log/$pool.access.log 
```
access.log를 보고 싶다면 해당 라인 주석을 풀고 원하는 위치로 설정합니다.

```bash
sudo /usr/local/bin/php-fpm
```

#### nginx 설정
```
sudo apt install nginx
vi /etc/nginx/sites-available/default
```
해당 파일을 열고 아래와 같이 수정합니다.

```conf
root /var/www/html;

# Add index.php to the list if you are using PHP
index index.html index.htm index.nginx-debian.html index.php;

server_name _;

location / {

        try_files $uri $uri/ =404;
}

# pass PHP scripts to FastCGI server
#
location ~ \.php$ {
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        include        fastcgi_params;

        fastcgi_pass 127.0.0.1:8999;
}
```

```bash
sudo service nginx restart
```
nginx를 재시작합니다. 

```
curl localhost:80/index.php
```
하면 php-fpm으로부터 index.php를 호출하게 됩니다. 

### 구조 분석
구조 분석전에 간략하게 설명하고 진행하겠습니다. `php-fpm`은 기본적으로 멀티 도메인을 지원합니다. 즉, 하나의 `php-fpm`으로 2개 이상의 서버를 열 수 있습니다. 
`php-fpm.d` 폴더에 `*.conf` 파일을 기반으로 진행합니다. 이름만 다르면 됩니다. ex) [www]. 이를 `php-fpm`에서는 `pool`이라고 합니다. 즉, `php-fpm`은 여러개의 pool을 하나의 자료구조에서 관리합니다. 그리고 이 `pool`들은 `*.conf` 값에 있는 `pm.max_children`의 값 만큼(`static` 이라면) 자식 프로세스를 생성합니다.   
즉, 여러개의 `pool`들이 존재하고 각 `pool`들은 자식 프로세스를 생성하고 자식 프로세스가 `nginx` 또는 `apache`가 던져주는 요청을 처리합니다. 또한 `php-fpm`에는 하위 프로세스(또는 `pool`)을 관리하는 `scoreboard`라는 개념이 존재합니다. 이는 `php-fpm`의 여러 `pool`들을 관리하는 `scoreboard`와 `pool`내에 프로세스를 관리하는 `scoreboard` 2개가 존재합니다.

#### 전반적인 구조
```C
/* fpm_main.c */

int main(int argc, char *argv[])
{
[...]
	int max_requests = 0;
	int requests = 0;
	fcgi_request *request;
[...]
	fcgi_init();
[...]
        enum fpm_init_return_status ret = fpm_init(argc, argv, fpm_config, ...);
[...]
	fcgi_fd = fpm_run(&max_requests);
[...]
	request = fpm_init_request(fcgi_fd);
[...]
        while (EXPECTED(fcgi_accept_request(request) >= 0)) {
[...]
                init_request_info();

                fpm_request_info();

                if (UNEXPECTED(php_request_startup() == FAILURE)) {
                        fcgi_finish_request(request, 1);
[...]
                        return FPM_EXIT_SOFTWARE;
                }
[...]
                if (UNEXPECTED(fpm_status_handle_request())) {
                        goto fastcgi_request_done;
                }
[...]
                fpm_request_executing();
                php_execute_script(&file_handle);
[...]
fastcgi_request_done:
[...]
                fpm_request_end();
[...]
                php_request_shutdown((void *) 0);
[...]
                requests++;
                if (UNEXPECTED(max_requests && (requests == max_requests))) {
                        fcgi_request_set_keep(request, 0);
                        fcgi_finish_request(request, 0);
                        break;
                }
        }
		fcgi_destroy_request(request);
		fcgi_shutdown();
[...]
	return exit_status;
}
```
`php-fpm`의 구조를 전반적으로 보여주는 코드는 `main`함수에 존재합니다. 함수가 너무 길어 이번 분석에서 필요하지 않는 부분은 다 쳐냈습니다.  
후술할 예정이지만 정말 간략하게만 말하자면 `fpm_init`함수를 호출하여 설정파일을 파싱하고 `worker pool`을 생성합니다. 이때 `worker pool`은 `pm.max_children`으로 설정된 프로세스가 아닌 서로 다른 도메인을 뜻합니다.   

그리고 `fpm_run`함수를 호출하여 `pm.max_children`만큼(`static` 모드라면) `fork syscall`을 호출하여 자식 프로세스를 생성합니다. 부모 프로세스는 `fpm_run`함수 내에서 `return`하지 않고 `fpm_event_loop`함수를 호출하여 자식 프로세스의 이벤트를 대기합니다.   
자식 프로세는 `fpm_run` 함수를 빠져나와 `fcgi_accept_request`함수를 호출하여 클라이언트의 요청(nginx or apache)을 accept 합니다. 그리고 사용하는 운영체제에 따라 `poll or select`을 사용하여 클라이언트의 입력을 대기하고 그에 맞게 처리합니다. 
실질적인 처리는 `php_request_startup`함수에서 진행합니다. 

그리고 요청이 끝났다면 `php_execute_script`함수를 호출하여 종료합니다. 또한 `*.conf`에 `max_request`값을 명시했다면 `max_request`만큼 처리한 자식 프로세느는 종료되고 `SIGCHILD` 시그널을 내보냅니다.   
이때 부모프로세스는 `fpm_event_loop`함수를 실행하며서 `epoll(linux라면)`을 통해 자식 프로세스의 `SIGCHILD` 시그널을 `wait`합니다. 시그널을 받게 된다면 `fpm_postponed_children_bury` 함수를 호출하여 다시 자식 프로세스를 만들고 사용자의 요청을 처리할 수 있도록 합니다.   
`max_request`의 장점은 자식 프로세스를 다시 실행함으로서 써드파티에 존재할 수 있는 메모리 누수를 방지하는데 간접적인 도움을 줄 수 있습니다. 다만 프로세스를 재생성하는 것이므로 성능에는 조금 악영향을 끼치게 됩니다. 

여기까지가 전반적인 `php-fpm`의 구조이지만 적다보니 전반적인 내용을 다 적었네요 너무나도 간략하게 다뤘습니다. 내부 코어를 좀 더 분석해보면서 트래킹 해보겠습니다. 

### Config 파일 기반 초기 세팅
`*.conf` 파일과 `php-fpm.conf` 파일을 기반으로 초기 세팅을 진행하기 위해서 `main`함수에서 `fpm_init` 함수를 호출합니다. 

```C
enum fpm_init_return_status fpm_init(int argc, char **argv, char *config, [...]){
[...]
	if (0 > fpm_php_init_main()           ||
	    0 > fpm_stdio_init_main()         ||
	    0 > fpm_conf_init_main(test_conf, force_daemon) ||
	    0 > fpm_unix_init_main()          ||
	    0 > fpm_scoreboard_init_main()    ||
	    0 > fpm_pctl_init_main()          ||
	    0 > fpm_env_init_main()           ||
	    0 > fpm_signals_init_main()       ||
	    0 > fpm_children_init_main()      ||
	    0 > fpm_sockets_init_main()       ||
	    0 > fpm_worker_pool_init_main()   ||
	    0 > fpm_event_init_main()) {
[...]
        }
}
```
`fpm_init`함수는 나열된 함수를 호출하여 전반적인 세팅을 진행합니다.(listener socket 생성, config 기반 pool 생성{도메인 마다 생성}, scoreboard 생성) 중요하다고 생각하는것만 살펴보겠습니다.  

`fpm_conf_init_main`함수는 내부적으로 config 파일 하나당 `fpm_conf_load_ini_file` - `fpm_conf_ini_parser` - `fpm_conf_ini_parser_include` 함수를 쌍으로 반복적으로 호출을 진행합니다. 
이때 `fpm_conf_ini_parse` 함수는 내부적으로 `fpm_conf_ini_parser_section` 함수를 호출하여 도메인(*.conf)마다 하나의 worker pool을 생성합니다. 이때 생성하는 함수와 구조체입니다. 
```C
static void *fpm_worker_pool_config_alloc(void)
{
	struct fpm_worker_pool_s *wp;

	wp = fpm_worker_pool_alloc();
[...]
	wp->config = malloc(sizeof(struct fpm_worker_pool_config_s));
[...]
	memset(wp->config, 0, sizeof(struct fpm_worker_pool_config_s));
/* 
config 설정 생략 
*/
	if (!fpm_worker_all_pools) {
		fpm_worker_all_pools = wp;
	} else {
		struct fpm_worker_pool_s *tmp = fpm_worker_all_pools;
		while (tmp) {
			if (!tmp->next) {
				tmp->next = wp;
				break;
			}
			tmp = tmp->next;
		}
	}
	current_wp = wp;
	return wp->config;
}
```
해당 함수는 `fpm_worker_pool_alloc`함수를 호출하여 하나의 `worker pool`을 생성하고 설정 파일을 담을 구조체 또한 할당합니다. 
그리고 `fpm_worker_all_pools`이 `NULL`이라면 head로 설정하고 이미 다른 pool이 있다면 이를 next에 담습니다. 
다음은 `fpm_worker_pool_s`의 구조체 내용입니다. 
```C
/* fpm_worker_pool.h */
struct fpm_worker_pool_s {
	struct fpm_worker_pool_s *next;
	struct fpm_worker_pool_s *shared;
	struct fpm_worker_pool_config_s *config;
	char *user, *home;									/* for setting env USER and HOME */
	enum fpm_address_domain listen_address_domain;
	int listening_socket;
	int set_uid, set_gid;								/* config uid and gid */
	int socket_uid, socket_gid, socket_mode;

	/* runtime */
	struct fpm_child_s *children;
	int running_children;
	int idle_spawn_rate;
	int warn_max_children;

	struct fpm_scoreboard_s *scoreboard;
	int log_fd;
	char **limit_extensions;
[...]
};
```
`fpm_worker_pool_s`를 보면 `fpm_child_s`를 통해 `woeker pool`마다 `child process`를 가지고 관리하는 것을 확인할 수 있습니다. 
그리고 자식 프로세스간 공유자원인 `scoreboard` 또한 존재하는 것을 확인할 수 있습니다. `fpm_child_s`와 `fpm_scoreboard_s`는 추후 살펴보겠습니다.

```C
int fpm_unix_init_main(void)
{
[...]
        struct timeval tv;
        fd_set rfds;
        int ret;

        if (pipe(fpm_globals.send_config_pipe) == -1) {
                zlog(ZLOG_SYSERROR, "failed to create pipe");
                return -1;
        }

        /* then fork */
        pid_t pid = fork();
        switch (pid) {
[...]
        case 0 : /* children */
                close(fpm_globals.send_config_pipe[0]); /* close the read side of the pipe */
                break;

        default : /* parent */
                close(fpm_globals.send_config_pipe[1]); /* close the write side of the pipe */

                /*
                        * wait for 10s before exiting with error
                        * the child is supposed to send 1 or 0 into the pipe to tell the parent
                        * how it goes for it
                        */
[...]
                ret = select(fpm_globals.send_config_pipe[0] + 1, &rfds, NULL, NULL, &tv);
[...]
                if (ret) { /* data available */
                        int readval;
                        ret = read(fpm_globals.send_config_pipe[0], &readval, sizeof(readval));
[...]  
                        if (readval == 1) {
                                zlog(ZLOG_DEBUG, "I received a valid acknowledge from the master process, I can exit without error");
                                fpm_cleanups_run(FPM_CLEANUP_PARENT_EXIT);
                                exit(FPM_EXIT_OK);
                        } 
                }
	}

	/* continue as a child */
	setsid();

	return 0;
}
```
다음은 `fpm_unix_init_main`함수입니다. 해당 함수는 내부적으로 `fork`함수를 호출합니다. 부모프로세스는 자식 프로세스들이 이후 수행할 작업을 정상적으로 수행했는지 파이프라인을 생성하고 값을 10초간 대기합니다. 
만약 파이프라인을 통해 값을 받지 못했거나 받아도 1이 아니라면 비정상 종료를 진행합니다. 정상이라면 정상 종료를 진행하고 `setsid syscall`을 호출하여 자식 프로세스가 마스터 프로세스(프로세스 그룹의 세션리더)로 진행됩니다. 

다음은 fpm_scoreboard_init_main 함수입니다.
```C
/* fpm_scoreboard.c */
int fpm_scoreboard_init_main(void)
{
	struct fpm_worker_pool_s *wp;

	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		size_t scoreboard_procs_size;
		void *shm_mem;
[...]
		scoreboard_procs_size = sizeof(struct fpm_scoreboard_proc_s) * wp->config->pm_max_children;
		shm_mem = fpm_shm_alloc(sizeof(struct fpm_scoreboard_s) + scoreboard_procs_size);

		if (!shm_mem) {
			return -1;
		}
		wp->scoreboard = shm_mem;
		wp->scoreboard->pm = wp->config->pm;
		wp->scoreboard->nprocs = wp->config->pm_max_children;
		wp->scoreboard->start_epoch = time(NULL);
		strlcpy(wp->scoreboard->pool, wp->config->name, sizeof(wp->scoreboard->pool));

		if (wp->shared) {
			/* shared pool is added after non shared ones so the shared scoreboard is allocated */
			wp->scoreboard->shared = wp->shared->scoreboard;
		}
	}
	return 0;
}
```
`fpm_worker_all_pools`를 for loop를 이용하여 각 각의 `wp`에 할당합니다. 이 때 `fpm_worker_all_pools`는 이전에 `*.conf` 파일 기반으로 만들어진 `worker pool list`입니다. 
각 `worker pool`마다 `fpm_shm_alloc`함수를 호출하여 `fpm_scoreboard_s` 구조체를 `share memory`로 할당하고 저장합니다. 미리 말하자면 이 `share memory`는 `worker pool`이 관리하는 자식 프로세스가 `spin lock`을 통해 접근할 수 있는 메모리입니다.

```C
scoreboard_procs_size = sizeof(struct fpm_scoreboard_proc_s) * wp->config->pm_max_children;
shm_mem = fpm_shm_alloc(sizeof(struct fpm_scoreboard_s) + scoreboard_procs_size);
```
할당하는 메모리 크기는 `socreboard` 하나 크기와 `pm.max_children` 만큼의 `fpm_scoreboard_proc_s` 크기만큼 할당하는 것을 알 수 있습니다. 

`scoreboard`란 추후 계속 언급될 예정이지만 간단하게 말하자면 각 각의 `worker pool`은 하나의 `scoreboard`와 여러개의 자식 프로세스를 가지고 있습니다. `scoreboard`는 현재 `worker pool`의 상태를 나타내는 것뿐만 아니라 자식 프로세스들의 상태를 확인하고 현재 `idle`인 프로세스는 얼마인지 `active`한 프로세스는 얼마인지등 확인하는 전반적인 구조체입니다. 그리고 이 구조체는 자식 프로세스도 확인할 수 있도록 공유메모리를 통해 만들어집니다.

```C
/* fpm_scoreboard.h */
struct fpm_scoreboard_s {
	union {
		atomic_t lock;
		char dummy[16];
	};
	char pool[32];
	int pm;
	time_t start_epoch;
	int idle;
	int active;
	int active_max;
	unsigned long int requests;
	unsigned int max_children_reached;
	int lq;
	int lq_max;
	unsigned int lq_len;
	unsigned int nprocs;
	int free_proc;
	unsigned long int slow_rq;
	struct fpm_scoreboard_s *shared;
	struct fpm_scoreboard_proc_s procs[];
};
```
위는 `fpm_scoreboard_s` 구조체 내용입니다.

```C
/* fpm_scoreboard.h */
struct fpm_scoreboard_proc_s {
	union {
		atomic_t lock;
		char dummy[16];
	};
	int used;
	time_t start_epoch;
	pid_t pid;
	unsigned long requests;
	enum fpm_request_stage_e request_stage;
	struct timeval accepted;
	struct timeval duration;
	time_t accepted_epoch;
	struct timeval tv;
	char request_uri[128];
	char query_string[512];
	char request_method[16];
	size_t content_length; /* used with POST only */
	char script_filename[256];
	char auth_user[32];
[...]
	size_t memory;
};
```
위는 `fpm_scoreboard_proc_s` 구조체 내용입니다. 자식 프로세스가 접근하는 메모리입니다. 이 또한 공유메모리입니다.

```C
int fpm_sockets_init_main(void){
        for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
                switch (wp->listen_address_domain) {
                        case FPM_AF_INET :
                                wp->listening_socket = fpm_socket_af_inet_listening_socket(wp);
                                break;

                        case FPM_AF_UNIX :
                                if (0 > fpm_unix_resolve_socket_permissions(wp)) {
                                        return -1;
                                }
                                wp->listening_socket = fpm_socket_af_unix_listening_socket(wp);
                                break;
                }
        [...]
        if (wp->listen_address_domain == FPM_AF_INET && fpm_socket_get_listening_queue(wp->listening_socket, NULL, &lq_len) >= 0) {
                        fpm_scoreboard_update(-1, -1, -1, (int)lq_len, -1, -1, 0, FPM_SCOREBOARD_ACTION_SET, wp->scoreboard);
                }
        }
}
```
다음은 `fpm_sockets_init_main`함수입니다. 해당 함수는 `worker pool list`를 반복문 돌려서 각 각의 `worker pool`이 도메인에 해당하는 소켓을 생성, `bind`, `listen`하는 구조입니다. 
이 떄 만들어진 `listener socket`은 `worker pool`의 자식 프로세스가 공용으로 사용합니다. 그리고 `fpm_scoreboard_update` 함수를 확인할 수 있습니다. 앞서 말하기를 `scoreboard`는 `share memory`에 할당된 메모리이기에 `spin lock`을 통해서 접근 권한을 얻어야 한다고 말했습니다. 내부구조를 확인해보겠습니다.

```C
void fpm_scoreboard_update(
		int idle, int active, int lq, int lq_len, int requests, int max_children_reached,
		int slow_rq, int action, struct fpm_scoreboard_s *scoreboard) /* {{{ */
{
	fpm_scoreboard_update_begin(scoreboard);
	fpm_scoreboard_update_commit(
			idle, active, lq, lq_len, requests, max_children_reached, slow_rq, action, scoreboard);
}
```
`scoreboard`의 메모리의 값을 수정하기 위해서는 `begin`과 `commit`으로 이루어집니다. `begin`은 아래와 같습니다. 
```C
void fpm_scoreboard_update_begin(struct fpm_scoreboard_s *scoreboard) /* {{{ */
{
	scoreboard = fpm_scoreboard_get_for_update(scoreboard);
	if (!scoreboard) {
		return;
	}

	fpm_spinlock(&scoreboard->lock, 0);
}
```
`scoreboard`의 `atomic` 변수인 lock의 값이 0인지 확인할 때 까지 `spin lock`에 들어갑니다.
```C
static inline int fpm_spinlock(atomic_t *lock, int try_once)
{
	if (try_once) {
		return atomic_cmp_set(lock, 0, 1) ? 1 : 0;
	}

	for (;;) {

		if (atomic_cmp_set(lock, 0, 1)) {
			break;
		}

		sched_yield();
	}

	return 1;
}
```
`buzy wait`을 진행하지만 `sched_yield`함수를 호출하여 지속적으로 `buzy wait`하는 것이 아닌 다른 프로세스에게 해당 `CPU`를 양보하게 됩니다.
`lock`의 값이 `0`이라면 `1`로 바꿀 때 까지 대기합니다. 만약 성공하게 된다면 `1`을 반환하면서 함수가 종료됩니다. 그리고 `fpm_scoreboard_update_commit` 함수를 호출하여 `scoreboard`의 전반적인 내용을 업데이트 합니다. 

#### 자식 프로세스 라이프 사이클 및 요청 처리
`fpm_init` 함수를 통해 기본적인 초기 세팅 과정이 지났습니다. 이제 나올 내용은 자식 프로세스의 라이프 사이클과 클라이언트 요청 처리에 대해서 살펴보겠습니다.

```C
int fpm_run(int *max_requests) /* {{{ */
{
	struct fpm_worker_pool_s *wp;

	/* create initial children in all pools */
	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		int is_parent;

		is_parent = fpm_children_create_initial(wp);

		if (!is_parent) {
			goto run_child;
		}
	}

	/* run event loop forever */
	fpm_event_loop(0);

run_child: /* only workers reach this point */
	*max_requests = fpm_globals.max_requests;
	return fpm_globals.listening_socket;
}
```
`fpm_run`함수를 호출하게 되면 `worker pool`마다 `fpm_children_create_initial` 함수를 호출하여 `pm.max_children`의 수량만큼 자식 프로세스를 `fork syscall`을 사용하여 생성합니다. 
생성된 자식프로세스는 `goto run_child`로 이동하여 함수가 끝납니다. 부모 프로세스는 `fpm_event_loop`를 호출합니다. 이를 `마스터 프로세스`라고 부르겠습니다. 먼저 자식 프로세스의 생성 과정에 대해서 살펴보겠습니다. 
자식 프로세스 생성의 엔트리포인트는 `fpm_children_create_inital` 함수입니다. 내부적으로 `fpm_children_make`함수를 호출하여 자식프로세스를 생성합니다. 
```C
int fpm_children_create_initial(struct fpm_worker_pool_s *wp) /* {{{ */
{
	if (wp->config->pm == PM_STYLE_ONDEMAND) {
		wp->ondemand_event = (struct fpm_event_s *)malloc(sizeof(struct fpm_event_s));

		if (!wp->ondemand_event) {
			zlog(ZLOG_ERROR, "[pool %s] unable to malloc the ondemand socket event", wp->config->name);
			// FIXME handle crash
			return 1;
		}

		memset(wp->ondemand_event, 0, sizeof(struct fpm_event_s));
		fpm_event_set(wp->ondemand_event, wp->listening_socket, FPM_EV_READ | FPM_EV_EDGE, fpm_pctl_on_socket_accept, wp);
		wp->socket_event_set = 1;
		fpm_event_add(wp->ondemand_event, 0);

		return 1;
	}
	return fpm_children_make(wp, 0 /* not in event loop yet */, 0, 1);
}
```
만약 Process manager의 구성이 `static`이 아닌 `ondemand`라면 미리 자식 프로세스를 생성하지 않습니다. 다만 `fpm_pctl_on_socket_accept`함수를 콜백으로 걸어놓고 `accept` 요청이 있을 때만 자식프로세스를 생성합니다. 
만약 모든 자식 프로세스가 러닝중이라면 에러를 출력합니다. 다음은 `fpm_children_make`함수입니다.
```C
int fpm_children_make(struct fpm_worker_pool_s *wp, int in_event_loop, int nb_to_spawn, int is_debug) /* {{{ */
{
	pid_t pid;
	struct fpm_child_s *child;
	int max;
[...]
    max = wp->config->pm_max_children;

	while (fpm_pctl_can_spawn_children() && wp->running_children < max && (fpm_global_config.process_max < 1 || fpm_globals.running_children < fpm_global_config.process_max)) {

		warned = 0;
		child = fpm_resources_prepare(wp);

		pid = fork();

		switch (pid) {

			case 0 :
				fpm_child_resources_use(child);
				fpm_globals.is_child = 1;
				fpm_child_init(wp);
				return 0;

			default :
				zlog(ZLOG_DEBUG, "unblocking signals, child born");
				fpm_signals_unblock();
				child->pid = pid;
				fpm_clock_get(&child->started);
				fpm_parent_resources_use(child);

				zlog(is_debug ? ZLOG_DEBUG : ZLOG_NOTICE, "[pool %s] child %d started", wp->config->name, (int) pid);
		}

	}
[...]
	return 1; /* we are done */
}
```
`fpm_children_make` 함수는 반복문을 기반으로 설정된 `pm.max_children` 만큼 자식 프로세스를 생성하는 실질적인 함수이빈다. `fork syscall` 호출전 `fpm_resources_prepare` 함수를 호출하여 `fpm_child_s` 구조체를 하나 할당합니다. 그리고 `worker pool`이 가지고 있는 공유 메모리인 `scoreboard`의 값을 `fpm_scoreboard_proc_alloc` 함수를 호출하여 `scoreboard` 구조체 내 `proc` 배열의 `free` 공간에 자신의 프로세스가 사용중임을 마킹하고 `child->scoreboard_i`에 자신이 몇 번째 프로세스 인덱스인지 설정합니다. 
```C
/* fpm_scoreboard.c */
int fpm_scoreboard_proc_alloc(struct fpm_child_s *child) /* {{{ */
{
[...]
	scoreboard->procs[i].used = 1;
	child->scoreboard_i = i;

	/* supposed next slot is free */
	if (i + 1 >= nprocs) {
		scoreboard->free_proc = 0;
	} else {
		scoreboard->free_proc = i + 1;
	}
[...]
}
```
`fpm_scoreboard_proc_alloc`함수의 세팅부분만 가지고 왔습니다. 변수 `i`의 값은 `scoreboard->procs[i].used`가 `1`이 아닌 곳을 순회하면서 찾습니다. 현재 사용중이지 않은 곳을 찾았다면 자신이 사용하고 `child` 구조체의 멤버필드인 `scoreboard_i`에 인덱스를 세팅합니다.

```C
struct fpm_child_s {
	struct fpm_child_s *prev, *next;
	struct timeval started;
	struct fpm_worker_pool_s *wp;
	struct fpm_event_s ev_stdout, ev_stderr, ev_free;
	int shm_slot_i;
	int fd_stdout, fd_stderr;
	void (*tracer)(struct fpm_child_s *);
	struct timeval slow_logged;
	bool idle_kill;
	bool postponed_free;
	pid_t pid;
	int scoreboard_i;
	struct zlog_stream *log_stream;
};
```
위는 `fpm_child_s` 구조체입니다.  

다시 이어서 `fpm_resources_prepare`함수의 호출이 끝나면 `fork syscall`을 호출하여 자식프로세스를 생성합니다. 부모프로세스는 반복적으로 프로세스를 생성하고 `fpm_parent_resources_use` 함수를 호출하여 생성한 자식프로세스가 연결리스트로 연결될 수 있도록 설정합니다. 자식 프로세스는 `fpm_child_resources_use` 함수와 `fpm_child_init` 함수를 호출합니다. 

```C
static void fpm_child_resources_use(struct fpm_child_s *child) /* {{{ */
{
	struct fpm_worker_pool_s *wp;
	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		if (wp == child->wp || wp == child->wp->shared) {
			continue;
		}
		fpm_scoreboard_free(wp);
	}

	fpm_scoreboard_child_use(child, getpid());
	fpm_stdio_child_use_pipes(child);
	fpm_child_free(child);
}
```
`fpm_child_resources_use` 함수는 자신이 사용하는 `worker pool`이 아닌 다른 `worker pool`이 가지고 있는 `공유 메모리`인 `scoreboard`를 해제합니다.
`fpm_scoreboard_child_use`를 호출하여 해당 자식 프로세스에 설정된 전역변수 `fpm_scoreboard`와 `fpm_scoreboard_i`의 값을 세팅하고 `fpm_child_free` 함수를 호출하여 자원을 해제합니다. 의아할 수 있는데 `child`는 부모프로세스에서 관리하니 자식프로세스에 복제된 메모리는 해제해도 괜찮습니다. 중요한 정보인 `fpm_scoreboard`와 `fpm_scoreboard_i`(자신의 프로세스가 몇 번째 인덱스인지)의 값을 복사해놨습니다. 
이제 자식프로세스는 사용자의 요청을 처리하는 루틴을 탑니다. 해당 루틴을 분석하기전에 자식 프로세스의 생성이 끝난 부모 프로세스의 루틴을 살펴보겠습니다.ㄴ

부모 프로세스는 `fpm_run` 함수에서 자식 프로세스의 생성이 끝나면 `fpm_event_loop`에서 모든 시간을 보냅니다. `fpm_event_loop`함수를 살펴보겠습니다.
부모 프로세스는 `fpm_event_loop`함수에서만 동작하고 종료되지 않습니다. 자식 프로세스의 시그널을 처리하는 주 역할입니다.
```C
void fpm_event_loop(int err) /* {{{ */
{
	static struct fpm_event_s signal_fd_event;

	fpm_event_set(&signal_fd_event, fpm_signals_get_fd(), FPM_EV_READ, &fpm_got_signal, NULL);
	fpm_event_add(&signal_fd_event, 0);

	while (1) {
		struct fpm_event_queue_s *q, *q2;
		unsigned long int timeout;
		int ret;
[...]
		ret = module->wait(fpm_event_queue_fd, timeout);
[...]
		/* trigger timers */
		q = fpm_event_queue_timer;
		while (q) {
[...]
			fpm_event_fire(ev);
		}
[...]
	}
}
```
조금 많은 내용을 지우긴 했는데 핵심내용은 다음과 같습니다. 먼저 `fpm_event_set`함수를 호출하여 시그널을 등록합니다.
```C
zlog(ZLOG_DEBUG, "received SIGCHLD");
/* epoll_wait() may report signal fd before read events for a finished child
        * in the same bunch of events. Prevent immediate free of the child structure
        * and so the fpm_event_s instance. Otherwise use after free happens during
        * attempt to process following read event. */
fpm_event_set_timer(&children_bury_timer, 0, &fpm_postponed_children_bury, NULL);
fpm_event_add(&children_bury_timer, 0);
```
이는 `pm.max_request` 이상을 처리한 자식 프로세스는 종료되는데 이때 `SIGCHLD` 시그널을 내뱉습니다. 그리고 `fpm_postponed_children_bury`함수를 호출하도록 지정합니다.
`fpm_event_fire`함수를 살펴보면 해당 이벤트의 콜백함수를 호출할 수 있도록 구현되어 있습니다. `fpm_postponed_children_bury`함수는 내부적으로 기존의 자식 프로세스를 정리하고 `fpm_children_make`함수를 호출하여 이전과 같은 방식으로 자식 프로세스를 생성합니다.
```C
void fpm_event_fire(struct fpm_event_s *ev) /* {{{ */
{
	if (!ev || !ev->callback) {
		return;
	}

	(*ev->callback)( (struct fpm_event_s *) ev, ev->which, ev->arg);
}
```
자식 프로세스의 클라이언트 요청 처리르 보기전에 gdb로 자식 프로세스가 어떤 시그널을 넘기는지 확인해보겠습니다. 그전에 확인을 편리하게 하기 위해 `www.conf` 파일에서 `pm.max_request`의 값을 `1`로 수정합니다.
```bash
sudo gdb php-fpm 
b fpm_run
b fpm_event_loop
r
set follow-fork-mode parent
c
```
gdb를 실행하고 위 명령어를 실행합니다.

```bash
$ ps aux
root      436035  0.5  4.2 392728 170968 pts/2   Sl+  07:45   0:01 gdb php-fpm
root      436042  0.0  0.2  69620 11196 ?        ts   07:46   0:00 php-fpm: master proce
www-data  436043  0.0  0.3  70164 12472 ?        S    07:47   0:00 php-fpm: pool www
```
1개의 프로세스가 생성된 것을 확인할 수 있습니다. 이제 요청을 보내보겠습니다 

```bash 
$ curl localhost/index.php
tuuna
```
부모 프로세스에서 확인해보면 module->wait 함수의 반환값이 1로 나오는 것을 확인할 수 있습니다. 그리고 자식 프로세스는 max_request만큼 수행했으니 현재 좀비프로세스로 남아있습니다. 
```bash
root      436035  0.5  4.4 4593928 178016 pts/2  Sl+  07:45   0:01 gdb php-fpm
root      436042  0.0  0.2  69620 11196 ?        ts   07:46   0:00 php-fpm: master process 
www-data  436043  0.0  0.0      0     0 ?        Z    07:47   0:00 [php-fpm] <defunct>
```
자식 프로세스가 defunc로 설정되었습니다. 그리고 부모 프로세스는 fpm_event_fire 함수를 호출하여 등록한 콜백을 호출합니다. 
```bash
In file: /home/tuuna/tmp/php-src/sapi/fpm/fpm/fpm_events.c:483
   478 }
   479 /* }}} */
   480
   481 void fpm_event_fire(struct fpm_event_s *ev) /* {{{ */
   482 {
 ► 483         if (!ev || !ev->callback) {
   484                 return;
   485         }
   486
   487         (*ev->callback)( (struct fpm_event_s *) ev, ev->which, ev->arg);
   488 }
```
fpm_event_s의 값을 살펴보겠습니다. 
```bash
pwndbg> p *ev
$3 = {
  fd = -1,
  timeout = {
    tv_sec = 271802,
    tv_usec = 444961
  },
  frequency = {
    tv_sec = 0,
    tv_usec = 0
  },
  callback = 0xaaaaab21cfa8 <fpm_postponed_children_bury>,
  arg = 0x0,
  flags = 0,
  index = -1,
  which = 1
}
```
callback함수는 이전에 말한 `fpm_postponed_children_bury`함수임을 알 수 있습니다. 이는 내부적으로 `fpm_children_make`함수를 호출하여 새 프로세스를 생성합니다. 여담이지만 앞서 말한 `module->wait`에서 `wait`은 리눅스 기준 `epoll`을 사용한 것입니다.

이제 자식 프로세스들의 클라이언트 요청 처리 부분을 살펴보겠습니다. 자식 프로세스는 `fpm_run` 함수를 끝내고 아래 부분으로 돌아옵니다. 앞서 말했지만 자식 프로세스의 요청 처리 루틴은 다음과 같습니다. 
`fpm_init_request` -> (`fcgi_accept_request` -> `php_request_startup` -> `fpm_status_handle_request` -> `php_request_shutdown`)으로 이루어지고 괄호는 클라이언트마다 요청에 의하여 반복적으로 실행되는 것을 의미합니다. 

먼저 `fpm_init_request`입니다. 해당 함수는 현재 클라이언트의 요청을 처리하는 자식 프로세스가 어떤 상태에 놓여져 있음을 상태 변경하기 위한 함수입니다. 예를 들어 `fpm_request_accepting` 함수는 해당 프로세시는 `accept` 대기중이라고 설정합니다. 즉, `ACTIVE` 상태가 아닌 `IDLE` 상태임을 뜻합니다. 
```C
static fcgi_request *fpm_init_request(int listen_fd) /* {{{ */ {
	fcgi_request *req = fcgi_init_request(listen_fd,
		fpm_request_accepting,
		fpm_request_reading_headers,
		fpm_request_finished);
	return req;
}
```

```C
static const char *requests_stages[] = {
	[FPM_REQUEST_ACCEPTING]       = "Idle",
	[FPM_REQUEST_READING_HEADERS] = "Reading headers",
	[FPM_REQUEST_INFO]            = "Getting request information",
	[FPM_REQUEST_EXECUTING]       = "Running",
	[FPM_REQUEST_END]             = "Ending",
	[FPM_REQUEST_FINISHED]        = "Finishing",
};
```
위는 자식 프로세스의 상태를 나타내는 상수값입니다. 

```C
void fpm_request_accepting(void)
{
	struct fpm_scoreboard_proc_s *proc;
[...]
	fpm_scoreboard_update_begin(NULL);

	proc = fpm_scoreboard_proc_acquire(NULL, -1, 0);
[...]
	proc->request_stage = FPM_REQUEST_ACCEPTING;
[...]
	fpm_scoreboard_proc_release(proc);

	/* idle++, active-- */
	fpm_scoreboard_update_commit(1, -1, 0, 0, 0, 0, 0, FPM_SCOREBOARD_ACTION_INC, NULL);
}
```
`fpm_scoreboard_proc_acquire`함수를 호출하여 `scoreboard`에 저장된 `proc` 배열중 호출한 자식 프로세시의 인덱스 번호를 기반으로 `proc`를 반환합니다. 그리고 `proc`의 `request_stage`에 `FPM_REQUEST_ACCEPTING`을 설정하고 `commit`함으로서 `idle` 상태인 프로세스가 하나 늘어났음을 `scoreboard`에 저장합니다. 

다음은 `fcgi_accept_request`함수입니다. 
```C
int fcgi_accept_request(fcgi_request *req)
{
        while (1) {
[...]
                while (1) {
                        req->hook.on_accept();

                        int listen_socket = req->listen_socket;
[...]
                        req->fd = accept(listen_socket, (struct sockaddr *)&sa, &len);
[...]
                }
[...]
                fds.events = POLLIN;

                do {
                        errno = 0;
                        ret = poll(&fds, 1, 5000);
                } while (ret < 0 && errno == EINTR);

                if (ret > 0 && (fds.revents & POLLIN)) {
                        break;
                }
[...]
                req->hook.on_read();
                if (fcgi_read_request(req)) {

                        return req->fd;
                } 
        }
}
```
해당 반복문을 기반으로 프로세스가 살아있는 동안 클라이언트의 요청을 지속적으로 처리합니다. 먼저 `accept` 전에 `req->hook.on_accept()` 함수를 호출 하는 것을 볼 수 있는데 이는 방금 전 언급한 `fpm_request_accepting`함수입니다. 함수의 내용은 이전에 설명했으니 넘어가겠습니다. 그리고 `accept`함수를 호출하여 `listener socket`에 새로운 클라이언트가 접속하기를 기다립니다. 만약 연결이 성사되었다면 블로킹을 빠져나가고 `poll`함수를 호출하여 클라이언트의 데이터 입력을 기다립니다. 놀랍게도 `epoll`이 아닌 `poll`을 사용했는데 추측상 프로세스는 하나의 소켓만 처리할것이니 `poll`의 단점이 드러나지 않고 사용에 간편함 때문에 사용하는것 같습니다. 그리고 `POLLIN` 이벤트를 등록합니다. `POLLIN` 이벤트가 발생하게 되면 `fcgi_read_request` 함수를 호출하여 클라이언트의 요청을 읽습니다. (리눅스가 아니라면 select을 사용합니다.)

그전에 `req->hook.on_read` 함수를 호출하는 것을 알 수 있습니다. 이는 현재 프로세스가 클라이언트의 리퀘스트 헤더를 처리하고 있음으로 변경하고 `scoreboard`에 `idle` 상태인 프로세스를 줄이고 `active` 상태인 프로세스의 숫자를 늘립니다. 그리고 이때 현재 프로세스가 얼마만큼 `request`를 처리했는지 값을 증가시킵니다. 

다음은 `init_request_info` 함수를 호출하여 읽어낸 클라이언트의 요청을 다음 구조체에 저장합니다. 
```C
typedef struct _sapi_globals_struct {
	void *server_context;
	sapi_request_info request_info;
	sapi_headers_struct sapi_headers;
	int64_t read_post_bytes;
	unsigned char post_read;
	unsigned char headers_sent;
	zend_stat_t global_stat;
	char *default_mimetype;
	char *default_charset;
	HashTable *rfc1867_uploaded_files;
	zend_long post_max_size;
	int options;
	bool sapi_started;
	double global_request_time;
	HashTable known_post_content_types;
	zval callback_func;
	zend_fcall_info_cache fci_cache;
} sapi_globals_struct;
```
`init_request_info`함수가 왜 나오는지 이상할 수 있는데 맨 처음 `main`함수에서 언급한 로직 순서입니다. 여기까지 왔다면 까먹었을 겁니다.  

다음은 `fpm_request_info` 함수를 호출하여 `scoreboard`로부터 `proc`를 얻어내고 `proc`의 멤버필드인 `request_method`, `request_uri`, `query_stringe` 등을 저장합니다. 다음은 `php_request_startup` 함수를 호출하지만 이부분은 맨 처음 말한것과 같이 `zend` 관련은 분석하지 않기로했으니 넘어가겠습니다. 다음은 `fpm_status_handle_request`함수를 호출합니다. 해당 함수는 사용자가 `www.conf`에 지정한 `pm.status` 경로에 요청했는지 확인합니다. 그리고 맞다면 `php-fpm`의 `scoreboard`의 값을 출력하는 함수입니다. 그리고 추후 로직을 수행하지 않고 요청을 종료합니다.

```C
if (UNEXPECTED(fpm_status_handle_request())) {
				goto fastcgi_request_done;
			}
```

```C
[...]
/* STATUS */
	if (fpm_status_uri && !strcmp(fpm_status_uri, SG(request_info).request_uri)) {
		fpm_request_executing();

		/* full status ? */
		_GET_str = zend_string_init("_GET", sizeof("_GET")-1, 0);
		full = (fpm_php_get_string_from_table(_GET_str, "full") != NULL);
		short_syntax = short_post = NULL;
		full_separator = full_pre = full_syntax = full_post = NULL;
		encode_html = false;
		encode_json = false;
		has_start_time = 1;

		scoreboard_p = fpm_scoreboard_get();
		if (scoreboard_p) {
			scoreboard_p = fpm_scoreboard_copy(scoreboard_p->shared ? scoreboard_p->shared : scoreboard_p, full);
		}
		if (!scoreboard_p) {
			zlog(ZLOG_ERROR, "status: unable to find or access status shared memory");
			SG(sapi_headers).http_response_code = 500;
			sapi_add_header_ex(ZEND_STRL("Content-Type: text/plain"), 1, 1);
			sapi_add_header_ex(ZEND_STRL("Expires: Thu, 01 Jan 1970 00:00:00 GMT"), 1, 1);
			sapi_add_header_ex(ZEND_STRL("Cache-Control: no-cache, no-store, must-revalidate, max-age=0"), 1, 1);
			PUTS("Internal error. Please review log file for errors.");
			return 1;
		}
[...]
```
`fpm_status_uri`를 확인하여 해당 `/status uri`를 요청했는지 확인합니다. 만약 맞다면 `fpm_scoreboard_get`함수를 호출하여 전역변수로 설정한 `fpm_scoreboard`를 가져옵니다. 그리고 해당 내용을 복사해야하니 `fpm_scoreboard_copy`함수를 호출하여 `fpm_scoreboard`를 복제합니다. 

```C
// status 정보만 볼건데 굳이 스핀락할필요는 없지
	scoreboard = fpm_scoreboard_acquire(scoreboard, FPM_SCOREBOARD_LOCK_NOHANG);
	if (!scoreboard) {
		free(mem);
		zlog(ZLOG_ERROR, "scoreboard: failed to lock (already locked)");
		return NULL;
	}
```
복제하기 위해서는 공유 메모리인 `scoreboard`에 대해서 `lock` 점유권을 가지고 있어야 합니다. 이때 주어진 인자는 `FPM_SCOREBOARD_LOCK_NOHANG`입니다. 즉, 한번 `lock try`해보고 이미 `lock`이라면 `spin lock`걸지말고 나와라는 뜻입니다. 그리고 `500에러`를 출력합니다. 그 이유는 단순합니다. `status` 요청은 일반 사용자가 요청하는 것이 아닌 서버개발자가 주로 요청합니다. 해당 요청을 처리하기 위해서 해당 프로세스가 `scoreboard` 점유를 위해 `spin lock`을 하고 있다면 성능 저하를 야기합니다. 그렇기에 일찍 포기하고 중요하지 않으니 나중에 다시 처리해라는 뜻으로 해석할 수 있습니다.   

만약 상태 체크 요청이 아니라면 `fpm_request_executing` 함수를 호출하여 `scoreboard`에 현재 현재 이 프로세스는 `FPM_REQUEST_EXECUTING`이라고 설정합니다. 그리고 `php_execute_script`함수를 호출하여 `zend` 엔진이 주어진 `php` 파일을 해석하고 처리하는 역할을 수행하는데 앞서 말했듯이 넘깁니다. 요청처리가 끝나면 `fpm_request_end` 함수를 호출하여 현재 프로세스의 상태를 `FPM_REQUEST_FINISHED`로 설정합니다. 

마지막으로 `pm.max_request`에 값과 같아지면 `break` 호출해서 반복문을 탈출하고 프로세스가 종료됩니다. 이 때 종료되면 중간에 말한 부모 프로세스의 `fpm_event_loop` 함수에서 시그널을 포착하게 되고 다시 생성 합니다.
```C
if (UNEXPECTED(max_requests && (requests == max_requests))) {
                        fcgi_request_set_keep(request, 0);
                        fcgi_finish_request(request, 0);
                        break;
                }
```

### 코멘트
여기까지가 php-fpm의 전반적인 로직입니다. 물론 php 언어를 처리하는 zend엔진이나 클라이언트의 데이터를 어떻게 요리조리 처리하는 등의 부분은 없지만 php-fpm이 어떻게 동작하는지 어떠한 구조를 가지는지등 전반적으로 알 수 있는 글이라고 생각합니다. 그리고 php는 정보가 많이 없네요... 2016년 글이 가장 최신 같습니다.   

nginx는 멀티 프로세스로 구성하고 하나의 프로세스마다 epoll을 통해 처리하는데 php-fpm은 정말 프로세스 하나당 accept 하나입니다. 어쩌다가 이러한 구조가 나왔는지는 잘 모르겠네요. 멀티프로세스에 epoll 물리는게 더 좋아 보이긴 합니다. 물론 poll을 사용하긴 하는데 정말 소켓 하나만 넣고 관찰하는 용도입니다.