# accept(2) Internal Logic

### 개론

`accept(2)` syscall을 호출하면 클라이언트 소켓의 연결이 있기까지 해당 프로세스가 `Block`되는 것을 알 수 있다.  그리고 `accept4(2)` syscall을 호출하면 (종단의 연결이 없을 경우) `Blocking`되지 않고 `Non Blocking`의 형태로 `-EAGAIN`을 반환하는 것을 알 수 있다. 그렇다면 어떠한 커널 로직이 이러한 행동을 할 수 있도록 구현하였을까  분석할 가치가 있다고 생각한다. 

### 주의

**본 분석은 리눅스 커널 6.4.3기준으로 진행하며 TCP IPv4입니다.**

그 이후의 버전은 내용 구성이 조금 다릅니다.

### 본론

userspace에서 accept(2) syscall이나 accept4(2) syscall을 호출하면 아래와 같은 코드를 불러온다.

```c
/* socket.c */ 
SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen, int, flags)
{
	return __sys_accept4(fd, upeer_sockaddr, upeer_addrlen, flags);
}

SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen)
{
	return __sys_accept4(fd, upeer_sockaddr, upeer_addrlen, 0);
}
```

`accept4(2)` syscall은 `flags`값으로 `NONBLOCK`을 값을 보낼 수 있고 `accept(2)`는 flag가 존재하지 않기에 `0`으로 대체한다. 그리고 똑같이 `__sys_accept4()`함수를 호출하는 것을 볼 수 있다. 

```c
/* socket.c */

/*
 *	For accept, we attempt to create a new socket, set up the link
 *	with the client, wake up the client, then return the new
 *	connected fd. We collect the address of the connector in kernel
 *	space and move it to user at the very end. This is unclean because
 *	we open the socket then return an error.
 *
 *	1003.1g adds the ability to recvmsg() to query connection pending
 *	status to recvmsg. We need to add that support in a way thats
 *	clean when we restructure accept also.
 */

int __sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr,
		  int __user *upeer_addrlen, int flags)
{
	int ret = -EBADF;
	struct fd f;

	f = fdget(fd);
	if (f.file) {
		ret = __sys_accept4_file(f.file, upeer_sockaddr,
					 upeer_addrlen, flags);
		fdput(f);
	}

	return ret;
}
```

`__sys_accept4()`함수는 주석에 나와있는 거처럼 클라이언트 소켓을 만들고 파일디스크럽터를 반환한다. 

`fdget()`함수를 호출하여 주어진 파일디스크립터로부터 `struct fd`를 받아온다.  그리고 `__sys_accept4_file`함수를 호출하고 인자로 `fd`로부터 받아온 `struct fd`의 `file` 필드와 `accept(2)` syscall 호출시 인자로 넘겼던 연결할 종단의 `struct sockaddr`, `struct sockaddr`의 `len`, `flags`를 넘긴다. 그리고 반환값으로 연결된 종단의 파일 디스크립터를 반환한다. 

```c
/* include/linux/file.h */

struct fd {
	struct file *file;
	unsigned int flags;
};
```

```c
/* socket.c */
static int __sys_accept4_file(struct file *file, struct sockaddr __user *upeer_sockaddr,
			      int __user *upeer_addrlen, int flags)
{
	struct file *newfile;
	int newfd;

	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	newfd = get_unused_fd_flags(flags);
	if (unlikely(newfd < 0))
		return newfd;

	newfile = do_accept(file, 0, upeer_sockaddr, upeer_addrlen,
			    flags);
	if (IS_ERR(newfile)) {
		put_unused_fd(newfd);
		return PTR_ERR(newfile);
	}
	fd_install(newfd, newfile);
	return newfd;
}
```

해당 함수 내부에서는 `do_accept`함수를 호출하고 반환값으로 `struct file`을 받아오면 `fd_install`함수를 호출하여 현재 프로세스의 열린 파일 목록에 `newfile`과 `fd`를 설정한다. `do_accept`함수를 살펴보기전에 `fd_install`함수를 살짝 살펴본다. 

```c
/* fs/file.c */

void fd_install(unsigned int fd, struct file *file)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;

	rcu_read_lock_sched();

	if (unlikely(files->resize_in_progress)) {
		rcu_read_unlock_sched();
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		BUG_ON(fdt->fd[fd] != NULL);
		rcu_assign_pointer(fdt->fd[fd], file);
		spin_unlock(&files->file_lock);
		return;
	}
	/* coupled with smp_wmb() in expand_fdtable() */
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}
```

`current`의 `files`필드를 받아오는 것을 볼 수 있다. `current`는 해당 `syscall`을 호출한 프로세스의 포인터를 의미한다. 

ref : [https://stackoverflow.com/questions/22346545/current-in-linux-kernel-code](https://stackoverflow.com/questions/22346545/current-in-linux-kernel-code)

주석을 살펴보면 `/* open file information */` 해당 프로세스에 열린 파일 정보임을 알 수 있다. 

```c
fdt = rcu_dereference_sched(files->fdt);
```

`fdt`는 `struct fdtable`이다. 

```c
/* include/linux/fdtable.h */

struct fdtable {
	unsigned int max_fds;
	struct file __rcu **fd;      /* current fd array */
	unsigned long *close_on_exec;
	unsigned long *open_fds;
	unsigned long *full_fds_bits;
	struct rcu_head rcu;
};
```

`fd` 이중 포인터는 현재 할당된 `file`들의 배열임을 의미한다. 

```c
BUG_ON(fdt->fd[fd] != NULL);
```

`BUG_ON` 매크로는 주어진 인자가 참일 경우 에러를 일으킨다. 즉, 이미 `fd`가 존재하는 것(`NULL`이 아니라면) 에러를 발생시킨다. 

```c
rcu_assign_pointer(fdt->fd[fd], file);

#define rcu_assign_pointer(p, v)	do { (p) = (v); } while (0)
```

그리고 `fdt`의 `fd` 배열에 인자로 주어진 `fd`값의 인덱스에 `file`을 집어넣는다. 

즉, `fd_install`함수는 `accept(2)`와 같은 `syscall`을 호출한 프로세스(`current`)의 파일 해쉬 목록에 종단의 `fd`를 인덱스로 `newfile`값을 집어넣는다. 아래와 같은 뉘앙스다. 

```c
/* example pseudo code*/ 

fd_install(newfd, newfile); 

void fd_install(int newfd, struct file* newfile){
	if(current->fdt->fd != NULL) {
		/* occur error! */
		return;
	}
	current->fdt->fd[newfd] = newfile; 
}
```

다시 본론으로 돌아와서 `do_accept`함수를 살펴보자.  `do_accept`함수를 호출할때 주어지는 인자를 살펴보면 `file`은 `accept(2)` syscall을 호출한 서버 소켓의 `fd`를 `file`형태로 가지고 온 것, `upeer_sockaddr`와 `upeer_addrlen`은 연결될 종단의 주소정보를 저장할 곳, `flags`는 어떠한 방식으로 취할것인지(`NON-BLOCK`)를 나타낸다. 

```c
/* socket.c */

struct file *do_accept(struct file *file, unsigned file_flags,
		       struct sockaddr __user *upeer_sockaddr,
		       int __user *upeer_addrlen, int flags)
{
	struct socket *sock, *newsock;
	struct file *newfile;
	int err, len;
	struct sockaddr_storage address;

	sock = sock_from_file(file);
...
	newsock = sock_alloc();
...
	newsock->type = sock->type;
	newsock->ops = sock->ops;
...
	newfile = sock_alloc_file(newsock, flags, sock->sk->sk_prot_creator->name);
	if (IS_ERR(newfile))
		return newfile;
...
	/*
	 * const struct proto_ops inet_stream_ops의 경우 inet_accept 함수와 연결
	 */
	err = sock->ops->accept(sock, newsock, sock->file->f_flags | file_flags,
					false);
	if (err < 0)
		goto out_fd;

	if (upeer_sockaddr) {
		len = newsock->ops->getname(newsock,
					(struct sockaddr *)&address, 2);
		if (len < 0) {
			err = -ECONNABORTED;
			goto out_fd;
		}
		err = move_addr_to_user(&address,
					len, upeer_sockaddr, upeer_addrlen);
		if (err < 0)
			goto out_fd;
	}

	/* File flags are not inherited via accept() unlike another OSes. */
	return newfile;
...
}
```

먼저 `sock_from_file`함수를 호출하여 인자로 주어진 `file`에 대한 `struct socket`을 받아온다. 

그리고 연결된 종단의 `struct socket`을 만들기 위해 `sock_alloc`함수를 호출하고 `sock_alloc_file`함수를 호출하여 연결될 종단의 `socket`에 해당하는 `struct file`을 할당한다. 그리고 인자로 주어진 file에 해당하는 `sock`의 `accept` 함수포인터를 호출한다. (즉, `accept(2)` syscall을 호출한 소켓의 파일디스크립터) 이때 `accept`에 연결된 함수포인터는 inet_accept함수와 연결되어 있다. 

`inet_accept`함수가 호출되고 나서 `getname` 함수 포인터를 호출하는데 이는 `inet_getname`함수이다. 해당 함수 내부에서 종단 클라이언트의 주소정보를 주어진 인자 `address`에 기입한다. 

기입된 `address`는 커널 메모리에 할당되었기때문에 `userspace`로 전달이 불가능하다. 그렇기에 `move_addr_to_user`함수를 호출하여 커널메모리를 유저메모리로 복사를 진행한다. 

```c
/* af_ient.c */

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */

int inet_accept(struct socket *sock, struct socket *newsock, int flags,
		bool kern)
{
	struct sock *sk1 = sock->sk, *sk2;
	int err = -EINVAL;

	/* IPV6_ADDRFORM can change sk->sk_prot under us. */
	/* struct proto tcp_pro에서 inet_csk_accept함수와 연결 */
	/* flag는 accept4함수 호출시 전달되는 O_NONBLOCK 일반 accept이면 0 */
	sk2 = READ_ONCE(sk1->sk_prot)->accept(sk1, flags, &err, kern);
	if (!sk2)
		goto do_err;

	lock_sock(sk2);

	sock_rps_record_flow(sk2);
	WARN_ON(!((1 << sk2->sk_state) &
		  (TCPF_ESTABLISHED | TCPF_SYN_RECV |
		  TCPF_CLOSE_WAIT | TCPF_CLOSE)));
...
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk2);
do_err:
	return err;
}
```

`inet_accept`함수는 내부적으로 `accept`함수포인터를 호출한다. 이는 `inet_csk_accept`함수를 의미한다. 

```c
/* inet_connection_sock.c */

/*
 * This will accept the next outstanding connection.
 */
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *req;
	struct sock *newsk;
	int error;
...
	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (reqsk_queue_empty(queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}

	req = reqsk_queue_remove(queue, sk);
	newsk = req->sk;
...

out:
...
	}
	if (req)
		reqsk_put(req);
	return newsk;
out_err:
...
}
```

`inet_csk_accept`함수는 인자로 주어진 `struct sock`의 `sk`가 현재 `TCP_LISTEN`상태가 맞는지 확인한다. 그리고 `3WHS`가 끝난 `accept queue`에 들어있는 `child reqsk`가 있는지 확인한다. 만약 아직 `3HWS`가 끝난 종단 클라이언트(`child reqsk`)가 없다면 `inet_csk_wait_fro_connect`함수를 호출한다. 하지만 `accept4(2)` syscall을 호출하여 `NON_BLOCK flags`를 넘겼다면 `inet_csk_accept`함수는 `inet_csk_wait_for_connect`함수를 호출하지않고 `-EAGAIN`을 반환하며 함수를 종료 시킨다.

```c
/* inet_connection_sock.c */

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	DEFINE_WAIT(wait);
	int err;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&icsk->icsk_accept_queue)){
			timeo = schedule_timeout(timeo);
		}
		sched_annotate_sleep();
		lock_sock(sk);
		err = 0;

		if (!reqsk_queue_empty(&icsk->icsk_accept_queue)){
			break;
		}

		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}
```

`inet_csk_wait_for_connect`함수는 `DEFINE_WAIT` 매크로 함수를 호출하여 인자로 주어진 `wait`에 해당하는 지역변수를 만든다. 

```c
/* wait.h */

#define DEFINE_WAIT_FUNC(name, function)					\
	struct wait_queue_entry name = {					\
		.private	= current,					\
		.func		= function,					\
		.entry		= LIST_HEAD_INIT((name).entry),			\
	}

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
```

즉 `struct wait_queue_entry`타입의 `wait`변수가 하나 만들어진것이다.  

그리고 `prepare_to_wait_exclusive`함수를 호출하여 만들어진 `wait`을 `accept(2)` syscall을 호출한 `sk→sk_wq→wait` 커널 리스트 자료구조의 끝에 삽입한다. 그리고 해당 함수를 호출한 프로세스의 상태를 `TASK_RUNNING`에서 `TASK_INTERRUPTIBLE`로 설정한다. `TASK_INTERRUPTIBLE` 값 해당 프로세스를 대기모드에 넣으며 인터럽트가 간접적으로 전달이 되면 프로세스를 깨운다는 플래그값이다.

그리고 `schedule_timeout`함수를 호출하여 인자로 넣은 `timeout`시간에 도달할 때까지 프로세스를 대기모드에 넣는다. 만일 지정된 `timeout`에 도달해서 깨어난다 해도 `for loop`로 `accept queue`를 검사하기때문에 다시 대기모드에 빠지게 된다.  

### 그렇다면 timeout이 아닌 어떤 경우에 wake up signal을 받을까?

이 부분이 이 글을 쓰는 가장 핵심적인 이유이다. 이 부분을 알기 위해서는 3WHS의 과정이 어떻게 일어나는지 알아야할 필요가 있다. (이전 분석글 참고)

`tcp_child_process`함수 내부에서 `tcp_rcv_state_process`함수를 호출하면서 종단 클라이언트의 `sock(child sock)`의 `TCP_STATE`를 `TCP_ESTABLISHED`로 변경경하면서 `3HWS`가 종료된다. 그리고 이러한 사실을 `accept(2)` syscall을 호출하여 대기중인 프로세스에게 알려야 하는데 이때  `sk_data_ready`함수 포인터를 호출하게 된다. `sk_data_ready` 함수포인터는 `sock_def_readable`함수로 연결되어 있다. 

```c
/* sock.h */

void sock_def_readable(struct sock *sk)
{
	struct socket_wq *wq;

	trace_sk_data_ready(sk);

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq)){
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLIN | EPOLLPRI |
						EPOLLRDNORM | EPOLLRDBAND);
	}
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}
```

`sock_def_readable`함수는 `skwq_has_sleeper`함수를 호출하여 해당 프로세스가 현재 대기모드인지 확인한다. 이전에 `inet_csk_wait_for_connect`함수를 호출하면서 `sk→wq→wait` 리스트에 `entry`하나를 넣었기 때문에 당연히 참이 된다. 

```c
/* include/net/sock.h */

static inline bool skwq_has_sleeper(struct socket_wq *wq)
{
	return wq && wq_has_sleeper(&wq->wait);
}

/* wait.h */
static inline bool wq_has_sleeper(struct wait_queue_head *wq_head)
{
	/*
	 * We need to be sure we are in sync with the
	 * add_wait_queue modifications to the wait queue.
	 *
	 * This memory barrier should be paired with one on the
	 * waiting side.
	 */
	smp_mb();
	return waitqueue_active(wq_head);
}

static inline int waitqueue_active(struct wait_queue_head *wq_head)
{
	return !list_empty(&wq_head->head);
}
```

그리고 `wake_up_interruptible_sync_poll`함수를 호출하여 주어진 인자 `EPOLLIN | EPOLLPIR` …등을 넣고 대기모드인 프로세스를 깨우는 시그널을 보낸다. 

```c
/* wait.h */

#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))
```

```c
/* wait.c */

/**
 * __wake_up_sync_key - wake up threads blocked on a waitqueue.
 * @wq_head: the waitqueue
 * @mode: which threads
 * @key: opaque value to be passed to wakeup targets
 *
 * The sync wakeup differs that the waker knows that it will schedule
 * away soon, so while the target thread will be woken up, it will not
 * be migrated to another CPU - ie. the two threads are 'synchronized'
 * with each other. This can prevent needless bouncing between CPUs.
 *
 * On UP it can prevent extra preemption.
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 */
void __wake_up_sync_key(struct wait_queue_head *wq_head, unsigned int mode,
			void *key)
{
	if (unlikely(!wq_head))
		return;

	__wake_up_common_lock(wq_head, mode, 1, WF_SYNC, key);
}
```

`wake_up_interruptible_sync_poll`함수는 `__wake_up_sync_key`함수를 호출한다. 해당 함수의 주석을 참고하면 알 수 있듯이 `waitqueue`의 `block`된 `thread`를 깨우는 역할을 한다. 

호출을 따라가면 대기큐의 요소 하나를 가지고와서 `func` 함수 포인터를 호출하는 것을 볼 수 있다. 이는 이전에 `DEFINE_WAIT` 매크로함수를 실행하면서 설정한 `autoremove_wake_function`함수이다. 

해당 함수는 `default_wake_function`함수를 호출한다. 

```c
/* kernel/sched/core.c */ 

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
			  void *key)
{
	WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~WF_SYNC);
	return try_to_wake_up(curr->private, mode, wake_flags);
}
```

그리고 `try_to_wake_up`함수를 호출하여 해당 스레드를 깨운다. 그렇다면 `inet_csk_wait_for_connect`에서 대기중인 스레드는 해당 시그널을 받고 추후 클라이언트 처리 로직 수행을 진행한다. 그리고 `finish_wait`함수를 호출하여 대기 큐에서 요소를 `wait`을 제거한다.

해당 함수는 스케줄링과 깊은 관련이 존재하기에 여기서는 다루지않고 추후 분석할 예정이다.

### 요약

여기까지가 `accept(2)` syscall을 호출하면 프로세스가 블록되는데 어떠한 과정의 로직을 거치는지에 대한 설명이다. 

간단하게 요약하자면 `accept(2)` syscall 호출시 해당 프로세스는 `3WHS`가 끝난 `sock`이 있는지 `accept queue`에서 검사를 진행한다. 만약 없다면 해당 `syscall`을 호출한 프로세스는 대기모드에 빠지게 된다. 만약 `3WHS`가 끝난 `sock`이 존재한다면 `sock_data_readable`함수를 호출하여 대기모드에 빠진 프로세스를 꺠우고 해당 `sock`을 `accept queue`에서 꺼내고 클라이언트를 처리하는 과정을 거친다.