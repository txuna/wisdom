# EPOLL은 어떻게 동작하는가 

### 개론
하나의 프로세스 또는 스레드에서 여러개의 소켓을 모니터링하기 위해 리눅스는 EPOLL 인터페이스를 제공합니다. EPOLL을 통해 모니터링하는 소켓에 데이터가 왔거나 데이터를 쓸 수 있는 상태가 되면 사용자에게 알려줍니다.
epoll이 어떤식으로 동작하는지 구글링을 통해 많은 양의 정보를 얻을 수 있으며 직감적으로 동작방식을 알 수 있습니다. 하지만 직접 커널 소스코드를 보면서 세부적으로 이해하는 것도 좋은 방법이라고 생각하기에 글을 쓰게 되었습니다.

### 주의 
본 내용은 리눅스 커널 6.4.3 버전을 기준으로 하며 많은 양의 소스코드가 존재하여 분석에 있어 틀린 내용이 있을 수 있습니다. 그렇기에 ***재미로만 봐주시면 감사하겠습니다.***

### 본론 
리눅스에서 제공하는 epoll 인터페이스를 사용하기 위해서는 3가지의 syscall이 존재합니다.   
1. epoll_create 
2. epoll_ctl 
3. epoll_wait 

epoll_create함수는 epoll instance를 생성하며 epoll_ctl은 생성한 epoll instance에 모니터링하기를 원하는 파일디스크립터를 삽입합니다. 마지막으로 epoll_wait은 호출한 프로세스가 대기모드에 진입하여 관심 파일디스크립터의 알림을 대기합니다. 또한 타임아웃을 지정하여 대기모드에서 실행모드로 돌아올 수 있습니다.  
그렇다면 이러한 syscall들의 내부 구조는 어떨까 epoll_create() 함수부터 알아보도록 하겠습니다. 

### epoll_create
epoll_create함수를 호출하면 내부적으로 do_epoll_create함수를 호출하게 됩니다.
```C
/* fs/eventpoll.c  */
SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return do_epoll_create(0);
}
```
여기서 알 수 있듯이 size값은 무시됩니다.   

***지금부터 나오는 함수들은 크기가 크기 때문에 일부분만 발췌하겠습니다***

do_epoll_create함수를 살펴보도록 하겠습니다. 
```C
static int do_epoll_create(int flags)
{
	int error, fd;
	struct eventpoll *ep = NULL;
	struct file *file;
[...]
	error = ep_alloc(&ep);
[...]
	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
[...]
	file = anon_inode_getfile("[eventpoll]", &eventpoll_fops, ep,
				 O_RDWR | (flags & O_CLOEXEC));
[...]
	ep->file = file;
	fd_install(fd, file);
	return fd;
}
```
예외처리 로직등 설명에 필요없는 부분은 날리고 핵심적인 부분만 캐치했습니다.  
먼저 `ep_alloc` 함수를 호출해서 `struct eventpoll`구조체를 할당합니다. 그리고 `get_unused_fd_flags`함수를 호출하여 현재 프로세스의 파일목록중 사용하지않는 파일 디스크립터를 할당하고 반환합니다.  

`anon_inode_getfile`함수를 호출하여 "[eventpoll]"파일에 대한 `struct file`을 만들고 `file` 구조체의 `f_op` 멤버변수에 `eventpoll_fops`를 할당합니다. 그리고 `file` 구조체의 `private_data`로 `struct eventpoll *ep`를 대입하여 저장합니다.  최종적으로 할당한 fd_install함수를 호출하여 현재 프로세스 파일 목록에 대입하고 파일 디스크립터를 반환합니다.

```C
/* fs/eventpoll.c */
static const struct file_operations eventpoll_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= ep_show_fdinfo,
#endif
	.release	= ep_eventpoll_release,
	.poll		= ep_eventpoll_poll,
	.llseek		= noop_llseek,
};
```

ep의 file멤버에 file 구조체를 등록하고 fd_install함수를 호출하여 fd와 file을 현재 프로세스의 파일목록에 등록합니다. 그리고 최종적으로 epoll instance의 FD를 반환합니다.

```C
static int ep_alloc(struct eventpoll **pep)
{
	int error;
	struct user_struct *user;
	struct eventpoll *ep;
[...]
	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
[...]
	mutex_init(&ep->mtx);
	rwlock_init(&ep->lock);
	init_waitqueue_head(&ep->wq);
	init_waitqueue_head(&ep->poll_wait);
	INIT_LIST_HEAD(&ep->rdllist);
	ep->rbr = RB_ROOT_CACHED;
	ep->ovflist = EP_UNACTIVE_PTR;
	ep->user = user;
	refcount_set(&ep->refcount, 1);

	*pep = ep;

	return 0;
[...]
}
```
`ep_alloc`함수는 `struct eventpoll`구조체 할당을 진행하고 각 종 값을 초기화 합니다. 
`eventpoll`의 중요한 항목중 `mtx`는 다중 프로세스가 동일한 `epoll instance`에 접근할 수 있도록 락, 언락의 역할을 진행합니다. `wq` 멤버는 `epoll_wait`함수를 호출한 프로세스의 `struct wait_queue_t wait`을 즉, 태스크를 담기위한 연결리스트입니다. 후술할 예정이지만 미리 말하자면 `epoll_wait`함수를 호출하면 대기모드에 빠지게 되는데 `epoll instance`가 관리하는 파일디스크립터에 이벤트가 발생하게 되면 `ep_poll_callback`함수를 호출하여 `wakeup`하게 됩니다.  

그리고 `poll_wait`필드는 모니터링 대상이 다른 epoll instance의 경우 그의 wait queue로서 동작합니다. 그리고 `rbr`필드는 모니터링 원하는 파일디스크립터 항목들을(epitem)을 `RB Tree`형태로 관리합니다. 마지막으로 `rdllist`필드는 이벤트가 발생한 파일디스크립터가 담긴 연결리스트입니다.   

### epoll_ctl
```C
/* fs/eventpoll.c */
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	struct epoll_event epds;

	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		return -EFAULT;

	return do_epoll_ctl(epfd, op, fd, &epds, false);
}
```
epoll_ctl함수를 호출하면 유저가 전달한 인수를 `copy_from_user`함수를 호출하여 커널공간에 선언된 `epds`변수에 값을 복사합니다. 그리고 `do_epoll_ctl`함수를 호출하여 동작을 이어나갑니다.    
do_epoll_ctl함수는 3가지의 기능으로 분리가 됩니다.   
값 검증 및 세팅, 폐쇄루프 검증, 본연의 목적인 추가, 수정, 삭제 기능 수행으로 나눠집니다.

```C
int do_epoll_ctl(int epfd, int op, int fd, struct epoll_event *epds,
		 bool nonblock)
{
	int error;
	int full_check = 0;
	struct fd f, tf;
	struct eventpoll *ep;
	struct epitem *epi;
	struct eventpoll *tep = NULL;
```

```C
	error = -EBADF;
	f = fdget(epfd);
	if (!f.file)
		goto error_return;

	tf = fdget(fd);
	if (!tf.file)
		goto error_fput;

	error = -EPERM;
	if (!file_can_poll(tf.file))
		goto error_tgt_fput;

	error = -EINVAL;
	if (f.file == tf.file || !is_file_epoll(f.file))
		goto error_tgt_fput;

	if (ep_op_has_event(op) && (epds->events & EPOLLEXCLUSIVE)) {
		if (op == EPOLL_CTL_MOD)
			goto error_tgt_fput;
		if (op == EPOLL_CTL_ADD && (is_file_epoll(tf.file) ||
				(epds->events & ~EPOLLEXCLUSIVE_OK_BITS)))
			goto error_tgt_fput;
	}
```
먼저 인자로 주어진 `epoll instance` 파일디스크립터와 모니터링하기를 원하는 파일디스크립터를 `fdget`함수를 히용하여 `struct fd`구조체를 가지고옵니다.  

그리고 모니터링하기를 원하는 fd 구조체의 file멤버가 polling가능한지 확인한합니다. 이때 polling가능한지 확인하기 위해서는 단순히 file 구조체의 poll 멤버필드가 NULL인지 아닌지 검사합니다. 그리고 `epoll instance`가 정말 epoll instance가 맞는지 확인하기 위해 `is_file_epoll`함수를 호출합니다. 이 또한, 이전에 설정했던 `eventpoll_fops`의 주소값과 같은지 확인합니다.  

그리고 만약 사용자가 `EPOLLEXCLUSIVE` 이벤트를 추가했다면 이는 `EPOLL_CTL_ADD`에서만 설정이 가능하기 때문에 추가나 삭제에 사용했는지 검증합니다.

```C
ep = f.file->private_data;
```
그리고 epoll fd를 통해서 얻어낸 `struct fd`구조체의 file 구조체의 private_data에는 이전에 `do_epoll_create`에서 할당한 `struct eventpoll`구조체 즉, epoll `instance`가 존재하기 때문에 이것을 가지고 옵니다.

```C
error = epoll_mutex_lock(&ep->mtx, 0, nonblock);
if (error)
	goto error_tgt_fput;
if (op == EPOLL_CTL_ADD) {
	if (READ_ONCE(f.file->f_ep) || ep->gen == loop_check_gen ||
		is_file_epoll(tf.file)) {
		mutex_unlock(&ep->mtx);
		error = epoll_mutex_lock(&epnested_mutex, 0, nonblock);
		if (error)
			goto error_tgt_fput;
		loop_check_gen++;
		full_check = 1;
		if (is_file_epoll(tf.file)) {
			tep = tf.file->private_data;
			error = -ELOOP;
			if (ep_loop_check(ep, tep) != 0)
				goto error_tgt_fput;
		}
		error = epoll_mutex_lock(&ep->mtx, 0, nonblock);
		if (error)
			goto error_tgt_fput;
	}
}
```
다음은 `epoll instance`의 모니터링 파일디스크립터가 또 다른 `epoll instance`일 경우 closed loop에 빠질 수 있습니다. 그렇기에 여기서 루프의 검증을 진행합니다. 

```C
epi = ep_find(ep, tf.file, fd);
```
`ep_find`함수를 호출하여 모니터링 원하는 파일디스크립터가 이미 `struct epitem`구조체를 가지고 있는지 레드블랙 트리에서 검색을 진행합니다. 만약 해당 값이 NULL이 아니라면 이미 이전에 등록했음을 의미합니다. 

```C
error = -EINVAL;
switch (op) {
case EPOLL_CTL_ADD:
	if (!epi) {
		epds->events |= EPOLLERR | EPOLLHUP;
		error = ep_insert(ep, epds, tf.file, fd, full_check);
	} else
		error = -EEXIST;
	break;
case EPOLL_CTL_DEL:
	if (epi) {
		ep_remove_safe(ep, epi);
		error = 0;
	} else {
		error = -ENOENT;
	}
	break;
case EPOLL_CTL_MOD:
	if (epi) {
		if (!(epi->event.events & EPOLLEXCLUSIVE)) {
			epds->events |= EPOLLERR | EPOLLHUP;
			error = ep_modify(ep, epi, epds);
		}
	} else
		error = -ENOENT;
	break;
}
mutex_unlock(&ep->mtx);

return error;
```
사용자가 설정한 플래그 값 `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`, `EPOLL_CTL_DEL`에 따라 기능을 수행합니다. 딥하게 알아볼 부분은 `EPOLL_CTL_ADD`부분입니다.    
먼저 이전에 사용자가 추가한 epitem이 있다면 오류를 반환하고 없다면 `EPOLLERR`이벤트와 `EPOLLHUP`이벤트를 기존 이벤트가 추가합니다. 여기서 알 수 있듯이 커널에서 자동으로 위 이벤트를 추가해줍니다. 그리고 `ep_insert`함수를 호출하여 `epoll instance`에 모니터링 하기를 원하는 파일디스크립터를 추가합니다.  

`ep_insert`함수의 분량 또한 방대하기 때문에 핵심적인 요소만 남겨두고 나머지는 쳐냈습니다.   
`ep_insert`함수는 크게 3가지의 기능을 수행합니다. 
1. `epoll instance`의 파일디스크립터 관리하는 RB Tree에 모니터링하고자하는 파일디스크립터 삽입 
2. 모니터링하고자하는 (tcp socket의 예로)소켓의 wait queue에 해당 태스크(wait) 후킹(삽입)
3. epoll_wait 호출전 이미 이벤트가 있는지 확인

```C
/* fs/eventpoll.c */
static int ep_insert(struct eventpoll *ep, const struct epoll_event *event,
		     struct file *tfile, int fd, int full_check)
{
	int error, pwake = 0;
	__poll_t revents;
	struct epitem *epi;
	struct ep_pqueue epq;
	struct eventpoll *tep = NULL;
[...]
	epi = kmem_cache_zalloc(epi_cache, GFP_KERNEL)

	INIT_LIST_HEAD(&epi->rdllink);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->next = EP_UNACTIVE_PTR;
[...]
	ep_rbtree_insert(ep, epi);
[...]
```
`epoll instance`에서 모니터링하고자하는 파일디스크립터를 관리하고자할 때 사용하는 자료구조르는 앞서 언급했듯이 Red Black Tree를 사용합니다. 그렇기에 파일디스크립터 이벤트, `epoll instance`등의 정보가 포함된 `struct epitem`구조체를 할당하고 초기화합니다. `struct epitem`구조체 또한 크기가 크기 때문에 모든 내용을 넣을 수 없어 위에서 나온 필드만 소개하고자 합니다.   

```C
struct epitem {
	union {
		struct rb_node rbn;
		struct rcu_head rcu;
	};

	struct list_head rdllink;
	struct epoll_filefd ffd;
	struct eppoll_entry *pwqlist;
	struct eventpoll *ep;
	struct epoll_event event;
};

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;


struct eppoll_entry {
	struct eppoll_entry *next;
	struct epitem *base;
	wait_queue_entry_t wait;
	wait_queue_head_t *whead;
};

/* Wrapper struct used by poll queueing */
struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};
```
1. `rbn` 필드를 통해서 레드블랙트리를 연결합니다.   
2. `ffd` 필드를 통해서 파일디스크립터와 파일구조체를 저장합니다.
3. `ep` 필드를 통해서 `epoll instance` 즉, `struct eventpoll`을 가리킵니다. 
4. `event` 필드를 통해서 유저가 인수로 전달한 `struct epoll_event`를 저장합니다.


```C
/* ep_insert 함수 이어서 */
epq.epi = epi;
init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);

revents = ep_item_poll(epi, &epq.pt, 1);
```
`struct ep_pqueue`의 `epi`필드에 파일디스크립터의 `epitem`을 대입한다. 그리고 `init_poll_funcptr`함수를 호출하여 `poll_table pt`의 `_qproc`필드에 `ep_ptable_queue_proc`함수를 대입합니다.   
해당 내용은 아래에 정의 되어있습니다.
```C
typedef struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
} poll_table;

static inline void init_poll_funcptr(poll_table *pt, poll_queue_proc qproc)
{
	pt->_qproc = qproc;
	pt->_key   = ~(__poll_t)0; /* all events enabled */
}
```
해당 함수포인터는 추후 모니터링하기를 원하는 소켓의 wait queue에 wait을 넣기 위해 호출하는 함수입니다.   
그리고 `ep_item_poll`함수를 호출하여 모니터링하기를 원하는 소켓이 저장된 `epitem`와 소켓의 wait queue에 wait을 넣기위한 콜백함수가 저장된 필드를 인자를 함께 넘깁니다.
`ep_item_poll`함수는 모니터링하기 원하는 소켓의 wait_queue에 탐지하기를 원하는 프로세스의 wait을 넣습니다. 그리고 `epoll_wait`함수를 호출하기전 이미 발생한 이벤트가 있는지 확인하고 있다면 reevents로 반환합니다. 

```C
static __poll_t ep_item_poll(const struct epitem *epi, poll_table *pt,
				 int depth)
{
	struct file *file = epi->ffd.file;
	__poll_t res;

	pt->_key = epi->event.events;
	if (!is_file_epoll(file))
		res = vfs_poll(file, pt);
	else
		res = __ep_eventpoll_poll(file, pt, depth);
	return res & epi->event.events;
}
```
ep_item_poll함수에서 넘겨받은 epitem(모니터링 원하는 파일)이 `epoll instance`가 아니라면 `vfs_poll`함수를 호출합니다.
```C
static inline __poll_t vfs_poll(struct file *file, struct poll_table_struct *pt)
{
	if (unlikely(!file->f_op->poll))
		return DEFAULT_POLLMASK;
	return file->f_op->poll(file, pt);
}
```
`vfs_poll`함수는 `file->f_op->poll`함수포인터를 호출합니다. 만약 넘겨받은 file이 소켓파일이라면 `sock_poll`함수를 호출합니다.
```C
/* No kernel lock held - perfect */
static __poll_t sock_poll(struct file *file, poll_table *wait)
{
	struct socket *sock = file->private_data;
	__poll_t events = poll_requested_events(wait), flag = 0;

	if (!sock->ops->poll)
		return 0;

	if (sk_can_busy_loop(sock->sk)) {
		/* poll once if requested by the syscall */
		if (events & POLL_BUSY_LOOP)
			sk_busy_loop(sock->sk, 1);

		/* if this socket can poll_ll, tell the system call */
		flag = POLL_BUSY_LOOP;
	}

	return sock->ops->poll(file, sock, wait) | flag;
}
```
간단한 검증작업을 거친 후 `sock->ops->poll`함수포인터를 호출합니다. 만약 해당 파일이 tcp 소켓파일이라면 `poll`함수포인터는 `tcp_poll`함수가 됩니다. 

```C
__poll_t tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	__poll_t mask;
	struct sock *sk = sock->sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	u8 shutdown;
	int state;

	sock_poll_wait(file, sock, wait);

	state = inet_sk_state_load(sk);
	if (state == TCP_LISTEN)
		return inet_csk_listen_poll(sk);

[...]
}
```
해당 함수 또한 TCP_ESTABLISHED이후의 상태일때 코드가 있지만 그것은 추후 epoll_wait함수 분석 때 다시 살펴보도록 하겠습니다.  
지금은 단지 sock_poll_wait함수를 호출하고 현재 소켓의 상태가 `TCP_LISTEN`상태라면 소켓의 `accept queue`에서 connection 요청된 클라이언트 소켓이 존재하는지 확인합니다. 
이때 `accept queue`의 정의는 `TCP 3 Way Handshake`가 끝난 소켓을 의미합니다. 

sock_poll_wait함수를 살펴보도록 하겠습니다. 
```C
static inline void sock_poll_wait(struct file *filp, struct socket *sock,
				  poll_table *p)
{
	if (!poll_does_not_wait(p)) {
		poll_wait(filp, &sock->wq.wait, p);
		smp_mb();
	}
}
```
`poll_does_not_wait`함수를 호출해서 넘겨받은 `poll_table *p`의 콜백함수가 NULL이 아닌지 확인합니다. 이전에 `ep_insert`함수에서 `init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);` 해당 코드를 실행했기 때문에 해당 값은 참이 됩니다.  
그러면 `poll_wait`함수를 호출하게 됩니다. 
```C
static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	if (p && p->_qproc && wait_address)
		p->_qproc(filp, wait_address, p);
}
```
`poll_wait`함수는 `poll_talbe *p`의 `_qproc`함수포인터를 호출합니다. 이는 이전에 설정한 `ep_ptable_queue_proc`함수가 됩니다.해당 함수의 2번째 인자로 wait_address가 주어지는데 이는 모니터링하기를 원하는 소켓파일의 wait_queue입니다.

```C
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	struct ep_pqueue *epq = container_of(pt, struct ep_pqueue, pt);
	struct epitem *epi = epq->epi;
	struct eppoll_entry *pwq;

	if (unlikely(!epi))	// an earlier allocation has failed
		return;

	pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL);
	if (unlikely(!pwq)) {
		epq->epi = NULL;
		return;
	}

	init_waitqueue_func_entry(&pwq->wait, ep_poll_callback);
	pwq->whead = whead;
	pwq->base = epi;
	if (epi->event.events & EPOLLEXCLUSIVE)
		add_wait_queue_exclusive(whead, &pwq->wait);
	else
		add_wait_queue(whead, &pwq->wait);
	pwq->next = epi->pwqlist;
	epi->pwqlist = pwq;
}
```
`ep_ptable_queue_proc`함수는 `poll_table *pt`로 부터 `container_of`매크로 함수를 이용하여 `ep_pqueue`를 꺼내옵니다. 해당 구조체에는 이전에 대입한 epitem이 존재합니다.   
```C
static inline void
init_waitqueue_func_entry(struct wait_queue_entry *wq_entry, wait_queue_func_t func)
{
	wq_entry->flags		= 0;
	wq_entry->private	= NULL;
	wq_entry->func		= func;
}
```
그리고 `init_waitqueue_func_entry`함수를 호출하여 모니터링하기를 원하는 소켓의 wait queue에 넣기전 넣으려는 wait이 wakeup되었을 때 어떤 함수를 호출하게 할것인지 콜백함수를 설정합니다. 여기서는 `ep_poll_callback`함수를 설정했습니다.   

그리고 만약 사용자가 설정한 이벤트가 `EPOLLEXCLUSIVE`이벤트가 포함되어 있다면 `add_wait_queue_exclusive`함수를 호출하고 그렇지 않다면 `add_wait_queue`함수를 호출하여 소켓의 wait queue에 호출한 프로세스의 wait_entry를 LIFO냐, FIFO냐 형태로 넣습니다.   

만일 `add_wait_queue_exclusive`함수를 호출해서 큐에 넣는다면 이때 flags값으로 `WQ_FLAG_EXCLUSIVE`값을 추가하고 넣습니다. `add_wait_queue`라면 해당 값은 지우고 넣습니다. 

즉, 여기까지 정리하자면 `ep_insert`함수에서 epitem을 등록하고 모니터링하기를 원하는 소켓 파일의 wait queue에 요청한 프로세스의 wait_entry를 넣습니다. 이때 wait_entry는 프로세스의 태스크라고 보면 편합니다. 그리고 해당 소켓에 이벤트가 도착할 때는 `ep_poll_callback`함수를 호출함까지 보았습니다. 그리고 `epoll_wait`함수를 호출하기전에 이벤트가 도착한것이 있는지 확인하고 revents변수에 반환합니다. 

```C
/* ep_insert 함수 이어서 */
if (revents && !ep_is_linked(epi)) {
	list_add_tail(&epi->rdllink, &ep->rdllist);
	ep_pm_stay_awake(epi);

	if (waitqueue_active(&ep->wq))
		wake_up(&ep->wq);
	if (waitqueue_active(&ep->poll_wait))
		pwake++;
}
[...]
if (pwake)
	ep_poll_safewake(ep, NULL, 0);

return 0;
```
다시 `ep_insert`함수를 이어서 보겠습니다 이전에 `ep_item_poll`함수를 호출하고나서 revents값이 반환된다고 했는데 이는 대기하기전 이미 도착한 이벤트의 알림 유무입니다. 
이때는 어떤 상황이 발생할 수 있냐면 클라이언트의 소켓을 accept하고나서 `EPOLL_CTL_ADD`로 등록하기전에 이미 클라이언트가 데이터를 전송했을 때 해당 로직이 트리거될 수 있습니다. 그렇다면 이때의 revents값은 `(EPOLLIN | EPOLLRDNORM)`값이 세팅됩니다.

그리고 `epi->rdllink`를 `ep->rdllist`의 끝에 추가합니다. 추측컨대 이때 `epi->rdllink`를 넣는 이유는 커널 리스트 자료구조상 구조체를 바로 넣지 못하고 리스트형식으로 연결되어야 하기 때문이다. 그리고 `rdllist`는 준비가 된 epitem 리스트들입니다.

그리고 `waitqueue_active`함수를 호출하여 `epoll instance`의 wait queue에 프로세스들의 wait이 있는지 확인하고 있다고 wake_up함수를 호출해서 깨웁니다. 그렇지않다면 rdllist만 보존됩니다.

여기서 하나의 질문이 들 수 있습니다.   
***"왜 epoll_wait에서 한번에 하면 좋은데 왜 epoll_ctl과정에서 한번 체크를 해야하나요?"***
이에대한 답은 웹서버를 예로들 수 있습니다. 클라이언트를 accept하고 나서 클라이언 소켓을 epoll_ctl을 통해 모니터링하고자 하기전에 데이터를 주면 epoll_wait에서는 timeout 설정말고는 확인할 수 없습니다. 그 이유는 콜백함수인 `ep_poll_callback`은 해당 소켓에 변화가 감지되었을 때만 호출되기 때문입니다.   

즉, 데이터를 놓지지 않기 위해 epoll_ctl하는 과정에서 확인하는 이유입니다. 

### epoll_wait
이제 마지막 syscall입니다. 지금까지는 `epoll instance`를 만들고 모니터링하기를 원하는 소켓을 원하는 이벤트와 함께 등록을 진행했습니다. 이제는 모니터링을 진행하는 로직을 수해해야 합니다.

```C
/* fs/evevntpoll.c */
SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	struct timespec64 to;

	return do_epoll_wait(epfd, events, maxevents,
			     ep_timeout_to_timespec(&to, timeout));
}
```
epoll_wait syscall은 내부족으로 do_epoll_wait함수를 호출하여 로직을 수행합니다.   
```C
/* fs/eventpoll.c */
static int do_epoll_wait(int epfd, struct epoll_event __user *events,
			 int maxevents, struct timespec64 *to)
{
	int error;
	struct fd f;
	struct eventpoll *ep;

	/* The maximum number of event must be greater than zero */
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;

	/* Verify that the area passed by the user is writeable */
	if (!access_ok(events, maxevents * sizeof(struct epoll_event)))
		return -EFAULT;

	/* Get the "struct file *" for the eventpoll file */
	f = fdget(epfd);
	if (!f.file)
		return -EBADF;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an eventpoll file.
	 */
	error = -EINVAL;
	if (!is_file_epoll(f.file))
		goto error_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = f.file->private_data;

	/* Time to fish for events ... */
	error = ep_poll(ep, events, maxevents, to);

error_fput:
	fdput(f);
	return error;
}
```
`do_epoll_wait`함수는 각종 유효성 검사를 진행합니다. maxevents의 값이 옳은지, 사용자가 넘긴 events가 유효한 값인지, epfd가 epoll instance가 맞는등을 검사합니다.   
만약 적절하다면 private_data에서 이전에 저장한 `struct eventpoll`구조체를 가지고옵니다. 그리고 `ep_poll`함수를 호출하여 본격적인 로직을 수행합니다. 해당 함수 또한 크기가 크기 때문에 기능별로 나누어서 설명하겠습니다.
```C
/* fs/eventpoll.c */
static int ep_poll(struct eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, struct timespec64 *timeout)
{
	int res, eavail, timed_out = 0;
	u64 slack = 0;
	wait_queue_entry_t wait;
	ktime_t expires, *to = NULL;
[...]
	eavail = ep_events_available(ep);
```
먼저 루프에 들어가기전에 모니터링 대상에 이벤트가 발생했는지 `ep_events_available`함수를 호출하여 확인합니다. 

```C
static inline int ep_events_available(struct eventpoll *ep)
{
	return !list_empty_careful(&ep->rdllist) ||
		READ_ONCE(ep->ovflist) != EP_UNACTIVE_PTR;
}
```
`rdllist`의 값이 empty하지 않는가 또는 rb tree가 비지않았는가 등을 검사하여 이벤트가 있는지 확인합니다. 이전에 이벤트가 발생했다면 `epi->rdllink`의 값을 `ep->rdllist`에 추가하였는것을 기억할 수 있습니다. 


```C
while (1) {
	if (eavail) {
		res = ep_send_events(ep, events, maxevents);
		if (res)
			return res;
	}

	if (timed_out)
		return 0;
[...]
	__set_current_state(TASK_INTERRUPTIBLE);

	eavail = ep_events_available(ep);
	if (!eavail)
		__add_wait_queue_exclusive(&ep->wq, &wait);

	write_unlock_irq(&ep->lock);

	if (!eavail)
		timed_out = !schedule_hrtimeout_range(to, slack,
								HRTIMER_MODE_ABS);
	__set_current_state(TASK_RUNNING);

	eavail = 1;

	if (!list_empty_careful(&wait.entry)) {
		write_lock_irq(&ep->lock);

		if (timed_out)
			eavail = list_empty(&wait.entry);
		__remove_wait_queue(&ep->wq, &wait);
		write_unlock_irq(&ep->lock);
	}
}
}
```
그래서 만약 이벤트가 있었다면 `ep_send_events`함수를 호출하여 사용자가 전달한 events변수에 maxevents만큼 값을 쓰고 종료합니다. 그렇지않다면 루프를 진행합니다.   

만약 이벤트가 없어 루프가 진행된다면 해당 프로세스에대한 wait을하나 만들고 해당 프로세스의 상태를 `TASK_INTERRUPTIBLE`상태로 설정합니다. 그리고 정말 대기모드에 진입하기 전에 마지막으로 정말 이벤트가 없었는지 확인합니다. 만약 없다면 `epoll_instance`의 wait queue에 해당 프로세스의 wait을 추가합니다. 그리고 `schedule_hrtimeout_range`함수를 호출하여 지정된 시간동안 SLEEP합니다.  

그리고 지정된 시간이 지났거나 누군가 강제로 꺠웠다면 `epoll instance`의 wait_queue에서 자신의 wait을 제거한다음 프로세스의 상태를 `TASK_RUNNING`상태로 설정합니다. 그리고 다시 처음 루프문을 실행합니다.   

여기서 지정된 시간이 아닌 누군가가 깨웠다는 전제하에 설명을 추가적으로 해보겠습니다.   
과연 누가 대기모드에 빠진 프로세스를 깨운것일까요? 그것은 모니터링하고자 하는 소켓이 이벤트가 발생하여 wakeup된것입니다. 그럼 과정을 한번 살펴보겠습니다.

먼저 TCP 소켓기준 데이터가 온다면 `sock_def_readable`함수를 호출하게 됩니다. 
```C
void sock_def_readable(struct sock *sk)
{
	struct socket_wq *wq;

	trace_sk_data_ready(sk);

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLIN | EPOLLPRI |
						EPOLLRDNORM | EPOLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}
```
`sock_def_readable`함수는 자신의 소켓의 wait_queue를 가지고옵니다. 그리고 `wake_up_interruptible_sync_poll`함수를 호출하게 됩니다. 이때 넣는 인자로는 어떤 이벤트인지 알려주는 플래그값이 포함되어 있습니다. `wake_up_interruptible_sync_poll`함수는 내부적으로 `__wake_up_common`함수를 호출하게 됩니다.  

```C
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
			int nr_exclusive, int wake_flags, void *key,
			wait_queue_entry_t *bookmark)
{
	wait_queue_entry_t *curr, *next;
	int cnt = 0;

[...]
	list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
		unsigned flags = curr->flags;
		int ret;
[...]
		ret = curr->func(curr, mode, wake_flags, key);
		if (ret < 0)
			break;
		if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
			break;
[...]
	}

	return nr_exclusive;
}
```
많은 양의 로직을 제거하고 핵심적인 것만 뽑아냈습니다. 먼저 `list_for_each_entry_safe_from`매크로 함수를 호출하여 소켓의 wait queue를 이터레이팅합니다. 그리고 `curr->func`함수 포인터를 호출하는데 이는 이전에 설정한 `ep_poll_callback`함수입니다. 해당 함수를 호출하고나서 만약 flags값이 `WQ_FLAG_EXCLUSIVE`플래그가 포함되어 있다면 해당 로직을 중단합니다. 해당 플래그는 이전에 `EPOLLEXCLUSIVE`이벤트를 포함시켰을 때 같이 활성화된 것을 보았습니다. 즉, 여기서 알 수 있듯이 `EPOLLEXCLUSIVE`이벤트는 소켓의 wait queue에 물린 여러 프로세스중 하나의 프로세스만을 깨우는 것을 확인할 수 있습니다.   
그럼 다시 호출되는 콜백함수인 `ep_poll_callback`함수를 살펴보겠습니다.

```C
static int ep_poll_callback(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	int pwake = 0;
	struct epitem *epi = ep_item_from_wait(wait);
	struct eventpoll *ep = epi->ep;
	__poll_t pollflags = key_to_poll(key);
	unsigned long flags;
	int ewake = 0;
[...]
	if (READ_ONCE(ep->ovflist) != EP_UNACTIVE_PTR) {
		if (chain_epi_lockless(epi))
			ep_pm_stay_awake_rcu(epi);
	} else if (!ep_is_linked(epi)) {
		/* In the usual case, add event to ready list. */
		if (list_add_tail_lockless(&epi->rdllink, &ep->rdllist))
			ep_pm_stay_awake_rcu(epi);
	}

[...]
	if (waitqueue_active(&ep->wq)) {
		if ((epi->event.events & EPOLLEXCLUSIVE) &&
					!(pollflags & POLLFREE)) {
			switch (pollflags & EPOLLINOUT_BITS) {
			case EPOLLIN:
				if (epi->event.events & EPOLLIN)
					ewake = 1;
				break;
			case EPOLLOUT:
				if (epi->event.events & EPOLLOUT)
					ewake = 1;
				break;
			case 0:
				ewake = 1;
				break;
			}
		}
		wake_up(&ep->wq);
	}
[...]
	return ewake;
}
```
먼저 `list_add_tail_lockless`함수를 호출하여 이전처럼 활성화된 epitem을 `ep->rdllist`의 큐에 추가시킵니다. 그리고 `epoll instance`의 wait queue에 대기중인 프로세스가 있는지 확인하고 있다면 `wake_up`함수를 호출하여 `epoll instance`의 wait queue에 대기중인 프로세스를 깨웁니다. 깨우는 과정은 위에서 소켓의 경우를 예를 들어 설명하였습니다.

그럼 `ep_poll_callback`함수를 호출하여 프로세스를 깨운다면 이전에 `ep_poll`함수에서 SLEEP중인 프로세스가 깨어나게 되며 `ep_send_events`함수를 호출합니다.   
이제 정말 마지막입니다. 해당 함수에서 `Level Trigger`와 `Edge Trigger`의 동작 차이를 볼 수 있는 중요한 함수입니다. 
```C
static int ep_send_events(struct eventpoll *ep,
			  struct epoll_event __user *events, int maxevents)
{
	struct epitem *epi, *tmp;
	LIST_HEAD(txlist);
	poll_table pt;
	int res = 0;
[...]
	ep_start_scan(ep, &txlist);

	list_for_each_entry_safe(epi, tmp, &txlist, rdllink) {
		struct wakeup_source *ws;
		__poll_t revents;

		if (res >= maxevents)
			break;
[...]
		list_del_init(&epi->rdllink);
[...]
		revents = ep_item_poll(epi, &pt, 1);
		if (!revents)
			continue;

		events = epoll_put_uevent(revents, epi->event.data, events);
		if (!events) {
			list_add(&epi->rdllink, &txlist);
			ep_pm_stay_awake(epi);
			if (!res)
				res = -EFAULT;
			break;
		}

		res++;
[...]
		else if (!(epi->event.events & EPOLLET)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);
		}
	}
	ep_done_scan(ep, &txlist);
	mutex_unlock(&ep->mtx);

	return res;
}
```
해당 함수는 먼저 `ep_start_scan`함수를 호출하여 `ep->rdllist`를 `txtlist`로 list slice합니다. 그리고 이를 `list_for_each_entry_safe`매크로함수를 호출하여 리스트를 이터레이팅합니다.  
그리고 res값을 maxevents값과 비교하는데 이는 사용자가 요청한 검사할 최대값입니다.   
그리고 `ep_item_poll`함수를 호출하여 이벤트가 있는지 확인합니다.   
즉, TCP 소켓의 경우 `tcp_poll`함수를 호출합니다. 이전에 `TCP_LISTEN`상태일때만 보고 `TCP_ESTABLISHED`상태일 때는 확인하지 못했는데 지금 확인해보겠습니다.

```C
__poll_t tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
[...]
	shutdown = READ_ONCE(sk->sk_shutdown);
	if (shutdown == SHUTDOWN_MASK || state == TCP_CLOSE)
		mask |= EPOLLHUP;
	if (shutdown & RCV_SHUTDOWN)
		mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;

	/* Connected or passive Fast Open socket? */
	if (state != TCP_SYN_SENT &&
	    (state != TCP_SYN_RECV || rcu_access_pointer(tp->fastopen_rsk))) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);
		u16 urg_data = READ_ONCE(tp->urg_data);

		if (unlikely(urg_data) &&
		    READ_ONCE(tp->urg_seq) == READ_ONCE(tp->copied_seq) &&
		    !sock_flag(sk, SOCK_URGINLINE))
			target++;

		if (tcp_stream_is_readable(sk, target))
			mask |= EPOLLIN | EPOLLRDNORM;
	}
[...]
	return mask;
}
```
소켓의 상태를 확인하여 에러가 발생하면 에러 플래그를 반환합니다. 그렇지 않고 읽을 수 있는 데이터가 존재하는지 확인하기 위햇 `tcp_stream_is_readable`함수를 호출하여 데이터를 읽을 수 있다면 `EPOLLIN` 플래그를 활성화 시키고 반환합니다.   

다시 돌아와서 `ep_item_poll`함수를 호출하게 되면 활성화된 이벤트가 반환됩니다.   
여담으로 `ep_item_poll`함수를 호출하면 소켓에 후킹하는 것이 아니냐는 의문이 있을 수 있습니다. 하지만 지금 호출할 때는 `_qproc`값이 NULL이기 때문에 후킹을 진행하기 않습니다.  

만약 관심이벤트가 존재한다면 `epoll_put_event`함수를 호출하여 유저가 요청한 events목록에 값을 씁니다. 
```C
static inline struct epoll_event __user *
epoll_put_uevent(__poll_t revents, __u64 data,
		 struct epoll_event __user *uevent)
{
	if (__put_user(revents, &uevent->events) ||
	    __put_user(data, &uevent->data))
		return NULL;

	return uevent+1;
}
```
그리고 값을 썼다면 사용자가 요청한 EPOLL 플래그값에 `EPOLLET`값이 포함되어 있는지 확인합니다. 만약 포함되어 있지않다면 즉, `Level Trigger`모드라면 다시한번 `ep->rdllist`에 `epi->rdllink`값을 추가하여 이벤트가 있음을 알립니다.   

이는 `ep_poll`함수에서 `ep_events_available`함수를 호출하면서 이벤트가 있음을 알게됩니다.    그렇지않고 `Edge Trigger`모드라면 이번 이벤트가 끝이게 됩니다. 그리고 함수는 이벤트가 발생한 소켓의 갯수 `res`값을 반환하고 종료됩니다. 

### 요약 
epoll 인터페이스를 사용하기 위해서는 `epoll_create`, `epoll_ctl`, `epoll_wait`3개의 syscall이 존재합니다.  
먼저, `epoll_create`함수는 `struct eventpoll`구조체를 할당하고 이를 file의 private_data에 저장하여 추후 파일디스크립터로만으로 꺼낼 수 있도록 합니다. 그리고 EPOLL 파일디스크립터를 반환합니다. 

`epoll_ctl`함수는 3가지의 동작으로 나눌 수 있습니다. `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`, `EPOLL_CTL_DEL`.   
`EPOLL_CTL_ADD`의 경우 `ep_insert`함수를 호출하여 모니터링하려는 파일의 프로세스 대기큐인 wait queue에 `epoll_ctl`을 호출한 프로세스의 wait_entry를 삽입합니다. 그리고 wakeup시 호출되는 콜백함수로는 `ep_poll_callback`함수를 등록합니다.   
또한, `epoll_wait`함수를 호출하기전 이벤트가 있었는지 확인하고 있었다면 `ep->rdllist`에 활성화된 이벤트를 추가합니다.  

이렇게 동작하는 이유는 웹서버를 예를 들어 이전에 설명했듯이 클라이언트 수락후 `epoll_wait`하는 과정에서 사이에 데이터의 변화가 발생할 수 있다는 가정입니다. `ep_poll_callback`콜백함수는 데이터의 변화가 감지되어야 호출되는 콜백함수인데 `epoll_wait`전에 감지된 이벤트에대해서는 무시하게 되기때문입니다. 

또한 `ep_insert`함수는 모니터링하고자하는 파일디스크립터에 대한 `struct epitem`을 레드블랙트리로 관리합니다. 

마지막으로 `epoll_wait`함수는 사용자가 지정한 타임아웃 만큼 대기모드에 빠집니다. 이때 프로세스의 상태는 `TASK_INTERRUPTIBLE`로 설정합니다. 만일 `ep_poll_callback`함수를 통해 프로세스가 `TASK_RUNNING`상태로 바꼈다면 이벤트가 발생했다는 가정하게 로직을 수행하게 됩니다. 그렇기 때문에 `spurious wakeup`이 발생하여 활성화된 이벤트 목록 갯수 0이 반환될 수 있는 것입니다. 만약 이벤트가 존재한다면 `ep_send_events`함수를 호출하여 이벤트가 활성화된 `epitem`들을 이터레이팅하여 사용자가 전달한 `struct epoll_event`구조체에 값을 기입합니다.   

만약 사용자가 `Edge Trigger` 모드를 사용한다면 한번 발생한 이벤트에 대해서는 추가알림을 하지않습니다. 하지만 `Leve Trigger`모드를 사용한다면 데이터를 사용자에게 전달하고 나서 다시 활성화된 이벤트리스트에 `epitem`을 추가하게 됩니다. 즉, 데이터가 읽일때까지 무한적으로 알림을 발생시키게 됩니다. 


### 코멘트
지금까지 epoll이 어떻게 만들어졌는지 어떻게 동작하는지 등을 알아보았습니다. 물론 방대한 소스코드를 부족한 실력으로 분석한것이기때문에 분명히 틀린내용이 있을 수 있습니다. 그렇기에 해당 분석글만을 기반하지않고 다른 epoll 분석글을 읽어가면서 보시는것을 추천합니다.   
찾아본결과 거의다 중국어로 작성된 기술블로그가 많다보니 번역에 어려움이 있을 수 있지만 기술적으로 자세한 내용이 기입되어 있습니다. 

