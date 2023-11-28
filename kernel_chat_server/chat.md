# Kernelspace Chat Server

### 개론 
TCP기반으로 채팅서버를 만든다고 하면 유저스페이스에서 socket(2), listen(2), bind(2), recv(2), accept(2)등의 syscall을 사용하여 패킷을 처리한다. 이 과정에서 파일디스크립터가 무조건적으로 나오게 되며 전송과 받기에서 버퍼의 데이터를 유저스페이스에서 커널스페이스로, 커널스페이스에서 유저스페이스로의 복사가 발생한다.      

물론 서버의 성능은 버퍼 메모리, 처리시간등을 최적화하거나 분산처리 환경을 이용하여 향상시킬 수 있다. 하지만 유저스페이스에서 진행하는 코드를 커널스페이스에서 동작시킨다면 좀 더 빠르지 않을까라는 호기심에 커널기반 채팅 서버를 만들어봤으며 `커널에서 어떤식으로 TCP 서버를 구현할 수 있는지 설명하고자 이 글을 쓰게 되었다.`

### 주의 
***모든 과정은 커널 버전 6.4.3기준으로 진행되며 아래 예제코드는 불안정하기 때문에 직접 테스트 시 일회용 클라우드나 사용하지 않는 VM 등에 테스트 하는 것을 매우 권장합니다.   
물론, 커널모듈이기 때문에 재부팅하면 해결될것이라고 생각하긴합니다.***

### 의존성 
커널 스페이스에서 동작시킬거기 때문에 모듈 개발에 필요한 파일을 apt를 통해 설치해야 한다. 

Before you can build anything you’ll need to install the header files for your kernel.  
On Ubuntu/Debian GNU/Linux:
```Shell
sudo apt update
sudo apt-get install build-essential kmod
apt-cache search linux-headers-`uname -r`
```

This will tell you what kernel header files are available. Then for example:
```Shell
sudo apt-get install kmod linux-headers-5.4.0-80-generic
```
위는 `The Linux Kernel Module Programming Guide`에서 참고한 설치법입니다. 


### 설계
유저스페이스에서는 socket(2), bind(2), accpet(2)등의 syscall을 사용할 수 있지만 커널 스페이스에서는 직접적으로 사용할 수 없다. 그렇기에 해당 syscall을 호출하였을 때 어떤 커널 함수들이 호출되는지 트래킹할 필요가 있다.  
이는 이전에 `TCP 3 Way HandShake`, `Accept(2) 분석`에서 다룬적이 있다.

기본적으로 파일디스크립터를 사용하여 소켓을 처리하는 것이 아닌 `struct socket`, `struct sock`구조체를 이용하여 소켓을 직접적으로 처리하여야 한다. 

### Makefile 제작 
```
obj-m += server.o 
 
PWD := $(CURDIR) 
 
all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
 
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Makefile은 위와 같이 제작하면 현재 디렉토리에서 server.c라는 파일을 찾게 되며 컴파일을 진행한다. 컴파일의 결과물로는 server.ko가 나오게 된다. 

### 모둘 설치
```
lsmod | grep server
```
`lsmod` 명령어로 현재 어떤 모듈이 있는지 확인할 수 있다. 
```
insmod server
```
`insmod` 명령어로 해당 모듈을 설치할 수 있다. 
```
rmmod server
```
`rmmod` 명령어로 해당 모듈을 삭제할 수 있다. 

### 모듈의 구성 
```C
static int __init server_start(void)
{
    printk(KERN_INFO "Chat Server Start!");
    return 0;
}

static void __exit server_exit(void)
{
    printk(KERN_INFO "Chat Server Exit!");
}

MODULE_LICENSE("GPL");
module_init(server_start);
module_exit(server_exit);
```
모듈의 위와 같은 형식으로 구성됩니다. 커널 모듈의 이해가 아니기에 자세한 내용은 패스합니다. 

### 헤더파일
```C
#ifndef __SERVER_H_
#define __SERVER_H_

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#include <linux/list.h>
#include <linux/printk.h> /* Needed for pr_info() */ 

#include <net/sock.h>
#include <linux/socket.h>
#include <linux/err.h>

#include <linux/kthread.h> 

#include <net/tcp.h>
#include <linux/raid/pq.h>
#include <linux/fs.h>
#include <linux/list.h>

#include <linux/mutex.h> 

#include <linux/completion.h>

#define MAX_CLIENT 100

#define PORT 10106
#define BACKLOG 512

#define BLOCKING_SOCKET 0 
#define NON_BLOCKING_SOCKET O_NONBLOCK

#define CONNECTION_RESET 104

#endif 
```

### socket(2) 구현
유저스페이스에서 socket(2)함수를 호출하면 커널 내부적으로 `sock_create` 함수를 호출하고 프로토콜에 맞게 세팅하고 `struct socket` 구조체를 반환한다. 그리고 파일디스크립터를 반환한다.  
이 글은 커널스페이스에서 처리하기때문에 파일디스크립터를 만들 필요는 없다. 그렇기에 해당 코드는 가감히 제거한다. 
```C
static struct socket *__server_socket(int family, int type, int protocol)
{
    struct socket *sock; 
    int retval; 

    retval = sock_create(family, type, protocol, &sock);
    if(retval < 0)
    {
        return ERR_PTR(retval);
    }

    return sock;
}


struct socket *listener_sock = __server_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
```

### bind(2) 구현 
`sock_create`함수를 이용하여 `struct socket`구조체를 받았디면 socket의 멤버필드로 ops가 존재한다. 이는 소켓관련 함수포인터가 저장된 구조체포인터를 가리킨다.
```C
struct socket {
	socket_state		state;
	short			type;
	unsigned long		flags;
	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;
	struct socket_wq	wq;
};
```
```C
// net/ipv4/af_inet.c
const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = tcp_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
#ifdef CONFIG_MMU
	.mmap		   = tcp_mmap,
#endif
	.sendpage	   = inet_sendpage,
	.splice_read	   = tcp_splice_read,
	.read_sock	   = tcp_read_sock,
	.read_skb	   = tcp_read_skb,
	.sendmsg_locked    = tcp_sendmsg_locked,
	.sendpage_locked   = tcp_sendpage_locked,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_ioctl	   = inet_compat_ioctl,
#endif
	.set_rcvlowat	   = tcp_set_rcvlowat,
};
EXPORT_SYMBOL(inet_stream_ops);
```
해당 구조체를 보면 우리가 필요로 하는 bind, listen, accept 함수 포인터가 존재한다. 실제로 유저스페이스서 `bind(2)`, `listen(2)`, `accept(2)`함수를 호출하면 위의 함수포인터를 호출한다. 즉, bind는 inet_bind함수와 연결되기때문에 해당 함수를 호출해주면 된다.
```C
static int __server_bind(struct socket *sock)
{
    int err;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);
    err = sock->ops->bind(sock, (struct sockaddr*)&addr, addrlen);
    
    return err;
}

int err = __server_bind(listener_sock);
```

### listen(2) 구현 
bind와 똑같이 listen 함수 포인터에 연결되어 있는 inet_listen함수를 호출해주면 된다. 
```C
static int __server_listen(struct socket *sock, int backlog)
{
    int err; 
    err = sock->ops->listen(sock, backlog);
    return err;
}

int err = __server_listen(s, BACKLOG);
```

### accept(2) 구현 
여기서 부터 조금 복잡하다. inet_accept함수를 호출하면 되겠지만 그전에 클라이언트에 대한 새로운 `struck socket`을 하나 만들어줘야 하기 때문이다. 
```C
static struct socket *__server_accept(struct socket *listener_sock)
{   
    struct socket *sock; /* 클라이언트 소켓 */
    int err, len;
    struct sock *sk = listener_sock->sk;

    /* struct socket을 생성 */
    err = sock_create_lite(sk->sk_family,sk->sk_type, sk->sk_protocol, &cs->sock);

    if(err < 0)
    {
        return ERR_PTR(0);
    }

    /* listener_sock의 accept queue에서 3 way handshake가 끝난 sock확인 및 꺼내옴 */
    /* accept은 블로킹모드로 설정하고 커널에서 호출한것임을 알린다. */
    err = listener_sock->ops->accept(listener_sock, sock, BLOCKING_SOCKET, true); 
    if(err < 0)
    {
        sock_release(sock);
        return ERR_PTR(0);
    }

    /* inet관련 함수포인터 설정 */
    sock->ops = listener_sock->ops;

    /* 유저 소켓의 주소정보 세팅 */
    len = sock->ops->getname(sock, (struct sockaddr*)&cs->addr, 2);
    
    return sock;
}

struct socket *client_sock = __server_accept(listener_sock); 
```

### recvmsg(2)
이제 클라이언트로부터 소켓을 읽어야 한다. TCP 메시지를 읽는 함수의 콜스택 과정은 유저스페이스에서 recv나 recvmsg함수를 호출하면 내부적으로 sock_read_iter() -> sock_recvmsg() -> inet_recvmsg() -> tcp_recvmsg()함수를 호출한다. 그렇기에 어느 한 지점의 함수를 호출하여야 하는데 다행이도 커널스페이스에서 메시지를 보내고 받을 수 있도록 하는 인터페이스를 제공한다. 

```C
/**
 *	kernel_recvmsg - Receive a message from a socket (kernel space)
 *	@sock: The socket to receive the message from
 *	@msg: Received message
 *	@vec: Input s/g array for message data
 *	@num: Size of input s/g array
 *	@size: Number of bytes to read
 *	@flags: Message flags (MSG_DONTWAIT, etc...)
 *
 *	On return the msg structure contains the scatter/gather array passed in the
 *	vec argument. The array is modified so that it consists of the unfilled
 *	portion of the original array.
 *
 *	The returned value is the total number of bytes received, or an error.
 */

int kernel_recvmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size, int flags)
{
	msg->msg_control_is_user = false;
	iov_iter_kvec(&msg->msg_iter, ITER_DEST, vec, num, size);
	return sock_recvmsg(sock, msg, flags);
}
```
즉, 해당 함수를 사용하기 위해서는 클라이언트의 소켓과 msghdr, kvec의 세팅이 필요하다.
클라이언트와의 메시지 규약은 아래와 같이 정의한다. 
```
데이터의 길이(4 Byte) + 데이터본문(N Byte)
```

```C
static int __server_recvmsg(struct socket *sock, char **buffer)
{
    __u32 msg_len;
    struct kvec vec; 
    struct msghdr msg; 
    int ret; 
    int flags = MSG_WAITALL;

    memset(&vec, 0, sizeof(struct kvec));
    memset(&msg, 0, sizeof(struct msghdr));

    vec.iov_base = &msg_len; 
    vec.iov_len = sizeof(msg_len);

    ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, flags);

    if(ret < 0)
    {
        /* ret값이 -104라면 클라이언트로부터 연결 중단되었다는 뜻 */
        return ret;
    }

    *buffer = kmalloc(msg_len, GFP_KERNEL);

    // __u32만큼 읽고 길이 확인한다음 버퍼 할당하고 진행 
    memset(&vec, 0, sizeof(struct kvec));
    memset(&msg, 0, sizeof(struct msghdr));

    vec.iov_base = *buffer; 
    vec.iov_len = msg_len; 

    ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, flags);
    if(ret < 0)
    {
        kfree(*buffer);
    }
    
    return ret;
}

char *buffer = NULL;
int ret = __server_recvmsg(sock, &buffer);

```
그렇기에 먼저 4바이트만 읽고 데이터의 본문의 길이를 확인하고 kmalloc함수를 이용하여 메모리 할당을 한 다음 다시 N바이트 만큼 읽는다. 이때 flags에 MSG_WAITALL을 넣지 않는다면 확률적으로 데이터를 읽지않고 그대로 반환한다.

그리고 kvec 구조체의 iov_base필드에는 저장할 데이터의 주소, iov_len에는 읽을 데이터의 길이를 넣으면 된다. 


### sendmsg(2)
데이터의 전송도 같다. 커널에서 kernel_sendmsg라는 인터페이스를 제공한다. 
```C
/**
 *	kernel_sendmsg - send a message through @sock (kernel-space)
 *	@sock: socket
 *	@msg: message header
 *	@vec: kernel vec
 *	@num: vec array length
 *	@size: total message data size
 *
 *	Builds the message data with @vec and sends it through @sock.
 *	Returns the number of bytes sent, or an error code.
 */

int kernel_sendmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size)
{
	iov_iter_kvec(&msg->msg_iter, ITER_SOURCE, vec, num, size);
	return sock_sendmsg(sock, msg);
}
```
```C
static int __server_sendmsg(struct socket *sock, char *buffer)
{
    __u32 msg_len = strlen(buffer);
    struct kvec vec;
    struct msghdr msg;  
    int ret;
    char *send_buffer = NULL;
    int send_len = msg_len+sizeof(__u32);

    memset(&vec, 0, sizeof(struct kvec));
    memset(&msg, 0, sizeof(struct msghdr));

    send_buffer = kmalloc(send_len, GFP_KERNEL);
    memcpy(send_buffer, &msg_len, sizeof(__u32));
    memcpy(send_buffer+sizeof(__u32), buffer, msg_len);

    vec.iov_base = send_buffer; 
    vec.iov_len = send_len;

    ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);

    kfree(send_buffer);
    return ret;
}

int ret = __server_sendmsg(sock, buffer);
```

### 소켓 자원 해제 
close(2) 함수를 호출하는 것과 같다. 아래 코드가 확실하지는 않지만 기본적으로 tcp_close를 통해 커넥션을 끊고 sock_release함수를 통해 struct socket을 해제해주어야 한다.   
물론 좀 더 추가적인 코드를 적용하여 정상적으로 해제하여야 하지만 기본적인 틀은 같습니다.  
```C
tcp_close(sock->sk, 0);
sock_release(s->sock);
```

### 테스트
```
make
insmod server.ko
```

```Shell
python3 test.py
Message: HELLO KERNEL SPACE?
Message: I Send Message!
Message: ^C
```

```Shell
dmesg
[ 2853.919754] Chat Server Start!
[ 2857.095690] New Client Connected: 127.0.0.1:38252
[ 2862.545750] Client Say: HELLO KERNEL SPACE?
[ 2869.862234] Client Say: I Send Message!
```

```Shell
netstat -antp
tcp        0      0 0.0.0.0:10106           0.0.0.0:*               LISTEN      -
```

### 요약
처음 생각했던 것보다 할만한거 같은 생각이든다.  
추후 커널단에서 동작하는 로드밸런서를 제작해볼예정이다.

현재 kthread를 통해 1000대의 클라이언트와의 통신할 수 있는 코드를 작성했지만 약간의 버그가 발생하였기에 해당 부분은 추후 다시 올리겠습니다...