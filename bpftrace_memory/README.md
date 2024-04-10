### 개요
어플리케이션 개발시에 문제가 될 수 있는 부분은 메모리를 할당하고 정상적으로 해제 하였는가입니다.   
해당 부분은 디버깅으로도 확인하기 어렵기 때문에 문제가 될 만한 부분을 찾기 어렵습니다.    
그렇기에 일반적인 디버깅이아닌 ebpf를 사용해서 해당 문제를 해결해보고자 합니다.   
  
### ebpf 
처음 bpf가 세상에 나왔을 때는 단순히 패킷을 필터링하는 목적으로 나왔습니다. 하지만 bpf의 성능과 활용성이 너무나도 좋았기 때문에 커널내에 패킷 필터 목적 이외에 다른 다앙햔 곳에서 활용이 되기 시작합니다. 즉, bpf는 커널 레벨의 프로그램을 개발하기 위한 일종의 프레임워크 같은 형태가 되어가고 있습니다.   

ebpf는 기존 bpf(cbpf)보다 더 많은 메모리와 레지스터 명령어 셋을 가지기 때문에 좀 더 활용가능성이 있습니다. 기존 cbpf가 패킷이 들어올 때 마다 작동했다면 ebpf는 그 밖의 다양한 소스에서 이벤트를 받아 동작합니다. 이러한 이벤트를 기반으로 시스템의 성능 분석, 가시화등 여러 다앙햔 작업이 가능합니다.  

사용자 공간에서 ebpf 프로그램을 작성하고 실행시킨다면 커널에서는 검사기 기능을 기반으로 안정성을 체크합니다. 안정성이 확보되었다면 커널내 존재하는 BPF 가상머신을 기반으로 동작하게 됩니다. 동작하면서 커널내 존재하는 여러 컴포넌트와 상호작용하여 이벤트를 받을 수 있습니다. 이벤트 소스로는 `소켓`, `트레이스포인트`, `USDT`, `kprobe`, `kretprobe`, `uprobe`, `uretprobe`, `sofrware`, `hardware`입니다. 이벤트 기반으로 동작하기에 관심 이벤트가 활성화 되면 출력채널을 통해 이벤트의 결과를 내뱉게 됩니다. 

예를 들어 kprobe 이벤트 소스를 사용한다면 커널 함수의 진입점에 도달할 시 설정한 핸들러 구간을 호출할 수 있습니다 
```BASH
bpftrace -e 'kprobe:inet_csk_accept { pritnf("Hello World"); }'
```
이는 accept syscall을 호출했을 때 커널 내부의 `inet_csk_accept`함수에 진입할 때 트리거됩니다. 

이번 섹션은 ebpf에 대한 설명보단 ebpf를 활용한 메모리 누수 탐지 이기때문에 자세한 설명은 지나가겠습니다.  

### bpftrace 
eBPF를 사용하기 위해서는 BPF 바이트코드를 작성하는 방법이나 C 언어로 BPF 프로그래밍등 다양한 방법이 있지만 이 방법들은 조금 불편하다는 단점이 있습니다. 그렇기에 bpftrace라는 툴을 사용하여 스크립트를 작성할 수 있습니다. 

스크립트의 예시는 위의 bpfrace 명령어로 사용이 가능합니다. bpftrace또한 내부적으로 bcc를 사용하고 있습니다. 

### 메모리 누수탐지
먼저 사용자 프로그램을 작성하겠습니다. 
```C
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>
#include <stdint.h>

int main(void)
{
	printf("pid :%d\n", getpid());
	int64_t *ptr[10];  
	sleep(20); 	
	for(int i=0;i<10;i++){
		ptr[i] = (int64_t*)malloc(sizeof(int64_t));
	}

	for(int i=0;i<9;i++){
		free(ptr[i]);
	}
	return 0;
}
```
C 프로그램은 20초 뒤 10개의 malloc함수를 호출하고 9번을 free함수를 호출하여 해제합니다.   
여기서 원하는 점은 프로그램이 종료되었을 때 할당 받은 메모리를 모두 해제하였는가 입니다. 그렇기에 malloc함수와 free함수 호출 이벤트를 원할 수 있습니다.   
커널 이벤트는 kprobe와 kretprobe를 사용하여 할 수 있지만 유저 어플리케이션은 uprobe와 uretprobe를 사용할 수 있습니다. uprobe는 특정 함수가 호출되었을 때 이벤트이고 uretprobe는 특정 함수가 종료되었을 때 이벤트입니다.  

아래와 같이 bpf프로그램을 작성할 수 있습니다 
```BT
uprobe:/lib/x86_64-linux-gnu/libc.so.6:__libc_malloc /pid == 3295/
{
        printf("call malloc size: %d\n", arg0);
}

uretprobe:/lib/x86_64-linux-gnu/libc.so.6:__libc_malloc /pid == 3295/
{
        printf("alloc memory %p\n", retval);
        @[retval] = 1;
}

uprobe:/lib/x86_64-linux-gnu/libc.so.6:__libc_free /pid == 3295/
{
        @[arg0] = 0;
}
```
malloc과 free함수는 사용자 정의 함수가 아니며 glibc에 선언되어 있는 함수입니다. 그렇기에 ldd 명령어로 사용자가 사용하는 라이브러리가 어디에 있는지 확인하여야 합니다. 

위 bpf 프로그램은 malloc함수를 호출했을 때 얼마만큼 메모리를 요청했는가 출력합니다. 그리고 malloc함수가 종료되면 메모리 주소값을 반환합니다. 이를 맵의 키로 설정합니다. 그리고 사용중임을 뜻하는 1을 설정합니다. 

free함수가 호출되는 시점에 어떤 메모리주소를 해제하려는지 맵의 키로 설정하고 0을 대입합니다. 

그리고 프로그램이 끝난다면 할당받은 메모리 주소에 대해 0(해제) 또는 1(사용중)이 설정되게 됩니다. 

```BASH
➜  ~ ldd a.out
        linux-vdso.so.1 (0x00007ffe493d1000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f09dca00000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f09dcdfc000)
```
또한 bpf프로그램을 작성하면 모든 프로세스에 대해 이벤트가 발생하기에 필터 조건을 걸 필요성이 있습니다.   
```
/ pid = 3295 /
```
위의 필터를 설정하여 pid가 3295만 이벤트를 받겠다고 설정합니다.   
```BASH
➜  ~ sudo bpftrace memory.bt
```
관리자 권한으로 bpf 프로그램을 실행할 수 있습니다. 
```BASH
➜  ~ sudo bpftrace memory.bt
[sudo] password for tuuna:
Attaching 3 probes...
call malloc size: 8
alloc memory 0x55e1235636b0
call malloc size: 8
alloc memory 0x55e1235636d0
call malloc size: 8
alloc memory 0x55e1235636f0
call malloc size: 8
alloc memory 0x55e123563710
call malloc size: 8
alloc memory 0x55e123563730
call malloc size: 8
alloc memory 0x55e123563750
call malloc size: 8
alloc memory 0x55e123563770
call malloc size: 8
alloc memory 0x55e123563790
call malloc size: 8
alloc memory 0x55e1235637b0
call malloc size: 8
alloc memory 0x55e1235637d0
^C

@[94425448855472]: 0
@[94425448855248]: 0
@[94425448855376]: 0
@[94425448855344]: 0
@[94425448855408]: 0
@[94425448855216]: 0
@[94425448855312]: 0
@[94425448855280]: 0
@[94425448855440]: 0
@[94425448855504]: 1
```
결과를 보게 되면 10번 할당받고 9번 해제했기에 0x55e1235637d0 번지 즉,94425448855504에 0이 아닌 1이 되어있는 것을 확인할 수 있습니다. 

이처럼 BPF의 장점은 대상 프로그램을 수정 없이, 런타임에 분석할 수 있다는 장점을 지닙니다. 지금은 단순히 메모리 누수만 확인했는데 이를 좀 더 정밀하게 한다면 할당받은 메모리 주소와 사이즈를 기반으로 buffer overflow를 탐지할 수 있는 툴을 만들 수도 있을거 같습니다. 

또한 bpf 프로그램은 앞서 명시된 다양한 이벤트를 수집할 수 있습니다. 예를 들자면 아래와 같습니다. 
1. 특정 스레드가 얼마만큼 CPU에서 소모되었고 CPU ID는 무엇이었는가 
2. 특정 스레드가 얼마만큼 자주 컨텍스트 스위칭 되었는가
3. 특정 프로그램의 함수가 얼마만큼 호출되었고 시간은 얼마만큼 잡아먹었는가   
... 