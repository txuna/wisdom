# 1.22 Golang 함수 호출규약

### 개론 
ebpf의 트레이싱의 경우 kernel event source와 user event source로 나뉩니다. 그중 uprobe와 uretprobe의 경우 어플리케이션의 함수 시작과 끝을 처리할 수 있습니다. 기본적으로 ebpf코드는 python, golang 등과 같은 다양한 언어로 작성할 수 있지만 실제 bpf 코드는 C 언어로 작성이 이루어집니다. 그렇기에 probe대상이 C/C++로 되어 있을 경우 인자값의 파싱이 기본적으로 간단합니다. (인자가 구조체이면 구조체 헤더 작성) 하지만 go, python, java같은 언어로 작성될 시 인자 파싱의 어려움이 존재합니다. 특히 go 1.17 버전 이전까지는 인자를 스택에 넣는 방식을 사용했었으며 go 1.17 버전 부터는 몇몇 인자는 레지스터를 활용하는 등의 다양성이 확보됩니다. 또한 go에서 사용하는 다양한 자료형들은 C 언어에서 처리하기 조금 까다롭기에 몇 가지의 전처리를 거쳐야 합니다.   

이번 섹션은 1.17 이전 버전과 1.17 이후 버전간의 호출 인자 차이를 비교합니다. 또한 1.17 이후버전에서 언제 레지스터를 활용하고 언제 스택을 활용하는지 살펴봅니다. 마지막으로 1.22 버전을 기준으로 uprobe로 함수로 전달되는 인자를 스택 또는 레지스터로부터 파싱하여 처리하는 것을 목표로 진행합니다. 
> !CAUTION  
> 아래 내용은 linux/amd64 기반으로 작성됩니다. 

### 본론 
go 1.17버전이 21년도 쯔음 출시되면서 함수 호출규약이 크게 변경되었습니다. 기존 스택을 사용하던것에서 레지스터를 같이 사용한다는 것입니다. 이는 x86 호출규약에서 x64 호출규약에서의 차이와 비슷하다라고 생각하면 됩니다. 다만 x64의 경우 RDI, RSI 레지스터 순으로 들어가고 함수의 인자가 7개 이상이 넘어가면 스택을 일부 차용합니다. (물론 리눅스 기준이며 사용하는 머신에 따라 크게 달라집니다.) 이 방식의 장점은 메모리의 접근이 아닌 레지스터를 이용한다는 것에서 접근 속도가 크게 향상됩니다. go 언어에 따르면 5% 정도의 성능향상이 있다고 합니다.

> NOTE  
> 인자 뿐만 아니라 결과값도 go 버전에 따라 스택에 저장할지 레지스터에 저장할지 달라집니다.

#### 기본 환경 세팅
go 1.16.15 버전과 1.22.3 버전 2가지를 다운받습니다. 
```bash
wget https://go.dev/dl/go1.16.15.linux-amd64.tar.gz
tar -zxvf go1.16.15.linux-amd64.tar.gz
mkdir research && cd research
../go/bin/go mod init main
```

```bash
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
tar -zxvf go1.22.3.linux-amd64.tar.gz
mkdir research && cd research
../go/bin/go mod init main
```

### 버전에 따른 인자, 리턴값 전달 과정
1.16버전과 1.22버전의 설치가 완료 되었다면 버전간의 함수 호출규약을 Go Assembly로 확인해보겠습니다. 해당 페이지에서는 Go Assembly에대한 자세한 설명은 하지 않으며 아래 블로그를 참고해주시면 감사하겠습니다. [Golang Internals](https://cppis.github.io/golang%20common/about.golang.internals/) 해당 문서는 Go Assembly 원서를 번역한 글이며 자세히 되어 있습니다. 

```go
package main

func function(a, b int) int {
	return a + b
}

func main(){
	ret := function(3, 7);

	// ret 변수를 사용하여 컴파일 에러를 발생 X
	ret += 2
}
```
```bash
# -S : 어셈블리코드 출력
# -N : 최적화 비활성화 
# -l : 인라인함수 비활성화
go build -gcflags '-S -N -l'
```
내용이 많기 때문에 필요없는 부분은 쳐냈습니다. 처낸 부분중에 `morestack`, `TLS(thread local stack)`, `FUNCDATA, PCDATA`등의 중요한 개념도 포함되어 있으며 나중에 쓱 정리해보겠습니다(저도 아직은 모르겠네요). 또한, 필요에 따라 Go assembly가 아닌 바이너리를 objdump나 gdb로 amd64 어셈블리로 보는것이 더 좋을 수도 있습니다. 
- 1.16 
```bash 
# main.function
"".function STEXT nosplit size=25 args=0x18 locals=0x0 funcid=0x0
	0x0000 00000 (/home/research/go-1.16/main/main.go:3)	MOVQ	$0, "".~r2+24(SP)
	0x0009 00009 (/home/research/go-1.16/main/main.go:4)	MOVQ	"".a+8(SP), AX
	0x000e 00014 (/home/research/go-1.16/main/main.go:4)	ADDQ	"".b+16(SP), AX
	0x0013 00019 (/home/research/go-1.16/main/main.go:4)	MOVQ	AX, "".~r2+24(SP)
	0x0018 00024 (/home/research/go-1.16/main/main.go:4)	RET
# main.main
"".main STEXT size=87 args=0x0 locals=0x28 funcid=0x0
	0x000f 00015 (/home/research/go-1.16/main/main.go:7)	SUBQ	$40, SP
	0x0013 00019 (/home/research/go-1.16/main/main.go:7)	MOVQ	BP, 32(SP)
	0x0018 00024 (/home/research/go-1.16/main/main.go:7)	LEAQ	32(SP), BP
	0x001d 00029 (/home/research/go-1.16/main/main.go:8)	MOVQ	$3, (SP)
	0x0025 00037 (/home/research/go-1.16/main/main.go:8)	MOVQ	$7, 8(SP)
	0x002e 00046 (/home/research/go-1.16/main/main.go:8)	CALL	"".function(SB)
	0x0033 00051 (/home/research/go-1.16/main/main.go:8)	MOVQ	16(SP), AX
	0x0038 00056 (/home/research/go-1.16/main/main.go:8)	MOVQ	AX, "".ret+24(SP)
	0x003d 00061 (/home/research/go-1.16/main/main.go:11)	ADDQ	$2, AX
	0x0041 00065 (/home/research/go-1.16/main/main.go:11)	MOVQ	AX, "".ret+24(SP)
	0x0046 00070 (/home/research/go-1.16/main/main.go:12)	MOVQ	32(SP), BP
	0x004b 00075 (/home/research/go-1.16/main/main.go:12)	ADDQ	$40, SP
	0x004f 00079 (/home/research/go-1.16/main/main.go:12)	RET
```
먼저 1.16버전입니다. main함수를 보면 SP(stack pointer)를 40만큼 빼고 SP+32에 main함수를 호출하기 이전의 함수가 가진 BP(base pointer)를 메모리에 넣습니다. 그리고 32(SP)의 주소값을 BP(base pointer)에 대입하여 BP가 현재 함수의 스택을 가리키게 됩니다. 이는 1.16버전의 함수 프롤로그 방식이며 1.22는 기존의 amd64 또는 x86과 유사한 방식을 사용합니다. 

1.16버전은 인자 패싱때 레지스터를 사용하지 않습니다. 그렇기에 $3과 $7을 각 각 SP와 8(SP)에 대입하는 것을 알 수 있습니다. (현재 스택의 최상단)

각 유사 레지스터의 역할은 아래와 같습니다. 
```bash
FP: Frame pointer: 인자와 지역(변수)(arguments and locals).
PC: Program counter: 점프와 분기(jumps and branches).
SB: Static base pointer: 정적 기본 포인터와 기호(global symbols).
SP: Stack pointer: 스택의 맨 위(top of stack).

출처 : https://cppis.github.io/golang%20common/about.golang.internals/
```

그리고 function함수를 보면 a+8(SP), b+16(SP)에 접근해서 레지스터에 넣고 더하는 것을 볼 수 있습니다. 이때 SP기반으로 0, 8 그리고 8, 16 값이 8 증가한 이유는 main.main에서 main.function함수를 call하는 과정에서 돌아갈 리턴주소를 스택에 넣었기 때문에 SP(stack pointer)의 변화가 발생했습니다. 그리고 결과값을 r2+24(SP) 즉, 스택에 저장하는 것을 알 수 있습니다.   
다시 main.main으로 돌아와 16(SP)에서 결과값을 AX 레지스터로 빼내오는 것을 확인할 수 있습니다. 그림으로 그려보면 main.function함수에서 24(SP)와 main.main에서의 16(SP)는 동일한 메모리 주소입니다. 

- 1.22
```bash
# main.function
main.function STEXT nosplit size=39 args=0x10 locals=0x10 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:3)	PUSHQ	BP
	0x0001 00001 (/home/research/go-1.22/main/main.go:3)	MOVQ	SP, BP
	0x0004 00004 (/home/research/go-1.22/main/main.go:3)	SUBQ	$8, SP
	0x0008 00008 (/home/research/go-1.22/main/main.go:3)	MOVQ	AX, main.a+24(SP)
	0x000d 00013 (/home/research/go-1.22/main/main.go:3)	MOVQ	BX, main.b+32(SP)
	0x0012 00018 (/home/research/go-1.22/main/main.go:3)	MOVQ	$0, main.~r0(SP)
	0x001a 00026 (/home/research/go-1.22/main/main.go:4)	ADDQ	BX, AX
	0x001d 00029 (/home/research/go-1.22/main/main.go:4)	MOVQ	AX, main.~r0(SP)
	0x0021 00033 (/home/research/go-1.22/main/main.go:4)	ADDQ	$8, SP
	0x0025 00037 (/home/research/go-1.22/main/main.go:4)	POPQ	BP
	0x0026 00038 (/home/research/go-1.22/main/main.go:4)	RET

# main.main 
main.main STEXT size=56 args=0x0 locals=0x20 funcid=0x0 align=0x0
	0x0006 00006 (/home/research/go-1.22/main/main.go:7)	PUSHQ	BP
	0x0007 00007 (/home/research/go-1.22/main/main.go:7)	MOVQ	SP, BP
	0x000a 00010 (/home/research/go-1.22/main/main.go:7)	SUBQ	$24, SP
	0x000e 00014 (/home/research/go-1.22/main/main.go:8)	MOVL	$3, AX
	0x0013 00019 (/home/research/go-1.22/main/main.go:8)	MOVL	$7, BX
	0x0018 00024 (/home/research/go-1.22/main/main.go:8)	CALL	main.function(SB)
	0x001d 00029 (/home/research/go-1.22/main/main.go:8)	MOVQ	AX, main.ret+16(SP)
	0x0022 00034 (/home/research/go-1.22/main/main.go:11)	LEAQ	2(AX), CX
	0x0026 00038 (/home/research/go-1.22/main/main.go:11)	MOVQ	CX, main.ret+16(SP)
	0x002b 00043 (/home/research/go-1.22/main/main.go:12)	ADDQ	$24, SP
	0x002f 00047 (/home/research/go-1.22/main/main.go:12)	POPQ	BP
	0x0030 00048 (/home/research/go-1.22/main/main.go:12)	RET
```
다음은 1.22버전입니다. main.main을 보았을 때 $3, $7을 스택이 아닌 레지스터로 넘기는 것을 확인할 수 있습니다. main.function에서는 레지스터끼리 계산후 결과값 또한 AX 레지스터에 넘기는 것을 확인할 수 있습니다. 다시 main.main으로 돌아와 AX(결과값)을 main.ret+16(SP)에 넣습니다.->(지역변수) 그리고 LEA 명령어로 AX의 주소에 +2를 한 값을 CX 레지스터에 넣습니다. 그리고 이를 다시 스택공간에 저장합니다. 이렇게 main.main이 끝이 납니다. 

여기서 궁금한 것이 생길 수 있습니다. 일반적으로 레지스터에 특정 값을 더하는 명령어는 ADD인데 LEA를 사용한 이유가 무엇인가.. 이는 속도 때문이거 같습니다. 하지만 머신에 따라 ADD와 LEA의 속도 차이는 미묘하게 있는 차이가 있는 모양입니다. 자세한 내용은 다음 사이트에서 확인해주세요.  
 [LEA or ADD Instruction](https://stackoverflow.com/questions/6323027/lea-or-add-instruction) 

#### function(p Person) Person
이전 예제는 조금 기본적이 예제였습니다. 이번에는 구조체를 이용하여 조금 복잡한 인수를 넘겨보겠습니다.
```go
package main

type Person struct{
	arr [3]int
	name string
	age int
}

func function(p Person) Person {
	p.age += 3
	return p
}

func main(){
	p := Person{arr: [3]int{1,2,3}, name: "tuuna", age: 7}
	ret := function(p)

	// ret 변수를 사용하여 컴파일 에러를 발생 X
	ret.age += 2
}
```
```bash
go build -gcflags '-S -N -l'
```

다음과 같이 구조체를 넘깁니다. 이 또한 지금 중요하지 않은 어셈블리 코드는 처내겠습니다.

- 1.16
```bash
# main.function
	0x0012 00018 (/home/research/go-1.16/main/main.go:10)	ADDQ	$3, "".p+48(SP)
	0x0036 00054 (/home/research/go-1.16/main/main.go:11)	RET
    
# main.main 
	0x0018 00024 (/home/research/go-1.16/main/main.go:14)	SUBQ	$200, SP
	0x001f 00031 (/home/research/go-1.16/main/main.go:14)	MOVQ	BP, 192(SP)
	0x0027 00039 (/home/research/go-1.16/main/main.go:14)	LEAQ	192(SP), BP
	0x004a 00074 (/home/research/go-1.16/main/main.go:15)	MOVQ	$1, "".p+144(SP)
	0x0056 00086 (/home/research/go-1.16/main/main.go:15)	MOVQ	$2, "".p+152(SP)
	0x0062 00098 (/home/research/go-1.16/main/main.go:15)	MOVQ	$3, "".p+160(SP)
	0x006e 00110 (/home/research/go-1.16/main/main.go:15)	LEAQ	go.string."tuuna"(SB), AX
	0x0075 00117 (/home/research/go-1.16/main/main.go:15)	MOVQ	AX, "".p+168(SP)
	0x007d 00125 (/home/research/go-1.16/main/main.go:15)	MOVQ	$5, "".p+176(SP) # string len
	0x0089 00137 (/home/research/go-1.16/main/main.go:15)	MOVQ	$7, "".p+184(SP)
	0x00c0 00192 (/home/research/go-1.16/main/main.go:16)	CALL	"".function(SB)
	0x00e6 00230 (/home/research/go-1.16/main/main.go:19)	ADDQ	$2, "".ret+136(SP)
	0x00ef 00239 (/home/research/go-1.16/main/main.go:20)	MOVQ	192(SP), BP
	0x00f7 00247 (/home/research/go-1.16/main/main.go:20)	ADDQ	$200, SP
	0x00fe 00254 (/home/research/go-1.16/main/main.go:20)	RET
```

- 1.22
```bash 
# main.function
	0x0012 00018 (/home/research/go-1.22/main/main.go:10)	ADDQ	$3, main.p+48(SP)
	0x0036 00054 (/home/research/go-1.22/main/main.go:11)	RET

# main.main 
	0x000f 00015 (/home/research/go-1.22/main/main.go:14)	PUSHQ	BP
	0x0010 00016 (/home/research/go-1.22/main/main.go:14)	MOVQ	SP, BP
	0x0013 00019 (/home/research/go-1.22/main/main.go:14)	SUBQ	$192, SP
	0x0035 00053 (/home/research/go-1.22/main/main.go:15)	MOVQ	$1, main.p+144(SP)
	0x0041 00065 (/home/research/go-1.22/main/main.go:15)	MOVQ	$2, main.p+152(SP)
	0x004d 00077 (/home/research/go-1.22/main/main.go:15)	MOVQ	$3, main.p+160(SP)
	0x0059 00089 (/home/research/go-1.22/main/main.go:15)	LEAQ	go:string."tuuna"(SB), AX
	0x0060 00096 (/home/research/go-1.22/main/main.go:15)	MOVQ	AX, main.p+168(SP)
	0x0068 00104 (/home/research/go-1.22/main/main.go:15)	MOVQ	$5, main.p+176(SP) # string len
	0x0074 00116 (/home/research/go-1.22/main/main.go:15)	MOVQ	$7, main.p+184(SP)
	0x00a6 00166 (/home/research/go-1.22/main/main.go:16)	CALL	main.function(SB)

	0x00cc 00204 (/home/research/go-1.22/main/main.go:19)	MOVQ	main.ret+136(SP), AX
	0x00d4 00212 (/home/research/go-1.22/main/main.go:19)	ADDQ	$2, AX
	0x00d8 00216 (/home/research/go-1.22/main/main.go:19)	MOVQ	AX, main.ret+136(SP)
	0x00e0 00224 (/home/research/go-1.22/main/main.go:20)	ADDQ	$192, SP
	0x00e7 00231 (/home/research/go-1.22/main/main.go:20)	POPQ	BP
	0x00e8 00232 (/home/research/go-1.22/main/main.go:20)	RET
```
1.16버전과 1.22버전을 서로 비교했을 때 약간의 차이가 있다면 함수의 프롤로그를 설정하는 부분만 제외한다면 똑같이 스택에 값을 넘기는 것을 확인할 수 있습니다. 마지막으로 아래 코드는 어떤가요? 

```go
package main

func function(q,w,e,r,t,y,u,i,o,p,a,s,d,f,g,h,j,k,l,z int) int {
	return q
}

func main(){
	ret := function(1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7,8,9,1,2)
	ret += 2
}
```

```bash
# main.main
	0x001a 00026 (/home/research/go-1.22/main/main.go:8)	MOVQ	$1, (SP)
	0x0022 00034 (/home/research/go-1.22/main/main.go:8)	MOVQ	$2, 8(SP)
	0x002b 00043 (/home/research/go-1.22/main/main.go:8)	MOVQ	$3, 16(SP)
	0x0034 00052 (/home/research/go-1.22/main/main.go:8)	MOVQ	$4, 24(SP)
	0x003d 00061 (/home/research/go-1.22/main/main.go:8)	MOVQ	$5, 32(SP)
	0x0046 00070 (/home/research/go-1.22/main/main.go:8)	MOVQ	$6, 40(SP)
	0x004f 00079 (/home/research/go-1.22/main/main.go:8)	MOVQ	$7, 48(SP)
	0x0058 00088 (/home/research/go-1.22/main/main.go:8)	MOVQ	$8, 56(SP)
	0x0061 00097 (/home/research/go-1.22/main/main.go:8)	MOVQ	$9, 64(SP)
	0x006a 00106 (/home/research/go-1.22/main/main.go:8)	MOVQ	$1, 72(SP)
	0x0073 00115 (/home/research/go-1.22/main/main.go:8)	MOVQ	$2, 80(SP)
	0x007c 00124 (/home/research/go-1.22/main/main.go:8)	MOVL	$1, AX
	0x0081 00129 (/home/research/go-1.22/main/main.go:8)	MOVL	$2, BX
	0x0086 00134 (/home/research/go-1.22/main/main.go:8)	MOVL	$3, CX
	0x008b 00139 (/home/research/go-1.22/main/main.go:8)	MOVL	$4, DI
	0x0090 00144 (/home/research/go-1.22/main/main.go:8)	MOVL	$5, SI
	0x0095 00149 (/home/research/go-1.22/main/main.go:8)	MOVL	$6, R8
	0x009b 00155 (/home/research/go-1.22/main/main.go:8)	MOVL	$7, R9
	0x00a1 00161 (/home/research/go-1.22/main/main.go:8)	MOVL	$8, R10
	0x00a7 00167 (/home/research/go-1.22/main/main.go:8)	MOVL	$9, R11
```
인자가 너무 많아 모든 레지스터에 담아도 부족한 상태입니다. 그렇기에 스택에도 인자를 넣고 있습니다. 그렇다면 언제 스택을 쓰고 언제 레지스터를 쓰는 것일까 한번 알아보도록 하겠습니다. 다만 그전에 잠시 go 자료형의 크기 및 오프셋 구하기 등의 내용을 살펴보고 넘어가겠습니다. 최종목표인 bpf로부터 인자 파싱하려면 아래 내용을 필수로 알고 가야합니다.

#### go 자료형 크기 정의 나열
```bash
Type	                    64-bit		    32-bit	
                        Size    Align   Size    Align
bool, uint8, int8	     1	     1	     1	     1
uint16, int16	         2	     2	     2	     2
uint32, int32	         4	     4	     4	     4
uint64, int64	         8	     8	     8	     4
int, uint	             8	     8	     4	     4
float32	                 4	     4	     4	     4
float64	                 8	     8	     8	     4
complex64	             8	     4	     8	     4
complex128	             16	     8	     16  	 4
uintptr, *T, unsafe.Pointer	8	 8	     4	     4 
```
- [N]TT와 같은 배열의 경우 타입 TT가 N개 있는 크기입니다.
- 문자열의 경우 *[len]byte pointer의 연속입니다. len(int) + unsafe.Pointer
- Slice의 []T는 *[cap]T pointer의 연속입니다. 
- 구조체의 경우 순서대로 크기를 계산하지만 8바이트 정렬을 기본으로 합니다. 
```
The padding byte prevents creating a past-the-end pointer by taking the address of the final, empty fN field.
```

### 구조체 나열 팁
위에서 go 언어에서 쓰이는 자료형의 크기를 보았습니다. 그럼 구조체에 적용해보겠습니다. 아래 2개의 코드가 어떤 크기를 가지는지 확인해보세요.  
크기확인은 unsafe 패키지의 Sizeof 함수를 사용하면 됩니다. 
```go
type Person struct{
    a bool
    name string 
    b bool
}
```
```bash
$ ./main 
$ sizeof: 32 byte
```

```go
type Person struct{
    a bool
    b bool
    name string
}
```
```bash
$ ./main
$ sizeof : 24 byte
```
같은 멤버필드여도 8바이트나 차이나느 것을 확인할 수 있습니다. 이는 구조체를 x64 아키텍쳐면 8바이트단위로 맞추기위해 패딩을 넣는 작업을 진행합니다. 전자의 경우 1+7, 16, 1+7이 되어서 32바이트가 정렬됩니다. 반면 후자는 2+6 + 16이 되어 24바이트가 정렬됩니다. 문자열이 16바이트인 이유는 문자열 내부는 문자열의 길이 int와 문자열 포인터를 가리키는 8바이트로 이루어져 있습니다. x64에서 포인터는 항상 8바이트이니까요.
```quote
A struct type struct { f1 t1; ...; fM tM } is laid out as the sequence t1, ..., tM, tP, where tP is either:
```

### 구조체 오프셋 구하기
마지막으로 인자 파싱전에 각 구조체의 멤버 필드들이 구조체 시작으로부터 얼마만큼 떨어져 있는지 알아야 합니다. 위와 마찬가지로 unsafe 패킷지의 Offsetof 함수로 확인이 가능합니다. 
```go 
type Person struct{
    a bool 
    b bool
    name string
}
[...]
p := Person{} 
fmt.Println(unsafe.Offsetof(p, a))
fmt.Println(unsafe.Offsetof(p, b))
fmt.Println(unsafe.Offsetof(p, name))
```
출력값은 아래와 같습니다. 
```bash
0
1
8
```
### 함수 호출규약 알고리즘
> !CAUTION  
> 지금부터 설명할 내용은 1.17 버전 이후의 함수 호출규약입니다. 물론 개발할 때는 이런거 
> 신경안쓰고도 충분히 가능하다고 생각합니다. 해당 부분을 언급하는 이유는 소스코드 레벨이 아닌
> 기계어/어셈블리 레벨에서의 디버깅때문입니다. 어셈블리 레벨에서 디버깅을 할 때 CALl 명령어로
> 함수 호출부분을 확인할 수 있습니다. 하지만 해당 함수에 어떤 인자값이 들어있는지는 go 언어가
> 인자를 어떻게 넣는지 알아야 알 수 있습니다.

go 언어에서 정의하기를 함수 호출 과정에서 필요한 인자와 호출이 끝나 반환하는 값은 아래 알고리즘을 기반으로 레지스터와 스택공간을 사용합니다.

1. NI와 NFP를 준비합니다. NI는 정수 레지스터 시퀀스의 길이이고 NFP는 부동 소수점 레지스터 시퀀스 길이로 설정합니다. 그리고 I와 FP는 시퀀시의 인덱스입니다. 스택 프레임의 시퀀스를 정의하는 S를 두고 비웁니다.

2. F가 메서드라면 F의 리시버를 지정한다. 

3. F의 각 인수 A에 대해 A를 할당합니다. (레지스터 or 스택) 레지스터에 할당한다면 I값 또는 FP값을 증가시킵니다. 만약 I 또는 FP값이 NI 또는 NFP값을 넘는다면 인수는 레지스터가 아닌 스택에 저장됩니다. 
- 포인터 정렬필드를 추가합니다. 

4. I와 FP를 0으로 재설정합니다.

5. F의 각 결과 값 R을 할당합니다. (레지스터 or 스택) 레지스터에 할당한다면 I값 또는 FP값을 증가시킵니다. 만약 I 또는 FP값이 NI 또는 NFP값을 넘는다면 인수는 레지스터가 아닌 스택에 저장됩니다. 

- 포인터 정렬필드를 추가합니다. 

6. F읜 인자를 할당했을 때 레지스터에 할당한 인수들에 대한 유형을 T로 둡니다. 그리고 T를 스택 시퀀스 S에 추가합니다. 이는 spill space(shadow space)이며 호출 시 초기화 되지 않습니다. 

- 포인터 정렬필드를 추가합니다.

위와 기본적인 알고리즘입니다. 약간의 의문이 생길 수 있습니다. 기본 타입에 해당하는 T에 해당하는 배열, 구조체, 인터페이스, 컴플렉스는 어떻게 레지스터에 넣으라는 것일까요? Go 언어에 따르면 아래 규칙에 의해 레지스터에 값이 할당됩니다. 

- T가 정수 레지스터에 맞는 부울 또는 정수 타입인 경우 레지스터 I에 V를 할당하고 I를 증가시킵니다. 

- T가 두 개의 정수 레지스터에 맞는 정수 타입인 경우 V의 최하위 및 최상위 절반을 각 각 레지스터 I 및 I+1에 할당하고 I를 2만큼 증가시킵니다. 

- T가 부동 소수점 타입이라면 값 V를 레지스터 FP에 넣고 FP값을 1증가 합니다. 

- T가 Complex 타입인 경우 실수 및 허수 부분을 재귀적으로 레지스터에 할당합니다. 

- T가 포인터, 맵, 채널, 함수 타입인 경우 값 V를 레지스터 I에 할당하고 I를 증가시킵니다. 

- T가 문자열, 인터페이스, 슬라이스 타입인 경우 값 V의 구성요소를 재귀적으로 맞는 레지스터에 할당합니다. (문자열의 경우 길이와 포인터, 인터페이스의 경우 타입과 포인터 즉 2개로 이루어져 있습니다. 슬라이스는 3개로 이루어져 있습니다. )

- T가 구조체 타입인 경우 값 V의 각 필드를 재귀적으로 할당합니다. 

- T의 길이가 0인 배열 타입의 경우 아무런 작업을 수행하지 않습니다. 

- T의 길이가 1이상인 배열 타입의 경우 레지스터 할당을 실패합니다. 바로 스택에 할당합니다. 
(구조체에 배열이 포함된 경우도 같습니다. 구조체 전체가 스택에 할당됩니다.)

- 아까 언급한 I와 FP가 각 각 NI, NFP보다 크다면 레지스터 할당을 실패합니다. 스택에 할당됩니다. 

- 위에서 언급한 재귀할당이 실패하면 스택행입니다. 

위의 규칙을 기반으로 하나의 예시 코드를 보겠습니다 
```go
package main

func function(a1 uint8, a2 [2]int, a3 uint8) (r1 struct { x int; y [2]int }, r2 string){
	r1.x = 9
	r1.y = [2]int{5, 7}
	r2 = "tuuna"
	return r1, r2
}

func main(){
	ret1, ret2 := function(uint8(3), [2]int{1,3}, uint8(5))
	ret1.x += 2
	ret2 += "H"
}
```
function함수는 3개의 인수를 받고 2개의 결과값을 가집니다.  

먼저 인수를 보겠습니다. `a1 uint8`과 `a3 uint8`은 레지스터에 할당됩니다. `a2 [2]int`은 배열이기 때문에 레지스터에 할당되지 않습니다. 스택에 할당됩니다. 리턴값을 살펴보겠습니다. r1 구조체를 보면 `y [2]int`이라는 배열이 존재합니다. 그렇기에 구조체의 모든 필드는 스택에 할당됩니다. 그리고 r2 string은 레지스터에 할당됩니다. 이 때 할당될 때 string type은 2개의 구성요소로 이루어져있습니다.(길이, 포인터) 각 각을 레지스터 할당합니다. 한번 어셈블리코드를 보겠습니다.
```bash
main.function STEXT nosplit size=43 args=0x30 locals=0x18 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:3)	PUSHQ	BP
	0x0001 00001 (/home/research/go-1.22/main/main.go:3)	MOVQ	SP, BP
	0x0004 00004 (/home/research/go-1.22/main/main.go:3)	SUBQ	$16, SP
	0x0008 00008 (/home/research/go-1.22/main/main.go:3)	MOVB	AL, main.a1+72(SP)
	0x000c 00012 (/home/research/go-1.22/main/main.go:3)	MOVB	BL, main.a3+73(SP)
	0x0021 00033 (/home/research/go-1.22/main/main.go:4)	MOVQ	$9, main.r1+48(SP)
	0x002a 00042 (/home/research/go-1.22/main/main.go:5)	MOVQ	$5, main.r1+56(SP)
	0x0033 00051 (/home/research/go-1.22/main/main.go:5)	MOVQ	$7, main.r1+64(SP)
	0x003c 00060 (/home/research/go-1.22/main/main.go:6)	LEAQ	go:string."tuuna"(SB), AX
	0x0043 00067 (/home/research/go-1.22/main/main.go:6)	MOVQ	AX, main.r2(SP)
	0x0047 00071 (/home/research/go-1.22/main/main.go:6)	MOVQ	$5, main.r2+8(SP)
	0x0050 00080 (/home/research/go-1.22/main/main.go:7)	MOVL	$5, BX
	0x0055 00085 (/home/research/go-1.22/main/main.go:7)	ADDQ	$16, SP
	0x0059 00089 (/home/research/go-1.22/main/main.go:7)	POPQ	BP
	0x005a 00090 (/home/research/go-1.22/main/main.go:7)	RET

main.main STEXT size=266 args=0x0 locals=0xb0 funcid=0x0 align=0x0
	0x000f 00015 (/home/research/go-1.22/main/main.go:7)	PUSHQ	BP
	0x0010 00016 (/home/research/go-1.22/main/main.go:7)	MOVQ	SP, BP
	0x0013 00019 (/home/research/go-1.22/main/main.go:7)	SUBQ	$168, SP
	0x001a 00026 (/home/research/go-1.22/main/main.go:8)	MOVUPS	X15, main..autotmp_5+136(SP)
	0x0023 00035 (/home/research/go-1.22/main/main.go:8)	MOVQ	$1, (SP)
	0x002b 00043 (/home/research/go-1.22/main/main.go:8)	MOVQ	$3, 8(SP)
	0x0034 00052 (/home/research/go-1.22/main/main.go:8)	MOVL	$3, AX
	0x0039 00057 (/home/research/go-1.22/main/main.go:8)	MOVL	$5, BX
	0x0040 00064 (/home/research/go-1.22/main/main.go:8)	CALL	main.function(SB)
[...]
	0x00f4 00244 (/home/research/go-1.22/main/main.go:11)	ADDQ	$168, SP
	0x00fb 00251 (/home/research/go-1.22/main/main.go:11)	POPQ	BP
```
제시된 어셈블리코드에서 지금 당장 필요하지 않은 부분은 다 쳐냈습니다. main.main을 보겠습니다. `a1 int8`와 `a3 int8`은 각 각 레지스터 AX, BX에 들어가는 것을 볼 수 있습니다.
```bash
0x0034 00052 (/home/research/go-1.22/main/main.go:8)	MOVL	$3, AX
0x0039 00057 (/home/research/go-1.22/main/main.go:8)	MOVL	$5, BX
```

그리고 `a2 [2]int`배열 타입은 각 각 스택에 들어가는 것을 볼 수 있습니다. 
```bash
0x0023 00035 (/home/research/go-1.22/main/main.go:8)	MOVQ	$1, (SP)
0x002b 00043 (/home/research/go-1.22/main/main.go:8)	MOVQ	$3, 8(SP)
```

반환값을 살펴보겠습니다. 
```bash
0x0021 00033 (/home/research/go-1.22/main/main.go:4)	MOVQ	$9, main.r1+48(SP)
0x002a 00042 (/home/research/go-1.22/main/main.go:5)	MOVQ	$5, main.r1+56(SP)
0x0033 00051 (/home/research/go-1.22/main/main.go:5)	MOVQ	$7, main.r1+64(SP)
```
반환값 `r1 struct { x int; y [2]int }`는 구조체 내부에 배열이 있습니다. 그렇기에 구조체 구성요소 모두 재귀적으로 스탹에 할당되게 됩니다. 

```bash
0x003c 00060 (/home/research/go-1.22/main/main.go:6)	LEAQ	go:string."tuuna"(SB), AX
0x0047 00071 (/home/research/go-1.22/main/main.go:6)	MOVQ	$5, main.r2+8(SP)
0x0050 00080 (/home/research/go-1.22/main/main.go:7)	MOVL	$5, BX
```
`r2 string`은 재귀적으로 레지스터에 할당됩니다. string 타입의 구성요소는 문자열 포인터와 길이 즉, 2개의 구성요소로 이루어져 있습니다. 그렇기에 문자열 포인터는 AX레지스터, 길이 값은 BX레지스터에 값이 설정됩니다. 

### amd64 아키텍처의 레지스터 역할

- amd64 아키텍쳐의 경우 아래 레지스터를 사용합니다. 이 레지스터는 인수로 사용될 수 있고 결과값으로 사용될 수 있습니다.
```bash
RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11
```
부동소수점의 경우 X0 ~ X14까지 사용됩니다. 추가적으로 레지스터의 의미는 다음과 같습니다. 
```bash

Register	Call meaning	        Return meaning	    Body meaning
RSP	        Stack pointer	        Same	            Same
RBP	        Frame pointer	        Same	            Same
RDX	        Closure context pointer	Scratch	            Scratch
R12	        Scratch	                Scratch	            Scratch
R13	        Scratch	                Scratch	            Scratch
R14	        Current goroutine	    Same	            Same
R15	        GOT reference temporary if dynlink	Same	Same
X15	        Zero value (*)	        Same	            Scratch
```

### Spill Space? Shadow Space!
함수 호출규약을 설명하면서 spill space에 대해 여러번 언급하였습니다. spill space의 다른말로는 shadow space라고 불립니다. 이 단어가 좀 더 익숙하실겁니다. spill space는 주로 최적화 되지 않은 상황에서 인수가 레지스터에 넘길때 스택에도 값을 넣음으로써 디버깅 측면에서 좀 더 편하게 하기 위해서 입니다. go언어에서 최적화되지 않았을 때와 최적회 되었을 때의 인자 호출 Go Assembly를 보여드리겠습니다. 또한, spill space(shadow space)에 대한 설명은 다음 글을 참고해주세요.  
[What is the 'shadow space' in x64 assembly?](https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly)

- 코드 
```go
package main

func good(a, b, c int) int {
	return a + b + c
}

func test(a, b int) int{
	return a + b
}

func main(){
	ret := test(3, 5)
	ret += 2
	ret = good(7, 9, 11)
	ret += 3
}
```

```bash
# 최적화 비활성화
go build -gcflags '-S -N -l' 

# 최적화 활성화
go build -gcflags '-S -l'
```

- 최적화 X 
```bash
main.good STEXT nosplit size=49 args=0x18 locals=0x10 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:3)	PUSHQ	BP
	0x0001 00001 (/home/research/go-1.22/main/main.go:3)	MOVQ	SP, BP
	0x0004 00004 (/home/research/go-1.22/main/main.go:3)	SUBQ	$8, SP
	0x0008 00008 (/home/research/go-1.22/main/main.go:3)	MOVQ	AX, main.a+24(SP)
	0x000d 00013 (/home/research/go-1.22/main/main.go:3)	MOVQ	BX, main.b+32(SP)
	0x0012 00018 (/home/research/go-1.22/main/main.go:3)	MOVQ	CX, main.c+40(SP)
	0x0017 00023 (/home/research/go-1.22/main/main.go:3)	MOVQ	$0, main.~r0(SP)
	0x001f 00031 (/home/research/go-1.22/main/main.go:4)	LEAQ	(AX)(BX*1), DX
	0x0023 00035 (/home/research/go-1.22/main/main.go:4)	LEAQ	(DX)(CX*1), AX
	0x0027 00039 (/home/research/go-1.22/main/main.go:4)	MOVQ	AX, main.~r0(SP)
	0x002b 00043 (/home/research/go-1.22/main/main.go:4)	ADDQ	$8, SP
	0x002f 00047 (/home/research/go-1.22/main/main.go:4)	POPQ	BP
	0x0030 00048 (/home/research/go-1.22/main/main.go:4)	RET
                                             .
main.test STEXT nosplit size=39 args=0x10 locals=0x10 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:7)	PUSHQ	BP
	0x0001 00001 (/home/research/go-1.22/main/main.go:7)	MOVQ	SP, BP
	0x0004 00004 (/home/research/go-1.22/main/main.go:7)	SUBQ	$8, SP
	0x0008 00008 (/home/research/go-1.22/main/main.go:7)	MOVQ	AX, main.a+24(SP)
	0x000d 00013 (/home/research/go-1.22/main/main.go:7)	MOVQ	BX, main.b+32(SP)
	0x0012 00018 (/home/research/go-1.22/main/main.go:7)	MOVQ	$0, main.~r0(SP)
	0x001a 00026 (/home/research/go-1.22/main/main.go:8)	ADDQ	BX, AX
	0x001d 00029 (/home/research/go-1.22/main/main.go:8)	MOVQ	AX, main.~r0(SP)
	0x0021 00033 (/home/research/go-1.22/main/main.go:8)	ADDQ	$8, SP
	0x0025 00037 (/home/research/go-1.22/main/main.go:8)	POPQ	BP
	0x0026 00038 (/home/research/go-1.22/main/main.go:8)	RET

main.main STEXT size=90 args=0x0 locals=0x28 funcid=0x0 align=0x0
	0x0006 00006 (/home/research/go-1.22/main/main.go:11)	PUSHQ	BP
	0x0007 00007 (/home/research/go-1.22/main/main.go:11)	MOVQ	SP, BP
	0x000a 00010 (/home/research/go-1.22/main/main.go:11)	SUBQ	$32, SP
	0x000e 00014 (/home/research/go-1.22/main/main.go:12)	MOVL	$3, AX
	0x0013 00019 (/home/research/go-1.22/main/main.go:12)	MOVL	$5, BX
	0x0018 00024 (/home/research/go-1.22/main/main.go:12)	PCDATA	$1, $0
	0x0018 00024 (/home/research/go-1.22/main/main.go:12)	CALL	main.test(SB)
	0x001d 00029 (/home/research/go-1.22/main/main.go:12)	MOVQ	AX, main.ret+24(SP)
	0x0022 00034 (/home/research/go-1.22/main/main.go:13)	LEAQ	2(AX), CX
	0x0026 00038 (/home/research/go-1.22/main/main.go:13)	MOVQ	CX, main.ret+24(SP)
	0x002b 00043 (/home/research/go-1.22/main/main.go:14)	MOVL	$7, AX
	0x0030 00048 (/home/research/go-1.22/main/main.go:14)	MOVL	$9, BX
	0x0035 00053 (/home/research/go-1.22/main/main.go:14)	MOVL	$11, CX
	0x003a 00058 (/home/research/go-1.22/main/main.go:14)	CALL	main.good(SB)
	0x003f 00063 (/home/research/go-1.22/main/main.go:14)	MOVQ	AX, main.ret+24(SP)
	0x0044 00068 (/home/research/go-1.22/main/main.go:15)	LEAQ	3(AX), CX
	0x0048 00072 (/home/research/go-1.22/main/main.go:15)	MOVQ	CX, main.ret+24(SP)
	0x004d 00077 (/home/research/go-1.22/main/main.go:16)	ADDQ	$32, SP
	0x0051 00081 (/home/research/go-1.22/main/main.go:16)	POPQ	BP
	0x0052 00082 (/home/research/go-1.22/main/main.go:16)	RET
```
최적화를 껐을 때입니다. 각 함수 good함수와 test함수를 호출하기 위해서 register에 인수값을 넣습니다. 하지만 호출자(caller)는 인수를 레지스터에 넣음에도 불구하고 인수의 크기만큼 공간을 할당하는 것을 볼 수 있습니다. `SUBQ $32, SP` 그리고 각 함수 test와 good함수에서 해당 공간에 인수값을 넣는 것을 볼 수 있습니다. 호출자는 공간을 예약만 할 뿐 채우지는 않습니다. 
```bash
the caller also reserves spill space on the stack for all register-based arguments (but does not populate this space).
```
메모리 그림을 종이에 그려보면 해당 함수가 끝나고 돌아갈 주소가 담긴 메모리 밑에 쓰이게 됩니다. (여기서 밑은 높은 주소를 의미합니다. ) 즉, x86, x64에서 사용하는 매개변수가 위치하는 공간과 일치합니다. 편한 BP나 FP를 두고 유동적인 SP를 사용하는 이유에 대해서는 아직 잘 모르겠네요. rsp 상대 주소 지정 방식을 사용하면 rbp 백업 및 복구 과정이 필요없어져서 효율적인것은 맞으나 백업 및 복구 과정을 하는 코드가 있는 것을 볼 수 있습니다... 이는 후에 분석해보도록 하겠습니다. 
spill space(shadow space)를 사용하면 좋은점이 디버깅시에 스택을 출력할 때 함수의 인자를 손쉽게 볼 수 있다는 점입니다.

- 최적화 O 
```bash
main.good STEXT nosplit size=9 args=0x18 locals=0x0 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:4)	LEAQ	(BX)(AX*1), DX
	0x0004 00004 (/home/research/go-1.22/main/main.go:4)	LEAQ	(CX)(DX*1), AX
	0x0008 00008 (/home/research/go-1.22/main/main.go:4)	RET

main.test STEXT nosplit size=4 args=0x10 locals=0x0 funcid=0x0 align=0x0
	0x0000 00000 (/home/research/go-1.22/main/main.go:8)	ADDQ	BX, AX
	0x0003 00003 (/home/research/go-1.22/main/main.go:8)	RET

main.main STEXT size=62 args=0x0 locals=0x20 funcid=0x0 align=0x0
	0x0006 00006 (/home/research/go-1.22/main/main.go:11)	PUSHQ	BP
	0x0007 00007 (/home/research/go-1.22/main/main.go:11)	MOVQ	SP, BP
	0x000a 00010 (/home/research/go-1.22/main/main.go:11)	SUBQ	$24, SP
	0x000e 00014 (/home/research/go-1.22/main/main.go:12)	MOVL	$3, AX
	0x0013 00019 (/home/research/go-1.22/main/main.go:12)	MOVL	$5, BX
	0x0018 00024 (/home/research/go-1.22/main/main.go:12)	PCDATA	$1, $0
	0x0018 00024 (/home/research/go-1.22/main/main.go:12)	CALL	main.test(SB)
	0x001d 00029 (/home/research/go-1.22/main/main.go:14)	MOVL	$7, AX
	0x0022 00034 (/home/research/go-1.22/main/main.go:14)	MOVL	$9, BX
	0x0027 00039 (/home/research/go-1.22/main/main.go:14)	MOVL	$11, CX
	0x002c 00044 (/home/research/go-1.22/main/main.go:14)	CALL	main.good(SB)
	0x0031 00049 (/home/research/go-1.22/main/main.go:16)	ADDQ	$24, SP
	0x0035 00053 (/home/research/go-1.22/main/main.go:16)	POPQ	BP
	0x0036 00054 (/home/research/go-1.22/main/main.go:16)	RET
```
최적화를 켰을 때는 spill space(shadow space)를 볼 수 없습니다. 그냥 good함수와 test함수가 반환하는 값(AX Register)을 ret 지역변수가 위치하는 곳(SP)에 AX 레지스터를 넣습니다. 앞서 설명했듯이 함수간에 레지스터는 공유할 수 있지만 스택은 공유하지 않습니다.  

### 레지스터 기반 인자 파싱 - bpftrace
우리는 인자파싱에 필요한 모든 것을 학습했습니다. 이제 진짜 eBPF를 이용해서 인자 파싱을 진행하겠습니다. 진행에 앞서 실습코드로 bpftrace를 사용할것입니다. bpftrace의 사용법은 아래 링크를 확인해주세요. [bpftrace tutorial](https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md)

```go
package main

import (
	"fmt"
	"time"
)

func function(a, b int) int {
	return a + b
}

func main(){
	for i:=0;i<1000;i++ {
		ret := function(i, i+1)
		fmt.Println(ret)
		time.Sleep(time.Second * 1)
	}
}
```

```bpftrace
uprobe:./main:main.function /pid == 4078607/
{
        printf("value: %d+%d\n", reg("ax"), reg("bx"));
}

uretprobe:./main:main.function /pid == 4078607/
{
        printf("return value: %d\n", reg("ax"));
}
```

```bash
user@user:~/research/go-1.22/main$ sudo bpftrace probe.bt
Attaching 2 probes...
value: 464+465
return value: 929

value: 465+466
return value: 931

value: 466+467
return value: 933

value: 467+468
return value: 935
```

### 스택 기반 인자 파싱 - bpftrace
```go
package main

import (
	"fmt"
	"time"
)

func function(a [3]int) int {
	return a[0] + a[1] + a[2]
}

func main(){
	for i:=0;i<1000;i++ {
		arg := [3]int{i, i+1, i+2}
		ret := function(arg)
		fmt.Println(ret)
		time.Sleep(time.Second * 1)
	}
}
```

```bpftrace
uprobe:./main:main.function /pid == 4079179/
{
        printf("value: %d+%d+%d\n", *(uint64*)(reg("sp")+8), *(uint64*)(reg("sp")+16), *(uint64*)(reg("sp")+24));
}

uretprobe:./main:main.function /pid == 4079179/
{
        printf("return value: %d\n", reg("ax"));
}
```

```bash
user@user:~/research/go-1.22/main$ sudo bpftrace loop.pt
Attaching 2 probes...
value: 26+27+28
return value: 81

value: 27+28+29
return value: 84

value: 28+29+30
return value: 87

value: 29+30+31
return value: 90
```

### 마무리 
amd64 기준 go 1.17부터는 함수의 인자와 결과값을 스택에만 저장하는 것이 아닌 레지스터에도 저장하는 로직이 추가되었으며 이는 이전 버전 대비 5~10%의 성능향상을 이뤄냈으며 지금까지 소개한 알고리즘을 기반으로 인자 및 결과값을 할당합니다.   

C 언어로 구성된 프로그램의 경우 bpftrace의 uprobe와 uretprobe는 잘 동작합니다. 구조체의 경우 정의하여 캐스팅하면 됩니다. 하지만 go언어 같은 경우에는 직접 어셈블리 코드를 보면서 레지스터와 스택을 기반으로 보면서 파싱을 진행해야 합니다. go 언어의 함수 호출규칙을 알고 있다면 파싱하는데 좀 더 도움이될거 같습니다. 

### 레퍼런스
- [go ABI internal](https://tip.golang.org/src/cmd/compile/abi-internal)  
- [Proposal: Create an undefined internal calling convention](https://go.googlesource.com/proposal/+/master/design/27539-internal-abi.md)  
- [cmd/compile: switch to a register-based calling convention for Go functions](https://github.com/golang/go/issues/40724)   
- [Golang Internals](https://cppis.github.io/golang%20common/about.golang.internals/)   
- [The Design of the Go Assembler](https://go.dev/talks/2016/asm.slide#1)  
- 