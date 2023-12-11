### 개론 
이전 분석글에서는 TCP 통신의 시작을 알리는 TCP 3 Way Handshake의 과정을 리눅스 커널 소스코드를 기반으로 살펴보았습니다. 이번에는 3WH가 끝난 Socket들에 대해(TCP State가 ESTABLISHED) 데이터가 입력되었을 때 데이터가 어디에 저장되며 유저 어플리케이션단에서 read함수를 호출하였을 때 어떠한 과정을 통해 저장된 데이터를 읽어나가는지 커널 소스코드를 바탕으로 알아볼것입니다. 

### 주의 
분석할 커널의 버전은 6.4.3 버전이며 컴파일 및 사전내용은 이전문서를 참고하시길 바랍니다.  
[HOW TCP 3 Way Handshake In Linux Kernel](../tcp_3wh/tcp_3wh.md)    
[accept(2) syscall internal logic](./accept_internal_logic/accept_internal_logic.md) 

### 본론
TCP 소켓이 3 Way Handshake과정을 거친 후 데이터가 도착한다면 Fast Path와 Slow Path가 존재합니다.   
작성 예정   

### 요약 
작성 예정   

### 코멘트
작성 예정

### 레퍼런스 
작성 예정   
