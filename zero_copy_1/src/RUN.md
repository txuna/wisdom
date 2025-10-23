# XDP 로드밸런서 실행
`clang`, `llvm`등은 따로 설치가 필요합니다.

### 네트워크 네임스페이스 셋업
```bash
sh script/network_setup.sh
```

### 웹서버 빌드 및 실행
```bash
cd web_server
go mod tidy && go build

sudo ip netns exec container5 ./main
sudo ip netns exec container6 ./main
```

### Stub XDP 실행
```bash
cd bpf_stub
go mod tidy && go generate && go build
sudo ./main brid4
```

### XDP 로드밸런서 실행
```bash
cd bpf_lb
go mod tidy && go generate && go build
sudo ip netns exec container4 ./main veth4
```

### 클라이언트 실행
```bash
sudo ip netns exec client1 curl 10.201.0.4:8000
```


### 정리
```bash
sh script/network_clean.sh
```