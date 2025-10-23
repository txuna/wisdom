//go:build ignore

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// #include "bpf_endian.h"
#include "common.h"
#include "xx_hash.h"

/*
	최종적으로 docker container까지 연결
*/

#define SERVER_NUM 2
#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent

#define CLIENT 1
#define SERVER 2

enum {
	ESTABLISHED = 1,
	FIN,
	START_FIN,
	END_FIN,
};

#define MAX_SESSION 40000

// TCP STATE
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */
	TCP_NEW_SYN_RECV,
	TCP_BOUND_INACTIVE, /* Pseudo-state for inet_diag */

	TCP_MAX_STATES	/* Leave at the end! */
};


char _license[] SEC("license") = "GPL";

// 10.201.0.4
int load_balancer_ip = bpf_htonl(0x0AC90004);
// de:ad:be:ef:00:04
__u8 load_balancer_mac[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};

struct server_config {
	__u32 ip;
	__u16 port;
	__u8 mac[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SERVER_NUM);
	__type(key, __u32);
	__type(value, struct server_config);
} servers SEC(".maps");

// LB에서 사용하는 source port는 30000~40000으로 제한 그 이상 요청은 XDP_DROP
struct session{
	__u32 client_ip;
	__u16 client_port;
	__u32 server_ip; 
	__u16 server_port;
	__u8 reserve;
	__u8 used; 
	__u16 lb_port;

	__u8 client_mac[ETH_ALEN];
	__u8 server_mac[ETH_ALEN];

	__u8 client_state;
	__u8 server_state;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(max_entries, MAX_SESSION);
	__type(key, __u32);
	__type(value, struct session);
} session_map SEC(".maps");

struct event {
	__u32 kind;
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	__u32 src_ip; 
	__u32 dst_ip; 
	__u16 src_port;
	__u16 dst_port;
	__u8 state;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) (((void *)PTR) + OFFSET > ((void *)END))

// get hash sip, dip 위치가 달라도 같은 hash가 나오게는 할 수 없남
static __always_inline __u32 get_hash(struct iphdr *iph, struct tcphdr *tcph) {
		struct {
		__u32 src_ip;
		__u32 dst_ip;
		__u16 src_port;
		__u16 dst_port;
	} four_tuple = {iph->saddr,
					iph->daddr,
					bpf_ntohs(tcph->source),
					bpf_ntohs(tcph->dest)
                    };

	return xxhash32((const char *)&four_tuple, sizeof(four_tuple), 0);
}

// get hash sip, dip 위치가 달라도 같은 hash가 나오게는 할 수 없남
static __always_inline __u32 get_two_hash(__u32 ip, __u16 port) {
		struct {
		__u32 ip;
		__u16 port;
	} two_tuple = {ip, bpf_ntohs(port)};

	return xxhash32((const char *)&two_tuple, sizeof(two_tuple), 0);
}


static __always_inline __u32 get_key(__u32 hash) {
	return hash % SERVER_NUM;
}

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 tcph_csum(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
	// debug
	__u32 tcp_header_len = tcph->doff * 4;
	__u32 total_len = bpf_ntohs(iph->tot_len);
	__u32 ip_header_len = (iph->ihl*4);
	__u32 payload_len = total_len - ip_header_len - tcp_header_len;

	__u32 tcp_len = tcp_header_len + payload_len; 

    // Clear checksum
    tcph->check = 0;

    // Pseudo header checksum calculation
    __u32 sum = 0;
    sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
    sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
    sum += bpf_htons(IPPROTO_TCP);
    // sum += bpf_htons((__u16)(data_end - (void *)tcph));
	sum += bpf_htons(tcp_len);

    // TCP header and payload checksum
    #pragma clang loop unroll_count(MAX_TCP_CHECK_WORDS)
    for (int i = 0; i <= MAX_TCP_CHECK_WORDS; i++) {
        __u16 *ptr = (__u16 *)tcph + i;
        if ((void *)ptr + 2 <= data_end){
			sum += *(__u16 *)ptr;
			continue;
		}

		// ptr + 1 == data_end 했을때는 안된 이유는?? 무조건 <=이나 >로 조건 검사해야하나 ?
		if ((void *)ptr + 1 <= data_end) {
			__u8 value = *(__u8 *)ptr;
			sum += value & bpf_htons(0xFF00);
		}

		// https://docs.kernel.org/bpf/verifier.html?utm_source=chatgpt.com#direct-packet-access
		// 해당 조건이 옳아도 bpf 검증기에서 아래 조건과 ptr 접근이 관련이 없어서 검증되지않았다고 판단하는건가? 커널 소스 분석좀 해야겠다.
		// if ((void*)ptr + 1 == data_end){
		// 	// *ptr blah blah
		// 	__u8 value = *(__u8 *)ptr;
		// 	sum += value & bpf_htons(0xFF00);
		// }

        break;
    }

	sum = ~csum_reduce_helper(sum);
	return (__u16)sum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
	if (csum <= 0) {
		bpf_printk("csum is minus");
	}
    return csum_fold_helper(csum);
}

// client & server 모두 TCP_FIN인경우
static __always_inline int is_closed(struct session *ss) {
	if(ss->client_state == FIN && ss->server_state == FIN) {
		return 1;
	}

	return 0;
}

// key: client:10.201.0.1, client:port - lb:10.201.0.4, lb:8000
static __always_inline int process_from_client(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
	__u32 hash = get_two_hash(iph->saddr, tcph->source);
	__u32 port_num = (hash % MAX_SESSION) + 10000;
	__u32 server_key = hash % SERVER_NUM;

	struct session *ss; 
	struct server_config *server;

	// 첫 연결 - 포트 여유분 확인 없다면 패킷 DROP
	if(tcph->syn) {
		ss = bpf_map_lookup_elem(&session_map, &port_num);
		// 이미 있다면 (점유로 의심)
		if(ss != NULL && ss->used) {
			// bpf_printk("[client] [0x%x:%d] already used lb port: %d, will be drop", iph->saddr, tcph->source, port_num);
			return XDP_DROP;
		}

		server = bpf_map_lookup_elem(&servers, &server_key);
		if(server == NULL) {
			return XDP_DROP;
		}

		struct session ss = {
			.client_ip = iph->saddr,
			.client_port = tcph->source,
			.server_ip = server->ip, 
			.server_port = server->port,
			.lb_port = port_num,
			.used = 1,
			.client_state = ESTABLISHED,
			.server_state = ESTABLISHED,
		};

		__builtin_memcpy(&ss.client_mac, eth->h_source, ETH_ALEN);
		__builtin_memcpy(&ss.server_mac, server->mac, ETH_ALEN);

		bpf_map_update_elem(&session_map, &port_num, &ss, BPF_NOEXIST);

		// bpf_printk("[client] [0x%x:%d] new client assigned lb port: %d and server: 0x%x:%d", iph->saddr, tcph->source, port_num, server->ip, server->port);
	}

	ss = bpf_map_lookup_elem(&session_map, &port_num);
	if (ss == NULL){
		return XDP_DROP;
	}

	// bpf_printk("[client] [0x%x:%d] redirect to 0x%x:%d, lb port: %d", ss->client_ip, ss->client_port, ss->server_ip, ss->server_port, ss->lb_port);
	
	__builtin_memcpy(eth->h_dest, ss->server_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);

	iph->saddr = load_balancer_ip;
	iph->daddr = ss->server_ip;

	/*
		단일 클라이언트가 아닌 여러개의 클라이언트 컨테이너가 존재한다고 가정했을 때
		172.17.0.2:30000, 172.17.0.3:30000 포트가 겹칠 수 있음. 물론 IP로 구별이 되겠지만 세션 정보를 포트넘버를 키로 하고 있음
		그렇기에 LB단에서 포트 배정으로 진행 (포트 배정은 곧 커넥션 추가)
		서버측에서 넘어갈때 다시 클라이언트 소스 포트로 변경 필요
	*/
	tcph->source = ss->lb_port;

	// 체크섬 계산
	iph->check = iph_csum(iph);
	tcph->check = tcph_csum(tcph, iph, data_end);

	if(tcph->rst) {
		// bpf_printk("client rst");
		goto delete;
	}

	switch(ss->client_state) {
		case ESTABLISHED:
			if(tcph->fin) {
				ss->client_state = FIN;
				goto update;
			}
			break;
		case FIN:
			if(tcph->ack) {
				if(is_closed(ss)) {
					goto delete;
				}
			}
			break;
	}

	return XDP_TX;

update:
	bpf_map_update_elem(&session_map, &port_num, ss, BPF_ANY);
	// bpf_printk("[client] [0x%x:%d] send FIN to 0x%x:%d, lb port: %d", ss->client_ip, ss->client_port, ss->server_ip, ss->server_port, ss->lb_port);
	return XDP_TX;

delete:
	bpf_map_delete_elem(&session_map, &port_num);
	// bpf_printk("[client] [0x%x:%d] close session to 0x%x:%d, lb port: %d", ss->client_ip, ss->client_port, ss->server_ip, ss->server_port, ss->lb_port);
	return XDP_TX;
}


static __always_inline int process_from_server(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
	// 서버가 설정한 목적지 포트를 키로 지정한다. 
	__u32 port_num = tcph->dest;
	
	struct session *ss = bpf_map_lookup_elem(&session_map, &port_num);
	if (ss == NULL) {
		return XDP_DROP;
	}

	// bpf_printk("[server] [0x%x:%d] redirect to 0x%x:%d, lb port: %d", ss->server_ip, ss->server_port, ss->client_ip, ss->client_port, ss->lb_port);

	__builtin_memcpy(eth->h_dest, ss->client_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, load_balancer_mac, ETH_ALEN);

	iph->saddr = load_balancer_ip;
	iph->daddr = ss->client_ip;
	tcph->dest = ss->client_port;

	// 체크섬 계산
	iph->check = iph_csum(iph);
	tcph->check = tcph_csum(tcph, iph, data_end);

	if(tcph->rst) {
		// bpf_printk("server rst!");
		goto delete;
	}

	switch(ss->server_state) {
		case ESTABLISHED:
			if(tcph->fin) {
				ss->server_state = FIN;
				goto update;
			}
			break;
		case FIN:
			if(tcph->ack){
				if(is_closed(ss)) {
					goto delete;
				}
			}
			break;
	}

	return XDP_TX;

update:
	bpf_map_update_elem(&session_map, &port_num, ss, BPF_ANY);
	// bpf_printk("[server] [0x%x:%d] send FIN to 0x%x:%d, lb port: %d", ss->server_ip, ss->server_port, ss->client_ip, ss->client_port, ss->lb_port);
	return XDP_TX;

delete:
	bpf_map_delete_elem(&session_map, &port_num);
	// bpf_printk("[server] [0x%x:%d] close session to 0x%x:%d, lb port: %d", ss->server_ip, ss->server_port, ss->client_ip, ss->client_port, ss->lb_port);
	return XDP_TX;
}

static __always_inline int process_packet(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
	if (tcph->dest == bpf_htons(8000)) {
		return process_from_client(eth, iph, tcph, data_end);
	}

	if (tcph->source == bpf_htons(8000)) {
		return process_from_server(eth, iph, tcph, data_end);
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;
	struct event *es;

	struct ethhdr *eth = data;
	if ((void*)(eth + 1) > data_end) {
		return XDP_PASS;
	}
	
	// check IPv4
	if(eth->h_proto != __constant_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// ip header
	struct iphdr *iph = (struct iphdr*)(eth + 1);
	if ((void*)(iph + 1) > data_end) {
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	// tcp header
	struct tcphdr *tcph = (void*)iph + iph->ihl * 4;
	if ((void*)tcph + sizeof(*tcph) > data_end) {
		return XDP_PASS;
	}

	return process_packet(eth, iph, tcph, data_end);
}
