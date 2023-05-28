# 패킷이 USERSPACE로 전송되는 과정

### 개론

netfilter hook에 대해서 살펴보는중 어쩌다보니 잠시 커널 소스를 조금 보게 되었는데 어쩌다보니 패킷이 네트워크 인터페이스에 도착해서 관련함수들을 콜하고 그 후 ip_rcv함수를 콜하는 것부터 udp_rcv, tcp_v4_rcv 함수를 콜하는 과정을 보게 되었는데 정리할겸 포스팅 

**(문서 참조 없이 커널 소스만 보면서 정리한것이기에 틀린것이 있을 수 있음)**

### Netfilter Hook

Netfilter Hook에는 주로 5가지의 Hook Point가 존재한다. 

1. NF_INET_PRE_ROUTING
2. NF_INET_LOCAL_IN
3. NF_INET_FORWARD
4. NF_INET_PORT_ROUTING
5. NF_INET_LOCAL_OUT

우리는 패킷이 로컬 호스트의 응용프로그램단으로 흘러가는 과정을 볼것이기에 NF_INET_PRE_ROUTING HOOK과 NF_INET_LOCAL_IN HOOK만 보면 된다. 

Ref : Linux Kernel Source Code 6.3v

net/ipv4/ip_input.c

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```

패킷이 도착되고나서 네트워킹 스택버퍼 등 관련함수들을 모두 콜하고 나서 호ip패킷을 읽기 시작하는 함수이다. 

관심가져야 할 부분은 NF_HOOK함수와 인자로 주어지는 NF_INET_PRE_ROUTING 값과  ip_rcv_finish함수이다. 

include/linux/netfilter.h

```c
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}
```

include/linux/netfilter.h

```c
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	struct nf_hook_entries *hook_head = NULL;
	int ret = 1;

#ifdef CONFIG_JUMP_LABEL
	if (__builtin_constant_p(pf) &&
	    __builtin_constant_p(hook) &&
	    !static_key_false(&nf_hooks_needed[pf][hook]))
		return 1;
#endif

	rcu_read_lock();
	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
		break;
	case NFPROTO_IPV6:
		hook_head = rcu_dereference(net->nf.hooks_ipv6[hook]);
		break;
	case NFPROTO_ARP:
#ifdef CONFIG_NETFILTER_FAMILY_ARP
		if (WARN_ON_ONCE(hook >= ARRAY_SIZE(net->nf.hooks_arp)))
			break;
		hook_head = rcu_dereference(net->nf.hooks_arp[hook]);
#endif
		break;
	case NFPROTO_BRIDGE:
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
		hook_head = rcu_dereference(net->nf.hooks_bridge[hook]);
#endif
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	if (hook_head) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, pf, indev, outdev,
				   sk, net, okfn);

		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();

	return ret;
}
```

전달된(NF_PRE_ROUTING) 훅과 연결된 함수 엔트리들을 뽑아와서 hook_head에 저장하고 nf_hook_slow 함수를 통해 해당 hook_head에 저장된 함수엔트리(훅 포인트)를 실행한다. 

net/netfilter/core.c

```c
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
		 const struct nf_hook_entries *e, unsigned int s)
{
	unsigned int verdict;
	int ret;

	for (; s < e->num_hook_entries; s++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			break;
		case NF_DROP:
			kfree_skb_reason(skb,
					 SKB_DROP_REASON_NETFILTER_DROP);
			ret = NF_DROP_GETERR(verdict);
			if (ret == 0)
				ret = -EPERM;
			return ret;
		case NF_QUEUE:
			ret = nf_queue(skb, state, s, verdict);
			if (ret == 1)
				continue;
			return ret;
		default:
			/* Implicit handling for NF_STOLEN, as well as any other
			 * non conventional verdicts.
			 */
			return 0;
		}
	}

	return 1;
}
```

해당 함수를 통해 해당 훅 포인트에 연결된 함수 엔트리를 실행하면서 해당 패킷에 대해서 ACCEPT할지 DROP할지 등을 결정한다. 만약 ACCEPT한다면 다음 함수 엔트리를 확인하고 DROP이라면 다음 함수 엔트리를 확인하지 않고 그대로 함수를 종료한다. 

즉, 함수엔트리가 어떤것이 가장 먼저 걸려있는지가 우선순위인거 같음

만약 끝났다면 nf_hook 함수에서 return 값이 1일 경우(ACCEPT) 그 다음 사항을 진행하는데 그 때 인자로 들어온 ip_rcv_finish함수가 콜된다. 

net/ipv4/ip_input.c

```c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int ret;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
	if (ret != NET_RX_DROP)
		ret = dst_input(skb);
	return ret;
}
```

dst_input 함수를 통해서 ip_local_deliver 함수가 콜되어 local host로 패킷을 전송할 수 있게 된다. 

어떤 문서는 ip_rcv_finish함수에서 forward할지 결정한다는 데 좀 더 확인해봐야할듯, core함수를 타고 내부를 타다보면 forward부분이 나오긴하는데 어떤 루틴인지 아직 파악 못함 

include/net/dst.h

```c
static inline int dst_input(struct sk_buff *skb)
{
	return INDIRECT_CALL_INET(skb_dst(skb)->input,
				  ip6_input, ip_local_deliver, skb);
}
```

net/ipv4/ip_input.c

```c
/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```

해당 ip_local_deliver함수를 통해 NF_INET_LOCAL_IN 훅을 트리거 하게 되고 이전 처럼 해당 훅에 걸려있는 함수 엔트리를 실행하여 ACCEPT, DROP들을 결정한다. 만약 DROP등의 이유가 아니라면 ip_local_deliver_finish함수가 콜된다. 

net/ipv4/ip_input.c

```c
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_delivery_time(skb);
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
	rcu_read_unlock();

	return 0;
}
```

패킷이 ACCECPT되었다면 해당 함수가 콜되는데 이는 ip_protocol_deliver_rcu함수를 콜하여 상위 계층으로 패킷을 전송한다. 

net/ipv4/ip_input.c

```c
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
	const struct net_protocol *ipprot;
	int raw, ret;

resubmit:
	raw = raw_local_deliver(skb, protocol);

	ipprot = rcu_dereference(inet_protos[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
			if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb_reason(skb,
						 SKB_DROP_REASON_XFRM_POLICY);
				return;
			}
			nf_reset_ct(skb);
		}
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv,
				      skb);
		if (ret < 0) {
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
			if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
				icmp_send(skb, ICMP_DEST_UNREACH,
					  ICMP_PROT_UNREACH, 0);
			}
			kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
		} else {
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
}
```

해당 패킷의 프로토콜이 TCP라면 tcp_v4_rcv함수를 콜하고 UDP라면 udp_rcv함수를 콜하는 루틴을 지닌다. 이때 발생하는 ICMP UNREACHABLE또한 이부분에서 발생한다. 

이를 통해 USERSPACE에서 tcp or udp 프로토콜을 이용하여 read하는 과정을 코드기반으로 나열하였다. 

### 결론

패킷이 로컬시스템으로 들어오는 과정은 아래와 같다. 

ip_rcv() → ip_rcv_finish() → ip_local_deliver() → ip_local_deliver_finish() → ip_protocol_deliver_rcu() → tcp_v4_rcv() or udp_rcv() 

그리고 ip_rcv 함수와 ip_rcv_finish 함수 사이의 NF_INET_PRE_ROUTING HOOK 

ip_local_deliver함수와 ip_local_deliver_finish함수 사이의 NF_INET_LOCAL_IN HOOK이 존재한다. 

사실 tcp_v4_rcv나 udp_rcv이후 더 코드가 있지만 관심있는 부분은 HOOK POINT이기에 여기까지만

다음 포스팅은 해당 HOOK을 이용하여 실제 iptables과 같은 방화벽 시스템을 코드로 표현할 예정
