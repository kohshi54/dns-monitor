#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DOMAIN_OFFSET 12

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[255]);
	__type(value, int);
	__uint(max_entries, 255);
} domain_cnt SEC(".maps");

static __always_inline unsigned short is_dns_request(void *data, void *data_end)
{
	struct ethhdr *eth = data;	
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;
	if (ntohs(eth->h_proto) != ETH_P_IP)
		return 0;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return 0;
	if (ip->protocol != 0x11) //udp
		return 0;
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
		return 0;
	return (ntohs(udp->dest) == 53);
}

///*
static __always_inline int fill_domain_name(char domain[255], void *data, void *data_end)
{
	if (data + sizeof(struct ethhdr) > data_end)
		return 1;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return 1;
	struct udphdr *udp = data + sizeof(struct ethhdr) + (ip->ihl * 4);
	if (data + sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
		return 1;
	void *dnshdr = data + sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr);
	if (data + sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr) + DOMAIN_OFFSET > data_end)
		return 1;

	dnshdr = dnshdr + DOMAIN_OFFSET;
	__u8 i = 0;
	#pragma unroll	
	for (i = 0; i < 255; ++i){
		dnshdr = dnshdr + 1;
		if (dnshdr + 1 > data_end)
			break;
		char c = *(char *)dnshdr;
		//bpf_printk("%d, %c", i, c);
		domain[i] = c;
		if (c == 0)
			break;
	}
	return i; // domain mojisuu kaesu
}
//*/

//SEC("tc")
SEC("classifier")
int dns_monitor(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	//bpf_printk("packet arrived!\n");
	
	if (!is_dns_request(data, data_end))
		return TC_ACT_OK;

	bpf_printk("dns request arrived!\n");

	char domain[255] = {0};
	int i = 0;
	if ((i = fill_domain_name(domain, data, data_end)) == 1)
		return TC_ACT_OK;

	#pragma unroll
	for (__u8 j = 0; j < i; ++j) {
		if (domain[j] == 0)
			break;
		bpf_printk("%c", domain[j]);
	}
	
	int *cnt = bpf_map_lookup_elem(&domain_cnt, domain);
	if (cnt) {
		(*cnt)++;
		bpf_map_update_elem(&domain_cnt, domain, cnt, BPF_EXIST);
	} else {
		int tmp = 1;
		bpf_map_update_elem(&domain_cnt, domain, &tmp, BPF_NOEXIST);
	}

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

