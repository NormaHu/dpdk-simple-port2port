#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <sys/stat.h>

//We assume these values are host value (little-endian)
#define IPV4_HDR_DF_SHIFT           14
#define IPV4_HDR_MF_SHIFT           13
#define IPV4_HDR_FO_SHIFT           3

#define IPV4_HDR_DF_MASK            (1 << IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_MF_MASK            (1 << IPV4_HDR_MF_SHIFT)
#define IPV4_HDR_FO_MASK            ((1 << IPV4_HDR_FO_SHIFT) - 1)
#define PORT_NUM 2
#define MEMPOOL_NUM 1
#define MBUF_NUM 32

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define LOCAL_IP_ADDR (uint32_t)(456)
#define KV_IP_ADDR (uint32_t)(789)
#define LOCAL_UDP_PORT (uint16_t)(123)
#define KV_UDP_PORT (uint16_t)(124)

static struct rte_mbuf *tx_packets[MBUF_NUM];

struct _statistic_ {
	uint64_t tx_pkts;
	uint64_t rx_pkts;
};

static struct _statistic_ statistic = {
	.tx_pkts = 0,
	.rx_pkts = 0
};

/*
 *  * Ethernet device configuration.
 *   */
static struct rte_eth_rxmode rx_mode = {
	.max_rx_pkt_len = ETHER_MAX_LEN, /**< Default maximum frame length. */
	.split_hdr_size = 0, 
	.header_split   = 0, /**< Header Split disabled. */
	.hw_ip_checksum = 0, /**< IP checksum offload disabled. */
	.hw_vlan_filter = 0, /**< VLAN filtering disabled. */
	.hw_vlan_strip  = 0, /**< VLAN strip disabled. */
	.hw_vlan_extend = 0, /**< Extended VLAN disabled. */
	.jumbo_frame    = 0, /**< Jumbo Frame Support disabled. */
	.hw_strip_crc   = 0, /**< CRC stripping by hardware disabled. */
};

static struct rte_eth_txmode tx_mode = {
	.mq_mode = ETH_MQ_TX_NONE
};

static struct rte_eth_conf port_conf_default;
static void
packet_ipv4hdr_constructor(struct ipv4_hdr *iph, int payload_len)
{
	iph->version_ihl = 0x40 | 0x05;
	iph->type_of_service = 0;
	iph->packet_id = 0;
	/* set DF flag */
	iph->fragment_offset = htons(IPV4_HDR_DF_MASK);
	iph->time_to_live = 64;

	/* Total length of L3 */
	iph->total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct
				udp_hdr) + payload_len);

	iph->next_proto_id = IPPROTO_UDP;
	iph->src_addr = LOCAL_IP_ADDR;
	iph->dst_addr = KV_IP_ADDR;
}

#ifdef PRINT_INFO
static
void display_mac_address(struct ether_hdr *ethh, uint8_t pid_from, uint8_t pid_to)
{
	printf("port_from %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_from,
			ethh->s_addr.addr_bytes[0], ethh->s_addr.addr_bytes[1],
			ethh->s_addr.addr_bytes[2], ethh->s_addr.addr_bytes[3],
			ethh->s_addr.addr_bytes[4], ethh->s_addr.addr_bytes[5]);
	printf("port_to %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_to,
			ethh->d_addr.addr_bytes[0], ethh->d_addr.addr_bytes[1],
			ethh->d_addr.addr_bytes[2], ethh->d_addr.addr_bytes[3],
			ethh->d_addr.addr_bytes[4], ethh->d_addr.addr_bytes[5]);
}
#endif

static void
packet_constructor_udp(char *pkt, uint8_t pid_from, uint8_t pid_to, int
		payload_len)
{
	struct ether_hdr *ethh;
	struct ipv4_hdr *iph;
	struct udp_hdr *udph;
	char *data;
	uint16_t ip_ihl;

	ethh = (struct ether_hdr *)pkt;
	iph = (struct ipv4_hdr *)((unsigned char *)ethh + sizeof(struct ether_hdr));
	ip_ihl = (iph->version_ihl & 0x0f) * 4;
	assert(ip_ihl < sizeof(struct ipv4_hdr));
	udph = (struct udp_hdr *)((char *)iph + ip_ihl);

	/* 1. payload */
	data = ((char *)udph + sizeof(struct udp_hdr));
	for(int i = 0; i < payload_len; i++) {
		*(data + i) = 1;
	}
	/* 2. Ethernet headers for the packet */
	ethh->ether_type = htons(ETHER_TYPE_IPv4);
	rte_eth_macaddr_get(pid_from, &(ethh->s_addr));
	rte_eth_macaddr_get(pid_to, &(ethh->d_addr));
	
	/* 3. construct IP header */
	packet_ipv4hdr_constructor(iph, payload_len);

	udph->src_port = htons(LOCAL_UDP_PORT);
	udph->dst_port = htons(KV_UDP_PORT);
	udph->dgram_len = htons(8+payload_len);

	/* Init IPV4 and UDP checksum with 0 */
	iph->hdr_checksum = 0;
	udph->dgram_cksum = 0;

	/* calculate IPV4 and UDP checksum in SW */
	udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);
	iph->hdr_checksum = rte_ipv4_cksum(iph);
}

static void
setup_mbuf(uint8_t pid_from, uint8_t pid_to, struct rte_mempool *mp)
{
	char *pkt;
	int payload_len = 1000;

	for (int i = 0; i < MBUF_NUM; i++) {
		tx_packets[i] = rte_pktmbuf_alloc(mp);
		if (!tx_packets[i]) {
			printf("allocate mbuf failed\n");
			exit(1);
		}
		rte_pktmbuf_reset_headroom(tx_packets[i]);

		pkt = rte_pktmbuf_mtod(tx_packets[i], char *);
		packet_constructor_udp(pkt, pid_from, pid_to, payload_len);

		/*update mbuf metadata */
		tx_packets[i]->pkt_len = sizeof(struct ipv4_hdr) + sizeof(struct
				udp_hdr) + payload_len;
		tx_packets[i]->data_len = tx_packets[i]->pkt_len;
		tx_packets[i]->nb_segs = 1;
		tx_packets[i]->ol_flags = 0;
		tx_packets[i]->l2_len = sizeof(struct ether_hdr);
		tx_packets[i]->l3_len = sizeof(struct ipv4_hdr);
	}
}

static void
init_mempool(struct rte_mempool **mempool)
{
	uint32_t nb_mbufs = MBUF_NUM * 100 * PORT_NUM;
	uint16_t mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;

	*mempool = rte_pktmbuf_pool_create("mempool0", nb_mbufs, 32, 0,
			mbuf_size, rte_socket_id());
}

static void
display_stats(struct rte_eth_stats *stats, uint16_t nb, const char *name)
{
	printf("%s packets of HW statistics:\n", name);
	printf("error packets-%lu\treceived packets-%lu\ttransmitted packets-%lu\n",
			stats->ierrors, stats->ipackets, stats->opackets);
	printf("%s packets of SW-%u\n\n", name, nb);
}

static void
txrx_loop(uint8_t pid_from, uint8_t pid_to)
{
	uint16_t queue_id = 0;
	uint16_t nb_tx = 0;
	uint16_t nb_rx = 0;
	struct rte_mbuf *rx_packets[MBUF_NUM];
	struct rte_eth_stats stats;

	printf("port_from is %u, port_to is %u\n", pid_from, pid_to);

begin:
	nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, MBUF_NUM);
	if (nb_tx <= 0)
		goto begin;
	
	statistic.tx_pkts += nb_tx;
	rte_eth_stats_get(pid_from, &stats);
	display_stats(&stats, statistic.tx_pkts, "tx:");

	for (;;) {
		nb_rx = rte_eth_rx_burst(pid_to, queue_id, rx_packets, MBUF_NUM);
		statistic.rx_pkts += nb_rx;
		if (nb_rx > 0) {
			/* This function is to read register value, which is
			 * statisticed by HW */
			rte_eth_stats_get(pid_to, &stats);
			display_stats(&stats, statistic.rx_pkts, "rx:");
		}

		for (int i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(rx_packets[i]);

		sleep(2);

		nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, MBUF_NUM);
		statistic.tx_pkts += nb_tx;
		//rte_eth_stats_get(pid_from, &stats);
		//display_stats(&stats, statistic.tx_pkts, "tx:");
	}
}

int main(int argc, char **argv)
{
	uint8_t pid_from, pid_to, nb_ports;
	const uint16_t rx_rings = 1, tx_rings = 1;
	struct rte_eth_conf port_conf;
	int ret;
	struct rte_mempool *mp;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports >= 2) {
		pid_from = 1;
		pid_to = 0;
	} else {
		printf("port number is %u, not enough!\n", nb_ports);
		return 0;
	}

	init_mempool(&mp);
	setup_mbuf(pid_from, pid_to, mp);

	port_conf_default.rxmode = rx_mode;
	port_conf_default.txmode = tx_mode;

	port_conf = port_conf_default;
	for (int i = 0; i < PORT_NUM; i++) {
		ret = rte_eth_dev_configure(i, rx_rings, tx_rings, &port_conf);
		if (ret != 0)
			return ret;
	}

	for (int i = 0; i < rx_rings; i++) {
		ret = rte_eth_rx_queue_setup(pid_from, i, RX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), NULL, mp);
		if (ret < 0)
			return ret;
		ret = rte_eth_rx_queue_setup(pid_to, i, RX_RING_SIZE,
				rte_eth_dev_socket_id(pid_to), NULL, mp);
		if (ret < 0)
			return ret;
	}

	for (int i = 0; i < tx_rings; i++) {
		ret = rte_eth_tx_queue_setup(pid_from, i, TX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), NULL);
		if (ret < 0)
			return ret;
		ret = rte_eth_tx_queue_setup(pid_to, i, TX_RING_SIZE,
				rte_eth_dev_socket_id(pid_to), NULL);
		if (ret < 0)
			return ret;
	}

	ret = rte_eth_dev_start(pid_from);
	if (ret < 0)
		return ret;
	ret = rte_eth_dev_start(pid_to);
	if (ret < 0)
		return ret;

	rte_eth_promiscuous_enable(pid_from);
	//rte_eth_promiscuous_enable(pid_to);
	
	txrx_loop(pid_from, pid_to);
	return 0;
}
