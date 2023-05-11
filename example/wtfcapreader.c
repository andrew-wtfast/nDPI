/*
 *
 * Copyright (C) 2011-22 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

//#define WTFAST_SERIALIZE

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <errno.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WTFAST_SERIALIZE
#include <fcntl.h>
#endif

#define LOG_FATAL    (1)
#define LOG_ERR      (2)
#define LOG_WARN     (3)
#define LOG_INFO     (4)
#define LOG_DBG      (5)


#define LOG_PRINTF(level, ...) do {if (level <= g_log_verbosity) {fprintf( stdout, __VA_ARGS__ ); }} while(0 )
#ifdef WIN32
#include <windows.h>
#endif

//#define VERBOSE 1
#define MAX_FLOW_ROOTS_PER_THREAD 2048
#define MAX_IDLE_FLOWS_PER_THREAD 64
#define TICK_RESOLUTION 1000
#define MAX_READER_THREADS 4
#define IDLE_SCAN_PERIOD 10000	/* msec */
#define MAX_IDLE_TIME 300000	/* msec */
#define INITIAL_THREAD_HASH 0x03dd018b
#ifdef WTFAST_SERIALIZE
#define PIPE_FILE "/tmp/dpi.io"
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_VLAN
#define ETH_P_VLAN 0x8100
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

enum nDPI_l3_type
{
	L3_IP, L3_IP6
};

struct nDPI_flow_info
{
	uint32_t flow_id;
	unsigned long long int packets_processed;
	uint64_t first_seen;
	uint64_t last_seen;
	uint64_t hashval;

	enum nDPI_l3_type l3_type;
	union
	{
		struct
		{
			uint32_t src;
			uint32_t pad_00[3];
			uint32_t dst;
			uint32_t pad_01[3];
		} v4;
		struct
		{
			uint64_t src[2];
			uint64_t dst[2];
		} v6;

		struct
		{
			uint32_t src[4];
			uint32_t dst[4];
		} u32;
	} ip_tuple;

	struct ndpi_ethhdr ethernet; // record eth hdr of first packet of flow (wtfast)
	unsigned long long int first_packet; // record which packet caused this flow to be created (wtfast)

	unsigned long long int total_l4_data_len;
	uint16_t src_port;
	uint16_t dst_port;

	uint8_t is_midstream_flow:1;
	uint8_t flow_fin_ack_seen:1;
	uint8_t flow_ack_seen:1;
	uint8_t detection_completed:1;
	uint8_t tls_client_hello_seen:1;
	uint8_t tls_server_hello_seen:1;
	uint8_t flow_info_printed:1;
#ifdef WTFAST_SERIALIZE
	uint8_t flow_info_wtfast_json_sent:1;
#endif
	uint8_t reserved_00:1;
	uint8_t l4_protocol;

	struct ndpi_proto detected_l7_protocol;
	struct ndpi_proto guessed_protocol;

	struct ndpi_flow_struct *ndpi_flow;
#ifdef WTFAST_SERIALIZE
	ndpi_serializer ndpi_flow_serializer;
#endif
};

struct nDPI_workflow
{
	pcap_t *pcap_handle;

	volatile long int error_or_eof;

	unsigned long long int packets_captured;
	unsigned long long int packets_processed;
	unsigned long long int total_l4_data_len;
	unsigned long long int detected_flow_protocols;

	uint64_t last_idle_scan_time;
	uint64_t last_time;

	void **ndpi_flows_active;
	unsigned long long int max_active_flows;
	unsigned long long int cur_active_flows;
	unsigned long long int total_active_flows;

	void **ndpi_flows_idle;
	unsigned long long int max_idle_flows;
	unsigned long long int cur_idle_flows;
	unsigned long long int total_idle_flows;

	struct ndpi_detection_module_struct *ndpi_struct;
#ifdef WTFAST_SERIALIZE
	ndpi_serialization_format ndpi_serialization_format;
#endif
};

struct nDPI_reader_thread
{
	struct nDPI_workflow *workflow;
	pthread_t thread_id;
	uint32_t array_index;
};

static struct nDPI_reader_thread reader_threads[MAX_READER_THREADS] = { };

static int reader_thread_count = MAX_READER_THREADS;
static volatile long int main_thread_shutdown = 0;
static volatile long int flow_id = 0;

//Set via command line
static char *g_category;			// Only show results for this category
static uint8_t g_log_verbosity;		// Debug log output level
static char *g_pcap_or_device;		// Name of pcap file or device
static char *g_one_proto;			// Only show classifications of this protocol eg: MortalKombat
static char *g_bpf_filter;			// Filter

#ifdef WTFAST_SERIALIZE
int pipe_fd = 0;
#endif

static void free_workflow(struct nDPI_workflow **const workflow);

static struct nDPI_workflow *init_workflow(char const *const file_or_device)
{
	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	struct nDPI_workflow *workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));
	static struct bpf_program bpf_code;
	static struct bpf_program *bpf_cfilter = NULL;

	if (workflow == NULL) {
		return NULL;
	}

	if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
		workflow->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
	} else {
#ifdef WIN32
		workflow->pcap_handle = pcap_open_offline(file_or_device, pcap_error_buffer);
#else
		workflow->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO, pcap_error_buffer);
#endif
	}

	if (workflow->pcap_handle == NULL) {
		fprintf(stderr, "pcap_open_live / pcap_open_offline: %.*s\n", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
		free_workflow(&workflow);
		return NULL;
	}

	if (pcap_compile(workflow->pcap_handle, &bpf_code, g_bpf_filter, 1, 0xFFFFFF00) < 0) {
		LOG_PRINTF(LOG_FATAL, "pcap_compile error: '%s'\n", pcap_geterr(workflow->pcap_handle));
		exit(-1);
	}

	bpf_cfilter = &bpf_code;

	if (pcap_setfilter(workflow->pcap_handle, bpf_cfilter) < 0) {
		LOG_PRINTF(LOG_FATAL, "pcap_setfilter error: '%s'\n", pcap_geterr(workflow->pcap_handle));
		exit(-1);
	}

	ndpi_init_prefs init_prefs = ndpi_no_prefs;
	workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
	if (workflow->ndpi_struct == NULL) {
		free_workflow(&workflow);
		return NULL;
	}

	workflow->total_active_flows = 0;
	workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
	workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
	if (workflow->ndpi_flows_active == NULL) {
		free_workflow(&workflow);
		return NULL;
	}

	workflow->total_idle_flows = 0;
	workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
	workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
	if (workflow->ndpi_flows_idle == NULL) {
		free_workflow(&workflow);
		return NULL;
	}

	NDPI_PROTOCOL_BITMASK protos;
	NDPI_BITMASK_SET_ALL(protos);
	ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
	ndpi_finalize_initialization(workflow->ndpi_struct);

	return workflow;
}

static void ndpi_flow_info_freer(void *const node)
{
	struct nDPI_flow_info *const flow = (struct nDPI_flow_info *)node;

	ndpi_flow_free(flow->ndpi_flow);
	ndpi_free(flow);
}

static void free_workflow(struct nDPI_workflow **const workflow)
{
	struct nDPI_workflow *const w = *workflow;

	if (w == NULL) {
		return;
	}

	if (w->pcap_handle != NULL) {
		pcap_close(w->pcap_handle);
		w->pcap_handle = NULL;
	}

	if (w->ndpi_struct != NULL) {
		ndpi_exit_detection_module(w->ndpi_struct);
	}
	for (size_t i = 0; i < w->max_active_flows; i++) {
		ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
	}
	ndpi_free(w->ndpi_flows_active);
	ndpi_free(w->ndpi_flows_idle);
	ndpi_free(w);
	*workflow = NULL;
}

static char *get_default_pcapdev(char *errbuf)
{
	char *ifname;
	pcap_if_t *all_devices = NULL;

	if (pcap_findalldevs(&all_devices, errbuf) != 0) {
		return NULL;
	}

	ifname = strdup(all_devices[0].name);
	pcap_freealldevs(all_devices);

	return ifname;
}

static int setup_reader_threads(char const *const file_or_device)
{
	char *file_or_default_device;
	char pcap_error_buffer[PCAP_ERRBUF_SIZE];

	if (reader_thread_count > MAX_READER_THREADS) {
		return 1;
	}

	if (file_or_device == NULL) {
		file_or_default_device = get_default_pcapdev(pcap_error_buffer);
		if (file_or_default_device == NULL) {
			fprintf(stderr, "pcap_findalldevs: %.*s\n", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
			return 1;
		}
	} else {
		file_or_default_device = strdup(file_or_device);
		if (file_or_default_device == NULL) {
			return 1;
		}
	}

	for (int i = 0; i < reader_thread_count; ++i) {
		reader_threads[i].workflow = init_workflow(file_or_default_device);
		if (reader_threads[i].workflow == NULL) {
			free(file_or_default_device);
			return 1;
		}
	}

	free(file_or_default_device);
	return 0;
}

static int ip_tuple_to_string(struct nDPI_flow_info const *const flow, char *const src_addr_str, size_t src_addr_len, char *const dst_addr_str, size_t dst_addr_len)
{
	switch (flow->l3_type) {
	case L3_IP:
		return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src, src_addr_str, src_addr_len) != NULL && inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst, dst_addr_str, dst_addr_len) != NULL;
	case L3_IP6:
		return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0], src_addr_str, src_addr_len) != NULL && inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0], dst_addr_str, dst_addr_len) != NULL;
	}

	return 0;
}

#ifdef WTFAST_SERIALIZE
static char *serializeClassifiedFlowData(struct ndpi_detection_module_struct *ndpi_struct, struct nDPI_flow_info *flow, uint32_t * len)
{
	//TODO Currently this func returns the json string directly but sets the
	//json string length via a parameter.

	char *json_str = NULL;
	u_int32_t json_str_len = 0;
	char src_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };
	char dst_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };
	char l4_proto_name[32];

	ndpi_serializer *const serializer = &flow->ndpi_flow_serializer;

	ndpi_serialize_string_string(serializer, "l4_proto", ndpi_get_ip_proto_name(flow->l4_protocol, l4_proto_name, sizeof(l4_proto_name)));

	if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
		ndpi_serialize_string_string(serializer, "src_ip", src_addr_str);
		ndpi_serialize_string_string(serializer, "dst_ip", dst_addr_str);
	}

	if (flow->src_port != 0) {
		ndpi_serialize_string_uint32(serializer, "src_port", ntohs(flow->src_port));
	}

	if (flow->dst_port != 0) {
		ndpi_serialize_string_uint32(serializer, "dst_port", ntohs(flow->dst_port));
	}

	char buf[64];
	ndpi_serialize_string_string(serializer, "l7_proto", ndpi_protocol2name(ndpi_struct, flow->detected_l7_protocol, buf, sizeof(buf)));
	ndpi_serialize_string_string(serializer, "l7_proto_id", ndpi_protocol2id(ndpi_struct, flow->detected_l7_protocol, buf, sizeof(buf)));

	json_str = ndpi_serializer_get_buffer(serializer, &json_str_len);

	if (json_str == NULL || json_str_len == 0) {
		LOG_PRINTF(LOG_FATAL, "ERROR: nDPI serialization failed\n");
		exit(-1);				//TODO
	}

	LOG_PRINTF(LOG_DBG, "%.*s\n", (int)json_str_len, json_str);

	*len = json_str_len;

	return json_str;
}
#endif

#ifdef VERBOSE
static void print_packet_info(struct nDPI_reader_thread const *const reader_thread, struct pcap_pkthdr const *const header, uint32_t l4_data_len, struct nDPI_flow_info const *const flow)
{
	struct nDPI_workflow const *const workflow = reader_thread->workflow;
	char src_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };
	char dst_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };
	char buf[256];
	int used = 0, ret;

	ret = ndpi_snprintf(buf, sizeof(buf), "[%8llu, %d, %4u] %4u bytes: ", workflow->packets_captured, reader_thread->array_index, flow->flow_id, header->caplen);
	if (ret > 0) {
		used += ret;
	}

	if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]", src_addr_str, dst_addr_str);
	} else {
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[ERROR]");
	}
	if (ret > 0) {
		used += ret;
	}

	switch (flow->l4_protocol) {
	case IPPROTO_UDP:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> UDP[%u -> %u, %u bytes]", flow->src_port, flow->dst_port, l4_data_len);
		break;
	case IPPROTO_TCP:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> TCP[%u -> %u, %u bytes]", flow->src_port, flow->dst_port, l4_data_len);
		break;
	case IPPROTO_ICMP:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
		break;
	case IPPROTO_ICMPV6:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
		break;
	case IPPROTO_HOPOPTS:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP6 Hop-By-Hop");
		break;
	default:
		ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", flow->l4_protocol);
		break;
	}
	if (ret > 0) {
		used += ret;
	}

	printf("%.*s\n", used, buf);
}
#endif

static int ip_tuples_compare(struct nDPI_flow_info const *const A, struct nDPI_flow_info const *const B)
{
	// generate a warning if the enum changes
	switch (A->l3_type) {
	case L3_IP:
	case L3_IP6:
		break;
	}

	if (A->l3_type == L3_IP && B->l3_type == L3_IP) {
		if (A->ip_tuple.v4.src < B->ip_tuple.v4.src) {
			return -1;
		}
		if (A->ip_tuple.v4.src > B->ip_tuple.v4.src) {
			return 1;
		}
		if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst) {
			return -1;
		}
		if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst) {
			return 1;
		}
	} else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
		if (A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) {
			return -1;
		}
		if (A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) {
			return 1;
		}
		if (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]) {
			return -1;
		}
		if (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]) {
			return 1;
		}
	}

	if (A->src_port < B->src_port) {
		return -1;
	}
	if (A->src_port > B->src_port) {
		return 1;
	}
	if (A->dst_port < B->dst_port) {
		return -1;
	}
	if (A->dst_port > B->dst_port) {
		return 1;
	}

	return 0;
}

static void ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which, int depth, void *const user_data)
{
	struct nDPI_workflow *const workflow = (struct nDPI_workflow *)user_data;
	struct nDPI_flow_info *const flow = *(struct nDPI_flow_info **)A;

	(void)depth;

	if (workflow == NULL || flow == NULL) {
		return;
	}

	if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
		return;
	}

	if (which == ndpi_preorder || which == ndpi_leaf) {
		if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) || flow->last_seen + MAX_IDLE_TIME < workflow->last_time) {
			char src_addr_str[INET6_ADDRSTRLEN + 1];
			char dst_addr_str[INET6_ADDRSTRLEN + 1];
			ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
			workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
			workflow->total_idle_flows++;
		}
	}
}

static int ndpi_workflow_node_cmp(void const *const A, void const *const B)
{
	struct nDPI_flow_info const *const flow_info_a = (struct nDPI_flow_info *)A;
	struct nDPI_flow_info const *const flow_info_b = (struct nDPI_flow_info *)B;

	if (flow_info_a->hashval < flow_info_b->hashval) {
		return (-1);
	} else if (flow_info_a->hashval > flow_info_b->hashval) {
		return (1);
	}

	/* Flows have the same hash */
	if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
		return (-1);
	} else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
		return (1);
	}

	return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void check_for_idle_flows(struct nDPI_workflow *const workflow)
{
	if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
		for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
			ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

			while (workflow->cur_idle_flows > 0) {
				struct nDPI_flow_info *const f = (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
				if (f->flow_fin_ack_seen == 1) {
					LOG_PRINTF(LOG_DBG, "Free fin flow with id %u\n", f->flow_id);
				} else {
					LOG_PRINTF(LOG_DBG, "Free idle flow with id %u\n", f->flow_id);
				}
				ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
				ndpi_flow_info_freer(f);
				workflow->cur_active_flows--;
			}
		}

		workflow->last_idle_scan_time = workflow->last_time;
	}
}

static void print_flow_classification(struct nDPI_workflow *workflow, struct nDPI_flow_info *flow_info) 
{
	const char *category = ndpi_category_get_name(workflow->ndpi_struct, flow_info->detected_l7_protocol.category);
	char *proto_name = ndpi_get_proto_name(workflow->ndpi_struct, flow_info->detected_l7_protocol.app_protocol);

	// Only show results for the protocol chosen at the command line
	if (g_one_proto != NULL && strcmp(g_one_proto, proto_name) != 0) 
		return;

	// Only show results for the category chosen at the command line
	if (g_category != NULL && (strcmp(category, g_category) != 0))
		return;

	char src_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };
	char dst_addr_str[INET6_ADDRSTRLEN + 1] = { 0 };

	if (ip_tuple_to_string(flow_info, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) == 0) {
		LOG_PRINTF(LOG_DBG, "ip_tuple_to_string failed %s[%d]", __FILE__, __LINE__);
	}

	char client_mac_str[18];
	sprintf(client_mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",
		flow_info->ethernet.h_source[0],flow_info->ethernet.h_source[1],flow_info->ethernet.h_source[2],
		flow_info->ethernet.h_source[3],flow_info->ethernet.h_source[4],flow_info->ethernet.h_source[5]);

	char server_mac_str[18];
	sprintf(server_mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",
		flow_info->ethernet.h_dest[0],flow_info->ethernet.h_dest[1],flow_info->ethernet.h_dest[2],
		flow_info->ethernet.h_dest[3],flow_info->ethernet.h_dest[4],flow_info->ethernet.h_dest[5]);

	LOG_PRINTF(LOG_INFO, "Flow ID:\t\t%d\nStarted on Packet:\t%llu\nClassification:\t\t%s after %d packets\nCategory:\t\t%s\nClient:\t\t\t%s:%d (MAC: %s)\nServer:\t\t\t%s:%d (MAC: %s)\n", 
		flow_info->flow_id,
		flow_info->first_packet,
		ndpi_get_proto_name(workflow->ndpi_struct, flow_info->detected_l7_protocol.app_protocol),
		flow_info->ndpi_flow->num_processed_pkts,
		category,
		src_addr_str,
		flow_info->src_port, // port is already converted to host format
		client_mac_str,
		dst_addr_str,
		flow_info->dst_port, // port is already converted to host format
		server_mac_str
	);
	LOG_PRINTF(LOG_INFO, "\n");
}

static void ndpi_process_packet(uint8_t * const args, struct pcap_pkthdr const *const header, uint8_t const *const packet)
{
	struct nDPI_reader_thread *const reader_thread = (struct nDPI_reader_thread *)args;
	struct nDPI_workflow *workflow;
	struct nDPI_flow_info flow = { };

	size_t hashed_index;
	void *tree_result;
	struct nDPI_flow_info *flow_to_process;

	const struct ndpi_ethhdr *ethernet = NULL;
	const struct ndpi_iphdr *ip;
	struct ndpi_ipv6hdr *ip6;

	uint64_t time_ms;
	const uint16_t eth_offset = 0;
	uint16_t ip_offset;
	uint16_t ip_size;

	const uint8_t *l4_ptr = NULL;
	uint16_t l4_len = 0;

	uint16_t type;
	uint32_t thread_index = INITIAL_THREAD_HASH;	// generated with `dd if=/dev/random bs=1024 count=1 |& hd'

	uint8_t recheck_type;

	if (reader_thread == NULL) {
		return;
	}
	workflow = reader_thread->workflow;

	if (workflow == NULL) {
		return;
	}

	workflow->packets_captured++;
	time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
	workflow->last_time = time_ms;

	check_for_idle_flows(workflow);

	/* process datalink layer */
	switch (pcap_datalink(workflow->pcap_handle)) {
	case DLT_NULL:
		if (ntohl(*((uint32_t *) & packet[eth_offset])) == 0x00000002) {
			type = ETH_P_IP;
		} else {
			type = ETH_P_IPV6;
		}
		ip_offset = 4 + eth_offset;
		break;
	case DLT_EN10MB:
		if (header->len < sizeof(struct ndpi_ethhdr)) {
			fprintf(stderr, "[%8llu, %d] Ethernet packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
			return;
		}
		ethernet = (struct ndpi_ethhdr *)&packet[eth_offset];
		ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
		
		type = ntohs(ethernet->h_proto);

ether_recheck_type:
		recheck_type = 0;

		switch (type) {
		case ETH_P_IP:			/* IPv4 */
			if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
				fprintf(stderr, "[%8llu, %d] IP packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
				return;
			}
			break;
		case ETH_P_IPV6:		/* IPV6 */
			if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
				fprintf(stderr, "[%8llu, %d] IP6 packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
				return;
			}
			break;
		case ETH_P_ARP:		/* ARP */
			return;
		case ETH_P_VLAN:
			// WTFast hold my beer...
			if (ip_offset + 4 >= (int)header->caplen) {
				fprintf(stderr, "[%8llu, %d] VLAN packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
				return;
			}
			LOG_PRINTF(LOG_DBG, "[%8llu, %d] VLAN tagged packet vlan id = 0x%04x\n", workflow->packets_captured, reader_thread->array_index, ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF);
			type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
			ip_offset += 4;

			// Double tagged
			if (type == 0x8100) {
				if (ip_offset + 4 >= (int)header->caplen) {
					fprintf(stderr, "[%8llu, %d] Double tagged VLAN packet too short - skipping\n", workflow->packets_captured, reader_thread->array_index);
					return;
				}
				LOG_PRINTF(LOG_DBG, "[%8llu, %d] Double tagged VLAN packet vlan id = 0x%04x\n", workflow->packets_captured, reader_thread->array_index, ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF);
				type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
				ip_offset += 4;
			}

			recheck_type = 1;

			break;

		default:
			fprintf(stderr, "[%8llu, %d] Unknown Ethernet packet with type 0x%X - skipping\n", workflow->packets_captured, reader_thread->array_index, type);
			return;
		}

		// This is hideous but effective. The approach is copied from the
		// ndpiReader sample app.
		if (recheck_type)
			goto ether_recheck_type;

		break;

	default:
		fprintf(stderr, "[%8llu, %d] Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n", workflow->packets_captured, reader_thread->array_index, pcap_datalink(workflow->pcap_handle));
		return;
	}

	if (type == ETH_P_IP) {
		ip = (struct ndpi_iphdr *)&packet[ip_offset];
		ip6 = NULL;
	} else if (type == ETH_P_IPV6) {
		ip = NULL;
		ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
	} else {
		fprintf(stderr, "[%8llu, %d] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n", workflow->packets_captured, reader_thread->array_index, type);
		return;
	}
	ip_size = header->len - ip_offset;

	if (type == ETH_P_IP && header->len >= ip_offset) {
		if (header->caplen < header->len) {
			fprintf(stderr, "[%8llu, %d] Captured packet size is smaller than packet size: %u < %u\n", workflow->packets_captured, reader_thread->array_index, header->caplen, header->len);
		}
	}

	/* process layer3 e.g. IPv4 / IPv6 */
	if (ip != NULL && ip->version == 4) {
		if (ip_size < sizeof(*ip)) {
			fprintf(stderr, "[%8llu, %d] Packet smaller than IP4 header length: %u < %zu\n", workflow->packets_captured, reader_thread->array_index, ip_size, sizeof(*ip));
			return;
		}

		flow.l3_type = L3_IP;
		if (ndpi_detection_get_l4((uint8_t *) ip, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0) {
			fprintf(stderr, "[%8llu, %d] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n", workflow->packets_captured, reader_thread->array_index, ip_size - sizeof(*ip));
			return;
		}

		flow.ip_tuple.v4.src = ip->saddr;
		flow.ip_tuple.v4.dst = ip->daddr;
		uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ? flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
		thread_index = min_addr + ip->protocol;
	} else if (ip6 != NULL) {
		if (ip_size < sizeof(ip6->ip6_hdr)) {
			fprintf(stderr, "[%8llu, %d] Packet smaller than IP6 header length: %u < %zu\n", workflow->packets_captured, reader_thread->array_index, ip_size, sizeof(ip6->ip6_hdr));
			return;
		}

		flow.l3_type = L3_IP6;
		if (ndpi_detection_get_l4((uint8_t *) ip6, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0) {
			fprintf(stderr, "[%8llu, %d] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n", workflow->packets_captured, reader_thread->array_index, ip_size - sizeof(*ip6));
			return;
		}

		flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
		flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
		flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
		flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
		uint64_t min_addr[2];
		if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0]
			&& flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1]) {
			min_addr[0] = flow.ip_tuple.v6.dst[0];
			min_addr[1] = flow.ip_tuple.v6.dst[0];
		} else {
			min_addr[0] = flow.ip_tuple.v6.src[0];
			min_addr[1] = flow.ip_tuple.v6.src[0];
		}
		thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
	} else {
		fprintf(stderr, "[%8llu, %d] Non IP/IPv6 protocol detected: 0x%X\n", workflow->packets_captured, reader_thread->array_index, type);
		return;
	}

	/* process layer4 e.g. TCP / UDP */
	if (flow.l4_protocol == IPPROTO_TCP) {
		const struct ndpi_tcphdr *tcp;

		if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
			fprintf(stderr, "[%8llu, %d] Malformed TCP packet, packet size smaller than expected: %u < %zu\n", workflow->packets_captured, reader_thread->array_index, header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
			return;
		}
		tcp = (struct ndpi_tcphdr *)l4_ptr;
		flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
		flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
		flow.flow_ack_seen = tcp->ack;
		flow.src_port = ntohs(tcp->source);
		flow.dst_port = ntohs(tcp->dest);
	} else if (flow.l4_protocol == IPPROTO_UDP) {
		const struct ndpi_udphdr *udp;

		if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
			fprintf(stderr, "[%8llu, %d] Malformed UDP packet, packet size smaller than expected: %u < %zu\n", workflow->packets_captured, reader_thread->array_index, header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
			return;
		}
		udp = (struct ndpi_udphdr *)l4_ptr;
		flow.src_port = ntohs(udp->source);
		flow.dst_port = ntohs(udp->dest);
	}

	/* distribute flows to threads while keeping stability (same flow goes always to same thread) */
	thread_index += (flow.src_port < flow.dst_port ? flow.dst_port : flow.src_port);
	thread_index %= reader_thread_count;
	if (thread_index != reader_thread->array_index) {
		return;
	}
	workflow->packets_processed++;
	workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
	print_packet_info(reader_thread, header, l4_len, &flow);
#endif

	/* calculate flow hash for btree find, search(insert) */
	if (flow.l3_type == L3_IP) {
		if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst, flow.src_port, flow.dst_port, 0, 0, (uint8_t *) & flow.hashval, sizeof(flow.hashval)) != 0) {
			flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst;	// fallback
		}
	} else if (flow.l3_type == L3_IP6) {
		if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst, flow.src_port, flow.dst_port, 0, 0, (uint8_t *) & flow.hashval, sizeof(flow.hashval)) != 0) {
			flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
			flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
		}
	}
	flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

	hashed_index = flow.hashval % workflow->max_active_flows;
	tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
	if (tree_result == NULL) {
		/* flow not found in btree: switch src <-> dst and try to find it again */
		uint32_t orig_src_ip[4] = { flow.ip_tuple.u32.src[0], flow.ip_tuple.u32.src[1],
			flow.ip_tuple.u32.src[2], flow.ip_tuple.u32.src[3]
		};
		uint32_t orig_dst_ip[4] = { flow.ip_tuple.u32.dst[0], flow.ip_tuple.u32.dst[1],
			flow.ip_tuple.u32.dst[2], flow.ip_tuple.u32.dst[3]
		};
		uint16_t orig_src_port = flow.src_port;
		uint16_t orig_dst_port = flow.dst_port;

		flow.ip_tuple.u32.src[0] = orig_dst_ip[0];
		flow.ip_tuple.u32.src[1] = orig_dst_ip[1];
		flow.ip_tuple.u32.src[2] = orig_dst_ip[2];
		flow.ip_tuple.u32.src[3] = orig_dst_ip[3];

		flow.ip_tuple.u32.dst[0] = orig_src_ip[0];
		flow.ip_tuple.u32.dst[1] = orig_src_ip[1];
		flow.ip_tuple.u32.dst[2] = orig_src_ip[2];
		flow.ip_tuple.u32.dst[3] = orig_src_ip[3];

		flow.src_port = orig_dst_port;
		flow.dst_port = orig_src_port;

		tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

		flow.ip_tuple.u32.src[0] = orig_src_ip[0];
		flow.ip_tuple.u32.src[1] = orig_src_ip[1];
		flow.ip_tuple.u32.src[2] = orig_src_ip[2];
		flow.ip_tuple.u32.src[3] = orig_src_ip[3];

		flow.ip_tuple.u32.dst[0] = orig_dst_ip[0];
		flow.ip_tuple.u32.dst[1] = orig_dst_ip[1];
		flow.ip_tuple.u32.dst[2] = orig_dst_ip[2];
		flow.ip_tuple.u32.dst[3] = orig_dst_ip[3];

		flow.src_port = orig_src_port;
		flow.dst_port = orig_dst_port;
	}

	if (tree_result == NULL) {
		/* flow still not found, must be new */
		if (workflow->cur_active_flows == workflow->max_active_flows) {
			fprintf(stderr, "[%8llu, %d] max flows to track reached: %llu, idle: %llu\n", workflow->packets_captured, reader_thread->array_index, workflow->max_active_flows, workflow->cur_idle_flows);
			return;
		}

		flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
		if (flow_to_process == NULL) {
			fprintf(stderr, "[%8llu, %d] Not enough memory for flow info\n", workflow->packets_captured, reader_thread->array_index);
			return;
		}

		memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
		flow_to_process->flow_id = __sync_fetch_and_add(&flow_id, 1);

		flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
		if (flow_to_process->ndpi_flow == NULL) {
			fprintf(stderr, "[%8llu, %d, %4u] Not enough memory for flow struct\n", workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
			return;
		}
		memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

		// Save the ethernet addresses of the first packet of the flow.
		// If the first packet isn't mid-flow then hopefully this will accurately
		// tell us the mac address of the client ie: the hw addr associated with an 
		// rfc1918 ip address --ap.
		if (ethernet != NULL) {
			memcpy(&flow_to_process->ethernet, ethernet, sizeof(struct ndpi_ethhdr));
		}
		// Save the packet number of the first packet of the flow. Note that 
		// arps are not included in the total packet count.
		flow_to_process->first_packet = workflow->packets_captured;

		LOG_PRINTF(LOG_DBG, "[%8llu, %d, %4u] new %sflow\n", workflow->packets_captured, thread_index, flow_to_process->flow_id, (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));
		if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL) {
			/* Possible Leak, but should not happen as we'd abort earlier. */
			return;
		}

		workflow->cur_active_flows++;
		workflow->total_active_flows++;
	} else {
		flow_to_process = *(struct nDPI_flow_info **)tree_result;
	}

	flow_to_process->packets_processed++;
	flow_to_process->total_l4_data_len += l4_len;
	/* update timestamps, important for timeout handling */
	if (flow_to_process->first_seen == 0) {
		flow_to_process->first_seen = time_ms;
	}
	flow_to_process->last_seen = time_ms;
	/* current packet is an TCP-ACK? */
	flow_to_process->flow_ack_seen = flow.flow_ack_seen;

	/* TCP-FIN: indicates that at least one side wants to end the connection */
	if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
		flow_to_process->flow_fin_ack_seen = 1;
		LOG_PRINTF(LOG_DBG, "[%8llu, %d, %4u] end of flow\n", workflow->packets_captured, thread_index, flow_to_process->flow_id);
		return;
	}

	/*
	 * This example tries to use maximum supported packets for detection:
	 * for uint8: 0xFF
	 */

	// TODO Wtfast
	// ndpi_detection_process_packet() will set flow->fail_with_unknown after
	// flow->num_processed_packets >= ndpi_str->max_packets_to_process (this is
	// configurable, default is 32). Subsequent calls to
	// ndpi_detection_process_packet() just return without processing the
	// packet. So this last chance guess section of code needs to be
	// reconsidered. Possibly just use max_packets_to_process instead of 0xFF.
	//
	/*
	if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
		return;
	} else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
		// last chance to guess something, better then nothing
		uint8_t protocol_was_guessed = 0;
		flow_to_process->guessed_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow_to_process->ndpi_flow, 1, &protocol_was_guessed);
		if (protocol_was_guessed != 0) {
			LOG_PRINTF(LOG_DBG, "[%8llu, %d, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n", workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id, ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol), ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol), ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category));
		} else {
			LOG_PRINTF(LOG_DBG, "[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n", workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
		}
	}
	*/

	if (flow_to_process->detection_completed) {
		// This stops further packet processing and skips the tls certificate scraping below in "business section"
		return;
	}

	flow_to_process->detected_l7_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow, ip != NULL ? (uint8_t *) ip : (uint8_t *) ip6, ip_size, time_ms, NULL);

	// Give up on this flow, print unknown classification
	if (flow_to_process->ndpi_flow->fail_with_unknown == 1) {
		flow_to_process->detection_completed = 1;
		print_flow_classification(workflow, flow_to_process);
	}

	if (ndpi_is_protocol_detected(workflow->ndpi_struct, flow_to_process->detected_l7_protocol) != 0 && flow_to_process->detection_completed == 0) {
		if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN || flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
			flow_to_process->detection_completed = 1;
			workflow->detected_flow_protocols++;
			print_flow_classification(workflow, flow_to_process);
//			LOG_PRINTF(LOG_INFO, "ndpi_flow Packet direction: %d\n", flow_to_process->ndpi_flow->packet_direction);
//			LOG_PRINTF(LOG_INFO, "ndpi_flow client Packet direction: %d\n", flow_to_process->ndpi_flow->client_packet_direction);
//			LOG_PRINTF(LOG_INFO, "%s\n\n\n", flow_to_process->ndpi_flow->client_packet_direction == flow_to_process->ndpi_flow->packet_direction ? "client-->server" : "server-->client");
//			LOG_PRINTF(LOG_INFO, "ndpi_flow c_address: %d\n", flow_to_process->ndpi_flow->c_address.v4);
		}
	}

#ifdef WTFAST_SERIALIZE
	if (flow_to_process->detection_completed) {
		if (!flow_to_process->flow_info_wtfast_json_sent) {
			flow_to_process->flow_info_wtfast_json_sent = 1;

			char *json_str = NULL;
			uint32_t json_str_len = 0;

			if (ndpi_init_serializer(&flow_to_process->ndpi_flow_serializer, ndpi_serialization_format_json)
				!= 0) {
				fprintf(stderr, "serializer init failed\n");
				//TODO handle serialization init failure
			}

			json_str = serializeClassifiedFlowData(workflow->ndpi_struct, flow_to_process, &json_str_len);
			if (json_str == NULL) {
				fprintf(stderr, "serializeClassifiedFlowData() failed\n");
			} else {
				LOG_PRINTF(LOG_INFO, "%s\n", json_str);
				// Named pipe for later
				//int ret;
				//ret = write(pipe_fd, json_str, json_str_len);
				//if (ret == -1) {
				//} else {
				//fprintf(stderr, "pipe write okay bytes = %d\n", json_str_len);
				//}
				//// TODO The reader side expects delimiter '\n'.
				//// Using NULL was problematic during initial development.
				//ret = write(pipe_fd, "\n", 1);
				//if (ret == -1) {
				//fprintf(stderr, "pipe write failed err= %s\n", strerror(errno));
				//}
			}

			ndpi_term_serializer(&flow_to_process->ndpi_flow_serializer);
		}
	}
#endif

	if (flow_to_process->ndpi_flow->num_extra_packets_checked <= flow_to_process->ndpi_flow->max_extra_packets_to_check) {
		/*
		 * Your business logic starts here.
		 *
		 * This example does print some information about
		 * TLS client and server hellos if available.
		 *
		 * You could also use nDPI's built-in json serialization
		 * and send it to a high-level application for further processing.
		 *
		 * EoE - End of Example
		 */

		if (flow_to_process->flow_info_printed == 0) {
			char const *const flow_info = ndpi_get_flow_info(flow_to_process->ndpi_flow, &flow_to_process->detected_l7_protocol);
			if (flow_info != NULL) {
				LOG_PRINTF(LOG_DBG, "[%8llu, %d, %4d] info: %s\n", workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id, flow_info);
				flow_to_process->flow_info_printed = 1;
			}
		}

		if (flow_to_process->detected_l7_protocol.master_protocol == NDPI_PROTOCOL_TLS || flow_to_process->detected_l7_protocol.app_protocol == NDPI_PROTOCOL_TLS) {
			if (flow_to_process->tls_client_hello_seen == 0 && flow_to_process->ndpi_flow->protos.tls_quic.hello_processed != 0) {
				uint8_t unknown_tls_version = 0;
				char buf_ver[16];
				LOG_PRINTF(LOG_DBG,
						   "[%8llu, %d, %4d][TLS-CLIENT-HELLO] version: %s | sni: %s | (advertised) ALPNs: %s\n",
						   workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id, ndpi_ssl_version2str(buf_ver, sizeof(buf_ver), flow_to_process->ndpi_flow->protos.tls_quic.ssl_version, &unknown_tls_version), flow_to_process->ndpi_flow->host_server_name, (flow_to_process->ndpi_flow->protos.tls_quic.advertised_alpns != NULL ? flow_to_process->ndpi_flow->protos.tls_quic.advertised_alpns : "-"));

				flow_to_process->tls_client_hello_seen = 1;
			}
			if (flow_to_process->tls_server_hello_seen == 0 && flow_to_process->ndpi_flow->tls_quic.certificate_processed != 0) {
				uint8_t unknown_tls_version = 0;
				char buf_ver[16];
				LOG_PRINTF(LOG_DBG,
						   "[%8llu, %d, %4d][TLS-SERVER-HELLO] version: %s | common-name(s): %.*s | "
						   "issuer: %s | subject: %s\n", workflow->packets_captured,
						   reader_thread->array_index, flow_to_process->flow_id,
						   ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
												flow_to_process->ndpi_flow->protos.tls_quic.ssl_version,
												&unknown_tls_version),
						   (flow_to_process->ndpi_flow->protos.tls_quic.server_names_len ==
							0 ? 1 : flow_to_process->ndpi_flow->protos.tls_quic.server_names_len), (flow_to_process->ndpi_flow->protos.tls_quic.server_names == NULL ? "-" : flow_to_process->ndpi_flow->protos.tls_quic.server_names), (flow_to_process->ndpi_flow->protos.tls_quic.issuerDN != NULL ? flow_to_process->ndpi_flow->protos.tls_quic.issuerDN : "-"), (flow_to_process->ndpi_flow->protos.tls_quic.subjectDN != NULL ? flow_to_process->ndpi_flow->protos.tls_quic.subjectDN : "-"));

				flow_to_process->tls_server_hello_seen = 1;
			}
		}
	}
}

static void run_pcap_loop(struct nDPI_reader_thread const *const reader_thread)
{
	if (reader_thread->workflow != NULL && reader_thread->workflow->pcap_handle != NULL) {

		if (pcap_loop(reader_thread->workflow->pcap_handle, -1, &ndpi_process_packet, (uint8_t *) reader_thread) == PCAP_ERROR) {

			fprintf(stderr, "Error while reading pcap file: '%s'\n", pcap_geterr(reader_thread->workflow->pcap_handle));
			__sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
		}
	}
}

static void break_pcap_loop(struct nDPI_reader_thread *const reader_thread)
{
	if (reader_thread->workflow != NULL && reader_thread->workflow->pcap_handle != NULL) {
		pcap_breakloop(reader_thread->workflow->pcap_handle);
	}
}

static void *processing_thread(void *const ndpi_thread_arg)
{
	struct nDPI_reader_thread const *const reader_thread = (struct nDPI_reader_thread *)ndpi_thread_arg;

	LOG_PRINTF(LOG_DBG, "Starting Thread %d\n", reader_thread->array_index);
	run_pcap_loop(reader_thread);
	__sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
	return NULL;
}

static int processing_threads_error_or_eof(void)
{
	for (int i = 0; i < reader_thread_count; ++i) {
		if (__sync_fetch_and_add(&reader_threads[i].workflow->error_or_eof, 0) == 0) {
			return 0;
		}
	}
	return 1;
}

static int start_reader_threads(void)
{
#ifndef WIN32
	sigset_t thread_signal_set, old_signal_set;

	sigfillset(&thread_signal_set);
	sigdelset(&thread_signal_set, SIGINT);
	sigdelset(&thread_signal_set, SIGTERM);
	if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
		fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
		return 1;
	}
#endif

	for (int i = 0; i < reader_thread_count; ++i) {
		reader_threads[i].array_index = i;

		if (reader_threads[i].workflow == NULL) {
			/* no more threads should be started */
			break;
		}

		if (pthread_create(&reader_threads[i].thread_id, NULL, processing_thread, &reader_threads[i]) != 0) {
			fprintf(stderr, "pthread_create: %s\n", strerror(errno));
			return 1;
		}
	}

	if (pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0) {
		fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
		return 1;
	}

	return 0;
}

static int stop_reader_threads(void)
{
	unsigned long long int total_packets_captured = 0;
	unsigned long long int total_packets_processed = 0;
	unsigned long long int total_l4_data_len = 0;
	unsigned long long int total_flows_captured = 0;
	unsigned long long int total_flows_idle = 0;
	unsigned long long int total_flows_detected = 0;

	for (int i = 0; i < reader_thread_count; ++i) {
		break_pcap_loop(&reader_threads[i]);
	}

	LOG_PRINTF(LOG_DBG, "Stopping reader threads\n");

	for (int i = 0; i < reader_thread_count; ++i) {
		if (reader_threads[i].workflow == NULL) {
			continue;
		}

		if (pthread_join(reader_threads[i].thread_id, NULL) != 0) {
			fprintf(stderr, "pthread_join: %s\n", strerror(errno));
		}

		total_packets_processed += reader_threads[i].workflow->packets_processed;
		total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
		total_flows_captured += reader_threads[i].workflow->total_active_flows;
		total_flows_idle += reader_threads[i].workflow->total_idle_flows;
		total_flows_detected += reader_threads[i].workflow->detected_flow_protocols;

		LOG_PRINTF(LOG_DBG, "Stopping Thread %d, processed %10llu packets, %12llu bytes, total flows: %8llu, " "idle flows: %8llu, detected flows: %8llu\n", reader_threads[i].array_index, reader_threads[i].workflow->packets_processed, reader_threads[i].workflow->total_l4_data_len, reader_threads[i].workflow->total_active_flows, reader_threads[i].workflow->total_idle_flows, reader_threads[i].workflow->detected_flow_protocols);
	}

	/* total packets captured: same value for all threads as packet2thread distribution happens later */
	total_packets_captured = reader_threads[0].workflow->packets_captured;

	for (int i = 0; i < reader_thread_count; ++i) {
		if (reader_threads[i].workflow == NULL) {
			continue;
	}

	free_workflow(&reader_threads[i].workflow);
	}

	printf("Total packets captured.: %llu\n", total_packets_captured);
	printf("Total packets processed: %llu\n", total_packets_processed);
	printf("Total layer4 data size.: %llu\n", total_l4_data_len);
	printf("Total flows captured...: %llu\n", total_flows_captured);
	printf("Total flows timed out..: %llu\n", total_flows_idle);
	printf("Total flows detected...: %llu\n", total_flows_detected);

	return 0;
}

static void sighandler(int signum)
{
	fprintf(stderr, "Received SIGNAL %d\n", signum);

	if (__sync_fetch_and_add(&main_thread_shutdown, 0) == 0) {
		__sync_fetch_and_add(&main_thread_shutdown, 1);
	} else {
		fprintf(stderr, "Reader threads are already shutting down, please be patient.\n");
	}
}

static void usage(char *appname) 
{
	printf("Usage: %s -i <file|device> [-c category] [-p protocol] [-f BPF filter] [-v loglevel]\n", appname);
	printf("  -i\tpcap file or device name\n");
	printf("  -c\tshow only results for this category eg: Game\n");
	printf("  -p\tshow only results this protocol eg: MortalKombat\n");
	printf("  -f\tspecify a BPF filter eg: \"ether host e8:2a:ea:44:55:66\"\n");
	printf("  -v\tlog verbosity low=1, high=5, default=4\n");
}

int main(int argc, char **argv)
{
	int opt;
	g_log_verbosity = LOG_INFO;
	g_pcap_or_device = NULL;
	g_category = NULL;
	g_one_proto = NULL;

	while ((opt = getopt(argc, argv, "f:p:i:c:v:")) != -1) {
		switch (opt) {
			case 'c':
				g_category = optarg;
				break;
			case 'v':
				g_log_verbosity = atoi(optarg);
				if (g_log_verbosity < LOG_FATAL || g_log_verbosity > LOG_DBG) {
					printf("Invalid value for -v\n");
					usage(argv[0]);
					return -1;
				}
				break;
			case 'i':
				g_pcap_or_device = optarg;
				break;
			case 'p':
				g_one_proto = optarg;
				break;
			case 'f':
				g_bpf_filter = optarg;
				break;
			default:
				usage(argv[0]);
				return -1;
		}
	}

	if (g_pcap_or_device == NULL) {
		usage(argv[0]);
		return -1;
	}

	printf("\n");
	printf("nDPI version: %s\n", ndpi_revision());
	printf("API version: %u\n", ndpi_get_api_version()); 
	printf("libgcrypt: %s\n", (ndpi_get_gcrypt_version() == NULL ? "-" : ndpi_get_gcrypt_version()));
	printf("\n");

	if (setup_reader_threads(g_pcap_or_device) != 0) {
		fprintf(stderr, "%s: setup_reader_threads failed\n", argv[0]);
		return -1;
	}

	if (start_reader_threads() != 0) {
		fprintf(stderr, "%s: start_reader_threads\n", argv[0]);
		return -1;
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	while (__sync_fetch_and_add(&main_thread_shutdown, 0) == 0 && processing_threads_error_or_eof() == 0) {
		sleep(1);
	}

	if (stop_reader_threads() != 0) {
		fprintf(stderr, "%s: stop_reader_threads\n", argv[0]);
		return -1;
	}

	return 0;
}
