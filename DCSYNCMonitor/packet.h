#pragma once

#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <Windows.h>

#define ETHER_ADDR_LEN	6
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_IPV6  0x86DD
#define IPPROTOCOL_TCP  0x06
#define SIZE_ETHERNET 14
#define SIZE_IPV4 32
#define SIZE_IPV6 40
#define SIZE_TCP  20

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip4 {
	u_char version_ihl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_IHL(ihl)               ((ihl) & 0x0f)
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct sniff_ip6 {
	u_char version : 4,
		traffic_class : 8;
	u_short flow_label1;
	u_char flow_label2;
	u_short ip_len;		/* total length */
	u_char ip_nhdr;		/* next header */
	u_char ip_hop_limit;		/* hop limit */
	struct in6_addr ip_src, ip_dst; /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_off_rsv_ns; 	/* data offset + rsv + ns*/
#define TH_OFF(th_off)      ((th_off & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};