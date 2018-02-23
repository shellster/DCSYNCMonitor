#include "packet_dissector.h"

bool get_tcp_payload(const u_char * packet, bpf_u_int32 packet_size, packet_return &tcpdata) {
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip4 *ip4; /* IPv4 header */
	const struct sniff_ip6 *ip6; /* IPv6 header */
	const struct sniff_tcp *tcp; /* The TCP header */
	int payload_size = 0;
	int payload_start = 0;
	
	if (packet_size < 54)
	{
		debug_print("Packet too small to be TCP or we didn't grab it all\n");
		return false;
	}
	
	ethernet = (struct sniff_ethernet*)(packet);

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4)
	{
		//No need to check size as previous check ensures packet is large enough
		ip4 = (struct sniff_ip4*)(packet + SIZE_ETHERNET);
		
		//Double check that the IP packet wraps a TCP packet
		if (ip4->ip_p != IPPROTOCOL_TCP)
		{
			debug_print("IPv4 packet does not contain TCP packet\n");
			return false;
		}

		//packet not even as large as the header states
		//We're going to pretend fragmentation doesn't exist, because it's a pain (though it could be used to defeat this tool).
		if (packet_size < SIZE_ETHERNET + ntohs(ip4->ip_len))
		{
			debug_print("Packet smaller than IPv4 states\n");
			return false;
		}

		u_short ip4_offset = IP_IHL(ip4->version_ihl) * 4;

		//make sure that the total header size is under the total length size
		if (ip4_offset > ntohs(ip4->ip_len))
		{
			debug_print("IPv4 header size claims to be bigger than packet length\n");
			debug_print("%d %d", ip4_offset, ntohs(ip4->ip_len));
			return false;
		}

		payload_size = ntohs(ip4->ip_len) - ip4_offset;

		//Inner data is too small to be a TCP packet, not even enough room for minimal headers.
		if (payload_size < SIZE_TCP)
		{
			debug_print("IPv4 packet too small to contain TCP packet.\n");
			return false;
		}

		payload_start = SIZE_ETHERNET + ip4_offset;

		tcpdata.source_ip.type = AF_INET;

		char tempstring[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET, (void *)&ip4->ip_src, tempstring, INET6_ADDRSTRLEN) == NULL)
		{
			//Unable to convert ipaddress to printable version. 
			debug_print("IPv4 address cannot be converted to printable string.\n");
			return false;
		}
		
		tcpdata.source_ip.address = string(tempstring);
	}
	else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6)
	{
		ip6 = (struct sniff_ip6*)(packet + SIZE_ETHERNET);

		//Double check that the IP packet wraps a TCP packet
		//We're going to ignore the fact that extension headers could be used (though this could be used to defeat this tool).
		if (ip6->ip_nhdr != IPPROTOCOL_TCP)
		{
			debug_print("IPv6 packet does not contain TCP packet\n");
			return false;
		}

		//packet not even as large as the header states
		//We're going to pretend Jumbograms don't exist (though it could be used to defeat this tool, maybe).
		if (packet_size < SIZE_ETHERNET + SIZE_IPV6 + ntohs(ip6->ip_len))
		{
			debug_print("IPv6 packet not as large as the header states\n");
			return false;
		}

		payload_size = ntohs(ip6->ip_len);

		//Inner data is too small to be a TCP packet, not even enough room for minimal headers.
		if (payload_size < SIZE_TCP)
		{
			debug_print("IPv6 packet too small to contain TCP packet.\n");
			return false;
		}

		payload_start = SIZE_ETHERNET + SIZE_IPV6;

		tcpdata.source_ip.type = AF_INET6;

		char tempstring[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, (void *)&ip6->ip_src, tempstring, INET6_ADDRSTRLEN) == NULL)
		{
			//Unable to convert ipaddress to printable version. 
			debug_print("IPv6 address cannot be converted to printable string.\n");
			return false;
		}

		tcpdata.source_ip.address = string(tempstring);
	}
	else
	{
		//Not an IPv4 or IPv6 packet
		debug_print("Not IPv4 or IPv6 packet type: 0x%4x\n", ntohs(ethernet->ether_type));
		return false;
	}

	tcp = (struct sniff_tcp*) (packet + payload_start);
	
	u_short tcp_offset = (u_short)TH_OFF(tcp->th_off_rsv_ns) * 4;

	//Our TCP packet is specifying that the header is either larger than or equal to our remaining packet size, so
	//it is either invalid or an empty packet.
	if (tcp_offset > payload_size)
	{
		debug_print("TCP packet is specifying that the header is larger than the remaining packet size.\n");
		return false;
	}

	payload_start += tcp_offset;
	payload_size -= tcp_offset;

	tcpdata.data = malloc(payload_size);
	tcpdata.data_length = payload_size;
	memcpy_s(tcpdata.data, payload_size, packet + payload_start, payload_size);

	return true;
}

bool compare_bytes(u_char * data, u_int datalength, u_int offset, u_char * search, u_int searchlength)
{
	if (datalength < (offset + searchlength))
		return false;

	if (memcmp(data + offset, search, searchlength) == 0)
		return true;
	
	return false;
}

#ifdef _DEBUG
/*DEBUG*/

//borrowed from: https://www.tcpdump.org/sniffex.c

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
* print packet payload data (avoid printing binary data)
*/
void print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}
/*DEBUG*/
#endif