#pragma once

#include <iostream>
#include "pcap.h"

using namespace std;

#include "packet.h"
#include "debug_print.h"
#include "misc_helpers.h"

struct packet_return {
	ip_addr source_ip;
	void * data;
	int data_length;
};

#ifdef _DEBUG
void print_hex_ascii_line(const u_char *, int, int);
void print_payload(const u_char *, int);
#endif

bool get_tcp_payload(const u_char *, bpf_u_int32, packet_return &);
bool compare_bytes(u_char *, u_int, u_int, u_char *, u_int);

