#include "monitor.h"

vector<pcap_t *> devicelist;
mutex devicelist_mutex;

vector<ip_addr> dc_ip_list;
map<string, time_t> alerts;

bool start_monitoring()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	vector<thread> threads;

	if (!is_elevated())
	{
		fprintf(stderr, "This tool must be run from an elevated account.\n");
		return false;
	}

	if (!install_event_log_source("DCSYNCALERT"))
		return false;

	get_dc_list(dc_ip_list);

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		debug_print("There was an error getting your network interfaces: %s", errbuf);
		return false;
	}

	/* Scan the list printing every entry */
	for (d = alldevs; d; d = d->next)
	{
		threads.push_back(thread(sniff_interface, d));
	}

	join_all(threads);

	/* Free the device list */
	pcap_freealldevs(alldevs);

	return true;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	packet_return tcppacket;

	if (get_tcp_payload(pkt_data, header->caplen, tcppacket))
	{
#ifdef _DEBUG
		//debug_print("TCP SRC IP: %s\nData:\n", tcppacket.source_ip.address.c_str());
		//print_payload((const u_char *)tcppacket.data, tcppacket.data_length);
#endif

		u_char * packet = (u_char *) tcppacket.data;
		
		//Check for DRSUAPI packet flags of 0x03 followed by the data representation type of little endian, ASCII, Float: IEEE
		u_char packet_header[8] = { 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 };
		u_char packet_opnum[3] = { 0x00, 0x03, 0x00 };

		if (compare_bytes((u_char *)tcppacket.data, tcppacket.data_length, 0, packet_header, 8))
		{
			debug_print("Passed first check\n");
			//Checking for DRSUAPI OpNum 3 (DSGetNCChanges)
			if (compare_bytes((u_char *)tcppacket.data, tcppacket.data_length, 21, packet_opnum, 3))
			{
				debug_print("Passed second check\n");

				if (!check_for_previous_alert(alerts, tcppacket.source_ip))
				{
					string event_message = "DC SYNC FROM: ";
					event_message.append(tcppacket.source_ip.address.c_str());
					
					debug_print("%s\n", event_message.c_str());

					if (is_from_valid_dc(dc_ip_list, tcppacket.source_ip))
						log_event_log_message(event_message, EVENTLOG_WARNING_TYPE, "DCSYNCALERT");
					else
						log_event_log_message(event_message, EVENTLOG_ERROR_TYPE, "DCSYNCALERT");
				}
				else
					debug_print("DC SYNC already occured from %s within alert window.\n", tcppacket.source_ip.address.c_str());
			}
		}

		free(tcppacket.data);
	}
	else
	{
		debug_print("Packet failed to parse.\n");
	}
}

void sniff_interface(pcap_if_t *d) {
	
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	pcap_t *adhandle;

	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		0,				// normal mode (nonzero means promiscuous)
		10000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		return;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		debug_print("\nThis program works only on Ethernet networks.\n");
		pcap_close(adhandle);
		return;
	}

	if (pcap_compile(adhandle, &filter, "(ip or ip6) and tcp and dst portrange 49152-65535", true, PCAP_NETMASK_UNKNOWN) != 0)
	{
		debug_print("\nError compiling filter\n");
		pcap_close(adhandle);
		return;
	}

	if (pcap_setfilter(adhandle, &filter) != 0)
	{
		debug_print("\nError setting the filter\n");

		pcap_close(adhandle);
		return;
	}

	pcap_freecode(&filter);

	devicelist_mutex.lock();
	devicelist.push_back(adhandle);
	devicelist_mutex.unlock();

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return;
}

void end_monitoring() {
	lock_guard<mutex> lock(devicelist_mutex);
	
	for (pcap_t * device : devicelist) {
		//Causes all sniffing loops to close so that the threads can join in the main method and clean-up for a tidy exit.
		pcap_breakloop(device);
	}
}