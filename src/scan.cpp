/*  ------------------------------------------------------------------------
    degreaser - A tool for detecting network tarpits.
    Copyright (c) 2014, Lance Alt

    This file is part of degreaser.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    ------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <crafter.h>

#include <string>

#include "degreaser.h"
#include "scan.h"

using namespace Crafter;

Scan::Scan(DegreaserConfig& c, uint32_t a, uint32_t o) : config(c) {
	ia.s_addr = a;
	addr = inet_ntoa(ia);
	send_options = o;
	result = NOT_SCANNED;
	window_size = 0;
	response_flags = 0;
	response_time = 0;

	options = 0;
	timestamp.SetValue(0xabcfef);
	win_scale.SetKind(3);
	win_scale.SetPayload("\x7");
	win_scale.SetLength(3);
	mss.SetMaxSegSize(1234);
	sack.SetKind(4);
	sack.SetLength(2);
};

Scan::~Scan() { }

ScanResult Scan::get_result() const {
	return result;
}

bool Scan::scan(string dev, uint16_t dport, uint16_t sport, uint16_t timeout, uint16_t retries) {
	Packet *syn, *syn_resp, *ack, *ack_resp, *data, *data_resp, *rst, *fin, *fin_resp;
	TCP *syn_resp_tcp, *ack_resp_tcp;

	syn = syn_resp = ack = ack_resp = data = data_resp = fin = fin_resp = NULL;
	src_port = sport;
	dst_port = dport;
	src_seq = rand();

	/* Create the SYN packet to scan the host */
	syn = create_syn(dev, timeout, retries);
	src_seq++;
	if(!syn) {
		LOG_ERROR("Failed to create SYN packet. Aborting.\n");
		exit(EXIT_FAILURE);
	}

	/* Send the SYN and wait for a response */
	syn_resp = send_with_response(dev, syn, timeout, retries, &response_time);
	if(!syn_resp) {
		if(dry_run) {
			result = DRY_RUN; 
			LOG_DEBUG("Scanning %s: Not performed (dry run).\n", addr.c_str());
		} else {
			result = NO_RESPONSE;
			LOG_DEBUG("Scanning %s: No response.\n", addr.c_str());
		}
		goto cleanup;
	}

	syn_resp_tcp = syn_resp->GetLayer<TCP>();
	if(!syn_resp_tcp) {
		ICMP* icmp = syn_resp->GetLayer<ICMP>();
		if(icmp && icmp->GetType() == 3) {
			result = UNREACHABLE;
		} else {
			result = TCP_ERROR;
			LOG_WARNING("Response did not contain a TCP header.\n");
		}
		goto cleanup;
	}
	response_flags = syn_resp_tcp->GetFlags();
	window_size = syn_resp_tcp->GetWindowsSize();
	dst_seq = syn_resp_tcp->GetSeqNumber();

	/* Check to make sure we got a SYN/ACK like expected */
	if(syn_resp_tcp && response_flags != (TCP::SYN | TCP::ACK)) {
		if(response_flags & TCP::RST) {
			result = REJECT;
			LOG_DEBUG("Scanning %s: Rejected connection.\n", addr.c_str());
		} else {
			result = FLAGS_ERROR;
			LOG_DEBUG("Scanning %s: TCP Error.\n", addr.c_str());
		}
		goto cleanup;
	}

	/* Check to see if the SYN/ACK contained any TCP options */
	if(0 < get_tcp_option_count(syn_resp) && options != SCAN_OPT_MSS) {
		result = REAL_HOST;
		LOG_DEBUG("Scanning %s: Detected real host.\n", addr.c_str());
		goto cleanup;
	}

	/* Check to see if the window size is above the threshold */
	if(window_size > config.win_threshold) {
		result = REAL_HOST;
		LOG_DEBUG("Scanning %s: Detected real host.\n", addr.c_str());
		goto cleanup;
	}

	/* In fast scan mode, we stop here, and identify this host as a tarpit */
	if(config.fast_scan) {
		result = TARPIT;
		LOG_DEBUG("Scanning %s: Detected tarpit (Fast scan enabled).\n", addr.c_str());
		goto cleanup;
	}

	/* In non-fast scan mode, finish the 3-way handshake by sending the final ACK */
	ack = create_ack(dev);
	ack_resp = send_with_response(dev, ack, timeout, retries, NULL);

	/* Check to see if we got an ACK response. IPTABLES tarpit will respond to our ACK
	   with a zero-window ACK. Otherwise, if the SYN/ACK window was zero, but now the
	   host has a non-zero ACK, then this is a real "zero window"  host. */
	if(ack_resp) {
		ack_resp_tcp = ack_resp->GetLayer<TCP>();
		if(ack_resp_tcp) {
			if(ack_resp_tcp->GetFlags() & TCP::RST) {
				result = DELUDE;
				goto cleanup;
			} else if(ack_resp_tcp->GetWindowsSize() == 0) {
				result = IPTABLES;
				LOG_DEBUG("Scanning %s: Detected IPTABLES\n", addr.c_str());
				goto cleanup;
			} else if(window_size == 0) {
				result = ZERO_WIN;
				goto cleanup;
			}
		}
	}

	/* Now try sending a data packet with size one less than the window */
	data = create_data_packet(dev, window_size - 1);
	data_resp = send_with_response(dev, data, timeout, retries, NULL);

	/* Getting a valid response to the data packet indicates a real host that happens to have a small window size */
	if(data_resp) {
		result = REAL_HOST;
		LOG_DEBUG("Scanning %s: Detected real host (with small window).\n", addr.c_str());
	} else {
		result = LABREA;
		LOG_DEBUG("Scanning %s: Detected LABREA\n", addr.c_str());
	}

cleanup:
	rst = create_reset_packet(dev);
	if(!dry_run) {
		rst->Send(dev);
		dump_packet(rst);
	}

	if(rst)			delete rst;
	if(syn)			delete syn;
	if(syn_resp)	delete syn_resp;
	if(ack)			delete ack;
	if(ack_resp)	delete ack_resp;
	if(data)		delete data;
	if(data_resp)	delete data_resp;
	if(fin)			delete fin;
	if(fin_resp)	delete fin_resp;

	if(result != NO_RESPONSE) {
		return true;
	}
	return false;
}

Packet* Scan::create_syn(string dev, uint16_t timeout, uint16_t retries) {
uint16_t opt_count = 0;
	Packet* p = new Packet();
	IP ip;
	TCP tcp;

	/* Set data fields for IP and TCP layers */
	ip.SetSourceIP(GetMyIP(dev));
	ip.SetDestinationIP(addr);
	tcp.SetSrcPort(src_port);	
	tcp.SetDstPort(dst_port);
	tcp.SetFlags(TCP::SYN);
	tcp.SetSeqNumber(src_seq);

	p->PushLayer(ip);
	p->PushLayer(tcp);

	// Add on TCP options
	if(send_options & SCAN_OPT_SACK) {
		p->PushLayer(sack);
		opt_count += sack.GetLength();
	}
	if(send_options & SCAN_OPT_WINSCALE) {
		p->PushLayer(win_scale);
		opt_count += win_scale.GetLength();
	}
	if(send_options & SCAN_OPT_TIMESTAMP) {
		p->PushLayer(timestamp);
		opt_count += timestamp.GetLength();
	}
	if(send_options & SCAN_OPT_MSS) {
		p->PushLayer(mss);
		opt_count += mss.GetLength();
	}
	
	/* Pad the options to multiple of 4 bytes and add EOL option */
	if(opt_count > 0) {
		switch(opt_count % 4) {
			case 0:	p->PushLayer(TCPOption::NOP);
			case 1:	p->PushLayer(TCPOption::NOP);
			case 2:	p->PushLayer(TCPOption::NOP);
			case 3:	p->PushLayer(TCPOption::EOL);
		}
	}
	return p;
}

Packet* Scan::create_ack(string dev) {
	Packet* p = new Packet();
	IP ip;
	TCP tcp;

	/* Set data fields for IP and TCP layers */
	ip.SetSourceIP(GetMyIP(dev));
	ip.SetDestinationIP(addr);
	tcp.SetSrcPort(src_port);	
	tcp.SetDstPort(dst_port);
	tcp.SetFlags(TCP::ACK);
	tcp.SetSeqNumber(src_seq);
	tcp.SetAckNumber(dst_seq + 1);

	p->PushLayer(ip);
	p->PushLayer(tcp);

	return p;
}

Packet* Scan::create_data_packet(string dev, uint16_t size) {
	Packet* p = new Packet();
	IP ip;
	TCP tcp;
	RawLayer data;

	if(size > MAX_DATA_PACKET_SIZE) {
		size = MAX_DATA_PACKET_SIZE;
	}

	void* buffer = malloc(size);
	FILE* fd = fopen("/dev/urandom", "r");
	if(!fd) {
		fprintf(stderr, "warning: Failed to open /dev/urandom. Data packet will not be random!\n");
	} else {
		size = fread(buffer, 1, size, fd);
	}

	data.SetPayload((byte*)buffer, size);

	free(buffer);
	if(fd) {
		fclose(fd);
	}

	/* Set data fields for IP and TCP layers */
	ip.SetSourceIP(GetMyIP(dev));
	ip.SetDestinationIP(addr);
	tcp.SetSrcPort(src_port);	
	tcp.SetDstPort(dst_port);
	tcp.SetSeqNumber(src_seq);
	tcp.SetAckNumber(dst_seq + 1);
	tcp.SetFlags(TCP::ACK);

	p->PushLayer(ip);
	p->PushLayer(tcp);
	p->PushLayer(data);

	return p;
}

Packet* Scan::create_reset_packet(string dev) {
	Packet* p = new Packet();
	IP ip;
	TCP tcp;

	/* Set data fields for IP and TCP layers */
	ip.SetSourceIP(GetMyIP(dev));
	ip.SetDestinationIP(addr);
	tcp.SetSrcPort(src_port);	
	tcp.SetDstPort(dst_port);
	tcp.SetFlags(TCP::RST | TCP::ACK);
	tcp.SetSeqNumber(src_seq + 1);
	tcp.SetAckNumber(dst_seq + 1);

	p->PushLayer(ip);
	p->PushLayer(tcp);

	return p;
}

Packet* Scan::create_fin_packet(string dev) {
	Packet* p = new Packet();
	IP ip;
	TCP tcp;

	/* Set data fields for IP and TCP layers */
	ip.SetSourceIP(GetMyIP(dev));
	ip.SetDestinationIP(addr);
	tcp.SetSrcPort(src_port);	
	tcp.SetDstPort(dst_port);
	tcp.SetFlags(TCP::FIN | TCP::ACK);
	tcp.SetSeqNumber(src_seq);
	tcp.SetAckNumber(dst_seq + 1);

	p->PushLayer(ip);
	p->PushLayer(tcp);

	return p;
}

Packet* Scan::send_with_response(string dev, Packet* pkt, uint16_t timeout, uint16_t retries, uint32_t* rtime) {
	struct timeval start_time;
	struct timeval end_time;
	Packet* resp = NULL, *ip_resp;

	dump_packet(pkt);
	
	/* Get the time, then send packet and wait for response. */
	gettimeofday(&start_time, NULL);
	if(!dry_run) {
		resp = pkt->SendRecv(dev, timeout, retries);
	}
	gettimeofday(&end_time, NULL);

	/* No response received */
	if(!resp) {
		return NULL;
	}

	if(rtime) {
		*rtime = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);
	}

	/* Remove the Ethernet header */
	ip_resp = new Packet();
	*ip_resp = resp->SubPacket(1, resp->GetLayerCount());
	delete resp;

	dump_packet(ip_resp);

	return ip_resp;
}

uint8_t Scan::get_tcp_option_count(Packet* p) {
	int lcount = p->GetLayerCount();
	int count = 0;
	for(int i = 0; i < lcount; i++) {
		TCPOptionLayer* opt = p->GetLayer<TCPOptionLayer>(i);
		if(opt) {
			count++;
			switch(opt->GetKind()) {
				case 0:
				case 1: break;
				case 2: options |= SCAN_OPT_MSS; break;
				case 3: options |= SCAN_OPT_WINSCALE; break;
				case 4:
				case 5: options |= SCAN_OPT_SACK; break;
				case 8: options |= SCAN_OPT_TIMESTAMP; break;
				default:
						fprintf(stderr, "warning: Unknown TCP option kind: %d\n", opt->GetKind());
						break;
			}
		}
	}
	return count;
}

void Scan::dump_packet(Packet* p) {
	struct pcap_pkthdr header;

	if(config.pcap_dumper == NULL) {
		return;
	}

	gettimeofday(&header.ts, NULL);
	header.len = p->GetSize();
	header.caplen = p->GetSize();

	pthread_mutex_lock(&config.pcap_lock);
	DumperPcap(config.pcap_dumper, &header, p->GetRawPtr());
	pthread_mutex_unlock(&config.pcap_lock);
}

const char* Scan::address_to_string() {
	uint32_t be_addr = htonl(ia.s_addr);
	uint8_t* be_bytes = (uint8_t*)&be_addr;
	snprintf(address_str, 16, "%hhu.%hhu.%hhu.%hhu",
			be_bytes[3], be_bytes[2], be_bytes[1], be_bytes[0]);
	return address_str;
}

const char* Scan::result_to_string() {
	switch(result) {
		case UNREACHABLE:	return "Unreachable";
		case NOT_SCANNED:	return "Not scanned";
		case NO_RESPONSE:	return "No response";
		case REJECT:		return "Rejecting";
		case FLAGS_ERROR:	return "Bad Flags";
		case REAL_HOST:		return "Real Host";
		case LABREA:		return "Labrea";
		case IPTABLES:		return "iptables - tarpit";
		case DELUDE:		return "iptables - delude";
		case TCP_ERROR:		return "Error in TCP packet";
		case DRY_RUN:		return "Not scanned. Running in dry run mode.";
		case TARPIT:		return "Tarpit";
		case ZERO_WIN:		return "Zero Window";
		default:			return "Unknown Result";
	}
}

const char* Scan::options_to_string() {
	char* opt_ptr = opt_str;

	if(options & SCAN_OPT_MSS)			*opt_ptr++ = 'M';
	if(options & SCAN_OPT_WINSCALE)		*opt_ptr++ = 'W';
	if(options & SCAN_OPT_SACK)			*opt_ptr++ = 'S';
	if(options & SCAN_OPT_TIMESTAMP)	*opt_ptr++ = 'T';
	*opt_ptr = '\0';

	return opt_str;
}

const char* Scan::flags_to_string() {
	char* flag_ptr = flags_str;

	if(response_flags & TCP::SYN)	*flag_ptr++ = 'S';
	if(response_flags & TCP::ACK)	*flag_ptr++ = 'A';
	if(response_flags & TCP::FIN)	*flag_ptr++ = 'F';
	if(response_flags & TCP::RST)	*flag_ptr++ = 'R';
	*flag_ptr = '\0';

	return flags_str;
}

bool Scan::dry_run = false;
