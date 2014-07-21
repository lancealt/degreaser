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

#ifndef SCAN_H
#define SCAN_H

#include <stdint.h>
#include <crafter.h>

#include <string>

#include "degreaser.h"
#include "subnet_list.h"

using namespace Crafter;

#define SCAN_OPT_SACK		(1<<1)
#define SCAN_OPT_TIMESTAMP	(1<<2)
#define SCAN_OPT_WINSCALE	(1<<3)
#define SCAN_OPT_MSS		(1<<4)

/* Possible results from a scan. Errors should be negative. */
enum ScanResult {	UNREACHABLE	= -4,
					DRY_RUN		= -3,
					FLAGS_ERROR = -2,
					TCP_ERROR	= -1,
					NOT_SCANNED = 0,
					NO_RESPONSE = 1,
					REAL_HOST	= 2,
					REJECT		= 3,
					LABREA		= 4,
					IPTABLES	= 5,
					TARPIT		= 6,
					DELUDE		= 7,
					ZERO_WIN	= 8 };

class Scan {
	public:
		Scan(DegreaserConfig& c, uint32_t a, uint32_t o);
		~Scan(); 

		bool scan(string dev, uint16_t dst_port, uint16_t src_port, uint16_t timeout, uint16_t retries);
		ScanResult get_result() const;

		DegreaserConfig& config;
		in_addr ia;
		string addr;
		uint32_t send_options;
		uint32_t options;
		uint32_t response_time;
		uint32_t window_size;
		uint16_t response_flags;
		TCPOption win_scale;
		TCPOptionTimestamp timestamp;
		TCPOptionMaxSegSize mss;
		TCPOption sack;

		const char* address_to_string();
		const char* options_to_string();
		const char* flags_to_string();
		const char* result_to_string();

		static bool dry_run;
	private:
		Packet* create_syn(string dev, uint16_t timeout, uint16_t retries);
		Packet* create_ack(string dev);
		Packet* create_data_packet(string dev, uint16_t size);
		Packet* create_reset_packet(string dev);
		Packet* create_fin_packet(string dev);
		Packet* send_with_response(string dev, Packet* pkt, uint16_t timeout, uint16_t retries, uint32_t* rtime);
		bool parse_response(Packet* resp);
		uint8_t get_tcp_option_count(Packet* p);
		bool is_restricted();
		void dump_packet(Packet* p);

		ScanResult result;
		uint16_t src_port;
		uint16_t dst_port;
		uint32_t src_seq;
		uint32_t dst_seq;
		char address_str[16];
		char opt_str[5];
		char flags_str[5];

		const static uint16_t MAX_DATA_PACKET_SIZE = 100;
};

#endif /* SCAN_H */
