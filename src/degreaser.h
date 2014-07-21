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

#ifndef DEGREASER_H
#define DEGREASER_H

#include <stdint.h>
#include <pthread.h>
#include <string>
#include <list>
#include <pcap.h>

#include "subnet_list.h"
#include "random.h"

#define LOG_OUT(level, format, ...)
//#define LOG_OUT(level, format, ...) fprintf(stderr, level format, ##__VA_ARGS__);
#define LOG_DEBUG(format, ...) LOG_OUT("debug: ", format, ##__VA_ARGS__);
#define LOG_WARNING(format, ...) LOG_OUT("warning: ", format, ##__VA_ARGS__);
#define LOG_ERROR(format, ...) LOG_OUT("error: ", format, ##__VA_ARGS__);

using namespace std;

class Output;

struct DegreaserConfig {
	string device;
	uint16_t max_threads;
	uint16_t port;
	uint32_t win_threshold;
	uint8_t verbose;
	string in_file;
	string out_file;
	uint32_t skip_lines;
	uint16_t timeout;
	uint16_t retries;
	bool all_scans;
	bool dry_run;
	bool fast_scan;
	bool exclude_rfc6890;
	uint16_t src_port_min;
	uint16_t src_port_max;
	bool random;

	uint32_t total_scans;
	uint32_t total_hits;
	uint32_t total_tarpits;
	uint32_t total_labrea;
	uint32_t total_iptables;
	uint32_t total_delude;
	uint32_t total_excluded;
	uint32_t total_errors;
	uint32_t total_real;
	uint32_t total_rejecting;

	SubnetList* subnets;
	SubnetList* exclude_list;

	list<Output*> outputs;

	pthread_mutex_t global_lock;
	pthread_mutex_t pcap_lock;

	string pcap_file;
	pcap_t* pcap_handle;
	pcap_dumper_t* pcap_dumper;
};



#endif /* DEGREASER_H */
