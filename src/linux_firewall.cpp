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
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "degreaser.h"

static const char* port_range_file = "/proc/sys/net/ipv4/ip_local_port_range";
static char iptables_filter[256];

static bool linux_firewall_get_ephemeral_range(uint16_t* min, uint16_t* max);
static bool linux_firewall_filter_packets(bool dry_run, uint16_t min, uint16_t max);

bool linux_firewall_init(DegreaserConfig& config) {
	uint16_t emph_min, emph_max;

	if(config.dry_run || config.fast_scan) {
		return true;
	}

	if(!linux_firewall_get_ephemeral_range(&emph_min, &emph_max)) {
		return false;
	}

	config.src_port_max = emph_min - 1;
	config.src_port_min = config.src_port_max - 1000;

	if(!linux_firewall_filter_packets(config.dry_run, config.src_port_min, config.src_port_max)) {
		return false;
	}

	return true;
}

bool linux_firewall_clear(DegreaserConfig& config) {

	if(config.dry_run || config.fast_scan) {
		return true;
	}

	char* ptr = strstr(iptables_filter, "-A");
	if(!ptr) {
		LOG_WARNING("Failed to parse iptables filter string. Iptables rules will not be removed!\n");
		return false;
	}

	ptr[1] = 'D';

	LOG_DEBUG("Removing iptables rule: %s\n", iptables_filter);
	if(0 != system(iptables_filter)) {
		LOG_WARNING("Removing iptables filter failed!\n");
	}

	return true;
}

static bool linux_firewall_get_ephemeral_range(uint16_t* min, uint16_t* max) {
	FILE* fd = fopen(port_range_file, "r");
	if(!fd) {
		LOG_WARNING("Failed to open '%s'. Reason: %s\n", port_range_file, strerror(errno));
		return false;
	}

	if(2 != fscanf(fd, "%hu %hu", min, max)) {
		LOG_WARNING("Failed to determin ephemeral port range.\n");
		fclose(fd);
		return false;
	}

	LOG_DEBUG("Ephemeral port range: %hu - %hu\n", *min, *max);
	fclose(fd);
	return true;
}

static bool linux_firewall_filter_packets(bool dry_run, uint16_t min, uint16_t max) {

	if(0 > snprintf(iptables_filter , 256, "iptables -A INPUT -p tcp --dport %hu:%hu -j DROP", min, max)) {
		LOG_WARNING("Failed to build iptables filter string.\n");
		return false;
	}

	LOG_DEBUG("Adding iptables filter: %s\n", iptables_filter);

	if(!dry_run) {
		if(0 != system(iptables_filter)) {
			LOG_WARNING("Adding iptables filter failed!\n");
			return false;
		}
	}

	return true;
}
