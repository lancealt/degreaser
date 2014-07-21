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

#include <stdint.h>
#include <string>

#include "degreaser.h"
#include "subnet_list.h"
#include "scan.h"
#include "output.h"

#define IP_ADDRESS(a,b,c,d) (uint32_t)((a<<24) + (b<<16) + (c<<8) + (d))

struct IPv4AddressRange {
	uint32_t min;
	uint32_t max;
	uint8_t netmask;
};

static IPv4AddressRange reserved_addresses[] = {
	{ IP_ADDRESS(0,0,0,0),			IP_ADDRESS(0,255,255,255),		8	},
	{ IP_ADDRESS(10,0,0,0),			IP_ADDRESS(10,255,255,255),		8	},
	{ IP_ADDRESS(100,64,0,0),		IP_ADDRESS(100,127,255,255),	10	},
	{ IP_ADDRESS(127,0,0,0),		IP_ADDRESS(127,255,255,255),	8	},
	{ IP_ADDRESS(169,254,0,0),		IP_ADDRESS(169,254,255,255),	16	},
	{ IP_ADDRESS(172,16,0,0),		IP_ADDRESS(172,31,255,255),		12	},
	{ IP_ADDRESS(192,0,0,0),		IP_ADDRESS(192,0,0,7),			29	},
	{ IP_ADDRESS(192,0,2,0),		IP_ADDRESS(192,0,2,255),		24	},
	{ IP_ADDRESS(192,88,99,0),		IP_ADDRESS(192,88,99,255),		24	},
	{ IP_ADDRESS(192,168,0,0),		IP_ADDRESS(192,168,255,255),	16	},
	{ IP_ADDRESS(198,18,0,0),		IP_ADDRESS(198,19,255,255),		15	},
	{ IP_ADDRESS(198,51,100,0),		IP_ADDRESS(198,51,100,255),		24	},
	{ IP_ADDRESS(203,0,113,0),		IP_ADDRESS(203,0,113,255),		24	},
	{ IP_ADDRESS(224,0,0,0),		IP_ADDRESS(239,255,255,255),	4	},
	{ IP_ADDRESS(240,0,0,0),		IP_ADDRESS(255,255,255,254),	4	},
	{ IP_ADDRESS(255,255,255,255),	IP_ADDRESS(255,255,255,255),	32	},
	{ 0,								0,							0	},
};


static uint16_t scanner_get_random_port(uint16_t min, uint16_t max);
static void scanner_add_restricted_addresses(DegreaserConfig* config);

void scanner(DegreaserConfig* config) {
	uint32_t addr;

	if(config->exclude_rfc6890) {
		scanner_add_restricted_addresses(config);
	}

	/* Keep looping while there are more addressed to scan */
	while(0 != (addr = config->subnets->next_address())) {

		pthread_mutex_lock(&config->global_lock);
		if(config->exclude_list->exists(htonl(addr))) {
			config->total_excluded++;
			pthread_mutex_unlock(&config->global_lock);
			continue;
		}
		config->total_scans++;
		pthread_mutex_unlock(&config->global_lock);

		Scan* s = new Scan(*config, addr, 0xffffffff);
		uint16_t src_port = scanner_get_random_port(config->src_port_min, config->src_port_max);

		/* Perform the scan */
		if(true == s->scan(config->device, config->port, src_port, config->timeout, config->retries)) {
			pthread_mutex_lock(&config->global_lock);
			switch(s->get_result()) {
				case TARPIT:
					config->total_tarpits++;
					break;
				case LABREA:
					config->total_tarpits++;
					config->total_labrea++;
					break;
				case IPTABLES:
					config->total_tarpits++;
					config->total_iptables++;
					break;
				case DELUDE:
					config->total_delude++;
					break;
				case REAL_HOST:
					config->total_real++;
					break;
				case REJECT:
					config->total_rejecting++;
					break;
				case FLAGS_ERROR:
				case TCP_ERROR:
					config->total_errors++;
					break;
				default:
					break;
			}

			config->total_hits++;
			pthread_mutex_unlock(&config->global_lock);
		}

		/* Iterate through all the output modules with the results of this scan */
		list<Output*>::iterator iter = config->outputs.begin();
		for(;iter != config->outputs.end(); ++iter) {
			(*iter)->output_scan(s);
		}

		delete s;
	}
}

static uint16_t scanner_get_random_port(uint16_t min, uint16_t max) {
	uint32_t range = max - min;
	double r = rand();

	return (r / RAND_MAX) * range + min;
}

static void scanner_add_restricted_addresses(DegreaserConfig* config) {
	IPv4AddressRange* r;

	for(r = reserved_addresses; r->min != 0 || r->max != 0; r++) {
		config->exclude_list->add_subnet(r->min, r->netmask);
	}

}
