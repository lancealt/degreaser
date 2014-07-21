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

#ifdef HAVE_LIBCPERM
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <cperm.h>

#include "degreaser.h"
#include "random.h"

#define FLIP_BYTES(a) ((((a) & 0xff) << 24) | ((((a) >> 8) & 0xff) << 16) | ((((a) >> 16) & 0xff) << 8) | ((((a) >> 24) & 0xff)))

RandomSubnetList::RandomSubnetList() {
	seeded = false;
	perm = NULL;
	pthread_mutex_init(&lock, NULL);
}

RandomSubnetList::~RandomSubnetList() {
	if(perm) {
		cperm_destroy(perm);
	}
	pthread_mutex_destroy(&lock);
}

void RandomSubnetList::seed() {
	uint8_t buffer[16];
	PermMode mode = PERM_MODE_CYCLE;

	/* Switch to libperm's prefix mode if the total number of hosts to scan is less than 50000. This number
	   is completely arbitrary. The choice is a time/space tradeoff. More testing should be done to select
	   the right switchover point.
	   */
	if(addr_count < 50000) {
		mode = PERM_MODE_PREFIX;
	}
	perm = cperm_create(addr_count, mode, PERM_CIPHER_RC5, buffer, 16);
	if(!perm) {
		LOG_ERROR("Failed to initialize permutation of size %u. Code: %d\n", count, cperm_get_last_error());
		exit(1);
	}
	seeded = true;
}
	

uint32_t RandomSubnetList::next_address() {
	list<Subnet>::iterator iter;
	uint32_t next, subnet_count, current = 0;

	pthread_mutex_lock(&lock);

	if(!seeded) {
		seed();
	}

	if(PERM_END == cperm_next(perm, &next)) {
		pthread_mutex_unlock(&lock);
		return 0;
	}

	pthread_mutex_unlock(&lock);

	for(iter = subnets.begin(); iter != subnets.end(); iter++) {
		subnet_count = (*iter).count();
		if(next >= current && next < current + subnet_count) {
			addr_offset++;
			return FLIP_BYTES((*iter).first() + (next - current));
		}
		current += subnet_count;
	}

	return 0;
}

uint32_t RandomSubnetList::rand(uint32_t min, uint32_t max) {
	return ::rand() % (max - min) + min;
}

#endif /* HAVE_LIBCPERM */
