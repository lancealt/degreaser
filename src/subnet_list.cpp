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
#include <pthread.h>
#include <string>
#include <list>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "degreaser.h"
#include "subnet_list.h"

using namespace std;

SubnetList::SubnetList() {
	addr_offset = addr_count = 0;
	pthread_mutex_init(&lock, NULL);
};

SubnetList::~SubnetList() {
	pthread_mutex_destroy(&lock);
};

void SubnetList::add_subnet(string s) {
	Subnet subnet = Subnet(s);
	subnets.push_back(subnet);
	addr_count += subnet.count();
}

void SubnetList::add_subnet(uint32_t addr, uint8_t prefix) {
	Subnet subnet = Subnet(addr, prefix);
	subnets.push_back(subnet);
	addr_count += subnet.count();
}

uint32_t SubnetList::count() {
	return addr_count;
}

uint32_t SubnetList::offset() {
	return addr_offset;
}


uint32_t SubnetList::next_address() {
	uint32_t next = 0;

	pthread_mutex_lock(&lock);
	
	while(subnets.size() > 0) {
		Subnet& s = *(subnets.begin());
		next = s.next();

		if(next != 0) {
			break;
		}

		subnets.pop_front();
	}

	addr_offset++;

	pthread_mutex_unlock(&lock);

	return next;
}

bool SubnetList::exists(uint32_t addr) {
	list<Subnet>::iterator iter = subnets.begin();
	while(iter != subnets.end()) {
		if((*iter).exists(addr)) {
			return true;
		}
		iter++;
	}
	return false;
}


void SubnetList::normalize() {
//	coalesce();
//	remove_restricted();

	LOG_DEBUG("List of subnets:\n");
	list<Subnet>::iterator iter;
	for(iter = subnets.begin(); iter != subnets.end(); iter++) {
		LOG_DEBUG("%u => %u\n", (*iter).first(), (*iter).last());
	}
}

void SubnetList::coalesce() {
	subnets.sort();
	list<Subnet>::iterator iter, prev;

	prev = subnets.begin();
	iter = subnets.begin();
	for(iter++; iter != subnets.end(); iter++, prev++) {
		Subnet& a = *prev;
		Subnet& b = *iter;
		if(prev == iter) {
			break;
		} else if(a.last() >= b.first()) {
			if(a.last() >= b.last()) {
				iter = subnets.erase(iter);
				LOG_DEBUG("Removing completely overlapping subnet.\n");
			} else {
				a.set(a.first(), b.last());
				iter = subnets.erase(iter);
				LOG_DEBUG("Coalescing adjacent subnets.\n");
			}
		}
	}
}

void SubnetList::add_all_subnets(uint8_t prefix) {
	if(prefix > 32) {
		LOG_WARNING("Prefix size was greater than 32. Ignoring.\n");
		return;
	}

	uint32_t subnet_size = 1 << (32-prefix);
	uint32_t count = 0, restrict_count = 0, addr = 0;

	LOG_DEBUG("Adding all /%u subnets...\n", prefix);
	do {
		add_subnet(addr, prefix);
		count++;
		addr += subnet_size;
	} while(addr != 0);
	LOG_DEBUG("Added %u subnets. %u restricted subnets were not added.\n", count, restrict_count);
}

