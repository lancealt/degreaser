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
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <list>

#include "degreaser.h"
#include "subnet.h"

using namespace std;

static uint32_t NETMASKS[] = {
        0x00000000,
        0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
        0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
        0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
        0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
        0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
        0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
        0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
        0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
};

Subnet::Subnet(string s) {
	uint32_t a;
	uint8_t m;
	char* p = strdup(s.c_str());

	if(2 == sscanf(s.c_str(), "%[0-9.]/%hhu", p, &m)) {
		a = ntohl(inet_addr(p));
		if(m > 32) {
			start = end = offset = 0;
			fprintf(stderr, "Error parsing subnet string: %s\n", s.c_str());
			return;
		}

		start = a & NETMASKS[m];
		smask = m;
		offset = 0;
		end = start + (1 << (32 - m));
	} else {
		fprintf(stderr, "Error parsing subnet string: %s\n", s.c_str());
	}

	free(p);
}

Subnet::Subnet(uint32_t addr, uint8_t prefix) {
	if(prefix > 32) {
		start = end = offset = 0;
	}

	start = addr & NETMASKS[prefix];
	smask = prefix;
	offset = 0;
	end = start + (1 << (32 - prefix));
}


Subnet::~Subnet() { }

void Subnet::set(uint32_t b, uint32_t e) {
	start = b;
	end = e;
	offset = 0;
}

uint32_t Subnet::next() {
	if(offset + 1 > (end - start)) {
		return 0;
	}
	return htonl(start + offset++);
}

uint32_t Subnet::mask() {
	return NETMASKS[smask];
}

uint32_t Subnet::first() {
	return start;
}

uint32_t Subnet::last() {
	return end - 1;
}

bool Subnet::exists(uint32_t addr) {
	return (addr < end && addr >= start);
}

bool Subnet::operator<(const Subnet& s) {
	return (start == s.start ? end < s.end : start < s.start);
}

uint32_t Subnet::count() {
	return (end - start);
}
