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

#ifndef SUBNET_LIST_H
#define SUBNET_LIST_H
#include <stdint.h>
#include <pthread.h>
#include <string>
#include <list>

#include "subnet.h"

using namespace std;

class SubnetList {
	public:
		SubnetList();
		virtual ~SubnetList();

		virtual void add_subnet(string s);
		virtual void add_subnet(uint32_t addr, uint8_t prefix);
		void normalize();

		bool exists(uint32_t addr);

		void add_all_subnets(uint8_t prefix);

		virtual uint32_t next_address();

		uint32_t count();
		uint32_t offset();

	protected:
		pthread_mutex_t lock;
		list<Subnet> subnets;
		uint32_t addr_count;
		uint32_t addr_offset;

		bool restricted_address(Subnet& subnet);
		bool restricted_address(uint32_t min, uint32_t max);
	private:
		void coalesce();
		void remove_restricted();
};

#endif /* SUBNET_LIST_H */
