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

#ifndef RANDOM_H
#define RANDOM_H

#ifdef HAVE_LIBCPERM

#include <stdint.h>
#include <pthread.h>
#include "cperm.h"

#include "subnet_list.h"

using namespace std;

class RandomSubnetList : public SubnetList {
	public:
		RandomSubnetList();
		~RandomSubnetList();

		uint32_t rand(uint32_t min, uint32_t max);

		void seed();
		uint32_t next_address();

	private:
		uint8_t key[32];
		bool seeded;
		cperm_t* perm;
		pthread_mutex_t lock;
};

#endif /* HAVE_LIBCPERM */
#endif /* RANDOM_H */
