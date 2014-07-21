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

#ifndef SUBNET_H
#define SUBNET_H
#include <stdint.h>
#include <string>

using namespace std;

class Subnet {
	public:
		Subnet(string s);
		Subnet(uint32_t addr, uint8_t prefix);
		~Subnet();

		void set(uint32_t begin, uint32_t end);

		uint32_t next();
		uint32_t mask();

		uint32_t first();
		uint32_t last();
		uint32_t count();

		bool exists(uint32_t addr);

		bool operator<(const Subnet&);
	private:
		uint32_t start;
		uint32_t end;
		uint32_t offset;
		uint8_t smask;
};

#endif /* SUBNET_H */
