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

#ifndef OUTPUT_CONSOLE_H
#define OUTPUT_CONSOLE_H

#include <string>
#include <pthread.h>

#include "../output.h"

class OutputConsole: public Output {
	public:
		OutputConsole(const DegreaserConfig*);
		~OutputConsole();

		void output_scan(Scan*);
		void output_message(const char* f, ...);
	private:
		pthread_mutex_t lock;
};

#endif /* OUTPUT_CONSOLE_H */
