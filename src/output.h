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

#ifndef OUTPUT_H
#define OUTPUT_H

#include "degreaser.h"
#include "scan.h"

class Output {
	public:
		Output(const DegreaserConfig* c) : config(c) { };
		virtual ~Output() { };
		virtual void output_scan(Scan*) = 0;
		virtual void output_message(const char* f, ...) = 0;
	protected:
		const DegreaserConfig* config;
};

#endif /* OUTPUT_H */
