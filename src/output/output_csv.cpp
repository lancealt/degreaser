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
#include <string>
#include <crafter.h>

#include "output_csv.h"
#include "../scan.h"

using namespace Crafter;

OutputCSV::OutputCSV(const DegreaserConfig* c, string filename) : Output(c) {
	out = fopen(filename.c_str(), "w");
	if(!out) {
		fprintf(stderr, "error: failed to open output file '%s'\n", filename.c_str());
		exit(EXIT_FAILURE);
	}
	fprintf(out, "IP Address,Scan Result,Response Time, Window Size, TCP Flags, TCP Options\n");
}

OutputCSV::~OutputCSV() {
	fclose(out);
}

void OutputCSV::output_scan(Scan* s) {

	fprintf(out, "%s,%s,%u,%u,%s,%s\n",
			s->addr.c_str(),
			s->result_to_string(),
			s->response_time,
			s->window_size,
			s->flags_to_string(),
			s->options_to_string());
	fflush(out);
}

void OutputCSV::output_message(const char* f, ...) {
	// Messages don't get written to output file.
}

