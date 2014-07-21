#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <crafter.h>

#include "output_console.h"
#include "../scan.h"

using namespace Crafter;

OutputConsole::OutputConsole(const DegreaserConfig* c) : Output(c) {
}

OutputConsole::~OutputConsole() {
}

void OutputConsole::output_scan(Scan* s) {
	char tcp_data[128];

	if(!config->all_scans && s->get_result() == NO_RESPONSE) {
		return;
	}

	if(s->get_result() > NO_RESPONSE) {
		snprintf(tcp_data, 128, "RespTime=%-7u  WinSize=%-7u  TCPFlags=%-7s  TCPOptions=%s",
				s->response_time,
				s->window_size,
				s->flags_to_string(),
				s->options_to_string());
	} else {
		tcp_data[0] = '\0';
	}

	fprintf(stdout, "Host %-15s : %s %s\n", s->addr.c_str(), s->result_to_string(), tcp_data);
	fflush(stdout);
}

void OutputConsole::output_message(const char* f, ...) {
	va_list ap;
	va_start(ap, f);
	vprintf(f, ap);
	va_end(ap);
	fflush(stdout);
}

