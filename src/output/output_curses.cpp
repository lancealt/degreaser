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

#ifdef HAVE_CURSES
#include <stdio.h>
#include <string>
#include <crafter.h>
#include <ncurses.h>

#include "output_curses.h"
#include "../scan.h"

using namespace Crafter;

OutputCurses::OutputCurses(const DegreaserConfig* c) : Output(c) {
	pthread_mutex_init(&console_lock, NULL);
	initscr();
	start_color();
	init_pair(1, COLOR_RED, COLOR_BLACK);
	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	init_pair(3, COLOR_YELLOW, COLOR_BLACK);
//	output_scan(NULL);
}

OutputCurses::~OutputCurses() {
	printw("\n\nScan Complete. Press any key to exit.");
	refresh();
	getch();
	endwin();
	printf("\n");
	pthread_mutex_destroy(&console_lock);
}

void OutputCurses::output_scan(Scan* s) {
	const static int header_size = 5;
	int num_rows, num_cols;
	int row, col;

	pthread_mutex_lock(&console_lock);

	getmaxyx(stdscr, num_rows, num_cols);
	getyx(stdscr, row, col);

	uint32_t total_count = config->subnets->count();
	uint32_t current_count = config->subnets->offset();
	uint32_t percent = (total_count == 0? 0 : current_count * 100 / total_count);
	uint8_t width = num_cols - 10;
	char* bar_str = (char*)alloca(width+1);

	for(int i = 0; i < width; i++) {
		if(i < (percent * width / 100)) {
			bar_str[i] = '=';
		} else if(i == (percent * width / 100)) {
			bar_str[i] = '>';
		} else {
			bar_str[i] = ' ';
		}
	}
	bar_str[width] = '\0';

	if(scan_history.size() > num_rows - header_size - 4) {
		scan_history.pop_front();
	}
	scan_history.push_back(*s);


	move(0, 0);
	printw("IP: %10u/%-10u Scanned IPs: %-10u       Excluded IPs: %-10u   ",
			config->subnets->offset(), config->subnets->count(),
			config->total_scans, config->total_excluded);
	move(1, 0);
	printw("Real Hosts: %-10u    Rejecting Hosts: %-10u   Errors: %-10u",
			config->total_real, config->total_rejecting, config->total_errors);
	move(2, 0);
	printw("Tarpits: %-10u       LaBrea: %-10u            iptables(tarpit): %-10u",
			config->total_tarpits, config->total_labrea, config->total_iptables);
	move(3, 0);
	printw("         %-10s               %-10s            iptables(delude): %-10u",
			"", "", config->total_delude);
	move(4, 0);
	printw("%3u%% [%s]", percent, bar_str);


	display_history(header_size, 0, num_cols, 0);

	refresh();

	pthread_mutex_unlock(&console_lock);
}

void OutputCurses::display_history(int top, int left, int width, int rows) {
	int attr;

	move(top, left);
	attron(A_BOLD);
	printw("%-18s  %15s  %13s  %-10s  %-10s  %s", "IP Address", "Response Time", "Window Size", "TCP Flags", "TCP Options", "Scan Result");
	attroff(A_BOLD);

	list<Scan>::iterator iter =  scan_history.begin();
	while(iter != scan_history.end()) {
		Scan& s = *iter;

		move(++top, left);
		switch(s.get_result()) {
			case TARPIT:
			case LABREA:
			case IPTABLES:
			case DELUDE:
				attr = A_BOLD | COLOR_PAIR(1);
				break;
			case REAL_HOST:
				attr = COLOR_PAIR(2);
				break;
			case FLAGS_ERROR:
			case TCP_ERROR:
			case UNREACHABLE:
				attr = COLOR_PAIR(3);
				break;
			default:
				attr = 0;
		}

		if(attr) {
			attron(attr);
		}
		printw("%-18s  %15u  %10u       %-6s      %-6s     %-25s",
				s.address_to_string(),
				s.response_time,
				s.window_size,
				s.flags_to_string(),
				s.options_to_string(),
				s.result_to_string());
		if(attr) {
			attroff(attr);
		}

		iter++;
	}
}

void OutputCurses::output_message(const char* f, ...) {
	va_list ap;
	char buffer[100];
	int num_rows, num_cols;

	va_start(ap, f);
	vsnprintf(buffer, 100, f, ap);
	va_end(ap);

	getmaxyx(stdscr, num_rows, num_cols);
	move(num_rows - 1, 0);

	attron(A_BOLD | COLOR_PAIR(2));
	printw("%s\n", buffer);
	attroff(A_BOLD | COLOR_PAIR(2));
	refresh();
}

#endif /* HAVE_CURSES */
