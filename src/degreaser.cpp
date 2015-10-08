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
#include <getopt.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_LIBCAP_NG
	#include <cap-ng.h>
#endif /* HAVE_LIBCAP_NG */

#include <crafter.h>

#include "subnet_list.h"
#include "degreaser.h"
#include "scanner.h"
#include "linux_firewall.h"
#include "output/output_console.h"
#include "output/output_curses.h"
#include "output/output_csv.h"

static struct option long_options[] = {
	{"dev",				required_argument,	0,	'd'},
	{"max-threads",		required_argument,	0,	't'},
	{"port",			required_argument,	0,	'd'},
	{"win-threshold",	required_argument,	0,	'w'},
	{"help",			no_argument,		0,	'h'},
	{"quiet",			no_argument,		0,	'q'},
	{"input-file",		required_argument,	0,	'i'},
	{"skip-lines",		required_argument,	0,	's'},
	{"output-file",		required_argument,	0,	'o'},
	{"all-scans",		no_argument,		0,	'a'},
	{"dry-run",			no_argument,		0,	'D'},
	{"sequential",		no_argument,		0,	's'},
	{"random",			no_argument,		0,	'r'},
	{"fast-scan",		no_argument,		0,	'f'},
	{"pcap",			required_argument,	0,	'P'},
	{"exclude",			required_argument,	0,	'x'},
	{"exclude-rfc6890",	required_argument,	0,	'X'},
	{NULL,				0,					0,	0}
};

void usage(char* prog) {
	fprintf(stderr, "Usage: %s [OPTIONS]... [SUBNETS]...\n", prog);
	fprintf(stderr, "Configuration Options:\n"
	                "  -d, --dev=<dev>            Network device to capture from.\n"
	                "  -t, --max-threads=<num>    Maximum number of threads to use (default: 10).\n"
	                "  -h, --help                 Show this message.\n"
	                "  -q, --quiet                Don't print to the console.\n"
	                "Scan Options:\n"
	                "  -p, --port=<num>           TCP port to scan (default: 80).\n"
	                "  -w, --win-threshold=<num>  Window size threshold (default: 20).\n"
	                "  -a, --all-scans            Output results from all scans, not just LaBrea hosts.\n"
	                "  -D, --dry-run              Simulate scan, but don't actually send out packets.\n"
	                "  -f, --fast-scan            Performs a fast scan.\n"
	                "Subnet Options:\n"
	                "  -i, --input-file=<file>    Input file to read subnets from.\n"
	                "  -o, --output-file=<file>   Write output to this file.\n"
					"  -x, --exclude=<file>       List of subnets to exclude from the scan.\n"
					"      --exclude-rfc6890=<yes/no> Exclude RFC 6890 special-purpose addresses <default: yes>.\n"
#ifdef HAVE_LIBCPERM
	                "  -s, --sequential           Perform a sequential scan.\n"
	                "  -r, --random               Perform a random scan (default).\n"
#endif /* HAVE_LIBCPERM */
	                "  -P, --pcap=<file>          Save all packets sent and received to a PCAP file.\n"
	                "\n"
	                "Subnets to scan can be specified on the command line or read from a file\n"
	                "specified using the -i switch. If no subnets are given and no input file\n"
	                "is given, subnets are read from standard input.\n");
	fprintf(stderr, "Compile Configuration:\n  "
#ifdef HAVE_LIBCAP_NG
					"LIBCAP_NG=1 "
#else
					"LIBCAP_NG=0 "
#endif
#ifdef HAVE_LIBCPERM
					"LIBCPERM=1 "
#else
					"LIBCPERM=0 "
#endif
#ifdef HAVE_CURSES
					"LIBCURSES=1 "
#else
					"LIBCURSES=0 "
#endif
					"\n\n");
}

void capability_check() {
#ifdef HAVE_LIBCAP_NG
	if(capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_RAW)) {
		// TODO: Drop all capabilities except CAP_NET_RAW
		return;
	}
	LOG_ERROR("Degreaser requires root or CAP_NET_RAW capabilities.\n");
	exit(EXIT_FAILURE);
#else
	if(0 == getuid()) {
		return;
	}

	fprintf(stderr, "error: Degreaser requires root.\n");
	exit(EXIT_FAILURE);
#endif /* HAVE_LIBCAP_NG */
}

void load_from_file(SubnetList* subnet_list, string fn) {
	FILE* fd = fopen(fn.c_str(), "r");
	char* line = NULL;
	size_t size;

	if(!fd) {
		fprintf(stderr, "Failed to open input file. Reason: %s\n", strerror(errno));
		return;
	}

	while(-1 != getline(&line, &size, fd)) {
		subnet_list->add_subnet(line);
	}

	fclose(fd);
	free(line);
}

int main(int argc, char** argv) {
	list<pthread_t> threads;
	list<string> input_files;
	list<string> exclude_files;
	DegreaserConfig config;
	char* endptr;
	int c;
	int opt_index;
	long int port;
	pthread_t tid;
	/* Set default config values */
	config.device = "";
	config.max_threads = 10;
	config.port = 80;
	config.win_threshold = 20;
	config.verbose = 1;
	config.retries = 1;
	config.timeout = 5;
	config.total_scans = 0;
	config.total_hits = 0;
	config.total_tarpits = 0;
	config.total_labrea = 0;
	config.total_iptables = 0;
	config.total_delude = 0;
	config.total_excluded = 0;
	config.total_real = 0;
	config.total_rejecting = 0;
	config.total_errors = 0;
	config.all_scans = false;
	config.dry_run = false;
	config.random = true;
	config.fast_scan = false;
	config.exclude_rfc6890 = true;
	config.pcap_handle = NULL;
	config.pcap_dumper = NULL;
	pthread_mutex_init(&config.global_lock, NULL);
	pthread_mutex_init(&config.pcap_lock, NULL);

	/* Process command line arguments */
	while(-1 != (c = getopt_long(argc, argv, "d:t:p:w:hqi:o:aDrsP:fx:X:", long_options, &opt_index))) {
		switch(c) {
			case 'd':
				config.device = optarg;
				break;
			case 't':
				config.max_threads = strtol(optarg, &endptr, 10);
				if(*endptr != '\0') { 
					LOG_ERROR("invalid number of threads (%s)\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 'p':
				port = strtol(optarg, &endptr, 10);
				if(*endptr != '\0' || config.port > 65535) { 
					LOG_ERROR("invalid TCP port number (%s)\n", optarg);
					exit(EXIT_FAILURE);
				}
				config.port = port;
				break;
			case 'w':
				config.win_threshold = strtol(optarg, &endptr, 10);
				if(*endptr != '\0') { 
					LOG_ERROR("invalid window size (%s)\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 'q':
				config.verbose = 0;
				break;
			case 'i':
				input_files.push_back(optarg);
				break;
			case 'o':
				config.outputs.push_back(new OutputCSV(&config, optarg));
				break;
			case 'a':
				config.all_scans = true;
				 break;
			case 'D':
				 config.dry_run = true;
				 Scan::dry_run = true;
				 LOG_DEBUG("degreaser running in dry run mode. No packets will be sent.\n");
				 break;
			case 's':
				 config.random = false;
				 break;
			case 'r':
				 config.random = true;
				 break;
			case 'P':
				 config.pcap_file = optarg;
				 break;
			case 'f':
				 config.fast_scan = true;
				 break;
			case 'x':
				 exclude_files.push_back(optarg);
				 break;
			case 'X':
				 config.exclude_rfc6890 = false;
				 break;
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if(!config.dry_run) {
		capability_check();
	}

	linux_firewall_init(config);

#ifdef HAVE_LIBCPERM
	if(config.random) {
		config.subnets = new RandomSubnetList();
	} else {
		config.subnets = new SubnetList();
	}
#else
	config.subnets = new SubnetList();
#endif /* HAVE_LIBCPERM */

	config.exclude_list = new SubnetList();

	if(config.pcap_file != "") {
		OpenPcapDumper(DLT_RAW, config.pcap_file, config.pcap_handle, config.pcap_dumper);
	}

	/* Add subnets from input files */
	for(list<string>::iterator iter = input_files.begin(); iter != input_files.end(); iter++) {
		load_from_file(config.subnets, *iter);
	}

	/* Add subnets from the command line */
	for(int i = optind; i < argc; i++) {
		LOG_DEBUG("Adding subnet: %s\n", argv[i]);
		config.subnets->add_subnet(argv[i]);
	}

	/* Add excluded subnets from input files */
	for(list<string>::iterator iter = exclude_files.begin(); iter != exclude_files.end(); iter++) {
		load_from_file(config.exclude_list, *iter);
	}

	//subnet_list.normalize();

	if(config.verbose) {
#ifdef HAVE_CURSES
		config.outputs.push_back(new OutputCurses(&config));
#else
		config.outputs.push_back(new OutputConsole(&config));
#endif
	}

	/* Spawn worker threads (if needed) and start scanning */
	int spawn_delay = config.timeout * 1000000 / config.max_threads;
	for(int i = 1; i < config.max_threads; i++) {
		pthread_create(&tid, NULL, (void* (*)(void*))scanner, (void*)&config);
		for(list<Output*>::iterator iter = config.outputs.begin(); iter != config.outputs.end(); iter++) {
			(*iter)->output_message("Starting thread %d/%d...", i, config.max_threads);
		}
		threads.push_back(tid);
		usleep(spawn_delay);
	}
	for(list<Output*>::iterator iter = config.outputs.begin(); iter != config.outputs.end(); iter++) {
		(*iter)->output_message("");
	}
	
	scanner(&config);

	/* Clean up threads */
	while(threads.size() > 0) {
		tid = *threads.begin();
		threads.pop_front();
		pthread_join(tid, NULL);
	}

	for(list<Output*>::iterator iter = config.outputs.begin(); iter != config.outputs.end(); iter++) {
		delete (*iter);
	}

	linux_firewall_clear(config);

	LOG_DEBUG("Total Scanned Hosts: %u\n", config.total_scans);
	LOG_DEBUG("Total Responding Hosts: %u (%.2f%%)\n", config.total_hits,
			config.total_hits/(double)config.total_scans * 100);
	LOG_DEBUG("Total Tarpit Hosts: %u (%.2f%%)\n", config.total_tarpits,
			config.total_tarpits/(double)config.total_scans * 100);
	LOG_DEBUG("Total LaBrea Hosts: %u (%.2f%%)\n", config.total_labrea,
			config.total_labrea/(double)config.total_scans * 100);
	LOG_DEBUG("Total iptables Hosts: %u (%.2f%%)\n", config.total_iptables,
			config.total_iptables/(double)config.total_scans * 100);
	LOG_DEBUG("Total Excluded Hosts: %u\n", config.total_excluded);

	pthread_mutex_destroy(&config.pcap_lock);
	pthread_mutex_destroy(&config.global_lock);

	if(config.pcap_file != "") {
		ClosePcapDumper(config.pcap_handle, config.pcap_dumper);
	}

	delete config.subnets;
	
	return 0;
}
