bin_PROGRAMS = degreaser
degreaser_SOURCES = src/degreaser.cpp				\
					src/scan.cpp					\
					src/scanner.cpp					\
					src/subnet.cpp					\
					src/subnet_list.cpp				\
					src/random.cpp					\
					src/linux_firewall.cpp			\
					src/output/output_csv.cpp		\
					src/output/output_curses.cpp	\
					src/output/output_console.cpp	
degreaser_CXXFLAGS = ${CRAFTER_CXXFLAGS}
degreaser_LDADD = ${CRAFTER_LIBS} ${CAPNG_LDADD} ${CURSES_LIB}
man_MANS = degreaser.1

