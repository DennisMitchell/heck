CC = gcc
WARN = -Wall -Wextra -Wpedantic -Werror
OPT = -march=native -O2 -s
CFLAGS = $(WARN) $(OPT)

%: %.c Makefile
	$(CC) $(CFLAGS) -o $@ $<