CC = gcc
WARN = -Wall -Wextra -Wpedantic -Werror
OPT = -march=native -O2 -s
CFLAGS = $(WARN) $(OPT)

heck: *.c Makefile
	$(CC) $(CFLAGS) -o $@ $<