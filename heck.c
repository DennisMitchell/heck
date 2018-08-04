#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>

typedef uint8_t cell_t;
typedef int64_t word_t;

static const size_t word_size = sizeof(word_t);

#define	op_add      0x20444441
#define op_add_ofst 0x4f444441
#define op_cmpz     0x5a504d43
#define op_fma      0x20414d46
#define op_getc     0x43544547
#define op_jnz      0x205a4e4a
#define op_jz       0x20205a4a
#define op_nop      0x20504f4e
#define op_putc     0x43545550
#define op_seek     0x4b454553
#define op_setm     0x4d544553
#define op_zero     0x4f52455a

typedef struct he_s
{
	word_t *mjmps, *pjmps, *pcode;
	char *mcode;
	size_t mcpos, mjpos, pjpos, pcpos;
	cell_t add_ofst, add_orig;
	word_t seek, seekmax, seekmin;
	bool loopopt;
} he_t;

const cell_t neginv[] =
{
	  0, 255,   0,  85,   0,  51,   0,  73,   0, 199,   0,  93,   0,  59,   0,  17,
	  0,  15,   0, 229,   0, 195,   0,  89,   0, 215,   0, 237,   0, 203,   0,  33,
	  0,  31,   0, 117,   0,  83,   0, 105,   0, 231,   0, 125,   0,  91,   0,  49,
	  0,  47,   0,   5,   0, 227,   0, 121,   0, 247,   0,  13,   0, 235,   0,  65,
	  0,  63,   0, 149,   0, 115,   0, 137,   0,   7,   0, 157,   0, 123,   0,  81,
	  0,  79,   0,  37,   0,   3,   0, 153,   0,  23,   0,  45,   0,  11,   0,  97,
	  0,  95,   0, 181,   0, 147,   0, 169,   0,  39,   0, 189,   0, 155,   0, 113,
	  0, 111,   0,  69,   0,  35,   0, 185,   0,  55,   0,  77,   0,  43,   0, 129,
	  0, 127,   0, 213,   0, 179,   0, 201,   0,  71,   0, 221,   0, 187,   0, 145,
	  0, 143,   0, 101,   0,  67,   0, 217,   0,  87,   0, 109,   0,  75,   0, 161,
	  0, 159,   0, 245,   0, 211,   0, 233,   0, 103,   0, 253,   0, 219,   0, 177,
	  0, 175,   0, 133,   0,  99,   0, 249,   0, 119,   0, 141,   0, 107,   0, 193,
	  0, 191,   0,  21,   0, 243,   0,   9,   0, 135,   0,  29,   0, 251,   0, 209,
	  0, 207,   0, 165,   0, 131,   0,  25,   0, 151,   0, 173,   0, 139,   0, 225,
	  0, 223,   0,  53,   0,  19,   0,  41,   0, 167,   0,  61,   0,  27,   0, 241,
	  0, 239,   0, 197,   0, 163,   0,  57,   0, 183,   0, 205,   0, 171,   0,   1
};

void error(char *message)
{
	if(message)
		fprintf(stderr, "%s\n", message);
	else
		err(errno, "Error");

	exit(1);
}

void bounds(int signal)
{
	if(signal == SIGSEGV)
		error("Memory pointer out of bounds.");
}

void *mmap_alloc(size_t size)
{
	static const int prot = PROT_READ | PROT_WRITE;
	static const int flags = MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE;
	return mmap(NULL, size, prot, flags, -1, 0);
}

void he_flush(he_t *he, bool set_flags)
{
	if(!he->seek)
	{
		he->add_ofst += he->add_orig;
		he->add_orig = 0;
	}
	else if(he->add_orig)
	{
		he->pcode[he->pcpos++] = op_add;
		he->pcode[he->pcpos++] = he->add_orig;
		he->add_orig = 0;
	}

	if(he->seek)
	{
		he->pcode[he->pcpos++] = op_seek;
		he->pcode[he->pcpos++] = he->seek;
		he->seek = 0;
	}

	if(he->add_ofst)
	{
		he->pcode[he->pcpos++] = op_add;
		he->pcode[he->pcpos++] = he->add_ofst;
		he->add_ofst = 0;
	}
	else if(set_flags)
	{
		he->pcode[he->pcpos++] = op_cmpz;
	}
}

void he_scode_to_pcode(he_t *he, char *filename)
{
	FILE *fileptr = fopen(filename, "rb");

	if(fileptr == NULL)
		error(NULL);

	char buffer[PAGE_SIZE];

	do
	{
		size_t nbytes = fread(buffer, sizeof(char), PAGE_SIZE, fileptr);

		if(ferror(fileptr))
			error(NULL);

		he->pjmps = realloc(he->pjmps, (he->pjpos + PAGE_SIZE) * word_size);
		he->pcode = realloc(he->pcode, (he->pcpos + PAGE_SIZE * 2) * word_size);

		if(he->pjmps == NULL || he->pcode == NULL)
			error(NULL);

		for(size_t byte, bufpos = 0; bufpos < nbytes; bufpos++)
		{
			word_t jzpos;

			switch((byte = buffer[bufpos]))
			{
				case '+':
					++he->add_ofst;
					break;

				case '-':
					--he->add_ofst;
					break;

				case '<':
				case '>':
					if(he->add_ofst)
					{
						if(!he->seek)
						{
							he->add_orig += he->add_ofst;
						}
						else
						{
							he->pcode[he->pcpos++] = op_add_ofst;
							he->pcode[he->pcpos++] = he->add_ofst;
							he->pcode[he->pcpos++] = he->seek;
						}

						he->add_ofst = 0;
					}

					he->seek += byte - '=';
					he->seekmax = he->seek > he->seekmax ? he->seek : he->seekmax;
					he->seekmin = he->seek < he->seekmin ? he->seek : he->seekmin;
					break;

				case '[':
					he_flush(he, true);
					he->pjmps[he->pjpos++] = he->pcpos;
					he->pcode[he->pcpos++] = op_jz;
					he->pcode[he->pcpos++] = op_nop;
					he->loopopt = true;
					break;

				case ']':
					jzpos = he->pjmps[--he->pjpos];

					if(he->seek)
					{
						he->loopopt = false;
					}
					else
					{
						he->add_orig += he->add_ofst;
						he->add_ofst = 0;
						he->loopopt &= (he->add_orig & 1) == 1;
					}
					
					if(he->loopopt)
					{
						cell_t factor = neginv[he->add_orig];
						he->add_orig = 0;

						if(he->pcode[jzpos - 1] == op_cmpz)
							he->pcode[jzpos - 1] = op_nop;

						he->pcode[jzpos++] = op_setm;
						he->pcode[jzpos++] = op_nop;

						for(size_t pcpos = jzpos; pcpos < he->pcpos; pcpos++)
						{
							switch(he->pcode[pcpos])
							{
								case op_add_ofst:
									he->pcode[pcpos++] = op_fma;
									he->pcode[pcpos++] *= factor;
									break;

								case op_add:
								case op_seek:
									++pcpos;
									break;

								default:
									error("Internal error.");
							}
						}

						he->pcode[he->pcpos++] = op_zero;
					}
					else
					{
						he_flush(he, true);
						he->pcode[he->pcpos++] = op_jnz;
						he->pcode[he->pcpos++] = ++jzpos + 1;
						he->pcode[jzpos] = he->pcpos;
					}

					he->loopopt = false;
					break;

				case ',':
					he_flush(he, false);
					he->pcode[he->pcpos++] = op_zero;
					he->pcode[he->pcpos++] = op_getc;
					he->pcode[he->pcpos++] = op_nop;
					break;

				case '.':
					he_flush(he, false);
					he->pcode[he->pcpos++] = op_putc;
					he->pcode[he->pcpos++] = op_nop;
					break;
			}
		}
	}
	while(!feof(fileptr));

	he_flush(he, false);
}

void emit(he_t *he, void *src, size_t nbytes)
{
	memcpy(&he->mcode[he->mcpos], src, nbytes);
	he->mcpos += nbytes;
}

void he_pcode_to_mcode(he_t *he)
{
	he->mjmps = realloc(he->mjmps, he->pcpos * word_size);
	size_t mcsize_max = he->pcpos * word_size * 2 + 16;
	he->mcode = mmap_alloc(mcsize_max);

	if(he->mjmps == NULL || he->mcode == MAP_FAILED)
		error(NULL);

	for(size_t pcpos = 0; pcpos < he->pcpos; )
	{
		word_t jmpdist, jzpos;

		switch(he->pcode[pcpos++])
		{
			case op_add:
			{
				cell_t add = he->pcode[pcpos++];

				if(add == 1)
				{
					emit(he, "\xfe\x06", 2);
				}
				else if(add == 255)
				{
					emit(he, "\xfe\x0e", 2);
				}
				else
				{
					emit(he, "\x80\x06", 2);
					emit(he, &add, 1);
				}

				break;
			}

			case op_add_ofst:
			{
				cell_t add = he->pcode[pcpos++];
				word_t offset = he->pcode[pcpos++];

				if((int8_t) offset == offset)
				{
					emit(he, "\x80\x46", 2);
					emit(he, &offset, 1);
				}
				else
				{
					emit(he, "\x80\x86", 2);
					emit(he, &offset, 4);
				}

				emit(he, &add, 1);
				break;
			}

			case op_cmpz:
				emit(he, "\x80\x3e\x00", 3);
				break;

			case op_fma:
			{
				cell_t factor = he->pcode[pcpos++];
				word_t offset = he->pcode[pcpos++];
				bool small = (int8_t) offset == offset;

				if(factor == 1)
				{
					emit(he, small ? "\x00\x56" : "\x00\x96", 2);
				}
				else if(factor == 255)
				{
					emit(he, small ? "\x28\x56" : "\x28\x96", 2);
				}
				else
				{
					emit(he, "\xb0", 1);
					emit(he, &factor, 1);
					emit(he, small ? "\xf6\xe2\x00\x46" : "\xf6\xe2\x00\x86", 4);
				}

				emit(he, &offset, small ? 1 : 4);
				break;
			}

			case op_getc:
				emit(he, "\x48\x31\xc0\xb2\x01\x48\x31\xff\x0f\x05", 10);
				break;

			case op_jnz:
			{
				jzpos = he->mjmps[--he->mjpos];
				jmpdist = he->mcpos - jzpos;
				bool small = jmpdist - 4 < 128;

				jmpdist -= small ? 4 : 0;
				memcpy(&he->mcode[jzpos + 2], &jmpdist, 4);
				jmpdist=-jmpdist;

				if(small)
				{
					emit(he, "\x75", 1);
					emit(he, &jmpdist, 1);
				}
				else
				{
					emit(he, "\x0f\x85", 2);
					emit(he, &jmpdist, 4);
				}

				break;
			}

			case op_jz:
				he->mjmps[he->mjpos++] = he->mcpos;
				emit(he, "\x0f\x84????", 6);
				break;

			case op_nop:
				break;

			case op_putc:
				emit(he, "\xb2\x01\x48\x89\xd0\x48\x89\xd7\x0f\x05", 10);
				break;

			case op_seek:
				{
					word_t offset = he->pcode[pcpos++];

					if((int8_t) offset == offset)
					{
						emit(he, "\x48\x83\xc6", 3);
						emit(he, &offset, 1);
					}
					else
					{
						emit(he, "\x48\x81\xc6", 3);
						emit(he, &offset, 4);
					}

					break;
				}

			case op_setm:
				emit(he, "\x0f\xb6\x16", 3);
				break;

			case op_zero:
				emit(he, "\xc6\x06\x00", 3);
				break;
		}
	}

	emit(he, "\xc3", 1);

	if(mprotect(he->mcode, mcsize_max, PROT_EXEC) == -1)
		error(NULL);
}

void he_run(he_t *he)
{
	size_t lguard = -(he->seekmin & PAGE_MASK), rguard = -(-he->seekmax & PAGE_MASK);
	size_t tape_size = 0;
	cell_t *tape = MAP_FAILED;

	while (tape == MAP_FAILED)
	{
		tape_size = (tape_size - 1) / 2 + 1;
		tape = mmap_alloc(tape_size);
	}

	if(mprotect(tape, lguard, PROT_NONE) == -1)
		error(NULL);

	if(mprotect(&tape[tape_size - rguard], rguard, PROT_NONE) == -1)
		error(NULL);

	signal(SIGSEGV, bounds);

	size_t head = (lguard + tape_size - rguard) / 2;;
	asm volatile("mov %0, %%rsi" : : "r" (tape + head));
	asm volatile("call *%0" : : "r" (he->mcode));
}

int main(int argc, char *argv[])
{
	if(argc < 2)
		error("Usage: bff FILENAME");

	he_t he = {0};
	he_scode_to_pcode(&he, argv[1]);
	he_pcode_to_mcode(&he);
	he_run(&he);

	return 0;
}
