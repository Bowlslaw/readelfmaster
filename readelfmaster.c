#define _GNU_SOURCE
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#include "/opt/libelfmaster/include/libelfmaster.h"

void usage(const char *progname);
void print_section_headers(void);
void print_program_headers(void);
void print_dynsym_headers(void);
void print_elf_sections(elfobj_t obj, elf_section_iterator_t s_iter,
		struct elf_section section);
void print_elf_phdrs(elfobj_t obj, elf_segment_iterator_t p_iter,
		struct elf_segment segment);
void print_dynamic_symbols(elfobj_t obj, elf_dynsym_iterator_t ds_iter,
		struct elf_symbol symbol);

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	elf_section_iterator_t s_iter;
	elf_segment_iterator_t p_iter;
	elf_dynsym_iterator_t ds_iter;
	struct elf_section section;
	struct elf_segment segment;
	struct elf_symbol symbol;
	const char *progname = argv[0];
	int c;

	bool sectflag = false;
	bool segflag = false;
	bool dynsymflag = false;

	if(argc < 2) {
		usage(progname);
		exit(EXIT_SUCCESS);
	}

	while((c = getopt(argc, argv, ":hdlS")) != 1)
		switch(c) {
			case 'h':
				usage(progname);
				exit(EXIT_SUCCESS);
			case 'd':
				dynsymflag = true;
				break;
			case 'S':
				sectflag = true;
				//printf("Executable base: %#lx\n", elf_executable_text_base(&obj));
				break;
			case 'l':
				segflag = true;
				break;
			case '?':
				fprintf(stderr, "Unknown options '-%c'.\n", optopt);
				exit(EXIT_FAILURE);
			default:
				/* Open the ELF object in forensics mode */
				if(elf_open_object(argv[optind], &obj, ELF_LOAD_F_FORENSICS,
							&error) == false) {
					printf("%s\n", elf_error_msg(&error));
					return -1;
				}
				if(sectflag)
					print_elf_sections(obj, s_iter, section);
				if(segflag)
					print_elf_phdrs(obj, p_iter, segment);
				if(dynsymflag)
					print_dynamic_symbols(obj, ds_iter, symbol);

				exit(EXIT_SUCCESS);
		}
}

void usage(const char *progname)
{
	printf("Usage: %s <binary> [-hdlS]\n"
			"-h\tDisplay this help output.\n"
			"-d\tDisplay Dynamic Symbols.\n"
			"-l\tDisplay Program Headers.\n"
			"-S\tDisplay Section Headers, reconstructing as necessary.\n",
			progname);
}

void print_section_headers(void)
{
	printf("[%s] %-16s  %-17s %-17s %-17s\n" \
			"%9s  %19s %15s  %s  %s  %s",
			"Nr", "Name", "Type", "Address", "Offset",
			"Size", "EntSize", "Flags", "Link", "Info", "Align");
}

void print_program_headers(void)
{
	printf("  %s%19s%17s\n  %s%17s%17s",
			"VAddr", "FileSz", "MemSz",
			"Offset", "Align", "Type");
}

void print_dynsym_headers(void)
{
	printf("    %s%8s%14s %s %7s %5s %8s %3s\n",
			"Num:", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
}

void print_elf_sections(elfobj_t obj, elf_section_iterator_t s_iter,
		struct elf_section section)
{
	unsigned int count = 0;
	elf_section_iterator_init(&obj, &s_iter);
	
	if(obj.flags & ELF_SHDRS_F) {
		printf("[+] Section Headers:\n");
		print_section_headers();
	}
	else {
		printf("[+] Reconstructing Section Headers:\n");
		print_section_headers();
	}

	while(elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		struct elf_section tmp_section;
		char section_link;

		printf("\n[%2u] %-16s  %016lx  %016lx  %08lx\n" \
				"     %016lx  %016lx  %C%C%C  ", 
				count++,
				section.name ? section.name : "",
				0, // Type
				section.address,
				section.offset,
				section.size,
				section.entsize,
				section.flags & SHF_ALLOC ? 'A' : ' ',
				section.flags & SHF_EXECINSTR ? 'X' : ' ',
				section.flags & SHF_WRITE ? 'W' : ' ');

	
		if(elf_section_by_index(&obj, section.link, &tmp_section) == true) {
			if(tmp_section.name != NULL)
				printf("%s", tmp_section.name);
			else
				printf("%u", section.link);
		}
		else {
			printf("%u", section.link);
		}
		printf("%4u  %4lx", section.info, section.align);
	}
	printf("\n");
}

void print_elf_phdrs(elfobj_t obj, elf_segment_iterator_t p_iter,
		struct elf_segment segment)
{
	elf_segment_iterator_init(&obj, &p_iter);
	
	if(obj.flags & ELF_PHDRS_F) {
		printf("\n[+] Program Headers:\n");
		print_program_headers();
	}

	while(elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		printf("\n  %#016lx  %#016lx  %#016lx" \
				"\n  %#016lx  %#016lx  %s\n",
				segment.vaddr,
				segment.filesz,
				segment.memsz,
				segment.offset,
				segment.align,
				elf_segment_type_string(segment.type));
	}
	printf("\n");
}

void print_dynamic_symbols(elfobj_t obj, elf_dynsym_iterator_t ds_iter,
		struct elf_symbol symbol)
{
	unsigned int count = 0;
	elf_dynsym_iterator_init(&obj, &ds_iter);
	print_dynsym_headers();

	while(elf_dynsym_iterator_next(&ds_iter, &symbol) == ELF_ITER_OK) {
		printf("    %d: %#016lx %6d %d %7d %6d %8d   %s\n",
				count++,
				symbol.value,
				symbol.size,
				symbol.type,
				symbol.bind,
				symbol.visibility,
				symbol.shndx,
				symbol.name);
	}
	printf("\n");
}

