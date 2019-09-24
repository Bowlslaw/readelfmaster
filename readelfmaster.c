#define _GNU_SOURCE
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#include "/opt/libelfmaster/include/libelfmaster.h"

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	elf_section_iterator_t s_iter;
	elf_segment_iterator_t p_iter;
	struct elf_section section;
	struct elf_segment segment;
	unsigned int count = 0;
	int c;

	if(argc < 2) {
		printf("Usage: %s <binary> [-S]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	/* Open the ELF object in forensics mode */
	if(elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		printf("%s\n", elf_error_msg(&error));
		return -1;
	}

	/* -S will print the sections headers. If they don't exist, libelfmaster
	 * will reconstruct and print them. */
	while((c = getopt(argc, argv, "Sl")) != 1)
		switch(c) {
			case 'S':
				/* Section headers */
				/*  [Nr] Name              Type             Address           Offset
				 *       Size              EntSize          Flags  Link  Info  Align */
				if(obj.flags & ELF_SHDRS_F) {
					printf("*** Section Headers:\n");
					printf("[%s] %-16s  %-17s %-17s %-17s\n" \
							"%9s  %19s %15s  %s  %s  %s", 
							"Nr", "Name", "Type", "Address", "Offset",
							"Size", "EntSize", "Flags", "Link", "Info", "Align");
				}
				else {
					printf("[+] Reconstructing Section Headers:\n");
					printf("[%s] %-16s  %-17s %-17s %-17s\n" \
							"%9s  %19s %15s  %s  %s  %s", 
							"Nr", "Name", "Type", "Address", "Offset",
							"Size", "EntSize", "Flags", "Link", "Info", "Align");
				}

				//printf("Executable base: %#lx\n", elf_executable_text_base(&obj));
				
				elf_section_iterator_init(&obj, &s_iter);
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
				break;
			case 'l':
				/* program headers */
				if(obj.flags & ELF_PHDRS_F) {
					printf("\n[+] Program Headers:\n");
					printf("  %s%19s%17s\n  %s%17s%17s",
							"VAddr", "FileSz", "MemSz",
							"Offset", "Align", "Type");
				}

				elf_segment_iterator_init(&obj, &p_iter);
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
				break;
			case '?':
				fprintf(stderr, "Unknown options '-%c'.\n", optopt);
			default:
				exit(EXIT_SUCCESS);
		}
}
