#include <argp.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <udis86.h>
#include <unistd.h>

const char *argp_program_version = "uses-sse2 0.1.0";
const char *argp_program_bug_address = "<hauzer.nv@gmail.com>";

struct args {
    char **input;
    bool quiet;
};

error_t handle_arg(int key, char *arg, struct argp_state *state) {
    struct args *args = state->input;
    switch(key) {
        case 'q':
            args->quiet = true;
            break;
        case ARGP_KEY_ARG:
            args->input = realloc(args->input, sizeof(char*) * (state->arg_num + 2));
            args->input[state->arg_num] = arg;
            args->input[state->arg_num + 1] = NULL;
            break;
        case ARGP_KEY_END:
            if(state->arg_num < 1) {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char **argv) {
    struct args args = {
        .input = NULL,
        .quiet = false,
    };

    #define aprintf(...) \
        do { \
            if(!args.quiet) { \
                printf(__VA_ARGS__); \
            } \
        } while(0)

    {
        const char *doc = "Examine ELF binaries for SSE2 instructions.\v";
        const char *args_doc = "file [files...]";
        struct argp_option opts[] = {
            {"quiet",   'q', 0, 0, "Suppress all output and exit upon first match."},
            { 0 }
        };
        struct argp argp = { opts, handle_arg, args_doc, doc };
        argp_parse(&argp, argc, argv, 0, 0, &args);
    }

    int exit_code = EXIT_FAILURE;

    ud_t ud;
    ud_init(&ud);
    ud_set_mode(&ud, 32);
    if(!args.quiet) {
        ud_set_syntax(&ud, UD_SYN_INTEL);
    }

    for(char **input = args.input; *input != NULL; ++input) {
        bool do_exit = false;

        aprintf(">%s: ", *input);

        int fd = open(*input, O_RDONLY);
        if(fd == -1) {
            aprintf("error: open() failed\n");
            continue;
        }

        struct stat st;
        {
            int ret = fstat(fd, &st);
            if(ret != 0) {
                aprintf("error: [%d] fstat() failed\n", ret);
                goto cleanup_close;
            }
        }

        unsigned char *data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if(data == MAP_FAILED) {
            aprintf("error: mmap() failed\n");
            goto cleanup_close;
        }

        if(data[EI_MAG0] != ELFMAG0 || data[EI_MAG1] != ELFMAG1 || data[EI_MAG2] != ELFMAG2 || data[EI_MAG3] != ELFMAG3) {
            aprintf("error: not an ELF file\n");
            goto cleanup_munmap;
        }

        if(data[EI_CLASS] != ELFCLASS32) {
            aprintf("error: not a 32-bit ELF\n");
            goto cleanup_munmap;
        }

        {
            uint16_t e_type = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_type)];
            if(e_type != ET_EXEC && e_type != ET_DYN) {
                aprintf("error: not an executable nor a dynamic library\n");
                goto cleanup_munmap;
            }
        }

        {
            uint32_t e_shoff = *(uint32_t*)&data[offsetof(Elf32_Ehdr, e_shoff)];
            uint16_t e_shentsize = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_shentsize)];

            uint16_t e_shstrndx;
            unsigned char *shstr;
            uint32_t shstr_sh_offset;
            unsigned char *sh_names;
            if(!args.quiet) {
                e_shstrndx = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_shstrndx)];
                shstr = &data[e_shoff + e_shentsize * e_shstrndx];
                shstr_sh_offset = *(uint32_t*)&shstr[offsetof(Elf32_Shdr, sh_offset)];
                sh_names = &data[shstr_sh_offset];
            }

            uint16_t e_shnum = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_shnum)];
            for(unsigned char *section = &data[e_shoff + e_shentsize]; section != &data[e_shoff + e_shentsize * e_shnum]; section += e_shentsize) {
                uint32_t sh_type = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_type)];
                uint32_t sh_flags = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_flags)];
                if(sh_type == SHT_PROGBITS && ((sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR))) {
                    uint32_t sh_offset = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_offset)];
                    uint32_t sh_size = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_size)];
                    uint32_t sh_name;

                    ud_set_input_buffer(&ud, &data[sh_offset], sh_size);

                    bool did_print_newline;

                    if(!args.quiet) {
                        sh_name = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_name)];
                        ud_set_pc(&ud, sh_offset);
                        did_print_newline = false;
                    }

                    while(ud_disassemble(&ud)) {
                        switch(ud_insn_mnemonic(&ud)) {
                            case UD_Iaddpd:
                            case UD_Iaddsd:
                            case UD_Iandnpd:
                            case UD_Iandpd:
                            case UD_Icmppd:
                            case UD_Icmpsd:
                            case UD_Icomisd:
                            case UD_Icvtpi2pd:
                            case UD_Icvtpd2pi:
                            case UD_Icvtsi2sd:
                            case UD_Icvtsd2si:
                            case UD_Icvttpd2pi:
                            case UD_Icvttsd2si:
                            case UD_Icvtpd2ps:
                            case UD_Icvtps2pd:
                            case UD_Icvtsd2ss:
                            case UD_Icvtss2sd:
                            case UD_Icvtpd2dq:
                            case UD_Icvttpd2dq:
                            case UD_Icvtdq2pd:
                            case UD_Icvtps2dq:
                            case UD_Icvttps2dq:
                            case UD_Icvtdq2ps:
                            case UD_Idivpd:
                            case UD_Idivsd:
                            case UD_Imaxpd:
                            case UD_Imaxsd:
                            case UD_Iminpd:
                            case UD_Iminsd:
                            case UD_Imovapd:
                            case UD_Imovhpd:
                            case UD_Imovlpd:
                            case UD_Imovmskpd:
                            case UD_Imovsd: {
                                // We ignore the movsd string instruction.
                                if(ud_insn_opr(&ud, 0) == NULL) {
                                    continue;
                                }
                            }
                            case UD_Imovupd:
                            case UD_Imulpd:
                            case UD_Imulsd:
                            case UD_Iorpd:
                            case UD_Ishufpd:
                            case UD_Isqrtpd:
                            case UD_Isqrtsd:
                            case UD_Isubsd:
                            case UD_Isubpd:
                            case UD_Iucomisd:
                            case UD_Iunpckhpd:
                            case UD_Iunpcklpd:
                            case UD_Ixorpd:
                            case UD_Imaskmovdqu:
                            case UD_Iclflush:
                            case UD_Imovntpd:
                            case UD_Imovntdq:
                            case UD_Imovnti:
                            // This has the same bytecode as `ret rep`.
                            // case UD_Ipause:
                            case UD_Ilfence:
                            case UD_Imfence: {
                                exit_code = EXIT_SUCCESS;
                                if(!args.quiet) {
                                    if(!did_print_newline) {
                                        printf("\n");
                                        did_print_newline = true;
                                    }
                                    printf("  [%s] 0x%08llx  %-14s%s\n",
                                        &sh_names[sh_name], ud_insn_off(&ud), ud_insn_hex(&ud), ud_insn_asm(&ud));
                                } else {
                                    do_exit = true;
                                    goto cleanup_munmap;
                                }
                            }
                            default: break;
                        }
                    }
                }
            }
        }

    cleanup_munmap:
        munmap(data, st.st_size);
    cleanup_close:
        close(fd);
        if(do_exit) {
            break;
        }
    }

    free(args.input);
    exit(exit_code);
}
