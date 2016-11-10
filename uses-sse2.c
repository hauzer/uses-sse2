#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <udis86.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int exit_code = EXIT_FAILURE;

    if(argc != 2) {
        printf("usage: %s file\n\n", argv[0]);
        goto cleanup_exit;
    }

    int fd = open(argv[1], O_RDONLY);
    if(fd == -1) {
        printf("couldn't open file\n\n");
        goto cleanup_exit;
    }

    struct stat st;
    if(fstat(fd, &st) != 0) {
        printf("couldn't read file size\n\n");
        goto cleanup_close;
    }

    unsigned char *data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if(data == MAP_FAILED) {
        printf("couldn't map file into memory\n\n");
        goto cleanup_close;
    }

    if(data[EI_MAG0] != ELFMAG0 || data[EI_MAG1] != ELFMAG1 || data[EI_MAG2] != ELFMAG2 || data[EI_MAG3] != ELFMAG3) {
        printf("not an ELF file\n\n");
        goto cleanup_munmap;
    }

    if(data[EI_CLASS] != ELFCLASS32) {
        printf("not a 32-bit ELF\n\n");
        goto cleanup_munmap;
    }

    {
        uint16_t e_type = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_type)];
        if(e_type != ET_EXEC && e_type != ET_DYN) {
            printf("ELF is neither executable nor a dynamic library\n\n");
            goto cleanup_munmap;
        }
    }

    {
        ud_t ud;
        ud_init(&ud);
        uint32_t e_shoff = *(uint32_t*)&data[offsetof(Elf32_Ehdr, e_shoff)];
        uint16_t e_shentsize = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_shentsize)];
        uint16_t e_shnum = *(uint16_t*)&data[offsetof(Elf32_Ehdr, e_shnum)];
        for(unsigned char *section = &data[e_shoff + e_shentsize]; section != &data[e_shoff + e_shentsize * e_shnum]; section += e_shentsize) {
            uint32_t sh_type = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_type)];
            uint32_t sh_flags = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_flags)];
            if(sh_type == SHT_PROGBITS && sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) {
                uint32_t sh_offset = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_offset)];
                uint32_t sh_size = *(uint32_t*)&section[offsetof(Elf32_Shdr, sh_size)];
                ud_set_input_buffer(&ud, &data[sh_offset], sh_size);
                while(ud_disassemble(&ud)) {
                    enum ud_mnemonic_code mnemonic = ud_insn_mnemonic(&ud);
                    switch(mnemonic) {
                        case UD_Iaddpd:
                        case UD_Iaddsd:
                        case UD_Isubpd:
                        case UD_Imulpd:
                        case UD_Imulsd:
                        case UD_Idivpd:
                        case UD_Idivsd:
                        case UD_Imaxpd:
                        case UD_Imaxsd:
                        case UD_Iminpd:
                        case UD_Iminsd:
                        case UD_Ipaddq:
                        case UD_Ipaddsw:
                        case UD_Ipsubq:
                        case UD_Ipsubusw:
                        case UD_Ipmuludq:
                        case UD_Isqrtpd:
                        case UD_Isqrtsd:
                        case UD_Iandnpd:
                        case UD_Iandpd:
                        case UD_Ipslldq:
                        case UD_Ipsrldq:
                        case UD_Iorpd:
                        case UD_Ixorpd:
                        case UD_Icmppd:
                        case UD_Icmpsd:
                        case UD_Icomisd:
                        case UD_Iucomisd:
                        case UD_Icvtdq2pd:
                        case UD_Icvtdq2ps:
                        case UD_Icvtpd2pi:
                        case UD_Icvtpd2dq:
                        case UD_Icvtpd2ps:
                        case UD_Icvtpi2pd:
                        case UD_Icvtps2dq:
                        case UD_Icvtps2pd:
                        case UD_Icvtsd2si:
                        case UD_Icvtsd2ss:
                        case UD_Icvtsi2sd:
                        case UD_Icvtss2sd:
                        case UD_Icvttpd2pi:
                        case UD_Icvttpd2dq:
                        case UD_Icvttps2dq:
                        case UD_Icvttsd2si:
                        case UD_Imovsd:
                        case UD_Imovapd:
                        case UD_Imovupd:
                        case UD_Imovhpd:
                        case UD_Imovlpd:
                        case UD_Imovdq2q:
                        case UD_Imovq2dq:
                        case UD_Imovntpd:
                        case UD_Imovnti:
                        case UD_Imaskmovdqu:
                        case UD_Ipmovmskb:
                        case UD_Ipshufd:
                        case UD_Ipshufhw:
                        case UD_Ipshuflw:
                        case UD_Iunpckhpd:
                        case UD_Iunpcklpd:
                        case UD_Ipunpckhqdq:
                        case UD_Ipunpcklqdq:
                        case UD_Iclflush:
                        case UD_Ilfence:
                        case UD_Imfence:
                        case UD_Ipause:
                            printf("found a SSE2 instruction\n\n");
                            exit_code = EXIT_SUCCESS;
                            goto cleanup_munmap;
                        default: break;
                    }
                }
            }
        }
    }

printf("no SSE2 instructions found\n\n");

cleanup_munmap:
    munmap(data, st.st_size);
cleanup_close:
    close(fd);
cleanup_exit:
    exit(exit_code);
}
