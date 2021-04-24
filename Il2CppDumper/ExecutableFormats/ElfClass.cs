namespace Il2CppDumper
{
    public class Elf32_Ehdr
    {
        public uint ei_mag;
        public byte ei_class;
        public byte ei_data;
        public byte ei_version;
        public byte ei_osabi;
        public byte ei_abiversion;
        [ArrayLength(Length = 7)]
        public byte[] ei_pad;
        public ushort e_type;
        public ushort e_machine;
        public uint e_version;
        public uint e_entry;
        public uint e_phoff;
        public uint e_shoff;
        public uint e_flags;
        public ushort e_ehsize;
        public ushort e_phentsize;
        public ushort e_phnum;
        public ushort e_shentsize;
        public ushort e_shnum;
        public ushort e_shstrndx;
    }

    public class Elf32_Phdr
    {
        public uint p_type;
        public uint p_offset;
        public uint p_vaddr;
        public uint p_paddr;
        public uint p_filesz;
        public uint p_memsz;
        public uint p_flags;
        public uint p_align;
    }

    public class Elf32_Shdr
    {
        public uint sh_name;
        public uint sh_type;
        public uint sh_flags;
        public uint sh_addr;
        public uint sh_offset;
        public uint sh_size;
        public uint sh_link;
        public uint sh_info;
        public uint sh_addralign;
        public uint sh_entsize;
    }

    public class Elf32_Sym
    {
        public uint st_name;
        public uint st_value;
        public uint st_size;
        public byte st_info;
        public byte st_other;
        public ushort st_shndx;
    }

    public class Elf32_Dyn
    {
        public int d_tag;
        public uint d_un;
    }

    public class Elf32_Rel
    {
        public uint r_offset;
        public uint r_info;
    }

    public class Elf64_Ehdr
    {
        public uint ei_mag;
        public byte ei_class;
        public byte ei_data;
        public byte ei_version;
        public byte ei_osabi;
        public byte ei_abiversion;
        [ArrayLength(Length = 7)]
        public byte[] ei_pad;
        public ushort e_type;
        public ushort e_machine;
        public uint e_version;
        public ulong e_entry;
        public ulong e_phoff;
        public ulong e_shoff;
        public uint e_flags;
        public ushort e_ehsize;
        public ushort e_phentsize;
        public ushort e_phnum;
        public ushort e_shentsize;
        public ushort e_shnum;
        public ushort e_shstrndx;
    }

    public class Elf64_Phdr
    {
        public uint p_type;
        public uint p_flags;
        public ulong p_offset;
        public ulong p_vaddr;
        public ulong p_paddr;
        public ulong p_filesz;
        public ulong p_memsz;
        public ulong p_align;
    }

    public class Elf64_Shdr
    {
        public uint sh_name;
        public uint sh_type;
        public ulong sh_flags;
        public ulong sh_addr;
        public ulong sh_offset;
        public ulong sh_size;
        public uint sh_link;
        public uint sh_info;
        public ulong sh_addralign;
        public ulong sh_entsize;
    }

    public class Elf64_Sym
    {
        public uint st_name;
        public byte st_info;
        public byte st_other;
        public ushort st_shndx;
        public ulong st_value;
        public ulong st_size;
    }

    public class Elf64_Dyn
    {
        public long d_tag;
        public ulong d_un;
    }

    public class Elf64_Rela
    {
        public ulong r_offset;
        public ulong r_info;
        public ulong r_addend;
    }

    public static class ElfConstants
    {
        //e_machine
        public const int EM_386 = 3;
        public const int EM_ARM = 40;
        public const int EM_X86_64 = 62;
        public const int EM_AARCH64 = 183;

        //p_type
        public const int PT_LOAD = 1;
        public const int PT_DYNAMIC = 2;

        //p_f