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
        public ushort e_shstrndx