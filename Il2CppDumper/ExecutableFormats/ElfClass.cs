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
    