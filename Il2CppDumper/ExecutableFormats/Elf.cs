using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf : ElfBase
    {
        private Elf32_Ehdr elfHeader;
        private Elf32_Phdr[] programSegment;
        private Elf32_Dyn[] dynamicSection;
        private Elf32_Sym[] symbolTable;
        private Elf32_Shdr[] sectionTable;
        private Elf32_Phdr pt_dynamic;

        /*
        * LDR R1, [X]
        * ADD R0, X, X
        * ADD R2, X, X
        */
        private static readonly string ARMFeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0";
        private static readonly string X86FeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0"; //TODO

        public Elf(Stream stream) : base(stream)
        {
            Is32Bit = true;
            Load();
        }

        protected override void Load()
        {
    