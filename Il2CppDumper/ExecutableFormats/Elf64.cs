using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf64 : ElfBase
    {
        private Elf64_Ehdr elfHeader;
        private Elf64_Phdr[] programSegment;
        private Elf64_Dyn[] dynamicSection;
        private Elf64_Sym[] symbolTable;
        private Elf64_Shdr[] sectionTable;
        private Elf64_Phdr pt_dynamic;

        public Elf64(Stream stream) : base(stream)
        {
            Load();
        }

        protected override void Load()
        {
            elfHeader = ReadClass<Elf64_Ehdr>(0);
            programSegment = ReadClassArray<Elf64_Phdr>(elfHeader.e_phoff, elfH