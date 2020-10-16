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
        private Elf6