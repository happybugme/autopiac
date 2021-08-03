
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class NSO : Il2Cpp
    {
        private readonly NSOHeader header;
        private readonly bool isTextCompressed;
        private readonly bool isRoDataCompressed;
        private readonly bool isDataCompressed;
        private readonly List<NSOSegmentHeader> segments = new();
        private Elf64_Sym[] symbolTable;
        private readonly List<Elf64_Dyn> dynamicSection = new();
        private bool IsCompressed => isTextCompressed || isRoDataCompressed || isDataCompressed;