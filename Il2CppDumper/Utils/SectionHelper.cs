using System;
using System.Collections.Generic;
using System.Linq;

namespace Il2CppDumper
{
    public class SectionHelper
    {
        private List<SearchSection> exec;
        private List<SearchSection> data;
        private List<SearchSection> bss;
        private readonly Il2Cpp il2Cpp;
        private readonly int methodCount;
