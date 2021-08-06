using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public sealed class PE : Il2Cpp
    {
        private readonly SectionHeader[] sections;