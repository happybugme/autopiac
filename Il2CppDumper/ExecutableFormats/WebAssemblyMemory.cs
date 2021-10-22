﻿using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssemblyMemory : Il2Cpp
    {
        private readonly uint bssStart;

        public WebAssemblyMemory(Stream stream, uint bssStart) : base(stream)
        {
            Is32Bit = true;
            this.bssStart = bssStart;
        }

        public override ulong MapVATR(ulong addr)
        {
            return addr;
        }

        p