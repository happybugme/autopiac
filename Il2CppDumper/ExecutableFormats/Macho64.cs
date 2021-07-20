
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmUtils;

namespace Il2CppDumper
{
    public sealed class Macho64 : Il2Cpp
    {
        private static readonly byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static readonly byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0
        private readonly List<MachoSection64Bit> sections = new();
        private readonly ulong vmaddr;

        public Macho64(Stream stream) : base(stream)
        {
            Position += 16; //skip magic, cputype, cpusubtype, filetype
            var ncmds = ReadUInt32();
            Position += 12; //skip sizeofcmds, flags, reserved
            for (var i = 0; i < ncmds; i++)
            {
                var pos = Position;
                var cmd = ReadUInt32();
                var cmdsize = ReadUInt32();
                switch (cmd)
                {
                    case 0x19: //LC_SEGMENT_64
                        var segname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                        if (segname == "__TEXT") //__PAGEZERO
                        {
                            vmaddr = ReadUInt64();
                        }
                        else