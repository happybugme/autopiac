using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmUtils;

namespace Il2CppDumper
{
    public sealed class Macho : Il2Cpp
    {
        private static readonly byte[] FeatureBytes1 = { 0x0, 0x22 };//MOVS R2, #0
        private static readonly byte[] FeatureBytes2 = { 0x78, 0x44, 0x79, 0x44 };//ADD R0, PC and ADD R1, PC
        private readonly List<MachoSection> sections = new();
        private readonly ulong vmaddr;

        public Macho(Stream stream) : base(stream)
        {
            Is32Bit = true;
            Position += 16; //skip magic, cputype, cpusubtype, filetype
            var ncmds = ReadUInt32();
            Position += 8; //skip sizeofcmds, flags
            for (var i = 0; i < ncmds; i++)
            {
                var pos = Position;
                var cmd = ReadUInt32();
                var cmdsize = ReadUInt32();
                switch (cmd)
                {
                    case 1: //LC_SEGMENT
                        var segname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                        if (segname == "__TEXT") //__PAGEZERO
                        {
                            vmaddr = ReadUInt32();
                        }
                        else
                        {
                            Position += 4;
                        }
                        Position += 20; //skip vmsize, fileoff, filesize, maxprot, initprot
                        var nsects = ReadUInt32();
                        Position += 4; //skip flags
                        for (var j = 0; j < nsects; j++)
                        {
                            var section = new MachoSection();
                            sections.Add(section);
                            section.sectname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                           