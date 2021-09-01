﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public sealed class PE : Il2Cpp
    {
        private readonly SectionHeader[] sections;

        public PE(Stream stream) : base(stream)
        {
            var dosHeader = ReadClass<DosHeader>();
            if (dosHeader.Magic != 0x5A4D)
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            Position = dosHeader.Lfanew;
            if (ReadUInt32() != 0x4550u) //Signature
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            var fileHeader = ReadClass<FileHeader>();
            var pos = Position;
            var magic = ReadUInt16();
            Position -= 2;
            if (magic == 0x10b)
            {
                Is32Bit = true;
                var optionalHeader = ReadClass<OptionalHeader>();
                ImageBase = optionalHeader.ImageBase;
            }
            else if (magic == 0x20b)
            {
                var optionalHeader = ReadClass<OptionalHeader64>();
                ImageBase = optionalHeader.ImageBase;
            }
            else
            {
                throw new NotSupportedException($"Invalid Optional header magic {magic}");
            }
            Position = pos + fileHeader.SizeOfOptionalHeader;
            sections = ReadClassArray<SectionHeader>(fileHeader.NumberOfSections);
        }

        public void LoadFromMemory(ulong addr)
        {
            ImageBase = addr;
            foreach (var section in sections)
            {
                section.PointerToRawData = section.VirtualAddress;
                section.SizeOfRawData = section.VirtualSize;
            }
        }

   