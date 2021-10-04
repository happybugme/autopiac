﻿using System;
using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssembly : BinaryStream
    {
        private readonly DataSection[] dataSections;

        public WebAssembly(Stream stream) : base(stream)
        {
            Is32Bit = true;
            var magic = ReadUInt32();
            var version = ReadInt32();
            while (Position < Length)
            {
                var id = ReadULeb128();
                var len = ReadULeb128();
                if (id == 11)
                {
                    var count = ReadULeb128();
                    dataSections = new DataSection[count];
                    for (int i = 0; i < count; i++)
                    {
                        var dataSection = new DataSection();
                        dataSections[i] = dataSection;
                        dataSection.Index = ReadULeb128();
                        var opCode = ReadByte();
                        if (opCode != 0x41) //i32.const
                        {
                            throw new InvalidOperationException();
                        }
                        dataSection.Offset = ReadULeb128();
                        opCode = ReadByte();
     