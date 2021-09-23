using System;
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
                var l