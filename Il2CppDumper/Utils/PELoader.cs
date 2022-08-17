
﻿using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Il2CppDumper
{
    public class PELoader
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static IntPtr LoadLibrary(string path);

        public static PE Load(string fileName)
        {
            var buff = File.ReadAllBytes(fileName);
            using var reader = new BinaryStream(new MemoryStream(buff));
            var dosHeader = reader.ReadClass<DosHeader>();
            if (dosHeader.Magic != 0x5A4D)
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            reader.Position = dosHeader.Lfanew;
            if (reader.ReadUInt32() != 0x4550u) //Signature
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            var fileHeader = reader.ReadClass<FileHeader>();
            if (fileHeader.Machine == 0x14c && Environment.Is64BitProcess) //64bit process can't load 32bit dll
            {