using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf : ElfBase
    {
        private Elf32_Ehdr elfHeader;
        private Elf32_Phdr[] programSegment;
        private Elf32_Dyn[] dynamicSection;
        private Elf32_Sym[] symbolTable;
        private Elf32_Shdr[] sectionTable;
        private Elf32_Phdr pt_dynamic;

        /*
        * LDR R1, [X]
        * ADD R0, X, X
        * ADD R2, X, X
        */
        private static readonly string ARMFeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0";
        private static readonly string X86FeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0"; //TODO

        public Elf(Stream stream) : base(stream)
        {
            Is32Bit = true;
            Load();
        }

        protected override void Load()
        {
            elfHeader = ReadClass<Elf32_Ehdr>(0);
            programSegment = ReadClassArray<Elf32_Phdr>(elfHeader.e_phoff, elfHeader.e_phnum);
            if (IsDumped)
            {
                FixedProgramSegment();
            }
            pt_dynamic = programSegment.First(x => x.p_type == PT_DYNAMIC);
            dynamicSection = ReadClassArray<Elf32_Dyn>(pt_dynamic.p_offset, pt_dynamic.p_filesz / 8u);
            if (IsDumped)
            {
                FixedDynamicSection();
            }
            ReadSymbol();
            if (!IsDumped)
            {
                RelocationProcessing();
                if (CheckProtection())
                {
                    Console.WriteLine("ERROR: This file may be protected.");
                }
            }
        }

        protected override bool CheckSection()
        {
            try
            {
                var names = new List<string>();
                sectionTable = ReadClassArray<Elf32_Shdr>(elfHeader.e_shoff, elfHeader.e_shnum);
                var shstrndx = sectionTable[elfHeader.e_shstrndx].sh_offset;
                foreach (var section in sectionTable)
                {
                    names.Add(ReadStringToNull(shstrndx + section.sh_name));
                }
                if (!names.Contains(".text"))
                {
                    return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var phdr = programSegment.First(x => addr >= x.p_vaddr && addr <= x.p_vaddr + x.p_memsz);
            return addr - phdr.p_vaddr + phdr.p_offset;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var phdr = programSegment.FirstOrDefault(x => addr >= x.p_offset && addr <= x.p_offset + x.p_filesz);
            if (phdr == null)
            {
                return 0;
            }
            return addr - phdr.p_offset + phdr.p_vaddr;
        }

        public override bool Search()
        {
            var _GLOBAL_OFFSET_TABLE_ = dynamicSection.First(x => x.d_tag == DT_PLTGOT).d_un;
            var execs = programSegment.Where(x => x.p_type == PT_LOAD && (x.p_flags & PF_X) == 1).ToArray();
            var resultList = new List<int>();
            var featureBytes = elfHeader.e_machine == EM_ARM ? ARMFeatureBytes : X86FeatureBytes;
            foreach (var exec in execs)
            {
                Position = exec.p_offset;
                var buff = ReadBytes((int)exec.p_filesz);
                foreach (var temp in buff.Search(featureBytes))
                {
                    var bin = buff[temp + 2].HexToBin();
                    if (bin[3] == '1') //LDR
                    {
                        resultList.Add(temp);
                    }
                }
            }
            if (resultList.Count == 1)
            {
                uint codeRegistration = 0;
                uint metadataRegistration = 0;
                var result = (uint)resultList[0];
                if (Version < 24)
                {
                    if (elfHeader.e_machine == EM_ARM)
                    {
                        Position = result + 0x14;
                        codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                        Position = result + 0x18;
                        var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                        Position = MapVATR(ptr);
                        metadataRegistration = ReadUInt32();
                    }
                }
                else if (Version >= 24)
                {
                    if (elfHeader.e_machine == EM_ARM)
                    {
                        Position = result + 0x14;
                        codeRegistratio