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
        private readonly int typeDefinitionsCount;
        private readonly long metadataUsagesCount;
        private readonly int imageCount;
        private bool pointerInExec;

        public List<SearchSection> Exec => exec;
        public List<SearchSection> Data => data;
        public List<SearchSection> Bss => bss;

        public SectionHelper(Il2Cpp il2Cpp, int methodCount, int typeDefinitionsCount, long metadataUsagesCount, int imageCount)
        {
            this.il2Cpp = il2Cpp;
            this.methodCount = methodCount;
            this.typeDefinitionsCount = typeDefinitionsCount;
            this.metadataUsagesCount = metadataUsagesCount;
            this.imageCount = imageCount;
        }

        public void SetSection(SearchSectionType type, Elf32_Phdr[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.p_offset,
                        offsetEnd = section.p_offset + section.p_filesz,
                        address = section.p_vaddr,
                        addressEnd = section.p_vaddr + section.p_memsz
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, Elf64_Phdr[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.p_offset,
                        offsetEnd = section.p_offset + section.p_filesz,
                        address = section.p_vaddr,
                        addressEnd = section.p_vaddr + section.p_memsz
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, MachoSection[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.offset,
                        offsetEnd = section.offset + section.size,
                        address = section.addr,
                        addressEnd = section.addr + section.size
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, MachoSection64Bit[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.offset,
                        offsetEnd = section.offset + section.size,
                        address = section.addr,
                        addressEnd = section.addr + section.size
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, ulong imageBase, SectionHeader[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.PointerToRawData,
                        offsetEnd = section.PointerToRawData + section.SizeOfRawData,
                        address = section.VirtualAddress + imageBase,
                        addressEnd = section.VirtualAddress + section.VirtualSize + imageBase
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, params NSOSegmentHeader[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.FileOffset,
                        offsetEnd = section.FileOffset + section.DecompressedSize,
                        address = section.MemoryOffset,
                        addressEnd = section.MemoryOffset + section.DecompressedSize
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, params SearchSection[] secs)
        {
            SetSection(type, secs.ToList());
        }

        private void SetSection(SearchSectionType type, List<SearchSection> secs)
        {
            switch (type)
            {
                case SearchSectionType.Exec:
                    exec = secs;
                    break;
                case SearchSectionType.Data:
                    data = secs;
                    break;
                case SearchSectionType.Bss:
                    bss = secs;
                    break;
            }
        }

        public ulong FindCodeRegistration()
        {
            if (il2Cpp.Version >= 24.2)
            {
                ulong codeRegistration;
                if (il2Cpp is ElfBase)
                {
                    codeRegistration = FindCodeRegistrationExec();
                    if (codeRegistration == 0)
                    {
                        codeRegistration = FindCodeRegistrationData();
                    }
                    else
                    {
                        pointerInExec = true;
                    }
                }
                else
                {
                    codeRegistration = FindCodeRegistrationData();
                    if (codeRegistration == 0)
                    {
                        codeRegistration = FindCodeRegistrationExec();
                        pointerInExec = true;
                    }
                }
                return co