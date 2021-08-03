
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class NSO : Il2Cpp
    {
        private readonly NSOHeader header;
        private readonly bool isTextCompressed;
        private readonly bool isRoDataCompressed;
        private readonly bool isDataCompressed;
        private readonly List<NSOSegmentHeader> segments = new();
        private Elf64_Sym[] symbolTable;
        private readonly List<Elf64_Dyn> dynamicSection = new();
        private bool IsCompressed => isTextCompressed || isRoDataCompressed || isDataCompressed;


        public NSO(Stream stream) : base(stream)
        {
            header = new NSOHeader
            {
                Magic = ReadUInt32(),
                Version = ReadUInt32(),
                Reserved = ReadUInt32(),
                Flags = ReadUInt32()
            };
            isTextCompressed = (header.Flags & 1) != 0;
            isRoDataCompressed = (header.Flags & 2) != 0;
            isDataCompressed = (header.Flags & 4) != 0;
            header.TextSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.TextSegment);
            header.ModuleOffset = ReadUInt32();
            header.RoDataSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.RoDataSegment);
            header.ModuleFileSize = ReadUInt32();
            header.DataSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.DataSegment);
            header.BssSize = ReadUInt32();
            header.DigestBuildID = ReadBytes(0x20);
            header.TextCompressedSize = ReadUInt32();
            header.RoDataCompressedSize = ReadUInt32();
            header.DataCompressedSize = ReadUInt32();
            header.Padding = ReadBytes(0x1C);
            header.APIInfo = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.DynStr = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.DynSym = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.TextHash = ReadBytes(0x20);
            header.RoDataHash = ReadBytes(0x20);
            header.DataHash = ReadBytes(0x20);

            if (!IsCompressed)
            {
                Position = header.TextSegment.FileOffset + 4;
                var modOffset = ReadUInt32();
                Position = header.TextSegment.FileOffset + modOffset + 4;
                var dynamicOffset = ReadUInt32() + modOffset;
                var bssStart = ReadUInt32();
                var bssEnd = ReadUInt32();
                header.BssSegment = new NSOSegmentHeader
                {
                    FileOffset = bssStart,
                    MemoryOffset = bssStart,
                    DecompressedSize = bssEnd - bssStart
                };
                var maxSize = (header.DataSegment.MemoryOffset + header.DataSegment.DecompressedSize - dynamicOffset) / 16;
                Position = MapVATR(dynamicOffset);
                for (int i = 0; i < maxSize; i++)
                {
                    var dynamic = ReadClass<Elf64_Dyn>();
                    if (dynamic.d_tag == 0)
                    {
                        break;
                    }
                    else
                    {
                        dynamicSection.Add(dynamic);
                    }
                }
                ReadSymbol();
                RelocationProcessing();
            }
        }

        private void ReadSymbol()
        {
            try
            {
                var symbolCount = 0u;
                var hash = dynamicSection.FirstOrDefault(x => x.d_tag == DT_HASH);
                if (hash != null)
                {
                    var addr = MapVATR(hash.d_un);
                    Position = addr;
                    var nbucket = ReadUInt32();
                    var nchain = ReadUInt32();
                    symbolCount = nchain;
                }
                else
                {
                    hash = dynamicSection.First(x => x.d_tag == DT_GNU_HASH);
                    var addr = MapVATR(hash.d_un);
                    Position = addr;
                    var nbuckets = ReadUInt32();
                    var symoffset = ReadUInt32();
                    var bloom_size = ReadUInt32();
                    var bloom_shift = ReadUInt32();
                    var buckets_address = addr + 16 + (8 * bloom_size);
                    var buckets = ReadClassArray<uint>(buckets_address, nbuckets);
                    var last_symbol = buckets.Max();
                    if (last_symbol < symoffset)
                    {
                        symbolCount = symoffset;
                    }
                    else
                    {
                        var chains_base_address = buckets_address + 4 * nbuckets;
                        Position = chains_base_address + (last_symbol - symoffset) * 4;
                        while (true)
                        {
                            var chain_entry = ReadUInt32();
                            ++last_symbol;
                            if ((chain_entry & 1) != 0)
                                break;
                        }
                        symbolCount = last_symbol;
                    }
                }
                var dynsymOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_SYMTAB).d_un);
                symbolTable = ReadClassArray<Elf64_Sym>(dynsymOffset, symbolCount);
            }
            catch
            {
                // ignored
            }
        }

        private void RelocationProcessing()
        {
            Console.WriteLine("Applying relocations...");
            try
            {
                var relaOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_RELA).d_un);
                var relaSize = dynamicSection.First(x => x.d_tag == DT_RELASZ).d_un;
                var relaTable = ReadClassArray<Elf64_Rela>(relaOffset, relaSize / 24L);
                foreach (var rela in relaTable)
                {
                    var type = rela.r_info & 0xffffffff;
                    var sym = rela.r_info >> 32;
                    switch (type)
                    {
                        case R_AARCH64_ABS64:
                            {
                                var symbol = symbolTable[sym];
                                Position = MapVATR(rela.r_offset);
                                Write(symbol.st_value + (ulong)rela.r_addend);
                                break;
                            }
                        case R_AARCH64_RELATIVE:
                            {
                                Position = MapVATR(rela.r_offset);
                                Write(rela.r_addend);
                                break;
                            }
                    }
                }
            }
            catch
            {
                // ignored
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var segment = segments.First(x => addr >= x.MemoryOffset && addr <= x.MemoryOffset + x.DecompressedSize);
            return addr - segment.MemoryOffset + segment.FileOffset;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var segment = segments.FirstOrDefault(x => addr >= x.FileOffset && addr <= x.FileOffset + x.DecompressedSize);