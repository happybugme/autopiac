using System.IO;

namespace Il2CppDumper
{
    public abstract class ElfBase : Il2Cpp
    {
        protected ElfBase(Stream stream) : base(stream) { }
        protected 