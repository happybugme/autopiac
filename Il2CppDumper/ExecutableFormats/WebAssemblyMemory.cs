using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssemblyMemory : Il2Cpp
    {
        private readonly uint bssStart;

        public WebAssemblyMemory(Stream stream, uint bssStart) : base(stream)