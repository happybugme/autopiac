using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssemblyMemory : Il2Cpp
    {
        private readonly uint bssStart;

        public WebAssemblyMemory(Stream stream, uint bssStart) : base(stream)
        {
            Is32Bit = true;
            this.bssStart = bssStart;
        }

        public override ulong MapVATR(ulong addr)
        {
            return addr;
        }

        public override ulong MapRTVA(ulong addr)
        {
            return addr;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var sectionHelper = GetSectionHelper(methodCount, typeDefinitionsCount, imageCount);
            var codeRegistration = sectionHelper.FindCodeRegistration();
            var metadataRegistration = sectionHelper.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
        }

        public override bool Sea