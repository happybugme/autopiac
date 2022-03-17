using System.IO;

namespace Il2CppDumper
{
    public static class DummyAssemblyExporter
    {
        public static void Export(Il2CppExecutor il2CppExecutor, string outputDir, bool addToken)
        {
            Directory.SetCurrentDirectory(outputDir);
            if (Directory.Exists("DummyDll"))
                Directory.Delete("DummyDll", true);
   