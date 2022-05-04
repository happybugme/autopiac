using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonSerializer.Deserialize<Config>(File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + @"config.json"));
            string il2cppPath = null;
            string metadataPath = null;
            string outputDir = null;

            if (args.Length == 1)
            {
        