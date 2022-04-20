
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class StructGenerator
    {
        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppTypeDefinition, string> typeDefImageNames = new();
        private readonly HashSet<string> structNameHashSet = new(StringComparer.Ordinal);
        private readonly List<StructInfo> structInfoList = new();
        private readonly Dictionary<string, StructInfo> structInfoWithStructName = new();
        private readonly HashSet<StructInfo> structCache = new();
        private readonly Dictionary<Il2CppTypeDefinition, string> structNameDic = new();
        private readonly Dictionary<ulong, string> genericClassStructNameDic = new();
        private readonly Dictionary<string, Il2CppType> nameGenericClassDic = new();
        private readonly List<ulong> genericClassList = new();
        private readonly StringBuilder arrayClassHeader = new();
        private readonly StringBuilder methodInfoHeader = new();
        private static readonly HashSet<ulong> methodInfoCache = new();
        private static readonly HashSet<string> keyword = new(StringComparer.Ordinal)
        { "klass", "monitor", "register", "_cs", "auto", "friend", "template", "flat", "default", "_ds", "interrupt",
            "unsigned", "signed", "asm", "if", "case", "break", "continue", "do", "new", "_", "short", "union", "class", "namespace"};
        private static readonly HashSet<string> specialKeywords = new(StringComparer.Ordinal)
        { "inline", "near", "far" };

        public StructGenerator(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
        }

        public void WriteScript(string outputDir)
        {
            var json = new ScriptJson();
            // 生成唯一名称
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    var typeDef = metadata.typeDefs[typeIndex];
                    typeDefImageNames.Add(typeDef, imageName);