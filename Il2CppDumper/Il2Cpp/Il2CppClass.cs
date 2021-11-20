
﻿using System;

namespace Il2CppDumper
{
    public class Il2CppCodeRegistration
    {
        [Version(Max = 24.1)]
        public ulong methodPointersCount;
        [Version(Max = 24.1)]
        public ulong methodPointers;
        [Version(Max = 21)]
        public ulong delegateWrappersFromNativeToManagedCount;
        [Version(Max = 21)]
        public ulong delegateWrappersFromNativeToManaged; // note the double indirection to handle different calling conventions
        [Version(Min = 22)]
        public ulong reversePInvokeWrapperCount;
        [Version(Min = 22)]
        public ulong reversePInvokeWrappers;
        [Version(Max = 22)]
        public ulong delegateWrappersFromManagedToNativeCount;
        [Version(Max = 22)]
        public ulong delegateWrappersFromManagedToNative;
        [Version(Max = 22)]
        public ulong marshalingFunctionsCount;
        [Version(Max = 22)]
        public ulong marshalingFunctions;
        [Version(Min = 21, Max = 22)]
        public ulong ccwMarshalingFunctionsCount;
        [Version(Min = 21, Max = 22)]
        public ulong ccwMarshalingFunctions;
        public ulong genericMethodPointersCount;
        public ulong genericMethodPointers;
        [Version(Min = 24.5, Max = 24.5)]
        [Version(Min = 27.1)]
        public ulong genericAdjustorThunks;
        public ulong invokerPointersCount;
        public ulong invokerPointers;
        [Version(Max = 24.5)]
        public ulong customAttributeCount;
        [Version(Max = 24.5)]
        public ulong customAttributeGenerators;
        [Version(Min = 21, Max = 22)]
        public ulong guidCount;
        [Version(Min = 21, Max = 22)]
        public ulong guids; // Il2CppGuid
        [Version(Min = 22)]
        public ulong unresolvedVirtualCallCount; //29.1 unresolvedIndirectCallCount;
        [Version(Min = 22)]
        public ulong unresolvedVirtualCallPointers;
        [Version(Min = 29.1)]
        public ulong unresolvedInstanceCallPointers;
        [Version(Min = 29.1)]
        public ulong unresolvedStaticCallPointers;
        [Version(Min = 23)]
        public ulong interopDataCount;
        [Version(Min = 23)]
        public ulong interopData;
        [Version(Min = 24.3)]
        public ulong windowsRuntimeFactoryCount;
        [Version(Min = 24.3)]
        public ulong windowsRuntimeFactoryTable;
        [Version(Min = 24.2)]
        public ulong codeGenModulesCount;
        [Version(Min = 24.2)]
        public ulong codeGenModules;
    }

    public class Il2CppMetadataRegistration
    {
        public long genericClassesCount;
        public ulong genericClasses;
        public long genericInstsCount;
        public ulong genericInsts;
        public long genericMethodTableCount;
        public ulong genericMethodTable;
        public long typesCount;
        public ulong types;
        public long methodSpecsCount;
        public ulong methodSpecs;
        [Version(Max = 16)]
        public long methodReferencesCount;
        [Version(Max = 16)]
        public ulong methodReferences;

        public long fieldOffsetsCount;
        public ulong fieldOffsets;

        public long typeDefinitionsSizesCount;
        public ulong typeDefinitionsSizes;
        [Version(Min = 19)]
        public ulong metadataUsagesCount;
        [Version(Min = 19)]
        public ulong metadataUsages;
    }

    public enum Il2CppTypeEnum
    {
        IL2CPP_TYPE_END = 0x00,       /* End of List */
        IL2CPP_TYPE_VOID = 0x01,
        IL2CPP_TYPE_BOOLEAN = 0x02,
        IL2CPP_TYPE_CHAR = 0x03,
        IL2CPP_TYPE_I1 = 0x04,
        IL2CPP_TYPE_U1 = 0x05,