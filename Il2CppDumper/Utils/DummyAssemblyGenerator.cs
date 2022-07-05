
﻿using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Collections.Generic;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public class DummyAssemblyGenerator
    {
        public List<AssemblyDefinition> Assemblies = new();

        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppTypeDefinition, TypeDefinition> typeDefinitionDic = new();
        private readonly Dictionary<Il2CppGenericParameter, GenericParameter> genericParameterDic = new();
        private readonly MethodDefinition attributeAttribute;
        private readonly TypeReference stringType;
        private readonly TypeSystem typeSystem;
        private readonly Dictionary<int, FieldDefinition> fieldDefinitionDic = new();
        private readonly Dictionary<int, PropertyDefinition> propertyDefinitionDic = new();
        private readonly Dictionary<int, MethodDefinition> methodDefinitionDic = new();

        public DummyAssemblyGenerator(Il2CppExecutor il2CppExecutor, bool addToken)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;

            //Il2CppDummyDll
            var il2CppDummyDll = AssemblyDefinition.ReadAssembly(new MemoryStream(Resource1.Il2CppDummyDll));
            Assemblies.Add(il2CppDummyDll);
            var dummyMD = il2CppDummyDll.MainModule;
            var addressAttribute = dummyMD.Types.First(x => x.Name == "AddressAttribute").Methods[0];
            var fieldOffsetAttribute = dummyMD.Types.First(x => x.Name == "FieldOffsetAttribute").Methods[0];
            attributeAttribute = dummyMD.Types.First(x => x.Name == "AttributeAttribute").Methods[0];
            var metadataOffsetAttribute = dummyMD.Types.First(x => x.Name == "MetadataOffsetAttribute").Methods[0];
            var tokenAttribute = dummyMD.Types.First(x => x.Name == "TokenAttribute").Methods[0];
            stringType = dummyMD.TypeSystem.String;
            typeSystem = dummyMD.TypeSystem;

            var resolver = new MyAssemblyResolver();
            var moduleParameters = new ModuleParameters
            {
                Kind = ModuleKind.Dll,
                AssemblyResolver = resolver
            };
            resolver.Register(il2CppDummyDll);

            var parameterDefinitionDic = new Dictionary<int, ParameterDefinition>();
            var eventDefinitionDic = new Dictionary<int, EventDefinition>();

            //创建程序集，同时创建所有类
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var aname = metadata.assemblyDefs[imageDef.assemblyIndex].aname;
                var assemblyName = metadata.GetStringFromIndex(aname.nameIndex);
                Version vers;
                if (aname.build >= 0)
                {
                    vers = new Version(aname.major, aname.minor, aname.build, aname.revision);
                }
                else
                {
                    //__Generated
                    vers = new Version(3, 7, 1, 6);
                }
                var assemblyNameDef = new AssemblyNameDefinition(assemblyName, vers);
                /*assemblyNameDef.Culture = metadata.GetStringFromIndex(aname.cultureIndex);
                assemblyNameDef.PublicKey = Encoding.UTF8.GetBytes(metadata.GetStringFromIndex(aname.publicKeyIndex));
                assemblyNameDef.HashAlgorithm = (AssemblyHashAlgorithm)aname.hash_alg;
                assemblyNameDef.Attributes = (AssemblyAttributes)aname.flags;
                assemblyNameDef.PublicKeyToken = aname.public_key_token;*/
                var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyNameDef, imageName, moduleParameters);
                resolver.Register(assemblyDefinition);
                Assemblies.Add(assemblyDefinition);
                var moduleDefinition = assemblyDefinition.MainModule;
                moduleDefinition.Types.Clear();//清除自动创建的<Module>类
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    var namespaceName = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                    var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);
                    var typeDefinition = new TypeDefinition(namespaceName, typeName, (TypeAttributes)typeDef.flags);
                    typeDefinitionDic.Add(typeDef, typeDefinition);
                    if (typeDef.declaringTypeIndex == -1)
                    {
                        moduleDefinition.Types.Add(typeDefinition);
                    }
                }
            }
            foreach (var imageDef in metadata.imageDefs)
            {
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    var typeDefinition = typeDefinitionDic[typeDef];

                    //nestedtype
                    for (int i = 0; i < typeDef.nested_type_count; i++)
                    {
                        var nestedIndex = metadata.nestedTypeIndices[typeDef.nestedTypesStart + i];
                        var nestedTypeDef = metadata.typeDefs[nestedIndex];
                        var nestedTypeDefinition = typeDefinitionDic[nestedTypeDef];
                        typeDefinition.NestedTypes.Add(nestedTypeDefinition);
                    }
                }
            }
            //提前处理
            foreach (var imageDef in metadata.imageDefs)
            {
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    var typeDefinition = typeDefinitionDic[typeDef];

                    if (addToken)
                    {
                        var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                        customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{typeDef.token:X}")));
                        typeDefinition.CustomAttributes.Add(customTokenAttribute);
                    }

                    //genericParameter
                    if (typeDef.genericContainerIndex >= 0)
                    {
                        var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                        for (int i = 0; i < genericContainer.type_argc; i++)
                        {
                            var genericParameterIndex = genericContainer.genericParameterStart + i;
                            var param = metadata.genericParameters[genericParameterIndex];
                            var genericParameter = CreateGenericParameter(param, typeDefinition);
                            typeDefinition.GenericParameters.Add(genericParameter);
                        }
                    }

                    //parent
                    if (typeDef.parentIndex >= 0)
                    {
                        var parentType = il2Cpp.types[typeDef.parentIndex];
                        var parentTypeRef = GetTypeReference(typeDefinition, parentType);
                        typeDefinition.BaseType = parentTypeRef;
                    }

                    //interfaces
                    for (int i = 0; i < typeDef.interfaces_count; i++)
                    {
                        var interfaceType = il2Cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                        var interfaceTypeRef = GetTypeReference(typeDefinition, interfaceType);
                        typeDefinition.Interfaces.Add(new InterfaceImplementation(interfaceTypeRef));
                    }
                }
            }
            //处理field, method, property等等
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; index++)
                {
                    var typeDef = metadata.typeDefs[index];
                    var typeDefinition = typeDefinitionDic[typeDef];

                    //field
                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                    for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                    {
                        var fieldDef = metadata.fieldDefs[i];
                        var fieldType = il2Cpp.types[fieldDef.typeIndex];
                        var fieldName = metadata.GetStringFromIndex(fieldDef.nameIndex);
                        var fieldTypeRef = GetTypeReference(typeDefinition, fieldType);
                        var fieldDefinition = new FieldDefinition(fieldName, (FieldAttributes)fieldType.attrs, fieldTypeRef);
                        typeDefinition.Fields.Add(fieldDefinition);
                        fieldDefinitionDic.Add(i, fieldDefinition);

                        if (addToken)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{fieldDef.token:X}")));
                            fieldDefinition.CustomAttributes.Add(customTokenAttribute);
                        }

                        //fieldDefault
                        if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefault) && fieldDefault.dataIndex != -1)
                        {
                            if (executor.TryGetDefaultValue(fieldDefault.typeIndex, fieldDefault.dataIndex, out var value))
                            {
                                fieldDefinition.Constant = value;
                            }
                            else
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                customAttribute.Fields.Add(offset);
                                fieldDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                        //fieldOffset
                        if (!fieldDefinition.IsLiteral)
                        {
                            var fieldOffset = il2Cpp.GetFieldOffsetFromIndex(index, i - typeDef.fieldStart, i, typeDefinition.IsValueType, fieldDefinition.IsStatic);
                            if (fieldOffset >= 0)
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(fieldOffsetAttribute));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{fieldOffset:X}"));
                                customAttribute.Fields.Add(offset);
                                fieldDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                    }
                    //method
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        var methodDef = metadata.methodDefs[i];
                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                        var methodDefinition = new MethodDefinition(methodName, (MethodAttributes)methodDef.flags, typeDefinition.Module.ImportReference(typeSystem.Void))
                        {
                            ImplAttributes = (MethodImplAttributes)methodDef.iflags
                        };
                        typeDefinition.Methods.Add(methodDefinition);
                        //genericParameter
                        if (methodDef.genericContainerIndex >= 0)
                        {
                            var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                            for (int j = 0; j < genericContainer.type_argc; j++)
                            {
                                var genericParameterIndex = genericContainer.genericParameterStart + j;
                                var param = metadata.genericParameters[genericParameterIndex];
                                var genericParameter = CreateGenericParameter(param, methodDefinition);
                                methodDefinition.GenericParameters.Add(genericParameter);
                            }
                        }
                        var methodReturnType = il2Cpp.types[methodDef.returnType];
                        var returnType = GetTypeReferenceWithByRef(methodDefinition, methodReturnType);
                        methodDefinition.ReturnType = returnType;

                        if (addToken)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{methodDef.token:X}")));
                            methodDefinition.CustomAttributes.Add(customTokenAttribute);
                        }

                        if (methodDefinition.HasBody && typeDefinition.BaseType?.FullName != "System.MulticastDelegate")
                        {
                            var ilprocessor = methodDefinition.Body.GetILProcessor();
                            if (returnType.FullName == "System.Void")
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else if (returnType.IsValueType)
                            {
                                var variable = new VariableDefinition(returnType);
                                methodDefinition.Body.Variables.Add(variable);
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloca_S, variable));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Initobj, returnType));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloc_0));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldnull));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                        }
                        methodDefinitionDic.Add(i, methodDefinition);
                        //method parameter
                        for (var j = 0; j < methodDef.parameterCount; ++j)
                        {
                            var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                            var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                            var parameterType = il2Cpp.types[parameterDef.typeIndex];
                            var parameterTypeRef = GetTypeReferenceWithByRef(methodDefinition, parameterType);
                            var parameterDefinition = new ParameterDefinition(parameterName, (ParameterAttributes)parameterType.attrs, parameterTypeRef);
                            methodDefinition.Parameters.Add(parameterDefinition);
                            parameterDefinitionDic.Add(methodDef.parameterStart + j, parameterDefinition);
                            //ParameterDefault
                            if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault) && parameterDefault.dataIndex != -1)
                            {
                                if (executor.TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                {
                                    parameterDefinition.Constant = value;
                                }
                                else
                                {
                                    var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                    var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                    customAttribute.Fields.Add(offset);
                                    parameterDefinition.CustomAttributes.Add(customAttribute);
                                }
                            }
                        }
                        //methodAddress
                        if (!methodDefinition.IsAbstract)
                        {
                            var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
                            if (methodPointer > 0)
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(addressAttribute));
                                var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{fixedMethodPointer:X}"));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2Cpp.MapVATR(methodPointer):X}"));
                                var va = new CustomAttributeNamedArgument("VA", new CustomAttributeArgument(stringType, $"0x{methodPointer:X}"));
                                customAttribute.Fields.Add(rva);
                                customAttribute.Fields.Add(offset);
                                customAttribute.Fields.Add(va);
                                if (methodDef.slot != ushort.MaxValue)
                                {
                                    var slot = new CustomAttributeNamedArgument("Slot", new CustomAttributeArgument(stringType, methodDef.slot.ToString()));
                                    customAttribute.Fields.Add(slot);
                                }
                                methodDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                    }
                    //property
                    var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                    for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                    {
                        var propertyDef = metadata.propertyDefs[i];
                        var propertyName = metadata.GetStringFromIndex(propertyDef.nameIndex);
                        TypeReference propertyType = null;
                        MethodDefinition GetMethod = null;
                        MethodDefinition SetMethod = null;
                        if (propertyDef.get >= 0)
                        {
                            GetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.get];
                            propertyType = GetMethod.ReturnType;
                        }
                        if (propertyDef.set >= 0)
                        {
                            SetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.set];
                            propertyType ??= SetMethod.Parameters[0].ParameterType;
                        }
                        var propertyDefinition = new PropertyDefinition(propertyName, (PropertyAttributes)propertyDef.attrs, propertyType)
                        {
                            GetMethod = GetMethod,
                            SetMethod = SetMethod
                        };
                        typeDefinition.Properties.Add(propertyDefinition);
                        propertyDefinitionDic.Add(i, propertyDefinition);

                        if (addToken)
                        {
                            var customTokenAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(tokenAttribute));
                            customTokenAttribute.Fields.Add(new CustomAttributeNamedArgument("Token", new CustomAttributeArgument(stringType, $"0x{propertyDef.token:X}")));
                            propertyDefinition.CustomAttributes.Add(customTokenAttribute);
                        }
                    }
                    //event
                    var eventEnd = typeDef.eventStart + typeDef.event_count;
                    for (var i = typeDef.eventStart; i < eventEnd; ++i)
                    {
                        var eventDef = metadata.eventDefs[i];
                        var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                        var eventType = il2Cpp.types[eventDef.typeIndex];