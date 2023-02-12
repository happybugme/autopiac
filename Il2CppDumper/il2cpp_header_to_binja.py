
import re

data = open("./il2cpp.h").read()

builtin = ["void", "intptr_t", "uint32_t", "uint16_t", "int32_t", "uint8_t", "bool",
           "int64_t", "uint64_t", "double", "int16_t", "int8_t", "float", "uintptr_t",
           "const", "union", "{", "};", "il2cpp_array_size_t", "il2cpp_array_lower_bound_t",
           "struct", "Il2CppMethodPointer"]
structs = []
notfound = []
header = ""

for line in data.splitlines():
    if line.startswith("struct") or line.startswith("union"):
        struct = line.split()[1]
        if struct.endswith(";"):
            struct = struct[:-1]
        structs.append(struct)
    if line.startswith("\t"):
        struct = line[1:].split()[0]
        if struct == "struct":
            struct = line[1:].split()[1]
        if struct.endswith("*"):
            struct = struct[:-1]
        if struct.endswith("*"):
            struct = struct[:-1]