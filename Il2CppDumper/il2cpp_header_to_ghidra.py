import re

header = "typedef unsigned __int8 uint8_t;\n" \
         "typedef unsigned __int16 uint16_t;\n" \
         "typedef unsigned __int32 uint32_t;\n" \
         "typedef unsigned __int64 uint64_t;\n" \
         "typedef __int8 int8_t;\n" \
         "typedef __int16 int16_t;\n" \
         "typedef __int32 int32_t;\n" \
         "typedef __int64 int64_t;\n" \
         "typedef __int64 intptr_t;\n" \
         "typedef __int64 uintptr_t;\n" \
         "typedef unsigned __int64 size_t;\n" \
         "typedef _Bool bool;\n"


def main():
    fixed_header_data = ""
    with open("il2cpp.h", 'r') as f:
        print("il2cpp.h opened...")
        original_header_data = f.read()
        print("il2cpp.h read...")
        fixed_header_data = re.sub(r": (\w+) {", r"{\n \1 super;", original_header_data)
        print("il2cpp.h data fixed...")
    print("il2cpp.h closed.")
    with 