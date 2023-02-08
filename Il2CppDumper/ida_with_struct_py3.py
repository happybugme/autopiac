# -*- coding: utf-8 -*-
import json

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

imageBase = idaapi.get_imagebase()

def get_addr(addr):
	return imageBase + addr

def set_name(addr, name):
	ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
	if ret == 0:
		new_name = name + '_' + str(addr)
		ret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)

def make_function(start, end):
	next_func = idc.get_next_func(start)
	if next_func < end:
		end = next_func
	if idc.get_func_attr(start, FUNCATTR_START) == start:
		ida_funcs.del_func(start)
	ida_funcs.add_func(start, end)

path = idaapi.ask_file(False, '*.json', 'script.json from Il2cppdumper')
hpath = idaapi.ask_file(False, '*.h', 'il2cpp.h from Il2cppdumper')
parse_decls(open(hpath, 'r').read(), 0)
data = json.loads(open(path, 'rb').read().decode('utf-8'))

if "Addresses" in data and "Addresses" in processFields:
	addresses = data["Addresses"]
	for index in range(len(addresses) - 1):
		start = get_addr(addresses[index])
		end = get_addr(addresses[index + 1])
		make_function(start, end)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"]
		set_name(addr, name)
		signature = scriptMethod["Signature"]
		if apply_type(addr, parse_decl(signature, 0), 1) == False:
			print("apply_type failed:", hex(addr), signature)

if "ScriptString" in data and "ScriptString" in proce