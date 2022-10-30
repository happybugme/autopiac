# -*- coding: utf-8 -*-
import json

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
	name = name.replace(' ', '-')
	createLabel(addr, name, True, USER_DEFINED)

def make_function(start):
	func = getFunctionAt(start)
	if func is None:
		createFunction(start, None)

f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))

if "ScriptMethod" in data and "ScriptMethod" in pro