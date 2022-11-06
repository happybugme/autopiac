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

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"].encode("utf-8")
		set_name(addr, name)
		monitor.incrementProgress(1)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	monitor.initialize(len(scriptStrings))
	monitor.setMessage("Strings")
	for scriptString in scriptStrings:
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"].encode("utf-8")
		name = "StringLiteral_" + str(index)
		createLabel(addr, name, True, USER_DEFINED)
		setEOLComment(addr, value)
		index += 1
		monitor.increment