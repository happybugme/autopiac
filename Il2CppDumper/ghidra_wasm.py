# -*- coding: utf-8 -*-
import json

from wasm import WasmLoader
from wasm.analysis import WasmAnalysis
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
WasmLoader.loadElementsToTable(currentProgram, WasmAnalysis.getState(currentProgram).module, 0, 0, 0, monitor)

runScript("analyze_dyncalls.py")

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
progspace = currentProgram.addressFactory.getAddressSpace("ram")
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return progspace.getAddress(addr)

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
	dynCallNamespace =  currentProgram.symbolTable.getNamespace("dynCall", None)
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		offset = scriptMethod["Address"]
		sig = scriptMethod["TypeSignature"]
		symbolName = "func_%s_%d" % (sig, offset)
		symbol = currentProgram.symbolTable.getSymbols(symbolName, dynCallNamespace)
		if len(symbol) > 0:
			addr = symbol[0].address
			name = scriptMethod["Name"].encode("utf-8")
			set_name(addr, name)
		else:
			print "Wa