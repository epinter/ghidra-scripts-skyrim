//Adds labels to functions found in vtables, the functions are found in the symbol tree.
//@category  Skyrim
//@author    epinter

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;

import java.util.Iterator;

@SuppressWarnings({"unused", "SpellCheckingInspection"})
public class SkyrimLabelVtableFunctions extends GhidraScript {
    private static final boolean DEBUG = false;
    //when true, label is set on function, when false label is set on pointer
    private static final boolean LABEL_TO_FUNC = false;

    @Override
    protected void run() throws Exception {
        Iterator<Relocation> relocations = currentProgram.getRelocationTable().getRelocations();
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolIterator();
        while (symbols.hasNext()) {
            Symbol s = symbols.next();
            if (s.getSymbolType().equals(SymbolType.CLASS)) {
                logDebug("%s %s %s%n", s.getName(), s.getSymbolType());
            }
        }

        while (relocations.hasNext()) {
            Relocation r = relocations.next();
            for (var s : currentProgram.getSymbolTable().getSymbols(r.getAddress())) {
                if (s.getName().equals("vftable")) {
                    Data data = getDataAt(s.getAddress());
                    Symbol symbol = getSymbolAt(data.getAddress());
                    Namespace parentClass = null;
                    if (symbol.getParentNamespace() != null && !symbol.getParentNamespace().isGlobal() && data.isArray()) {
                        parentClass = symbol.getParentNamespace();
                        logDebug("%s %s%n", r.getAddress(), parentClass);
                        for (int i = 0; i < data.getNumComponents(); i++) {
                            Address pointer = data.getComponent(i).getAddress();
                            Address vfAddr = (Address) data.getComponent(i).getValue();
                            Symbol symVf = getSymbolAt(vfAddr);
                            Function f = getFunctionAt(vfAddr);

                            logDebug("\t\t%s %s %s %n", data.getComponent(i).getValue(), symVf.getName(), f.getName());

//                            String labelStr;
//                            if (symVf.getParentNamespace().getName().equals(currentProgram.getGlobalNamespace().getName())) {
//                                labelStr = symVf.getName();
//                            } else {
//                                labelStr = String.format("%s::%s", symVf.getParentNamespace().getName(), symVf.getName());
//                            }
                            String labelStr = symVf.getName();
                            //pointer, labelStr, parentClass, false, SourceType.IMPORTED);
                            if (currentProgram.getSymbolTable().getSymbols(labelStr, parentClass).isEmpty()) {
                                Symbol label = currentProgram.getSymbolTable().createLabel(LABEL_TO_FUNC ? symVf.getAddress() : pointer, labelStr, parentClass, SourceType.IMPORTED);
                            } else {
                                logDebug("symbol '%s' already exists (%s)", labelStr, parentClass.getName());
                            }
                        }
                    }
                }
            }
        }
    }

    private void logError(String format, Object... args) {
        printerr(String.format(format, args));
    }

    private void logInfo(String format, Object... args) {
        println(String.format(format, args));
    }

    private void logDebug(String format, Object... args) {
        if (DEBUG)
            printerr(String.format(format, args));
    }
}