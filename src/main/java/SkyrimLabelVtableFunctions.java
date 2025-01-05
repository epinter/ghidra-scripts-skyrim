//Adds labels to functions found in vtables, the functions are found in the symbol tree.
//@category  Skyrim
//@author    epinter

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Structure;
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
    private static final boolean COMMENT_STRUCTURE = true;

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
                if (s.getName().equals("vftable") || s.getName().startsWith("vftable_for")) {
                    Data data = getDataAt(s.getAddress());
                    if(data == null) {
                        logError("unable to retrieve data from vtable: '%s' (%s)", s.getName(), s.getSymbolType());
                        continue;
                    }
                    Symbol symbol = getSymbolAt(data.getAddress());
                    Namespace parentClass = null;
                    if (symbol.getParentNamespace() != null && !symbol.getParentNamespace().isGlobal()
                            && (data.isArray() || data.isStructure())) {
                        parentClass = symbol.getParentNamespace();

                        for (int i = 0; i < data.getNumComponents(); i++) {
                            Address pointer = data.getComponent(i).getAddress();
                            Address vfAddr = (Address) data.getComponent(i).getValue();
                            Symbol symVf = getSymbolAt(vfAddr);
                            Function f = getFunctionAt(vfAddr);

                            String labelStr = null;
                            if (data.isArray()) {
                                labelStr = symVf.getName();
                            } else if (data.isStructure()) {
                                labelStr = f.getName();
                                if (COMMENT_STRUCTURE) {
                                    Structure structure = (Structure) data.getDataType();
                                    structure.getComponent(i).setComment(
                                            String.format("%s::%s", f.getParentNamespace().getName(), f.getName()));
                                    logDebug("%s %s %s", data.getDataType().getName(),
                                            data.getDataType().getDataTypePath(), structure.getComponent(i).getFieldName());
                                }
                            }

                            if (currentProgram.getSymbolTable().getSymbols(labelStr, parentClass).isEmpty()
                                    && currentProgram.getSymbolTable().getSymbols(f.getName(), parentClass).isEmpty()) {
                                Symbol label = currentProgram.getSymbolTable().createLabel(
                                        LABEL_TO_FUNC ? symVf.getAddress() : pointer, labelStr, parentClass, SourceType.IMPORTED);
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
        if (args.length > 0) {
            printerr(String.format(format, args));
        } else {
            printerr(format);
        }
    }

    private void logInfo(String format, Object... args) {
        if (args.length > 0) {
            println(String.format(format, args));
        } else {
            println(format);
        }
    }

    private void logDebug(String format, Object... args) {
        if (!DEBUG)
            return;
        logError(format, args);
    }
}