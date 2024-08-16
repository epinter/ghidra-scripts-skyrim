# ***Ghidra Scripts for Skyrim***

Steps:

- Auto-analysis
- RunRttiAnalyzerScript.java
- FixUpRttiAnalysisScript.java
- RecoverClassesFromRTTIScript.java (takes time, more than 1 hour)
- Save!

- SkyrimRenameFromAddressLibrary (renames functions using address library skyrimae.rename and offsets.txt
- SkyrimLabelVtableFunctions (get functions names from vftables and add labels to symbol tree)

Both SkyrimRenameFromAddressLibrary and SkyrimLabelVtableFunctions are quick to run, no need to save if just testing.
