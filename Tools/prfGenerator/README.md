To improve binary analysis of EFI files within Ghidra a new GDT file specific to UEFI should be
created. The file is created by first identifying the headerfiles within the source code (create
a pfr file). With the pfr file, Ghidra can create a gdt file usable only on the system or exportable
to other systems. When loaded the GDT file will contain the uefi specific structures. This tool helps
to automate the creation of the pfr file given source code.

1. Open options.yaml and fill out the following sections
  - ARCH - processor Architecture (choose from X64, Arm, Ebc, Ia32, RiscV, RiscV64, AArch64)
  - EDK2
    -PATH - location of EDK2 on the system
    -PKGS - Which packages to extract headers from (MdePkg, MdeModulePkg, etc)
    -Note - Custom Entries can be added with the same format of Name: PATH: PKGS []
  - REQUIRED - Headers required to ensure pfr processing works

2. Run gen_prf.py to generate a file named uefi_ARCH.prf

3. Copy the pfr file to /GHIDRA_DIR/Ghidra/Features/Base/data/parserprofiles/
  - GHIDRA_DIR - location of GHIDRA on the system
  - Recommend using version 10.1.5 or Greater

4. Open a Ghidra CodeBrowser instance
  a. open the Parse C Source option under file
  b. select uefi_ARCH.prf from the drop down menu
  c. select Parse to File to create a gdt file

Debugging:
1. If there is a parsing error debug by looking at the CParserPlugin.out to determine the source of the error
  a. known changes necessary:
    i. Add #include <Protocol/PxeBaseCode.h> to PxeBaseCodeCallBack.h
