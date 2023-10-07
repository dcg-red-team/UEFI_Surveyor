The EFISeek and UEFISurveyor Ghidra tools, rely upon a guid file to
correctly identify guids within the efi file being analysed. This tool
allows an easy way to modify or create new files. This tools adds the 
ability to not only switch between output formats of the tools but to 
also add new guids located within UEFI source code.

1. Open options.yaml.
   Note: a value will not be replaced if a collision is found.
         Values are input based upon order within options.yaml file
  - OUTPUT - EFISeek or UEFISurveyor
  - INPUT
    - TYPE - DEC, EFISeek, or UEFISurveyor
    - PATH - If DEC file the root directory for the source 
             If EFISeek or UEFISurveyor location of data file
    - OPTIONS - Only applicable for DEC files.  The packages 
                within the source to search for dec files

2. Run guid_finder.py to generate a file named tmp_guid_db

3a. If UEFISurveyor is used. Rename the file and relocate to where needed on
    the system.  Open the options.yaml file associated with UEFISurveyor and
    ensure the guid file name and location are specified to the name and location
    of the file created.

3b. If EFISeek is used, Copy tmp_guid_db to /efiSeek_DIR/data/guids-db.ini
  - efiSeek_DIR - location of efiSeek on the system
  - Recompile and install the EFISeek plugin for changes to take effect
