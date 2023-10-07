# decompressHelper

## Introduction
decompressHelper can be used to extract the files from a spi binary or firmware update. The script can utilize either CHIPSEC or UEFIExtract to conduct the decoding and gathering only the necessary files into a folder for UEFISurveyor to analyze. There is also a mode to compare the results of multiple decompression attempts to ensure there are no missing results based upon the use of a specific tool.

## Setup

### Pre-requisites
  - UEFIExtract -  (github.com/longsoft/uefitool)
  - CHIPSEC - (github.com/chipsec/chipsec)
    - Only need to compile the compression portion not the helper

### Configuration
Edit the configuraiton file before running
```
Decompress: # Do not change
  Program: # Do not change
    UEFIExtract: # Unique Name (Can be Multiple Entries)
      Type: # Either UEFIExtract or CHIPSEC
      Path: # Path to binary
    CHIPSEC: # Unique Name (Entry 2)
      Type: # Either UEFIExtract or CHIPSEC
      Path: # Path to binary
  Python: # Path to python3
  Destination: # base path for results
  Binary: # do not change
    Files: [ #do not change
      # path to 0 or more images
    ]
    Folders: [ # do not change
      # path to 0 or more folders containing images
    ]
  Compare: # Either True or False
```

### Running
python decompress.py

## Output
- UEFIExtract will create a filename.report.txt and filename.dump folder
- CHIPSEC will create a filename.dir, filename.UEFI.lst, filename.UEFI.json
- The script will copy files from the .dir or .dump file into a new folder with the uniquename_filename
  - Within the folder will be the efi or te files along with a .Map file which maps the location of the file within this folder to the .dir or .dump file

If the Compare option is enabled, the map files for each filename will be compared with the following output.
UniqueName1 Uniquename2 path_to_image:
'mismathedFiles' - If there are multiple files with the same name this ensures all are within both
uniqueGUIDS1 - Any unique file guids found within uniqueName1
uniqueGUIDS2 - Any unique file guids found within uniqueName2

```
UEFIExtract CHIPSEC path_to_image :
{'mismatchedFiles': [], 'uniqueGUIDS1': [], 'uniqueGUIDS2': []}
```