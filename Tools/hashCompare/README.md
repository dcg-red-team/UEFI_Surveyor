compareHashes.py was created to allow a user to compare the hash results from running UEFISurveyor with other runs from the tool.  The module can compare two files to return the differences, or two directories.

usage:
  compareHashes.py directory dir1 dir2
  compareHashes.py file file1 file2

output:
  hashlog.json will be created upon a successful run.

Interpreting Results:
    "uniqueFiles1" - list of files within directory 2 but not in directory 1
    "uniqueFiles2" - list of files within directory 1 but not in directory 2
    "misMatchedFiles" - list of files that did not match due to extra functions or hashes
    "00000000-0000-0000-0000-000000000000_Filename.json": - specific xml file
    "uniqueFunctions1" - list of functions within file 2 but not in file 1,
    "uniqueFunctions2" - list of functions within file 1 but not in file 2
    "mismatchedHashes" - list of funcions with hashes that do not match