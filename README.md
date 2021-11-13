# Sort Rules
### Sort YARA rules by targeted file type. 

This script can be used to reorganize/sort rules by the file type the rule was written to target. See [YARA_Rules_Project_Sorted_Ruleset](https://github.com/RandomRhythm/YARA_Rules_Project_Sorted_Ruleset) for an example repository of sorted YARA rules. Sub folders will be created for each identified file type and rule files will have the file type appended in the file name. These modifications make it easy to identify what file type the rule should be used to scan.

#### Prerequisite:

You must get a list of rules from [YARA_Rules_Util](https://github.com/RandomRhythm/YARA_Rules_Util) before you can sort rules:

                  YARA_Util.py -d C:\Path\To\Rules -s -v

#### Options:

  -h, --help            show this help message and exit

  -i INPUTPATH, --input=INPUTPATH
                        Path to input file containing rule to file mapping
                        (required). Use YARA_Rules_Util to create the rule
                        mapping file

  -a, --autosort        Sort rules by file type using rule content and
                        metadata (optional)

  -m MOVEPATH, --move=MOVEPATH
                        Path to file containing mapping of where rules should
                        be moved (optional)

  -l LOOKUPPATH, --lookups=LOOKUPPATH
                        Path to file containing VTTL hash lookup results
                        (optional)

  -o OUTPUTPATH, --output=OUTPUTPATH
                        Output log file path (optional)

#### Example command usage:
                        
The above command will create all_rules.csv in the script directory. Pass the path to all_rules.csv to Sort_Rules:

                  Sort_Rules.py -i "E:\\YARA_Rules_Util\\all_rules.csv" -o "E:\\YARA_Sort_Rules\\log.txt" -m "E:\\YARA_Rules_Util\\rule_remapping.csv" -l "E:\\YARA_Hash_Values\\yara_Hash_lookups.csv" -a
