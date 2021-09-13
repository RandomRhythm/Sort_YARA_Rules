# Sort Rules
### Sort YARA rules by targeted file type. 
You must get a list of rules from [YARA_Rules_Util](https://github.com/RandomRhythm/YARA_Rules_Util) before you can sort rules:
                  YARA_Util.py -d C:\Path\To\Rules -s -v

The above command will create all_rules.csv in the script directory. Pass the path to all_rules.csv to Sort_Rules:
                  Sort_Rules.py -i "E:\\YARA_Rules_Util\\all_rules.csv" -o "E:\\YARA_Sort_Rules\\log.txt" -m "E:\\YARA_Rules_Util\\rule_remapping.csv" -l "E:\\YARA_Hash_Values\\yara_Hash_lookups.csv" -a
                  
Options:
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