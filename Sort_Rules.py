#Sort YARA Rules by File Type - Ryan Boyle

import sys
from optparse import OptionParser
import csv
import os
import pathlib
import operator
import itertools
import re
import datetime
from collections import defaultdict
import populateHashDict
import sort_support


def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Sort YARA rules by file type")
    parser.add_option("-i", "--input", action="store", default=None, dest="InputPath",
                      help="Path to input file containing rule to file mapping (required). Use YARA_Rules_Util to create the rule mapping file")
    parser.add_option("-a", "--autosort", help="Sort rules by file type using rule content and metadata (optional)", action="store_true")
    parser.add_option("-m", "--move", action="store", default=None, dest="movePath",
                      help="Path to file containing mapping of where rules should be moved (optional)")
    parser.add_option("-l", "--lookups", action="store", default=None, dest="lookupPath",
                      help="Path to file containing VTTL hash lookup results (optional)")
    parser.add_option("-o", "--output", action="store", default=None, dest="OutputPath",
                      help="Output log file path (optional)")
    return parser




def ProcessRule(lstRuleFile, strYARApath, strOutPath):
  strYARAout = ""
  strLogOut = ""
  boolExcludeLine = False
  boolOverwrite = False
  boolOpenBracket = False
  boolRuleMoved = False
  boolCloseBracket = False
  boolSkipWrite = False #skip writing rule as it needs to go back into the rule file being read
  boolFirstCommentFound = False #license
  boolLicenseCaptured = False #end of license indicator
  boolCommentOpen = False
  boolMeta = False
  boolStringsSection = False
  boolConditionSection = False
  strReplacementFile = "" #if yara file still has rules in them then replace with these contents
  licenseReplicate = ""
  ruleOutputPath = ""
  vtFileType = ""
  ruleFileType = "" #not used. Can remove
  magicType = ""
  strRuleName = ""
  boolPEimported = False
  if strOutPath == "":
    strOutPath = strYARApath
  if not os.path.exists(lstRuleFile):
    logToFile(logoutput,"missing file! " + lstRuleFile +"\n", False, "a")
    return
  with open(lstRuleFile, 'r') as file1:
    Lines = file1.readlines() 
  for strRuleLine in Lines:


    strRuleOut = strRuleLine
    nameDepth = 0
    if strRuleLine[:5] == "rule ":
      nameDepth = 5
    elif strRuleLine[:13] == "private rule ":
      nameDepth = 13
    if nameDepth != 0:  
      strRuleName = strRuleLine[-(len(strRuleLine) -nameDepth):]
      strRuleName = strRuleName[:len(strRuleName) -1]
      if strRuleName[-1:] == "\r":
        strRuleName = strRuleName[:-1]
      if strRuleName[-1:] == "{":
        strRuleName = strRuleName[:-1]
      if strRuleName[-1:] == " ":
        while strRuleName[-1:] == " ":
          strRuleName = strRuleName[:-1]


      #print (strRuleName)
      if "without_urls" in strRuleName:
        debugme=True # right now I'm just setting a breakpoint here, but might use this to debug log
      if strRuleName not in ruleMapping and strRuleName.strip() in ruleMapping: #try to match rule name without whitespace against rule mapping
        strRuleName = strRuleName.strip()
    strYARAout = strYARAout + strRuleOut
    
    
    
    if strRuleOut[:2] == "/*" and  strRuleOut[-3:] == "*/\n": #one line comments are ignored right now
        boolFirstCommentFound = boolFirstCommentFound #do nothing
    elif strRuleOut[:2] == "/*" and boolLicenseCaptured == False: #license capture for replication into files
      boolFirstCommentFound = True
      licenseReplicate = strRuleLine
    elif strRuleOut[-3:] == "*/\n" and boolLicenseCaptured ==False:
      licenseReplicate = licenseReplicate + strRuleLine + "\n"
      boolLicenseCaptured = True
    elif boolLicenseCaptured ==False and boolFirstCommentFound == True:
      licenseReplicate = licenseReplicate + strRuleLine
      strRuleName = "" #still in comment so ignore any matched rule text. need to ignore in every comment not just this first one https://github.com/Yara-Rules/rules/blob/b496aadd3099c9d0955685d450b9fd2c871b1ce8/malware/RANSOM_MS17-010_Wannacrypt.yar
    elif (strRuleOut[:2] == "/*") and boolCommentOpen == False:
      boolCommentOpen = True
    elif (strRuleOut[:2] == "*/" or strRuleOut[-3:] == "*/\n") and boolCommentOpen == True:
      boolCommentOpen = False
    elif boolCommentOpen == True: #exclude rule since it is commented out
      if strRuleName in strRuleLine: #commented out rule will move into whatever file the next rule moves to. If no next rule then commented out rule will be lost 
        strRuleName = ""

    
    if boolCommentOpen == False: #if not in a comment
      #check bracket compliance
      if strRuleName != "" and "{" in strRuleLine and "\"" not in strRuleLine and "}" not in strRuleLine and "//" not in strRuleLine and "$" not in strRuleLine:
        if boolOpenBracket == True:
          #print("Two open brackets in a row: " + strYARAout)
          pass
        else:
          #print("open bracket")
          boolOpenBracket = True
          boolCloseBracket = False
      #elif "{" in strRuleLine and "}" not in strRuleLine and "\"" in strRuleLine:
      #  print("Possible quoted bracket missmatch: " + strRuleLine)
      elif "{" in strRuleLine and "}" not in strRuleLine and "\"" not in strRuleLine and "$" not in strRuleLine:
        #print("Possible non-quoted bracket missmatch: " + strRuleLine)    
        pass
      if boolConditionSection == True and strRuleName != "" and "}" in strRuleLine and "\"" not in strRuleLine and "//" not in strRuleLine and "$" not in strRuleLine:
        boolCloseBracket = True
        #print("close")
        boolOpenBracket = False
        boolMeta = False
        boolStringsSection = False
        boolConditionSection = False
      #elif "}" in strRuleLine and "{" not in strRuleLine and "\"" in strRuleLine:
      #  print("Possible quoted bracket missmatch: " + strRuleLine)
      elif "}" in strRuleLine and "{" not in strRuleLine and "\"" not in strRuleLine and "$" not in strRuleLine:
        #print("Possible non-quoted bracket missmatch: " + strRuleLine)
        pass
      if boolOpenBracket == True and "meta:" in strRuleLine:
        boolMeta = True
        #print("meta")
      elif "strings:" in strRuleLine:
        boolMeta = False
        boolStringsSection = True
        #print("strings")
      elif "condition:" in strRuleLine:
        boolStringsSection = False
        boolConditionSection = True
    
    #if in strings or conditional sections check for regex match against magic numbers
    if (boolStringsSection == True or boolConditionSection == True) and ruleFileType == "" and magicType == "":
       saniString = strRuleLine
       if "*/" in strRuleLine and  "/*" in strRuleLine:
        saniString = sort_support.removeComment(saniString) #remove comment from text that will be processed with regex
       tmpMagicType = sort_support.checkMagic(saniString) #regex check against magic numbers

       if "|" in tmpMagicType: #pipe separated value was returned
           magicType = "multi"
       if magicType == "" or magicType != tmpMagicType:
            if magicType == "" and tmpMagicType != "":
                magicType = tmpMagicType
            elif tmpMagicType != "": #more than one match
                magicType = "multi"
            
    
    if boolConditionSection == True:
        boolImportPE = False
        if "pe." in strRuleLine: #pe module usage
            ruleOutputPath = os.path.join(strOutPath , "pe" ) 
            ruleOutputPath = os.path.join(ruleOutputPath, os.path.splitext(os.path.basename(lstRuleFile))[0] + "_pe.yar")
            boolImportPE = True
        #check for hash values
        pattern = re.compile("hash\\.(md5|sha1|sha256)\\(0, filesize\\)")
        if pattern.search(strRuleLine): #if file hash in condition section
          #check against hash lookup results
          if len(populateHashDict.dictHashTypes) > 0: #if we have loaded the dictionary
            hashList = re.findall("[A-Fa-f0-9]{32,128}",strRuleLine)
            vtFileType = populateHashDict.hashCheck(hashList, vtFileType) #get file type from VirusTotal export
                
    #if in the metadata section check for file extensions in the strings
    if boolMeta == True:
      lastExtension = "";
      for extension in fileExtensions: #loop through file extensions and see what we come up with for a file type
        excludedExtension = False
          #exclude urls with matching file extensions.
        if (extension == ".pdf" or extension == ".htm" or extension == ".html" or extension == ".pl" or extension == ".aspx" or extension == ".asp" or extension == "jsp" or extension == "php") and ("http://" in strRuleLine.lower() or "https://" in strRuleLine.lower() or strRuleLine.lower()[:4] == "www."):
          excludedExtension = True #url to PDF/html can be ignored
        elif "_cmd" not in strRuleName.lower() and (extension.replace(".","_") in strRuleName.lower() or extension.replace(".","") + "_" == strRuleName.lower()[0:len(extension)]): #store output path for rule rule
          
        #exclusion check
          if extension in excludeDict:
            for excludeItem in excludeDict[extension]: # for list in dict
                excludedMatch = excludeItem.replace(".","_")
                if excludedMatch in strRuleName.lower():
                  excludedExtension = True
          if extension in lastExtension and "\\" + fileExtensions[lastExtension] in ruleOutputPath:
              excludedExtension = True
          if ruleOutputPath != "" and extension == ".txt": #.txt isn't a malicious file type. Use whatever is already set
              excludedExtension = True
          if excludedExtension == False and strRuleName not in ruleMapping: #if not excluded then set output path
            #set output file path for rule
            ruleOutputPath = os.path.join(strOutPath , fileExtensions[extension] ) 
            if not os.path.isdir(ruleOutputPath): 
              os.makedirs(ruleOutputPath)
            ruleOutputPath = os.path.join(ruleOutputPath, os.path.splitext(os.path.basename(lstRuleFile))[0] + "_" + fileExtensions[extension] + ".yar")
        elif excludedExtension == False and extension in strRuleLine.lower() and ruleOutputPath == "" and strRuleName not in ruleMapping: #store output path for rule
          ruleOutputPath = os.path.join(strOutPath , fileExtensions[extension] ) 
          if not os.path.isdir(ruleOutputPath): 
            os.makedirs(ruleOutputPath )
            #print(extension + "|" + strRuleLine)
          ruleOutputPath = os.path.join(ruleOutputPath, os.path.splitext(os.path.basename(lstRuleFile))[0] + "_" + fileExtensions[extension] + ".yar")
          #print(ruleOutputPath)
        lastExtension = extension;

      #check against hash lookup results
      if len(populateHashDict.dictHashTypes) > 0: #if we have loaded the dictionary
        hashList = re.findall("[A-Fa-f0-9]{32,128}",strRuleLine)
        vtFileType = populateHashDict.hashCheck(hashList, vtFileType) #get file type from VTTL VirusTotal export

      if boolOpenBracket == False and boolCloseBracket == True:
        print("bracket allignment problem")
    elif boolCloseBracket == True: #end of rule
      boolCloseBracket = False
      boolOpenBracket = False
      strYARAout = "\n" + strYARAout + "\n" #extra new line to separate rules in combined file
      if (vtFileType in populateHashDict.TrustedFileTypes or magicType != "" or ruleOutputPath == "") and strRuleName not in ruleMapping: #unknown or needs overwritten with file type identified by magic/VT. VirusTotal identification of some formats is accurate. Text based ones are less accurate

        if magicType != "" and boolAutoSort == True: #trust magic type identification the most
          
          if magicType == "zip" and vtFileType == "jar" and "\\war\\" not in ruleOutputPath: #jar is a zip with specific format
            magicType = "jar"
          if (magicType =="jar" or magicType =="zip") and ("\\war\\" in ruleOutputPath or "\\jar\\" in ruleOutputPath):
            pass #do nothing (use existing file type)
          else:
            ruleOutputPath = os.path.join(strOutPath , magicType )
          ruleOutputPath = os.path.join(ruleOutputPath, os.path.splitext(os.path.basename(lstRuleFile))[0] + "_" + magicType + ".yar")
        elif vtFileType != "" and boolAutoSort == True and "\\mem\\" not in ruleOutputPath: # if VT has file type and type not already set to memory
          ruleOutputPath = os.path.join(strOutPath , vtFileType )
          ruleOutputPath = os.path.join(ruleOutputPath, os.path.splitext(os.path.basename(lstRuleFile))[0] + "_" + vtFileType + ".yar")



      if ruleOutputPath == "":
        ruleOutputPath = os.path.join(strOutPath , "unknown" )
        if not os.path.isdir(ruleOutputPath): 
            os.makedirs(ruleOutputPath)
        ruleOutputPath = os.path.join(ruleOutputPath, os.path.basename(lstRuleFile))
      

      if licenseReplicate == "":
        licenseReplicate = strLicense

      if strRuleName in ruleMapping:
        if ruleMapping[strRuleName].replace("\\","/").lower() == strYARApath.replace("\\","/").lower(): #goes back into same file. Store for now to overwrite when finished sorting rules out of file.
            strReplacementFile = strReplacementFile + strYARAout
            if licenseReplicate.rstrip() not in strReplacementFile:
              strReplacementFile = licenseReplicate + Sort_Rules + strReplacementFile
            elif boolRuleMoved == True and Sort_Rules not in strReplacementFile:
              strReplacementFile = strReplacementFile.replace(licenseReplicate,licenseReplicate + Sort_Rules)
            boolSkipWrite = True #skip writing rule as it needs to go back into the rule file being read
        else: #move to path specified in mapping
            
            ruleOutputPath = ruleMapping[strRuleName] #change output path to predefined path
            
            if not os.path.isdir(os.path.dirname(ruleOutputPath)): 
              os.makedirs(os.path.dirname(ruleOutputPath))
            
            #log license
            if not os.path.exists(ruleOutputPath) and licenseReplicate.rstrip() not in strYARAout:
              logToFile(ruleOutputPath,licenseReplicate + Sort_Rules, False, "a")
            logToFile(ruleOutputPath,strYARAout, False, "a")
            boolRuleMoved = True
            boolSkipWrite = True
      else:
        if not os.path.isdir(os.path.dirname(ruleOutputPath)): 
              os.makedirs(os.path.dirname(ruleOutputPath))
      
        if boolAutoSort == True and boolSkipWrite == False:  
          #if file does not exist and license not in rule text then log license
          if not os.path.exists(ruleOutputPath) and licenseReplicate.rstrip() not in strYARAout:
            logToFile(ruleOutputPath,licenseReplicate + Sort_Rules, False, "a")
          if boolImportPE == True and boolPEimported ==False:
            logToFile(ruleOutputPath,"import \"pe\"\n", False, "a")
            boolPEimported= True
          #log YARA rule
          logToFile(ruleOutputPath,strYARAout, False, "a") #output rule contents
          boolRuleMoved = True # add Sort_Rules to license to indicate modification
      #output rule processing log
      logToFile(logoutput,strRuleName + "," + ruleOutputPath +"\n", False, "a") #log rule,path
      #reset variables
      ruleOutputPath = ""  
      strYARAout = ""
      vtFileType = ""
      magicType = ""
      boolSkipWrite = False

  
  if strReplacementFile != "": #overwrite yara file with new content
    if  boolRuleMoved == True: #if changes were made to the file then write out changes
      logToFile(strYARApath,strReplacementFile, False, "w")
  elif boolRuleMoved == True:
    #rule file no longer needed. All rules have been migrated out
    os.remove(strYARApath)
    
def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    target = open(strfilePathOut, strWriteMode)
    if boolDeleteFile == True:
      target.truncate()
    target.write(strDataToLog)
    target.close()                     

def loadRuleFileMapping(strDictFilePath): #-m, --move #Path to file containing mapping of where rules files should be moved (optional)
  file1 = open(strDictFilePath, 'r') 
  mappings = file1.readlines() 
  for strRuleLine in mappings:
    if "," in strRuleLine:
      arrayRule = strRuleLine.split(",")
      ruleMapping[arrayRule[0]] = arrayRule[1].replace("\n","")


def loadFilePaths(strDictFilePath): #Load input list of rules to assess moving #verbose log from YARA_Rules_Util
  file1 = open(strDictFilePath, 'r') 
  mappings = file1.readlines() 
  for strRuleLine in mappings:
    if "," in strRuleLine:
      arrayRule = strRuleLine.split(",")
      if arrayRule[1].replace("\n","") not in fileList:
        fileList[arrayRule[1].replace("\n","")] = ""



strInputFile = "E:\\git\\YARA_Hash_Values\\all_rules_9-8-2020.log" #verbose log from YARA_Rules_Util
strOutputFile = os.getcwd() + "\\log.txt" #output log
LicensePath = "E:\\git\\YARA_Hash_Values\\license.txt" #license text to include when sorting rules
strMoveLocations = "" #-m, --move #Path to file containing mapping of where rules files should be moved (optional)
strVTTLpath = "E:\\git\\YARA_Hash_Values\\yara_Hash_lookups.csv" #CSV output from VTTL
boolAutoSort = True #Move rules based on rule name and metadata contents
Sort_Rules = "\n//Rules reorganized/sorted by Sort_Rules on " + str(datetime.date.today()) + "\n\n" #date notification when rule file was modified



parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.InputPath:
    strInputFile = opts.InputPath
    print (strInputFile)
if opts.OutputPath:
    strOutputFile = opts.OutputPath
    print (strOutputFile)
if opts.movePath:
    strMoveLocations = opts.movePath
    print (strMoveLocations)
if opts.lookupPath:
    strVTTLpath = opts.lookupPath
    print (strVTTLpath)    
if opts.autosort:   
    boolAutoSort = opts.autosort
if not strInputFile:
    print ("Missing required parameter")
    sys.exit(-1)
logoutput = strOutputFile

ruleMapping = {} #used to move rules to appropiate location
fileList = {} #list of files to move rules out of


fileExtensions = { #file extensions are checked against the rule name and the metadata section of the YARA rule
#currently first match will be the extension so put longer extensions before matching short ones
".vbs":"vbs",
".exe":"pe",
".txt":"txt",
".cmd":"cmd",
".cgi":"cgi",
".php":"php",
".pl":"pl",
".py":"py",
".html":"html",
".hta":"hta",
".jsp":"jsp",
".js":"js",
".aspx":"aspx",
".asp":"asp",
".cfm":"cfm",
".dll":"pe",
".war":"war",
".rtf":"rtf",
".pdf":"pdf",
".xml":"xml",
".elf":"elf",
".ps1":"ps1",
"\"jar\"":"jar", #filetype = "jar"
"\"java\"":"jar", #filetype = "Java"
"\"exe\"":"pe", #sample_filetype = "exe"
"\"js-html\"":"html", #sample_filetype = "js-html"
"\"pe,dll\"":"pe", #filetype = "pe,dll"
"bootkit":"mbr", #apt_fancybear_downdelph_magic : bootkit
"\"memory\"":"mem", #filetype = "memory"
".memory":"mem", # rule malware_red_leaves_memory 
"memory scan":"mem" #rule_usage = "memory scan"
}

excludeDict = {#dictionary containing list of excluded terms
".war":[".warn", ".warp"],
".exe":[".exec"],
".pl":[".plat"],
".pl":[".plug"]
}

if strMoveLocations != "":
  #loadRuleFileMapping - if you already know where rules need to go
  loadRuleFileMapping(strMoveLocations) #case sensitivity matters for file contents

if strVTTLpath != "": #populate hash dictionary with results from VTTL
  populateHashDict.populateHashDict(strVTTLpath, "Hash", "File Type", "File Insight", "File Path", "Detection Type")
#for hashValue in populateHashDict.dictHashTypes:
#    print(hashValue)


CurrentDirectory = str(pathlib.Path(__file__).parent.resolve())
print(CurrentDirectory)
#magic number mapping to file type
sort_support.loadMagicNumbers(CurrentDirectory + "\\magic.dat")

#list of rules to assess moving
loadFilePaths(strInputFile) #case sensitivity matters for file contents

if os.path.exists(LicensePath):
  with open(LicensePath, 'r') as licenseContent:
    strLicense = licenseContent.read()
    if "/*" not in strLicense and "//" not in strLicense:
      print("license file missing comment")
      quit()
else:
  print ("Missing license file: " + LicensePath)
  quit()

#fileList = ["e:\\malware\\test\\rules-master\\webshells\\WShell_APT_Laudanum.yar"] #case sensitivity matters #debugging line for testing as rule list should come from loadFilePaths
print ("Loading complete. Rule processing started")
for filepath in fileList: 
  ProcessRule(filepath, filepath, os.path.dirname(filepath) )

print ("Rule processing complete")

