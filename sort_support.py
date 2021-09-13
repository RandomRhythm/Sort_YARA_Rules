import re
dictMagicType = {} #dictionary to load magic numbers into
yaraRegex = "(int\\d(\\d|)(be|)\\((\\d+)\\)|\\$[\\w\\d]+) *=(=|) *({ ?|0x|\")" #regex to identify YARA equal comparison

def loadMagicNumbers(strDictFilePath): #load list of magic numbers mapped to file type
  file1 = open(strDictFilePath, 'r') 
  mappings = file1.readlines() 
  for strRuleLine in mappings:
    if "," in strRuleLine:
      arrayRule = strRuleLine.split(",")
      #print(arrayRule)
      dictMagicType[arrayRule[0].lower()] = arrayRule[1].replace("\n","") #compare will happen in lower case
      
def checkMagic(strRuleContent): #check rule text against regex for magic numbers
  magicReturnVal = "" 
  if "is__elf" in strRuleContent: #rule refenced by other YARA rules
    magicReturnVal = appendVal(magicReturnVal, "elf")
  if "is__osx" in strRuleContent: #rule refenced by other YARA rules
    magicReturnVal = appendVal(magicReturnVal, "osx")
  if "RTFFILE" in strRuleContent: #rule refenced by other YARA rules
    magicReturnVal = appendVal(magicReturnVal, "rtf")

  for magicNumber in dictMagicType:
    
    if " " in magicNumber:
      strBigEndian = ""
      strLittleEndian = ""
      strAsciiText = ""
      arrayNumbers = magicNumber.split(" ")
      for hexNumber in arrayNumbers:
        try:
          asciiCHAR = bytearray.fromhex(hexNumber).decode()
        except: # not a character
          asciiCHAR = "Errrorrororororo" #unique string so we don't accidentally match something due to character conversion problem
        strBigEndian = strBigEndian + hexNumber
        strLittleEndian = hexNumber + strLittleEndian
        strAsciiText = strAsciiText + asciiCHAR
    strAsciiText = re.escape(strAsciiText)
    if re.search( yaraRegex + strBigEndian, strRuleContent.lower()):
      magicReturnVal = appendVal(magicReturnVal, dictMagicType[magicNumber])
    elif re.search( yaraRegex + strLittleEndian, strRuleContent.lower()):
      magicReturnVal = appendVal(magicReturnVal,dictMagicType[magicNumber])
    elif re.search( yaraRegex + strAsciiText, strRuleContent):
      magicReturnVal = appendVal(magicReturnVal, dictMagicType[magicNumber])
    elif re.search( yaraRegex + magicNumber, strRuleContent.lower()):
      magicReturnVal = appendVal(magicReturnVal, dictMagicType[magicNumber])
  return magicReturnVal


def appendVal(strAggregate, strAdd):
    if strAggregate == "":
        strAggregate = strAdd
    elif strAggregate != strAdd: #more than one file type match
        strAggregate = strAggregate + "|" + strAdd #pipe separated value will move rule to multi subfolder
    return strAggregate

def GetData(contents, endOfStringChar, matchString):
    matchStringLen = len(contents)
    x = contents.find(matchString)
    if x > 0:
        y = contents.find(endOfStringChar,x)
        if y > 0:
            return contents[x+ len(matchString):y]
        else:
            return contents[x:]


def removeComment(contents):
    strReturnContent = contents
    strRemove = GetData(contents, "*/", "/*")
    if len(strRemove) > 0:
           strReturnContent = strReturnContent.replace("/*" + strRemove + "*/", "")
    return strReturnContent