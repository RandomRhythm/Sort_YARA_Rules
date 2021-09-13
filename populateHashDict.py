#VTTL parser to get file type for hash values
import csv

strDelimiter = ","

def populateHashDict(csvFpath, hashColumnName, typeColumnName, insightColumnName, fileNameColumn, detectionTypeColumn):


  intFileTypeColumn = -1
  intInsightColumn = -1
  intHashColumn = -1
  intfileNameColumn = -1
  intDetectionTypeColumn = -1
  
  with open(csvFpath, "rt", encoding="utf-8-sig") as csvfile:
      reader = csv.reader(csvfile, delimiter=strDelimiter, quotechar='\"')
      #f2 = open(strOutputFile, 'a+', encoding="utf-8")
      boolHeader = False
      for row in reader:
        hashValue = ""
        pathType = ""
        hashType = ""
        fileType = ""
        fileInsight = ""
        detectionType = ""
        if boolHeader == False:
            boolHeader = True
            columnCount = 0
            for column in row:
              #print(column)
              if hashColumnName == column:
                intHashColumn = columnCount
              elif typeColumnName == column:
                intFileTypeColumn = columnCount
              elif insightColumnName == column:
                intInsightColumn = columnCount
              elif fileNameColumn == column:
                intfileNameColumn = columnCount
              elif detectionTypeColumn == column:
                intDetectionTypeColumn = columnCount
              columnCount +=1
        
        else: #header row set
          if len(row) >= intfileNameColumn:
            filepath = row[intfileNameColumn];  
          if len(row) >= intHashColumn:
            hashValue = row[intHashColumn];  
          if len(row) >= intFileTypeColumn:
            fileType = row[intFileTypeColumn];  
          if len(row) >= intInsightColumn:
            fileInsight = row[intInsightColumn];
          if len(row) >= intDetectionTypeColumn:
            detectionType = row[intDetectionTypeColumn];          
          
          if "." in filepath:
            tmpExtension = "." + filepath[filepath.rfind('.'):].lower()
            if tmpExtension in filExtensions:
              pathType = filExtensions[tmpExtension]
          
          if   fileInsight != "" and fileType != "":
            if fileType == "Win32 EXE" or fileType == "Win32 DLL":
              hashType = "pe"
            elif fileType == "XML" and fileInsight == "Microsoft Office XML Flat File Format Word Document (ASCII)":
              hashType = "doc"
            elif fileType == "XML" and detectionType == "macro":
              hashType = "office"
            elif fileType == "ZIP" and pathType == "zip":
              hashType = "zip"
            elif fileType == "ZIP" and pathType == "jar":
              hashType = "jar"
            elif fileType == "ZIP" and pathType == "war":
              hashType = "war"
            elif fileType == "Windows shortcut" and fileInsight == "Windows Shortcut":
              hashType = "lnk"
            elif fileType == "unknown" and fileInsight == "DOS batch file text" and pathType == "bat":
              hashType = "bat"
            elif fileType == "unknown" and fileInsight == "exported SGML document text" and pathType == "php":
              hashType = "php"
            elif fileType == "unknown" and "ASCII" in fileInsight and pathType == "sh":
              hashType = "sh"
            elif fileType == "unknown" and (fileInsight == "file seems to be plain text/ASCII" or fileInsight == "HyperText Markup Language") and pathType == "asp":
              hashType = "php"              
            elif fileType == "unknown" and "HyperText Markup Language" in fileInsight and pathType == "asp":
              hashType = "asp"
            elif fileType == "unknown" and ("HyperText Markup Language" in fileInsight or "Text - UTF-" in fileInsight or "Microsoft Jet DB" == fileInsight or "MP3 audio" == fileInsight) and pathType == "jsp":
              hashType = "jsp"
            elif fileType == "unknown" and fileInsight == "Windows Registry Data (Ver. 4.0)" and pathType == "reg":
              hashType = "reg"
            elif fileType == "C" and fileInsight == "ColdFusion Markup Language" and pathType == "cfm":
              hashType = "crm"
            elif fileType == "C" and fileInsight == "ASCII C program text" and pathType == "php":
              hashType = "php"                               
            elif fileType == "C" and (fileInsight == "HyperText Markup Language" or fileInsight == "ISO-8859 C program text, with very long lines" or fileInsight == "ISO-8859 C program text, with very long lines, with CRLF line terminators") and pathType == "php":
              hashType = "php" 
            elif (fileType == "C" or fileType == "HTML") and (fileInsight == "HyperText Markup Language" or fileInsight == "ISO-8859 C program text, with very long lines" or fileInsight == "ISO-8859 C program text, with very long lines, with CRLF line terminators") and pathType == "jsp":
              hashType = "jsp" 
            elif fileType == "C" and fileInsight == "file seems to be plain text/ASCII" and pathType == "aspx":
              hashType = "aspx"                  
            elif fileType == "C++" and (fileInsight == "ASCII C++ program text" or fileInsight == "HyperText Markup Language" or fileInsight == "Text - UTF-8 encoded") and pathType == "jsp":
              hashType = "jsp"                 
            elif fileType == "C++" and fileInsight == "ASCII C++ program text, with CRLF line terminators" and pathType == "wsf":
              hashType = "wsf"   
            elif fileType == "C++" and fileInsight == "ASCII C++ program text, with very long lines" and pathType == "js":
              hashType = "js" 
            elif (fileType == "C++" or fileType == "HTML") and pathType == "php":
              hashType = "php" 
            elif fileType == "C++" and fileInsight == "ASCII C++ program text, with very long lines, with CRLF line terminators" and pathType == "ps1":
              hashType = "ps1"
            elif fileType == "Compiled HTML Help" and fileInsight == "Windows HELP File":
              hashType = "chm"
            elif fileType == "DOS EXE":
              hashType = "pe"
            elif fileType == "ELF":
              hashType = "elf"              
            elif fileType == "Flash":
              hashType = "swf"              
            elif fileType == "GIF":
              hashType = "gif" #php, asp, etc. may hide as this file type                        
            elif fileType == "HTML" and pathType == "asp":
              hashType = "asp"
            elif fileType == "HTML" and pathType == "hta":
              hashType = "hta"
            elif fileType == "JAR":
              hashType = "jar" 
            elif fileType == "Java" and fileInsight == "ASCII Java program text" and pathType == "py":
              hashType = "py"
            elif fileType == "Java" and fileInsight == "Microsoft ASP.NET Web Form":
              hashType = "aspx"
            elif fileType == "JPEG" and fileInsight == "JFIF JPEG bitmap":
              hashType = "jpeg" 
            elif fileType == "MS Excel Spreadsheet":
              hashType = "xls" 
            elif fileType == "MS Word Document":
              hashType = "doc" 
            elif fileType == "Network capture":
              hashType = "pcap" 
            elif fileType == "Pascal" and fileInsight == "HyperText Markup Language" and pathType == "jsp":
              hashType = "jsp"
            elif fileType == "Pascal" and fileInsight == "ASCII Pascal program text, with CRLF line terminators" and pathType == "asp":
              hashType = "asp"
            elif fileType == "PDF":
              hashType = "pdf" 
            elif fileType == "Perl":
              hashType = "pl" 
            elif fileType == "PHP":
              hashType = "php" 
            elif fileType == "Python":
              hashType = "py" 
            elif fileType == "RAR":
              hashType = "rar" 
            elif fileType == "Rich Text Format":
              hashType = "rtf" 
            elif fileType == "Shell script":
              hashType = "sh" 
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "ps1":
              hashType = "ps1"
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "bat":
              hashType = "bat"
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "jsp":
              hashType = "jsp"
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "js":
              hashType = "js"
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "vbs":
              hashType = "vbs"
            elif fileType == "Text" and "ASCII" in fileInsight and pathType == "asp":
              hashType = "asp"
            elif fileType == "Text" and fileInsight == "Scalable Vector Graphics (var.1)	Text":
              hashType = "svg"
            elif fileType == "unknown" and fileInsight == "Linux/UNIX shell script":
              hashType = "sh"
            elif fileType == "unknown" and fileInsight == "Lisp/Scheme program text":
              hashType = "lsp"
            elif fileType == "XML" and "Generic XML" in fileInsight and pathType == "xml":
              hashType = "xml" 

            #if hashValue == '':
            #    print(hashType)
            if hashType != "":
              dictHashTypes[hashValue] = hashType



def hashCheck(hashMatchList, currentFileType):
  returnFileType = currentFileType
  for hashValue in hashMatchList: #loop through hashes to see if we have it
      if hashValue in dictHashTypes:
        tmpVTtype = dictHashTypes[hashValue]
        if returnFileType == "" and tmpVTtype != "": #if we got a file type back
          returnFileType = tmpVTtype
        elif tmpVTtype != "":
          if tmpVTtype != returnFileType:
            returnFileType = "multi"
  return returnFileType


#Map file extensions to file type   
filExtensions = {
".exe":"pe",
".sys":"pe",
".cmd":"cmd",
".cgi":"cgi",
".cfm":"cfm",
".bat":"bat",
".php":"php",
".pl":"pl",
".py":"py",
".html":"html",
".js":"js",
".jsp":"jsp",
".jar":"jar",
".asp":"asp",
".aspx":"aspx",
".cfm":"cfm",
".dll":"pe",
".war":"war",
".xml":"xml",
".lnk":"lnk",
".vbs":"vbs",
".ps1":"ps1",
".rar":"rar",
".rtf":"rtf",
".pdf":"pdf",
".hta":"hta",
".sh":"sh",
".reg":"reg",
".wsf":"wsf",
".zip":"zip"
}

TrustedFileTypes = ["pe", "elf", "rtf", "lnk", "rar", "swf", "pdf", "jar", "pl"]

dictHashTypes = {}




