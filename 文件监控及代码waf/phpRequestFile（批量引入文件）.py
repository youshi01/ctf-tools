import os
import re

def changeContent(dirPath,fileExt,oldStr,newStr,resultFile):
    for f in os.listdir(dirPath):
        fullName = dirPath + "\\" + f
        if(os.path.isdir(fullName)):
            changeContent(fullName,fileExt,oldStr,newStr,resultFile)
        else:
            extIndex = fullName.rfind(".")
            if(extIndex > -1 and fullName[extIndex:] == fileExt):
                try:
                    fl = open(fullName,"r")
                    content  = fl.read()
                    fl.close()
                    fl = open(fullName,"w")                    
                    content = content.strip()
                    if(content.find(oldStr) == 0):
                        content = content.replace(oldStr,newStr,1)
                    fl.write(content)
                    fl.close()
                    resultFile.write("【%s】文件修改成功！\n"%(fullName))
                except Exception as ex:
                    resultFile.write("【%s】文件修改失败，失败原因【%s】！\n"%(fullName,ex))
                

if __name__ == "__main__":
    topPath = r"C:\Users\y\Desktop\test"
    fileExt = ".php"
    oldStr = "<?php"
    newStr = '<?php require_once("phpwaf.php"); '
    resultFile = open(r"C:\Users\y\Desktop\result.txt","w+",encoding="utf-8")
    resultFile.write("替换相关信息如下：\n")
    changeContent(topPath,fileExt,oldStr,newStr,resultFile)
    resultFile.close()

