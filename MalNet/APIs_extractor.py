#Parse through training set and get the most used APIs by malwares to use it as features.

from xml.dom import minidom
import pyperclip
import numpy as np
import json
import tqdm


def FindApi(ApiName,ApiList):
    for x in range(len(ApiList)) :
        if ApiList[x] == ApiName:
            return x
    return -1 

dataset_path = "ember2018\\"
#get list of APIs that is suspicious and might be used by malwares from functions.xml.
#The file is from pestudio, check the file header for more info.
xmldoc = minidom.parse("MalNet\\functions.xml")
itemlist = xmldoc.getElementsByTagName('fct')
ApiList = []

for s in itemlist:
    if s.attributes['bl'].value == '1' and s.firstChild != None:
        ApiList.append(s.firstChild.nodeValue)

apicounts = np.zeros((len(ApiList),3),dtype='int32')

NumberOfSamplesToRead = 500
f = open(dataset_path + "test_features.jsonl", "r")
iteration = 0
line = f.readline()
numofmals = 0
for x in tqdm.tqdm(range(NumberOfSamplesToRead)):
    if line == "":
        break
    y = json.loads(line)
    for lib in y["imports"]:
        for api in y["imports"][lib]:
            apiindex = FindApi(api,ApiList)
            if apiindex >= 0:
                apicounts[apiindex][0] += 1
                if y["label"] == 1:
                     apicounts[apiindex][1] +=1
                if y["label"] == 0:
                     apicounts[apiindex][2] +=1 
    iteration += 1
    if y["label"] == 1:
        numofmals +=1
    if iteration % 500 == 0:
        print("File {} Done.".format(iteration))
    line = f.readline()


print("Scanned Files {}. Number Of Malwares {} . Percentage {}%".format(iteration,numofmals,100*numofmals/iteration))
iteration = 0
#sorting

sortindeces = np.argsort(apicounts[:,1])[::-1]
apicounts = apicounts[sortindeces]
ApiList = (np.array(ApiList)[sortindeces]).tolist()
for x in range(len(ApiList)):
    if apicounts[x][0] > 5 :
        print("API : {} Used : {}  Malwares : {}  Legit : {}".format(ApiList[x],apicounts[x][0],apicounts[x][1],apicounts[x][2]))
        iteration+=1
print("Used APIs are {} ".format(iteration))

