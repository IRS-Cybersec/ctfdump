data = ""
with open("flag.txt.encrypted.real") as f:
    data = f.read()

finalData = data
for i in range(24):
    tempData = ""
    for x in range(0, len(finalData), 2):
        portion = finalData[x:x+2]
        #print(portion)
        count = int(portion[0])
        tempData += count * portion[1]
    finalData = tempData

with open("output.txt", "w") as f:
    f.write(finalData)
print(finalData)