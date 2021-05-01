import sys
print("Randoms: ")
genNumbers = []
for i in range(1, 264+1, 1):
    y = (((i * 327) % 681 ) + 344) % 313
    genNumbers.append(y)

print(genNumbers)

print("Seeds: ")
seeds = []
for i in range(1, 264+1, 1):
    seeds.append((i * 127) % 500)
print(seeds)
contents = []
with open("outputGiven.txt") as f:
    contents =  f.read().split("\n")

result = 0
finalArray = []
for blockCount in range(0, len(contents), 1):
    output = int(contents[blockCount]) ^ result ^ genNumbers[blockCount]
    output = bin(output)[2:].zfill(60)
    #print(y)
    

    #print(output)
    finalOutput = ""
    finalSplit = []
    for x in range(0, len(output), 2):
        finalSplit.append(output[x:x+2])
    
        
    #finalSplit.length = $raw.length
    usedCounter = 0
    for x in range(0, len(finalSplit), 1):
        y = (x * seeds[blockCount]) % len(finalSplit)
        #print(y[x])
        #print("Length " + str(len(finalSplit)))
        current = finalSplit[y]
        if (current == "used"):
            while (current == "used"):
                y = (y+1)%len(finalSplit)
                current = finalSplit[y]
        
        if (current == "11"):
            finalOutput += "1"
            finalSplit[y] = "used"
            usedCounter += 1
        else:
            finalOutput += "0"
            finalSplit[y] = "used"
            usedCounter += 1
    print(finalSplit)
    print(usedCounter)
    
                
    
    
    result = int(contents[blockCount])

    finalArray.append(finalOutput)
    
columnOutput = []
for x in range(0, len(finalArray), 1):
    current = finalArray[x]
    counter = 0
    #print(current)
    for y in range(0, len(current), 6): #go down each row
        currentSplit = current[y:y+6].zfill(6)
        
        if (x == 0):
            columnOutput.append([currentSplit])
        else:
            columnOutput[counter].append(currentSplit)
            counter += 1
        #print(columnOutput)

with open("input.txt", "w") as f:
    for x in columnOutput:
        print(len(x))
        joined = ' '.join(x)
        f.write(joined + "\r\n")
with open("input.txt", "rb") as f:
    print(len(f.read()))

#print(columnOutput[0])