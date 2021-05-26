import hashlib

requiredBytes = ["4889fe48", "bff126dc", "b3070000", "00ffd6"]
offsets = [8,2,7,1]
requiredString = ["GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls"]
found = False
password = []
for x in range(0, len(requiredString), 1):
    found = False
    #Generate 4 characters per iteration
    for a in range(33, 123, 1):
        for b in range(33, 123, 1):
            for c in range(33, 123, 1):
                for d in range(33, 123, 1):
                    hashThis = chr(a) + chr(b) + chr(c) + chr(d) + requiredString[x]
                    result = hashlib.md5(hashThis.encode()).hexdigest()
                    #print(result)
                    if (result[offsets[x]*2:offsets[x]*2+len(requiredBytes[x])] == requiredBytes[x]):
                        password.append(hashThis)
                        print("Found smth!")
                        print(hashThis[:4])
                        found = True
                        break

                if found:
                    break
            if found:
                break
        if found:
            break

                        
                    
                    
print(password)
