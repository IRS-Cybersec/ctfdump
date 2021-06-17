v7 = [0] * 25

v7[0] = 99;
v7[1] = 101;
v7[2] = 100;
v7[3] = 103;
v7[4] = 121;
v7[5] = 108;
v7[6] = 130;
v7[7] = 110;
v7[8] = 57;
v7[9] = 124;
v7[10] = 127;
v7[11] = 126;
v7[12] = 65;
v7[13] = 92;
v7[14] = 110;
v7[15] = 121;
v7[16] = 70;
v7[17] = 113;
v7[18] = 118;
v7[19] = 68;
v7[20] = 132;
v7[21] = 101;
v7[22] = 71;
v7[23] = 132;
v7[24] = 150;

for x in range(0, len(v7), 1):
    print(chr(v7[x]-x-1), end="")
    #-1 because arrays start from 1 in fortran, and hence the counter should start from 1 as well
