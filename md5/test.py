import hashlib
import subprocess
import random
import time
import numpy


characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz#%&/()=?";
programName = "input_test.exe";
itterations = random.randrange(1000, 10000);

longestKeySeen = 0;

perfs = [];

for it in range(itterations):
    inputstr = "";
    inputLength = random.randrange(8192);

    for ipit in range(inputLength):
        inputstr += str(characters[random.randrange(len(characters))]);


    md5hash = hashlib.md5(str.encode(inputstr)).hexdigest();

    if(inputLength == 0):
        inputstr  += '0';

    start = time.time();
    result = subprocess.run([programName, str(inputstr), str(inputLength)], stdout=subprocess.PIPE).stdout.decode("utf-8").strip();
    end = time.time();
    
    dif = end-start;
    perfs.append(dif);

    if(len(inputstr) > longestKeySeen):
        longestKeySeen = len(inputstr);

    if(it%1000 == 0):
        print('{}/{} itterations successfull. longest input: {} current input: {} current seconds: {} average seconds: {} std seconds: {} mean seconds: {}'.format(it, itterations, longestKeySeen, len(inputstr), dif, numpy.average(perfs), numpy.std(perfs), numpy.mean(perfs) ));

    if(md5hash != result):
        print('Expected:\t{}\nActual\t{}\nCurrent input: {} {}'.format(md5hash, result, str(inputstr), str(inputLength)));
        exit(1);
print('{}/{} itterations successfull. average seconds: {} std seconds: {} mean seconds: {}'.format(itterations, itterations, numpy.average(perfs), numpy.std(perfs), numpy.mean(perfs)));