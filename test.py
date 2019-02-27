from pyblake2 import blake2b
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
    outputLength = random.randrange(1, 64);
    inputLength = random.randrange(8192);

    keystr = "";
    keyLength = random.randrange(64);

    for ipit in range(inputLength):
        inputstr += str(characters[random.randrange(len(characters))]);

    for kit in range(keyLength):
        keystr += str(characters[random.randrange(len(characters))]);

    blakeHash = blake2b(str.encode(inputstr), digest_size=outputLength, key=str.encode(keystr)).hexdigest();

    if(inputLength == 0):
        inputstr  += '0';

    if(keyLength == 0):
        keystr  += '0';

    start = time.time();
    result = subprocess.run([programName, str(outputLength), str(inputstr), str(inputLength), str(keystr), str(keyLength)], stdout=subprocess.PIPE).stdout.decode("utf-8").strip();
    end = time.time();
    
    dif = end-start;
    perfs.append(dif);

    if(len(inputstr) > longestKeySeen):
        longestKeySeen = len(inputstr);

    if(it%1000 == 0):
        print('{}/{} itterations successfull. longest input: {} current input: {} current seconds: {} average seconds: {} std seconds: {} mean seconds: {}'.format(it, itterations, longestKeySeen, len(inputstr), dif, numpy.average(perfs), numpy.std(perfs), numpy.mean(perfs) ));

    if(blakeHash != result):
        print('Expected:\t{}\nActual\t{}\nCurrent input: {} {} {} {} {}'.format(blakeHash, result, str(outputLength), str(inputstr), str(inputLength), str(keystr), str(keyLength)));
        exit(1);
print('{}/{} itterations successfull. average seconds: {} std seconds: {} mean seconds: {}'.format(itterations, itterations, numpy.average(perfs), numpy.std(perfs), numpy.mean(perfs)));