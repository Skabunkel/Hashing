FROM ubuntu 

WORKDIR build
RUN apt update && apt -y install build-essential clang

ADD . .

RUN clang -c -std=c99 blake2b.c -o blake2b.o
RUN clang -std=c99 blake2b.o test.c -o test
CMD [ "./test", "3", "abc", "3", "a", "1" ]