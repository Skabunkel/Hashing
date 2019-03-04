FROM alpine 

WORKDIR build
RUN apk add g++ gcc clang musl-dev


ADD . .

RUN clang -c -std=c99 blake2b.c -o blake2b.o
RUN clang -std=c99 blake2b.o input_test.c -o input_test
CMD [ "./input_test", "3", "abc", "3", "a", "1" ]