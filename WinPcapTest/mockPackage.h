#pragma once
#include<iostream>
#include<string>
using namespace std;

string MOCK_ARP = "\
ff ff ff ff ff ff 00 90 f5 fb 3e c0 08 06 \
00 01 08 00 06 04 00 01 \
00 90 f5 fb 3e c0 \
ca c0 51 2f \
00 00 00 00 00 00 \
ca c0 51 28 \
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
";

string ATCK_ARP = 
"ff ff ff ff ff ff \
00 0f e2 c3 d0 d0 \
08 06 \
00 01 \
08 00 06 04 00 02 \
9c da 3e 10 c1 b2 \
ca c0 51 FE \
01 0f e2 c3 d2 d1 \
00 00 00 00";


string ATCK_ARP2 = 
"9c da 3e 10 c0 b1 51 1d 93 f4 35 1f 08 06 00 01 \
08 00 06 04 00 02 51 1d 93 f4 35 1f ac 1d ff fe \
9c da 3e 10 c0 b1 ac 1d f5 9a 00 00 00 00 00 00 \
00 00 00 00 00 00 00 00 66 a0 1f 02 04 16 3e 8e \
51 02 01 00 02 01 00 30 11 30";

string BIG_PAK = 
"ff ff ff ff ff ff 9c da 3e 10 c0 b1 08 00 45 00 \
03 79 4c ca 40 00 80 06 74 57 ca c0 51 09 2f 5d \
eb 36 ce f6 01 bb c8 a1 48 4f c0 d8 2c 64 50 18 \
01 04 7c 1e 00 00 17 03 03 03 4c 00 00 00 00 00 \
00 00 04 02 f4 03 a6 9d 07 1f 79 d3 7f b0 51 33 \
fd 5b 8c e6 15 a3 fa 30 bf f0 47 83 81 5e 3c 68 \
4f 02 44 ed ae db 1d 5c 8f 95 c0 92 f3 0c 61 d1 \
ee a2 37 5d 3a 86 58 4b bc e5 61 3a 24 6f 43 50 \
83 4b a6 b1 2a 34 b0 ac f9 69 14 42 32 e7 82 0a \
eb 00 24 f0 66 1e f3 12 9d d5 64 f9 92 37 ac b7 \
a1 3a 84 c8 95 10 c7 29 e9 51 74 fc d3 38 65 b0 \
d2 e8 18 28 0c 5c bf df 3c 2c d2 84 18 e0 35 0b \
6b f3 15 6e 7e c8 d6 9d 3e 55 0c c6 4b d6 2b 7d \
f8 48 5b 0f c7 13 c2 02 56 40 cc 67 5c a3 90 87 \
96 e3 3f 68 eb 6f a1 b7 44 87 57 6d e0 08 db 6c \
6e db 50 4f b2 32 0f b8 d0 96 d8 53 81 8f fe da \
52 43 ca 53 ad 2e 37 d7 12 eb 99 1b 55 ce 5a 46 \
e7 ae 63 78 bf a4 b7 03 76 10 0d c1 b6 5e c3 b9 \
1f 61 5d d7 ee 83 d6 4a b6 7b ea 27 13 2c 2d 31 \
b5 b9 c2 66 3f 0c 69 bd 00 a7 d2 6b 41 eb 99 73 \
b8 72 38 36 c7 b9 ea 29 cc e0 59 e0 0c ad f0 f9 \
ed b7 fb 53 f7 19 9c 0c 58 78 e8 73 0f 30 ed d5 \
82 c5 0a 92 f6 7c 30 5f e8 ab cd 39 5e 60 d7 57 \
fd ba bc 81 ae 3b fb 69 52 15 de bf 55 a1 6c ef \
2e 7d 35 1d e9 2f cf 8c d7 b3 36 27 02 98 32 cc \
2c 74 2e 1d 44 6a a8 27 ed 28 29 ba c1 1d 11 51 \
7b 0d 4a cb ad e6 8e 32 89 56 ca 4e cf e3 30 c7 \
40 49 04 4d bf 30 ea 86 a3 63 6d 51 b4 ef bd 12 \
15 2d 2c dd 4a 24 ba fb 61 ef 53 6c 65 c2 9a cc \
aa bc da 63 3e 31 8f 36 25 65 67 33 c7 a7 12 fb \
14 75 cb 03 6a 38 9e 8d 8b 4f b9 03 2e 27 28 82 \
05 b6 5a e6 03 98 51 e0 37 c3 1e 44 e8 0b 08 57 \
96 fd e0 72 d6 fa 73 62 26 a4 ff cf af 01 6e eb \
b7 ec c8 0f 75 4e f1 fa 77 cc 18 11 a1 99 97 c3 \
20 27 0a 53 0f 64 06 44 71 60 ba ce a6 93 0d ea \
b9 df 76 f2 64 55 b9 4c ba 2c 77 ef 08 0c 91 9f \
38 1e f8 e6 4d 41 8e 46 16 f6 c4 d8 0f 99 ed 27 \
ba c7 48 c1 ed e9 8e d2 d2 ae e7 15 25 24 43 7a \
a0 fb 0a 90 a2 39 2f 1b 23 95 18 a0 0e 67 55 04 \
6e b0 f0 fa 3a 8f da 01 3a df d0 f7 fe 3e 88 b9 \
0a 56 62 b2 8f 75 c5 85 a3 65 39 b9 49 2b 67 2e \
c5 4c 5a 25 7a 80 ab 37 a4 21 e4 f9 26 47 9d 5b \
df dc 63 44 8d 7c 68 9b 6a 71 91 a1 9d 36 6a ad \
73 05 5a ff 2c 37 93 34 0e 6a 36 89 cf b4 17 f3 \
13 5e 9a df 81 7b 46 29 de bc ca 6f 74 d3 9b c4 \
ae 30 cd 0b 41 2e 98 e6 58 0c 1f 39 9e 97 07 f6 \
4e 9a 61 e8 3b c1 67 31 e5 22 34 5f 4b b9 fe 5d \
f0 f4 10 a1 64 f9 3d f2 3d 9c 0b 6e a2 84 d3 09 \
37 df 3e 5a 15 e4 a3 44 fb e4 47 4c 0d c2 b6 ff \
ab 15 40 be 6e 76 2a a1 d3 64 f1 3f 2e f9 d2 6d \
0e 2e df f5 7e 9b 6e 3f ac 5a de 96 23 4d fa 79 \
14 55 fb e1 dc a8 9e 36 79 3a 15 bf d1 dc 40 c2 \
25 79 b7 fc 8a 65 07 65 65 36 1b bd 6d c8 86 b7 \
c2 8d ac 88 29 e0 2f be 25 2a a3 0b d0 b4 9f bc \
7f 47 bb 7f 63 60 08 86 d2 12 e8 6a c4 c0 de 09 \
64 6c 0c f5 24 c7 f2 e8 f4 17 f9 bb b4 09 d9 fc \
70 08 13 3b 94 73 24 \
";