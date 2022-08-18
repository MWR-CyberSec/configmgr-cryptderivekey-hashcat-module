# AES-128 ConfigMgr CryptDeriveKey Hashcat Module

This repo contains the module and OpenCL code that implements an AES-128 key derivation for ConfigMgr media variable files. This key derivation is based completely on the documented steps at [https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks).The code has recently been updated to work with Hashcat 6.2.5. In order to use it, you will need to compile Hashcat to obtain a .so/.dll/.dylib library of `module_19850.c`. The OpenCL code is dynamically compiled by Hashcat during module initialisation. 

## Instructions

1. Clone the Hashcat source repository. Remember, this code base was developed with 6.2.5 in mind, but it will likely work with the latest version unless there has been a recent breaking change to the code base
2. Copy `module_19850.c` into src/modules/ folder of the main Hashcat code base
3. Copy `m19850_a0-pure.cl`, `m19850_a1-pure.cl` and `m19850_a3-pure.cl` into the OpenCL/ folder of the main Hashcat code base
4. Follow the compilation instructions in Hashcat's BUILD.md. I would very highly recommend using the WSL option if you are compiling on Windows, as I had the best results with that. 
5. After it is compiled, use it as you would any other Hashcat module. Keep in mind that it is tuned for the hashes produced with PXEThief by `pxethief 5 <media variables file name>`, although it should be straightforward to adapt this to any AES-128 CryptDeriveKey based key fairly easily

## Author Credit 

Copyright (C) 2022 Christopher Panayi, MWR CyberSec
