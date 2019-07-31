# SkaHash
My own implementations of different hashing algorithms in C99

I have decided that these implementations should not be dependent on a common file in this case.
So they will have their own definition of bool and Is_Big_Endian to make them easier to just drop in.

This project is free of any licence and obligations, however i or any other contributor shall never be liable for any issues incurred legal or otherwize by use of this code.

This code is to be considered unsafe for use in any security application, and is therefore used at your own risk.

- [X] Blake2B
    - average seconds: 0.013567558454566793, std seconds: 0.003345939873982601, samlpe size: 2436, output length: 1-64, keylength: 0, input length: 0
        - a little slow in my oppinion at least for hashing a 0 byte message with a 0 byte long key.


- [X] MD5
    - average seconds: 0.010582801423774685 std seconds: 0.006495074281656058, samlpe size: 2636, input length: 0

On hold for 3 months, something came up. Something i promised to do, and i suck doing stuff as it is. 

-- 2019-07-31 (i'll set an alarm for it)
   
- [ ] SHA1
- [ ] SHA256
