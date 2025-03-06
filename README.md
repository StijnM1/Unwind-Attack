# Unwind Attack for SBT cipher

This repository contains an implementation of the Unwind Attack, as explained in my Master's Thesis. The attack concerns the Philips UA-8295 Short Burst Terminal, which was manufactured and marketed by Philips Usfa in the 1980s and contains an algorithm backdoored by the American National Security Agency. The attack exploits the weak interaction between so-called byte paths in the primtive of the UA-8295.
## Usage
The following command line options are available

```
Command line options:
   -h [--help]                 Show options
   -i [--input] arg            Provide input block
   -k [--key] arg              Provide key (to compute output block)
   --knownkeybitmask arg (=0)  Leak key bits to attack
   -o [--output] arg           Provide output block
```

To execute the attack, one can enter a decimal input block, as well as either a key or an output block. When the key is given, the output is calculated and the attack commences without knowledge of this key. 

For testing purposes, one can leak key bits to the attack algorithm, on which possible options for the key are filtered.

All arguments (input/key/knownkeybitmask/output) are 64-bit integers and should be given in decimal.
## Acknowledgements

 - [Cryptomuseum](https://cryptomuseum.com) provided the binary data on the UA-8295 EPROMs on which this attack is based.
## Authors

- [Stijn Maatje](https://www.github.com/StijnM1)
- [dr. ir. Marc Stevens (CWI)](https://www.github.com/cr-marcstevens)

