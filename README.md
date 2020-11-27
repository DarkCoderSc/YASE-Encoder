# YASE Encoder

This is a tiny python script I created during my OSCE preparation to master sub encoding technique.

The cool thing with Brutforcing possible combination is that output encoded shellcode will always look different. 

## Optimization N°1

`EAX` register will be set to zero only at the beginning (using the two `and` operations) 

`and` operation to initialize a register is very costy (10 bytes)

After the first initializaion, `EAX` value is saved to `EBX`. During next sub decoding operations `EAX` is restored from `EBX` thus saving a huge amount of space (2 bytes instead of 10).

## Optimization N°2 - TODO

- Optimize sub encoding. (Minimize sub operations when possible)

## Support Multiple Output Formats

* Commented Python Variable
* Python Variable
* C Variable
* Hex Formated String
* Hex String
* Raw
