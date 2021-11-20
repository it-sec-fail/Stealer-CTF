# $tealer

Your enterprise network is experiencing a malware infection, and your SOC L1 colleague escalated the case for you to investigate. As an experienced L2/L3 SOC analyst, analyze the malware sample, figure out what it does and extract C2 server and other important IOCs.

P.S.: Make sure to analyze files in an isolated/virtualized environment as some artifacts may be malicious.
Compression password: `cyberdefenders.org_NeE6qBxcIo68R3Wj6DWw`

## Infos

| Start Date | End Date | CTF Type | CTF Authors |
| ---------- | ---------- | ---------- | ---------- |
| Nov. 20, 2021 | Nov. 21, 2021 | Public | Nidal Fikri |

## Files
[stealer.zip](https://download.cyberdefenders.org/misc/stealer.zip)   79b22089b56dbb6b6f422124393fa4ed55ab4f5e

## Questions
For the most things we are using some webtools or ghidra.
But we have to tell, this is a really hard one. We didn't analyse a malware on this level before.
Very hard learningrate and quite a lot of banging the head against some walls :-)


### Q#1 The provided sample is fully unpacked. How many sections does the sample contain?
If you load the `malware.bin` into ghidra, you will see four sections. So that should be the flag.

![GhidraScreenshot](images/sections_ghidra.png)

> 4

### Q#2 How many imported windows APIs are being used by the sample?
Also in Ghidra we can see the kernel dll file and the dll registerserver.


> 2

### Q#3 The sample is resolving the needed win APIs at run-time using API hashing. Looking at the DllEntryPoint, which function is responsible for resolving the wanted APIs?
While scrolling through the functions, I found this block in the `FUN_005f1570` (could be different in you tool, depending on which tool you are using, but the hex-value should be identical). In this function you can find this strange block of function-calls:

```c++
        if (iVar4 == 0x20) {
          FUN_00600b70((int)&local_ac0,0,0x47c);
          uStack1716 = FUN_00619650(param_2);
          uStack1724 = 0x56473829;
          iStack1684 = FUN_006015c0(0x588ab3ea,0x9cac62c7);
          iStack1680 = FUN_006015c0(0x588ab3ea,0xa8f2638d);
          iStack1676 = FUN_006015c0(0x588ab3ea,0xd8cc7390);
          iStack1672 = FUN_006015c0(0x588ab3ea,0xd16c9225);
          iStack1668 = FUN_006015c0(0x588ab3ea,0x649746ec);
          iStack1664 = FUN_006015c0(0x588ab3ea,0xe5ef1afa);
          iStack1660 = FUN_006015c0(0x588ab3ea,0x58d59bc9);
          iStack1656 = FUN_006015c0(0x588ab3ea,0x35b39b2b);
          iStack1652 = FUN_006015c0(0x588ab3ea,0xe9fbf3a8);
          iStack1648 = FUN_006015c0(0x588ab3ea,0xbcd9ca71);
          iStack1644 = FUN_006015c0(0x588ab3ea,0x4faea65b);
          iStack1640 = FUN_006015c0(0x588ab3ea,0xc0b67de0);
          iStack1636 = FUN_006015c0(0x588ab3ea,0x996e050f);
          iStack1632 = FUN_006015c0(0x588ab3ea,0x81c9e4a7);
          iStack1628 = FUN_006015c0(0x588ab3ea,0x97abe05f);
          iStack1624 = FUN_006015c0(0x588ab3ea,0x82d274c4);
          iStack1620 = FUN_006015c0(0xa1310f65,0x77be1f6);
          iStack1616 = FUN_006015c0(0xa1310f65,0xe2d27ff4);
          iStack1612 = FUN_006015c0(0xa1310f65,0x69121530);
          iStack1608 = FUN_006015c0(0xa1310f65,0xf1c64384);
          iStack1692 = iStack100;
          iStack1688 = local_68;
          FUN_00619710(local_a0,(int)&local_ac0,0x47c);
          uVar3 = FUN_005fe900(param_1,local_b0,0x4bc,local_a0);
        }
```

So I took a further investigation on the `FUN_006015c0` and this looks like some function to get the needed apis. Because you pass by some hex values and get the resolved apis back.

```c++
int FUN_006015c0(uint param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 extraout_ECX;
  undefined4 uVar4;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  int iVar5;
  
  if (DAT_0062b1f4 == 0xc139578) {
    DAT_0062b1f4 = 0;
  }
  iVar2 = DAT_0062b1f4;
  if (param_2 == 0xc0b67de0) {
    iVar1 = DAT_0062b1f8;
    if (DAT_0062b1f8 == -0x70f9e589) goto joined_r0x0060162d;
  }
  else {
    if (param_2 == 0x996e050f) {
      iVar1 = DAT_0062b1fc;
      if (DAT_0062b1fc == -0x6ea95563) {
joined_r0x0060162d:
        for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x180)) {
          iVar5 = 0;
          iVar1 = 0;
          do {
            if (param_2 == *(uint *)(iVar1 + 8 + iVar2)) {
              iVar1 = *(int *)(iVar1 + 0x14 + iVar2);
              goto LAB_00601621;
            }
            iVar5 = iVar5 + 1;
            iVar1 = iVar1 + 0x18;
          } while (iVar5 < 0x10);
        }
        goto LAB_00601652;
      }
    }
    else {
      if ((param_2 != 0xf271e04d) || (iVar1 = DAT_0062b200, DAT_0062b200 == -0x6334d3c8))
      goto joined_r0x0060162d;
    }
  }
LAB_00601621:
  if (iVar1 != 0) {
    return iVar1;
  }
LAB_00601652:
  if (param_1 != 0xe5ab9b45) {
    iVar2 = FUN_00607564();
    uVar4 = extraout_ECX;
    if ((iVar2 == 0) &&
       (uVar3 = FUN_00606c50(param_1), uVar4 = extraout_ECX_00, (char)uVar3 != '\0')) {
      iVar2 = FUN_00607564();
      uVar4 = extraout_ECX_01;
    }
    if (iVar2 != 0) {
      iVar2 = FUN_006067c8(uVar4,param_2);
      return iVar2;
    }
  }
  return 0;
}
```

> sub_6015c0

### Q#4 Looking inside the function being described in question 3, which function is responsible for locating & retrieving the targetted module (DLL)?


### Q#5 What type of hashing is being used for the API hashing technique?


### Q#6 What is the address of the function which performs the hashing?


### Q#7 What key is being used for XORing the hashed names?


### Q#8 What information is being accessed at the address 0X60769A?


### Q#9 Looking inside the function being described in question 3, which function is responsible for locating & retrieving the targetted API 
from the module export table?


### Q#10 Diving inside the function being described in question 9, what is being accessed at offset 0X3C within the first passed parameter?


### Q#11 Which windows API is being resolved at the address 0X5F9E47 ?


### Q#12 Looking inside sub_607980, which DLL is being resolved?


### Q#13 Also Looking inside sub_607980, which API is being resolved?


### Q#14 What is the appropriate data type of the only argument at function sub_607D40?


### Q#15 After reverse-engineering sub_607980 and knowing its purpose, Which assembly instruction is being abused for further anti-analysis complication, especially when running the sample? (one space included)


### Q#16 After reverse-engineering sub_607980 and knowing its purpose, Which assembly instruction is being used for altering the process execution flow? (Also adds anti-disassembly complication)


### Q#17 There are important encrypted strings in the .data section. Which encryption algorithm is being used for decryption?


### Q#18 What is the address of the function that is responsible for strings decryption?


### Q#19 What are the two first decrypted words (space separated strings) at 0X629BE8?


### Q#20 What is the key used for decrypting the strings in question 19?


### Q#21 What is the length (in bytes) of the used key in question 19?


### Q#22 What is the address of the function that is responsible for connecting to the C&C?


### Q#23 What is the first C&C IP address in the embedded configuration?


### Q#24 What is the port associated with the first C&C IP address?


### Q#25 How many C&C IP addresses are in the sample configuration?


### Q#26 What is the address of the function which may download additional modules to extend the malware functionality?

