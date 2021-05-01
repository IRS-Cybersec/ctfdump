# Hurry Up! Wait!

```
svchost.exe
```

We are given the file `svchost.exe`, but `file` command reveals that it is actually an ELF64

Looking at `main`, we see that is is pretty short:

```c
  char v4[8]; // [rsp+28h] [rbp-8h] BYREF

  gnat_argc = a1;
  gnat_argv = (__int64)a2;
  gnat_envp = (__int64)a3;
  __gnat_initialize(v4);
  sub_1D7C();
  sub_298A();
  sub_1D52();
  __gnat_finalize();
  return (unsigned int)gnat_exit_status;
```

Looking at `sub_298A()`, we spot it calling a lot more functions, and each function appears to print a letter of the flag like this:

```c
__int64 sub_298A()
{
  ada__calendar__delays__delay_for(1000000000000000LL);
  sub_2616();                                   // p
  sub_24AA();                                   // i
  sub_2372();                                   // c
  sub_25E2();                                   // o
  sub_2852();                                   // C
  sub_2886();                                   // T
  sub_28BA();                                   // F
  sub_2922();                                   // {
  sub_23A6();                                   // d
  sub_2136();                                   // 1
  sub_2206();                                   // 5
  sub_230A();                                   // a
  sub_2206();                                   // 5
  sub_257A();                                   // m
  sub_28EE();                                   // _
  sub_240E();                                   // f
  sub_26E6();                                   // t
  sub_2782();                                   // w
  sub_28EE();                                   // _
  sub_2102();                                   // 0
  sub_23DA();                                   // e
  sub_226E();                                   // 7
  sub_21D2();                                   // 4
  sub_2372();                                   // c
  sub_23A6();                                   // d
  sub_21D2();                                   // 4
  return sub_2956();                            // }
}
```

Hence the flag is:

```
picoCTF{d15a5m_ftw_0e74cd4}
```

Overall, a pretty brainless challenge