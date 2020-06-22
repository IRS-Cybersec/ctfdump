# IRS Internal CTF: RE

## Dynamic Library [350 Points]

**Basically just a dll file and reverse engineer it**

### Solution

Actually a very simple reverse enginnering challenge.

Firstly, by using PEid or Looking at the segment name of the DLL, we can discover that the file is packed by UPX.

By running

```
upx -d dll.dll
```

The dll can be easily unpacked.


After that, throw the file into IDA Pro, looking at the DllMain function, we can discover

```cpp
  v7 = fdwReason;
  if ( fdwReason == 1 )
  {
    v3 = sub_1000122B(std::cout, "It doesn't seem that the flag is here.");
    std::basic_ostream<char,std::char_traits<char>>::operator<<(v3, sub_1000131B);
  }
  else if ( v7 == 13425 )
  {
    v9 = &v5;
    sub_10001302(&unk_100172EC);
    v7 = sub_1000136B(&v8, v5);
    v6 = v7;
    v10 = 0;
    sub_1000125D(std::cout, v7);
    v10 = -1;
    CMFCToolBarButtonsListButton::RebuildLocations((CMFCToolBarButtonsListButton *)&v8);
  }
```

Basically the v7==13425 part will output the flag, you may get the flag by either running this part of code or trying to intepret what this part of code really do.

Obviously the easier one is to run it, there are multiple ways to do this, but since the Dll has **exported _DllMain@12** function, we can call it directly with the fdwReason being 13425.

The suggested code is shown below

```cpp
#include <Windows.h>

int main()
{
	typedef DWORD(*__stdcall dllmain)(  HINSTANCE hinstDLL,
                                      DWORD     fdwReason,
                                      LPVOID    lpvReserved);
	HMODULE hModule = LoadLibraryA("Dll.dll");
	dllmain DLLMain = (dllmain)GetProcAddress(hModule, "_DllMain@12");
	DLLMain(0, 13425, 0);
}
```

### Flag

```
IRS{Unpack_First_B4_Dec0mpile}
```


