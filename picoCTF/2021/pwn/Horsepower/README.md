# Horsepower
Author: wparks

Gotta go fast [d8](https://mercury.picoctf.net/static/82c8123ab241a98f01572b662078310f/d8) [source.tar.gz](https://mercury.picoctf.net/static/82c8123ab241a98f01572b662078310f/source.tar.gz) [server.py](https://mercury.picoctf.net/static/82c8123ab241a98f01572b662078310f/server.py) Connect at mercury.picoctf.net 1684

## Solving
```diff
@@ -0,0 +1,17 @@
+// Gotta go fast!!
+
+namespace array {
+
+transitioning javascript builtin
+ArraySetHorsepower(
+  js-implicit context: NativeContext, receiver: JSAny)(horsepower: JSAny): JSAny {
+    try {
+      const h: Smi = Cast<Smi>(horsepower) otherwise End;
+      const a: JSArray = Cast<JSArray>(receiver) otherwise End;
+      a.SetLength(h);
+    } label End {
+        Print("Improper attempt to set horsepower");
+    }
+    return receiver;
+}
```
The patch for this challenge introduces out-of-bounds r/w on any JSArray using the `setHorsepower()` method:
```diff
+    SimpleInstallFunction(isolate_, proto, "setHorsepower",
+                          Builtins::kArraySetHorsepower, 1, false);
```
The only thing different between this JSArray problem and [older](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) JSArray exploits is that the v8 patch involved comes after the introduction of [pointer compression](https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html). 
