x = [0, 0, 0];
const compare = (a, b) => {
	let s = '';
	for (let i = 0; i < Math.max(a.length, b.length); i++) {
		s += String.fromCharCode((a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0))
	}
	return s
};
if (location.protocol == 'file:') {
	x[0] = 23
} else {
	x[0] = 57
}
if (compare(window.location.hostname, "you're invited!!!") == unescape("%1E%00%03S%17%06HD%0D%02%0FZ%09%0BB@M")) {
	x[1] = 88
} else {
	x[1] = 31
}

function yyy() {
	var uuu = false;
	var zzz = new Image();
	Object.defineProperty(zzz, 'id', {
		get: function() {
			uuu = true;
			x[2] = 54
		}
	});
	requestAnimationFrame(function X() {
		uuu = false;
		console.log("%c", zzz);
		if (!uuu) {
			x[2] = 98
		}
	})
};
yyy();

function ooo(seed) {
	var m = 0xff;
	var a = 11;
	var c = 17;
	var z = seed || 3;
	return function() {
		z = (a * z + c) % m;
		return z
	}
}

function iii(eee) {
	// testing to find appropriate values of x
	possibleX = [
		[23, 57],
		[88, 31],
		[54, 98]
	];

	eee = [0, 0, 0];

	for (let i2 = 0; i2 < 2; i2++) {
		for (let i3 = 0; i3 < 2; i3++) {
			for (let i4 = 0; i4 < 2; i4++) {
				eee[0] = possibleX[0][i2];
				eee[1] = possibleX[1][i3];
				eee[2] = possibleX[2][i4];

				ttt = eee[0] << 16 | eee[1] << 8 | eee[2];
				rrr = ooo(ttt);
				ggg = window.location.pathname.slice(1);
				hhh = "govtech-csg";
				vvv = atob("3V3jYanBpfDq5QAb7OMCcT//k/leaHVWaWLfhj4=");
				mmm = "";
				if (hhh.slice(0, 2) == "go" && hhh.charCodeAt(2) == 118 && hhh.indexOf('ech-c') == 4) {
					for (i = 0; i < vvv.length; i++) {
						mmm += String.fromCharCode(vvv.charCodeAt(i) ^ rrr())
					}

					console.log(mmm);

					if (mmm[0] == "{") {
						alert("Thank you for accepting the invite!\n" + hhh + mmm);
					}
				}
			}
		}
	}
}
for (a = 0; a != 1000; a++) {
	debugger
}
$('.custom1').catLED({
	type: 'custom',
	color: '#FF0000',
	background_color: '#e0e0e0',
	size: 10,
	rounded: 5,
	font_type: 4,
	value: " YOU'RE INVITED! "
});
$('.custom2').catLED({
	type: 'custom',
	color: '#FF0000',
	background_color: '#e0e0e0',
	size: 10,
	rounded: 5,
	font_type: 4,
	value: "                 "
});
$('.custom3').catLED({
	type: 'custom',
	color: '#FF0000',
	background_color: '#e0e0e0',
	size: 10,
	rounded: 5,
	font_type: 4,
	value: "   WE WANT YOU!  "
});
setTimeout(function() {
	iii(x)
}, 2000);