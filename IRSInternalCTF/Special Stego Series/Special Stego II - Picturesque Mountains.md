# IRS Internal CTF: Steganography

## Special Stego II - Picturesque Mountains (itszzjj) [50 points]

***Due to the exploit discovered, VNI Inc.'s development team has patched the issue with a simple but confidential solution.***

***Sun Hong happens to be a digital artist, so he created a bunch of mountains.***

***That's where he realised that he had found a workaround to the original exploit.***

***Instead of reporting to the higher ups, he decided to send this screenshot to you as a toy example of how this workaround works.***

***Find a way to extract the hidden data.***

### Same same but different!

______

We are now given this picture.

![NiceMountains](images/NiceMountains.svg)

Opening the picture with an editor will give out this:

```svg
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="100%" height="100%" viewBox="0 0 1440 900" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xml:space="preserve" xmlns:serif="http://www.serif.com/" style="fill-rule:evenodd;clip-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:2;">
    <g>
        <g transform="matrix(2.75438e-17,0.449825,-1.21314,7.42833e-17,1410.5,64.8202)">
            <rect x="-144.101" y="-24.315" width="2000.78" height="1187.01" style="fill:url(#_Linear1);"/>
        </g>
        <g transform="matrix(-1,0,0,1,1440,-4.54747e-13)">
            <path d="M405.869,307.592L608.406,900L203.333,900L405.869,307.592Z" style="fill:rgb(0,81,65);"/>
        </g>
    </g>
    .
    . <!-- Skipped -->
    .
    <g>
        <g transform="matrix(34.9131,0,0,34.9131,255.759,843.038)">
            <rect x="0.083" y="-0.674" width="0.081" height="0.674" style="fill:rgb(0,81,65);fill-rule:nonzero;"/>
        </g>
        <g transform="matrix(34.9131,0,0,34.9131,264.383,843.038)">
            <path d="M0.158,-0.604L0.158,-0.335L0.26,-0.335C0.306,-0.335 0.341,-0.347 0.366,-0.373C0.39,-0.398 0.402,-0.43 0.402,-0.469C0.402,-0.559 0.352,-0.604 0.251,-0.604L0.158,-0.604ZM0.525,0L0.428,0L0.263,-0.266L0.158,-0.266L0.158,0L0.077,0L0.077,-0.674L0.246,-0.674C0.324,-0.674 0.383,-0.656 0.424,-0.619C0.464,-0.582 0.484,-0.532 0.484,-0.467C0.483,-0.42 0.47,-0.381 0.447,-0.348C0.424,-0.315 0.391,-0.292 0.348,-0.279L0.525,0Z" style="fill:rgb(0,81,65);fill-rule:nonzero;"/>  <!-- Describes the letter 'R' -->
        </g>
        .
        . <!-- Skipped -->
        .
    </g>
</svg>

```

The flag text was converted to curves.

The way to solve this is to remove the `<g>` elements that describe the mountain, the sky and the sun.

This in return outputs this image.

![NiceMountainsEdited](images/NiceMountainsEdited.svg)

### Flag

_____

```
IRS{b3cau53_m0dd1ng_g_3l3m3nt5_w1th0ut_c0d1ng_15_s0_0v3rRaT3d}
```
