# IRS Internal CTF: Steganography

## Special Stego I - 3D Room (itszzjj) [30 points]

***VNI Inc. is a company specialised in innovating VR technology.***
***Recently, the company unveiled a method to make any screenshots taken within the VR Visor have infinite resolution.***

***One of the employees, Sun Hong, placed a 2D text of an exploit he found within the technology in the middle of of a 3D room before taking a screenshot.***

***However, he realised that the colour of the text just so happens to be the same as the back wall.***

***Unfortunately, the room was deleted shortly after he left as a precaution.***

***With no proof to show this exploit, he had no choice but to approach you, an agent who happens to specialise in image forensics.***

***Can you help him out?***

### What is a SVG file?

_______

Scalable Vector Graphics (SVG) is an Extensible Markup Language-based vector image format for two-dimensional graphics with support for  interactivity and animation.

It basically takes in a bunch of parameters, and then draws out the vector image.

An example is shown below:

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" version="1.1">
   <rect width="200" height="100" stroke="black" stroke-width="6" fill="green"/>
</svg>
```

This draws a green rectangle.

### The Challenge

_____

We now look at the image given.

![3DRoom](3DRoom.svg)

We know that the entire image is just made out of different elements. How can we find the flag if the colours are exactly the same?

The answer is to open the image with an editor:

```svg
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="100%" height="100%" viewBox="0 0 1440 900" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xml:space="preserve" xmlns:serif="http://www.serif.com/" style="fill-rule:evenodd;clip-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:2;">
    <g transform="matrix(2.33985e-16,3.82127,-0.8,4.89859e-17,720,-3.30856e-13)">
        <path d="M117.762,0L235.524,900L0,900L117.762,0Z" style="fill:rgb(168,223,218);"/>
    </g>
    <g transform="matrix(-2.33985e-16,3.82127,0.8,4.89859e-17,720,-4.39746e-14)">
        <path d="M117.762,0L235.524,900L0,900L117.762,0Z" style="fill:rgb(200,223,218);"/>
    </g>
    <g transform="matrix(6.11404,7.85272e-17,-2.34427e-16,-0.5,-1.51527e-13,450)">
        <path d="M117.762,0L235.524,900L0,900L117.762,0Z" style="fill:rgb(182,223,218);"/>
    </g>
    <g transform="matrix(6.11404,-7.85272e-17,-2.34427e-16,0.5,3.24537e-13,450)">
        <path d="M117.762,0L235.524,900L0,900L117.762,0Z" style="fill:rgb(69,223,218);"/>
    </g>
    <rect x="446.625" y="280.045" width="546.75" height="339.91" style="fill:rgb(169,235,235);"/>
    <g transform="matrix(0.321999,0,0,0.321999,376.231,293.321)">
        <text x="720px" y="507.272px" style="font-family:'Hind-Regular', 'Hind';font-size:79.954px;fill:rgb(169,235,235);">IRS{V3ct0r_LaY3r5}</text>
    </g>
</svg>

```

The `<text>` parameter contains the flag.

### Flag

____

```
IRS{V3ct0r_LaY3r5}
```
