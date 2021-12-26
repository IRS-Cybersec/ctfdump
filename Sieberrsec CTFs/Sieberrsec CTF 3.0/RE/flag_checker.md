# Flag checker part 1 [50]
In `http://challs.sieberrsec.tech:15231/index.js`:
```js
function check_flag() {
    let flag = document.getElementById('flag');
    let result = document.getElementById('result');
    
    clearTimeout(hide);
    result.textContent = btoa(flag.value) === "SVJTe2luc3AzY3RfZTFlbWVudH0=" ?
        'Correct!' : 'Wrong.';
    hide = setTimeout(() => { result.textContent = ''; }, 500);

}
```
Unwrap the base64 password to get the flag:
```js
>>> atob("SVJTe2luc3AzY3RfZTFlbWVudH0=")
"IRS{insp3ct_e1ement}"
```
