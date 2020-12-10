# Welcome to Korovax Mobile!

**2000 Points // 19 Solves**



## Description

To be part of the Korovax team, do you really need to sign up to be a member?



## Solution

This challenge corresponds to the "User Login" page.

![User Login](user_login.jpg)



A username and password needs to be entered to login. The Forget Password button and Sign Up button have no use in this challenge.



Searching through the decompiled source code, we can find the following line .

```
const-string v0, "INSERT INTO Users VALUES (\'user\', \'My_P@s5w0Rd_iS-L34k3d\');"
```



However, entering these credentials into the textbox gives us "Do you think it will be that easy?" message, showing that this is not the way to solve this challenge.



Intuitively we will think of SQL injection and this is actually the correct way. Let the password be `' OR 1=1;` and the challenge is now solved.



## Flag

`govtech-csg{eZ_1nJ3CT10N}`

