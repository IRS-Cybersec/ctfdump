# What is he working on? Some high value project? 790 Points - 29 Solves (Cat 3)

```
The lead Smart Nation engineer is missing! He has not responded to our calls for 3 days and is suspected to be kidnapped! Can you find out some of the projects he has been working on? Perhaps this will give us some insights on why he was kidnapped…maybe some high-value projects! This is one of the latest work, maybe it serves as a good starting point to start hunting.

Flag is the repository name!

Developer's Portal - STACK the Flags (https://www.developer.tech.gov.sg/communities/events/stack-the-flags-2020)

Note: Just this page only! Only stack-the-flags-2020 page have the clues to help you proceed. Please do not perform any scanning activities on www.developer.tech.gov.sg. This is not part of the challenge scope!
```

Now let's head over to the developer portal! 

At first I did not find anything interesting in it, and went on a huge adventure stalking everybody in different govtech divisions as there were links to their Githubs in the footer of the page. But after hours of work, no result :sweat:.

Afterwards, my teammate spotted a HTML comment in the page that was just added a day ago (if you check the developer.tech.gov.sg github repository)

```html
<!-- Will fork to our gitlab - @joshhky -->
```

Now we have a username lead, let's run the good ole **Sherlock**:

```bash
python3 sherlock/ joshhky

[*] Checking username joshhky on:
[+] 500px: https://500px.com/p/joshhky
[+] Facebook: https://www.facebook.com/joshhky
[+] GitLab: https://gitlab.com/joshhky
[+] ICQ: https://icq.im/joshhky
[+] Instagram: https://www.instagram.com/joshhky
[+] Roblox: https://www.roblox.com/user.aspx?username=joshhky
[+] Sporcle: https://www.sporcle.com/user/joshhky/people
[+] Travellerspoint: https://www.travellerspoint.com/users/joshhky
[+] YouTube: https://www.youtube.com/joshhky
```

We checked through the various social media platforms first (Facebook, Instagram) just to make sure we do not miss anything, but they seemed unrelated to the challenge.

But hey, there's a [**gitlab account**](GitLab: https://gitlab.com/joshhky) with this handle, just as the comment said! 


