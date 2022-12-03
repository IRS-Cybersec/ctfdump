# Sounds of freedom! (OSINT)

750 points // 31 Solves

## Description

In a recent raid on a suspected COViD hideout, we found this video in a thumbdrive on-site. We are not sure what this video signifies but we suspect COViD's henchmen might be surveying a potential target site for a biological bomb. We believe that the attack may happen soon. We need your help to identify the water body in this video! This will be a starting point for us to do an area sweep of the vicinity! 

*Flag Format: govtech-csg{postal_code}* 



## Video

We are provided with this [video](https://github.com/IRS-Cybersec/ctfdump/blob/stack-chomusuke/STACK%20the%20Flags%202020/Chomusuke/osint/Sounds%20of%20freedom!/osint-challenge-7-compressed.mp4).

The following are 2 screenshots from the video:
![](5.png)
![](6.png)


We tried our best to focus on distinctive features in the video and there were 3 we thought of:

1. The circular water body
2. The white bus stop
3. The background sound.



Our attempt to look through water bodies was not successful :(. The white bus stop did remind us of Punggol but ultimately it was the third point that proved the most important. After all, the title of the challenge is 'Sounds of Freedom!' (*The title is always the best clue*)



It evidently sounded like some sort of aircraft but one of us was rather certain it is probably some sort of military jet, so we started looking around Paya Lebar Air Base. On hindsight, the title was also a hint that the plane was military-related!



## Maps

Pulling up Paya Lebar Air Base on Google Maps leads us to this sight:

![](1.png)

So the likely candidates are between Punggol Park, Tampines Quarry and Bedok Reservoir. We started off with the former since the latter 2 are unlikely. One is rather secluded while the other we had already checked when going by the googling water body approach.

Upon zooming in, 

![](2.png)

That bus stop at the bottom right and the shape made it seem especially promising (Yay!) so we decided to use street view and after moving it around a little, we saw this:

![](3.png)

The 3 walkway-like paths straight ahead leading to the pond looks just like the video, as does the shelter on the left of the pond. :D

We also took a look at the bus stop

![](4.png)

and it looked rather identical to the one in the video.



So we have found the spot, hurray!



## Flag

Initially we thought we were supposed to find the postal code of the building but it was not the flag and we realised they wanted the postal code of the pond.

However, the pond itself did not have a postal code so we were confused. We decided to just submit the postal code of the park and it was indeed the flag:

`flag: govtech-csg{538768}` :D

