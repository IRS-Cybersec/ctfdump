# Sounds of freedom!

## OSINT [750] - 31 Solves

***In a recent raid on a suspected COViD hideout, we found this video in a thumbdrive on-site. We are not sure what this video signifies but we suspect COViD's henchmen might be surveying a potential target site for a biological bomb. We believe that the attack may happen soon. We need your help to identify the water body in this video! This will be a starting point for us to do an area sweep of the vicinity!***

***Flag Format: govtech-csg{postal_code}***

__________

### The Video in Question

______

Let's start off by viewing the video.

![1](images/1.png)

After watching the video, we ran `ExifTool` on this video for any potential location information hidden in the metadata. 

`ExifTool` is a command line program which allows for reading, writing and editing meta information present in many types of files. If you are using a Linux terminal, you can simply install it using `sudo apt install libimage-exiftool-perl` on UNIX based system. 

After running the tool, we did not see any location information in there. Either the information had been wiped out by the video taker, or the device used to record the video did not record down the geographical location. 

Therefore, we have to identify the location by the clues present within the video.

We can start by identifying the relevant landmarks presented in the video, so that it can aid us in finding out where the water body is.

**The process will be as follows:**

**A. Gather information from the video.**

**B. Isolate the correct location and reject the wrong locations using online tools.**

**C. Collect evidence to prove that the location is the same as the one from the video.**



### A. Gather information from the video.

_____

We can use the following list below to identify as many possible information as possible:

1. What is present in the foreground?
2. What is present in the background?
3. What specific infrastructures are present in the vicinity?
4. What is the general shape of the target (the water body) in the video?
5. If present, does the audio provide any additional clues?



Thereafter, we will attempt to narrow down our search.



### 1. What is present in the foreground?

_____________

Let's see what is present in the foreground of the video.

![2](images/2.png)

It seems to be reminiscent of a **Housing Development Board (HDB) Flat**. These flats are a form of public housing provided by the Singapore government. An example of a cluster of HDB flats is shown below.

![3](images/3.png)

However, it could also be a **condominium**, so we will keep both of these in mind.

**That aside, we also note the air conditioner exhaust placement being on the right of the video taker, as well as the presence of beam like structures.**



### 2. What is present in the background?

________

Let's shift our focus to the background.

![5](images/5.png)



We can note that there is a **bus stop** below the building.

![6](images/6.png)

Furthermore, since there is a bus stop, we can also note that the water body is right beside a **road**.



Let's move the video to a **different frame where the camera is panned upwards**.

![7](images/7.png)



We see that the water body is surrounded by **a lot of foliage** (red); this **rules out any water body that has little to no trees**. We also see that there are **walkways with red roofs around the park** (blue), as well as more **HDB flats behind coloured green** behind the park area. (yellow) There are also **staircases** (green and magenta) within the park.

![8](images/8.png)



### 3. What specific infrastructures are present in the vicinity?

_________

As mentioned previously, we have found:

1. The HDB/Condominium the video taker was in
2. The bus stop at the ground floor beside the road
3. Red roofed walkways in the park
4. Green HDB flats at the back of the park
5. Staircases within the park



### 4. What is the general shape of the target (the water body) in the video?

______________

The water body seems to be **curved**, so when we look for the water body later on, we can take this shape into consideration as well.

![9](images/9.png)



### 5. If present, does the audio provide any additional clues?

________

Interestingly enough, when this video was shot, there was a **very loud and deep hum**. Let's just say it goes by this sound:

```
mmmmmmmmmmmmmmmmmmmmmmmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmmmmm (The audio clips at the large 'M', meaning it is much louder in real life than what the camera could record.)  
```

Since there are no specific vehicles on the ground that could make such a loud noise, **it must have been from the air.** **The sound likely came from an airplane.**

Additionally, the name of the challenge is called "Sounds of freedom!" It sounds like this park is located in the vicinity of an air flight path, likely to be from the **Republic of Singapore Air Force**. This indicates a **high likelihood of the presence of a nearby air base or airport.** 

**This is an especially important clue, because it essentially rules out all other water bodies in Singapore that are not near any air bases.**



### **B. Isolate the correct location and reject the wrong locations using online tools.**

______________

Alright, now that we have the relevant information, let's bring up Google Maps/Google Earth and find this water body! I will be using Google Earth as it offers a more cinematic view of the area.

![10](images/10.png)



Start by identifying the various air bases and airports:

![11](images/11.png)



Let's proceed on with the process of elimination.

![12](images/12.png)

This is Singapore Changi Airport and Changi Air Base. From this satellite image, we **cannot find any nearby HDB flats or condominiums.** Moreover, this area is **not close to any water body** other than the surrounding sea. As such, we reject this location.



![13](images/13.png)

This is Singapore Tengah Air Base. From this picture, **it is also very secluded from any HDB flats or condominium**, and the surrounding water bodies are **extremely large**. It is likely that this is not the area either.



This leaves us with three possible locations: Seletar Airport, Sembawang Air Base and Payar Lebar Air Base. Given that these airports/air bases are near many HDB flats, we can assume that the flight paths are likely localized around there.

![14](images/14.png)



The park with the water body is likely in the picture above.

However, this is still a really large area (approximately 18.95km by 11.33km). How can we start narrowing down our search?

For this we can use the parks and nature reserves service provided by the [NParks](https://www.nparks.gov.sg/gardens-parks-and-nature/parks-and-nature-reserves) website. For those wondering, National Parks Board (NParks) is a statutory board responsible for managing the various parks and nature reserves in Singapore.

Let's now go to the same area as the picture above.

![15](images/15.png)

Luckily, this map also happens to show all of the water bodies located around this area.

We know from before that our **water body target is not that big**, and it has a **curved shape**, and as such, we can reject everything to the left of the purple colour MRT line (North East Line). 

![16](images/16.png)

![18](images/18.png)



From here, ignoring all of the rivers, we see **four** possible water bodies.

![18edited](images/18edited.png)



Zooming into the **two adjacent water bodies** below, we see that it is Bedok Reservoir and Tampines Quarry (unnamed water body right beside Bedok Reservoir).

![19](images/19.png)

Using street view, we can note that the water body is **way too large to fit the one** from the video.

![20](images/20.png)

Tampines Quarry is **not near any HDB flats, and is thus automatically disqualified.**

We can scratch these two water bodies off our list and move on.

The picture below shows Pasir Ris Town Park.

![21](images/21.png)

Well, it seems like Pasir Ris Town Park actually ticks a bunch of requirements mentioned above, such as the presence of the red roof structures, as well as a road beside the park. 

However, we eventually rejected this park.

The main reason is: **The shape of the water body does not fit the one in the video.**

If we look back at the screenshot from the video:

![9](images/9.png)

From this point of view, the water body is **curved along the top left corner.**



Going back to this image:

![22](images/22.png)

We consider three vantage points, namely A, B and C. These vantage points are at the places with HDB flats (or Condominiums) The outlines of the lake is also shown here to indicate what the top left corner of the water body would have looked like when viewing from that vantage point.

If we look from A, we will see that the shape of the top left corner of the park does not match the one from the video.

If we look from B, the top left hand corner of the water body is somewhat pointy instead of a curve. Moreover, there is a river separating the building from the water body. This is however not present in the video.

If we look from C, the distance between water body and the building is way too far than the one from the video.



With that, we only have one location left, and that is Punggol Park.

![23](images/23.png)

The good sign is that the water body here looks somewhat curvy, which fits the picture from above. Additionally, the water colour is also a dark yellow green, which matches the water colour from the video.





### C. Collect evidence to prove that the location is the same as the one from the video.

______

Now, it is just a matter of confirming that this is indeed the water body. This is important as we only have three attempts, and when conducting real OSINT, dispatching security personnel to the wrong location will result in a massive waste of time for everyone involved.

![24edited](images/24edited.png)

Looking from this angle, we see that the **red roof structures** are also there, and that the shape of the **top left corner of the water body also fits the one from the video. (curved)**

Going into street view at the tip of the arrow:

![25](images/25.png)

Bingo! We found the bus stop!

![6](images/6.png)

Even the **lamp to the left of the bus stop** fits the one from the video.

Let's turn around the street view camera:

![26](images/26.png)

Hmm, seemed like the person **stood on one of the higher floors and took the video.** The **air conditioner exhaust placement**, along with the **presence of the beams in the foreground** as mentioned just now also matches.

![26annotated](images/26annotated.png)



Are there any more evidence we can find?

Entering the park, we find:

![27](images/27.png)

Both staircases seem to coincide with the ones below (green and magenta):

![8](images/8.png)



What about the green buildings at the top left corner of the picture above?

Going to the staircase reveals something **worrying**:

![28](images/28.png)

The buildings are ***red*** in colour, rather than ***green***. We note Block 401 here, and that it seems to have a coffee shop at the ground floor.

Going back to satellite view:

![29](images/29.png)

Block 401 is still red, even though when viewed from the same vantage point, it should have been green...

![30edited](images/30edited.png)



The big surprise came when we decided to go into street view right in front of the HDB Block (Block 401):

![31](images/31.png)

It is green here! The coffee shop is also present here as well!

This means that the 3D models that Google Earth/Maps have generated were based off an **old model** of the block, and it is likely that **these blocks around the estate were repainted a few months ago to green** .



**With all of this, we are convinced that the water body shown in the video is in fact Punggol Park.**



### Flag

_____________

A simple Google Search shows us the address of Punggol Park:

![32](images/32.png)

```
Hougang Ave 10, Singapore 538768
```

Since the flag format is `govtech-csg{postal_code}`, we only need the postal code `538768`.

The flag is as follows:

```
govtech-csg{538768}
```

And there we have it! The challenge is solved!



### Learning Outcomes

____________

Key takeaways from this challenge:

1. This challenge reveals some limitations that Google Maps/Earth have, such as not updating the 3D models of the HDB blocks. This led to confusion as it was an apparent contradiction to all of the other evidence. It is lucky that Google Street View actually displays the updated block colour so that we can disregard the colour of the 3D models. Therefore, **always** look out for more information just in case the one you found is contradictory.

2. There are many tools available online that can be used to narrow down from over 350 parks to just a few for further investigation.
3. Analyse all possible clues from the given resource, and make a list to check against the actual location in question!

