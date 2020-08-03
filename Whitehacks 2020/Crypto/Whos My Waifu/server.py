import math
from faker import Faker
import sympy
import Crypto.Random.random as random

class LCG():
    def __init__(self, mod): 
        # Mod should be a prime number
        while not sympy.isprime(mod):
            mod -= 1
            if mod == 1:
                print("You done messed up good")
                raise Exception

        a = v = 100
        while math.gcd(a, v) != 1:
            a = random.randrange(mod)
            v = random.randrange(mod)

        self.a = a
        self.v = v
        self.mod = mod
        self.counter = 0

    def next_bag(self):
        self.v += self.a
        self.value = 1

    def get_next(self):
        if self.counter == 0:
            self.next_bag()
            self.counter = self.mod // 2

        self.value = (self.a * self.value + self.v) % self.mod
        self.counter -= 1
        return self.value

class Gacha():

    def __init__(self):
        self.shipgirls = [
            "Aulick", "Beagle", "Benson", "Bulldog", "Cassin", "Comet", "Craven", "Crescent", "Cygnet", "Downes", "Foote", "Foxhound", "Kisaragi", "McCall", "Mikazuki", "Minazuki", "Mutsuki", "Shiranui", "Spence", "Uzuki", "Z20", "Z21",
            "Acasta", "Akatsuki", "Amazon", "Arashio", "Ardent", "Ariake", "Asashio", "Aylwin", "Bache", "Bailey", "Bush", "Dewey", "Echo", "Fletcher", "Forbin", "Fortune", "Fumizuki", "Gridley", "Halsey Powell", "Hamakaze", "Hammann", "Hatakaze", "Hatsuharu", "Hatsushimo", "Hazelwood", "Hobby", "Ikazuchi", "Inazuma", "Isokaze", "Jenkins", "Jersey", "Juno", "Jupiter", "Kagerou", "Kalk", "Kamikaze", "Kimberly", "Kiyonami", "Kuroshio", "Le Mars", "Matsukaze", "Michishio", "Mullany", "Nagatsuki", "Ooshio", "Oyashio", "Radford", "San Juan", "Shiratsuyu",
            "Sims", "Smalley", "Stanly", "Tanikaze", "Thatcher", "Urakaze", "Wakaba", "Yuugure", "Z18", "Z19", "Z36",
            "An Shan", "Ayanami", "Carabiniere", "Chang Chun", "Charles Ausburne", "Cooper", "Fu Shun", "Fubuki", "Glowworm", "Grenville", "Grozny", "Hanazuki", "Harutsuki", "Hibiki", "Javelin", "Kasumi", "L Opiniatre", "Laffey", "Le Temeraire", "Makinami", "Matchless", "Maury", "Minsk", "Musketeer", "Naganami", "Nicholas", "Niizuki", "Nowaki", "Shigure", "Tai Yuan", "Tartu", "Universal Bulin", "Uranami", "Vampire", "Vauquelin", "Yoizuki", "Z1", "Z23", "Z25", "Z35",
            "Eldridge", "Kawakaze", "Le Malin", "Le Triomphant", "Prototype Bulin MKII", "Tashkent", "Yudachi", "Yukikaze", "Z46"
        ]
        random.shuffle(self.shipgirls)
        self.lcg = LCG(len(self.shipgirls))

        self.counter = 0

    def get_next_shipgirl(self):
        return self.shipgirls[self.lcg.get_next()]

def main():
    gacha = Gacha()
    faker = Faker()

    print("Welcome to my stupid gameshow where you try to guess which shipgirl is our waifus!")
    print("Your task is to guess the name of our waifus. You have 5000 tries.")
    print("Get 250 of them correct in a row, and you will get a special prize!")
    print("Don't worry if you get it wrong, we will tell you our waifu's name anyways!\n")

    print("We're all degenerates here right?\n")

    solves = 0
    tries = 5000

    while tries:
        tries -= 1

        name = faker.name()
        correct = gacha.get_next_shipgirl()

        print(f"OK, what is {name}'s waifu?")
        guess = input()

        if (guess == "Quit"):
            print("See you another day!")
            tries = 0
            continue

        if (guess == correct):
            solves += 1
            print("Wow that is correct!")
        else:
            solves = 0
            print("Sorry, that is not correct...")

        print(f"{name}'s waifu is {correct}")

        if (solves == 250):
            print("CONGRATULATIONS, YOU ARE CLAIRVOYANT WINNER!")
            print("HERE FLAG: <CENSORED>")
            tries = 0

    print("Goodbye!")

if __name__ == "__main__":
    main()