#include <stdio.h>
#include <stdlib.h>
int main(){
    //FILE *f = fopen("credentials.txt", "r"); Nah, why not make it IMPOSSIBLE for you to get it???
    printf("Welcome to my Credentials Vault!\n\n\n");
	printf("To access you need the correct username and password!\n\n");
	char username[50];
	char password[50];
	printf("Username CODE %llx: ", username);
    gets(username);
	printf("\n");
    printf("Password CODE %llx: ", password);
	gets(password);
	printf("\n");
	printf("Actually, no. It doesn't matter whether you have the correct credentials or not. I'm not giving it. Why should I anyway?");
}
// $ gcc -zexecstack -fno-stack-protector credlogin.c