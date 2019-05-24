#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <errno.h>

#define IOCTL_CREATE 1000500
#define IOCTL_KEY 1000501
#define IOCTL_DESTROY 1000502
#define IOCTL_CLEAR 1000503
#define ENC_NAME "/dev/cryptEncrypt"
#define DEC_NAME "/dev/cryptDecrypt"
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

/*
 * This short program allows for simple control of the Kernel Module. Simply run it and follow the on screen 
 * instructons.
 */
int main(void) {
	int sel = -1, dev = -1, bigIndex = -1;
	char input[100] = {'\0'};
	char temp[100] = {'\0'};
	char* b = NULL;
	FILE* enc = NULL;
	FILE* dec = NULL;
	FILE* ctl = fopen("/dev/cryptctl", "r+");
	if (!ctl)
		goto out;
	printf("'cryptctl' is opened. Select a function by entering one of the following numbers:\n");
	begin:
	sel = -1;
	dev = -1;
	b = NULL;
	enc = NULL;
	dec = NULL;
	printf("1 - create a device pair\n");
	printf("2 - close cryptctl and exit\n");
	fgets(input, 30, stdin);
	sscanf(input, "%d", &sel);
	if (sel < 1 || sel > 2){
		printf("Incorrect input\n\n");
		goto begin;
	}
	if (sel == 1) {
		printf("New device. Enter the string length of the key you have in mind(integer): ");
		deviceNo:
                sel = -1;
		memset(input, 0, 100);
		fgets(input, 30, stdin);
		sscanf(input, "%d", &sel);
		if (sel < 1){
			printf("Please enter a positive number\n");
			goto deviceNo;
		}
		sprintf(input, "%d", sel);
		printf("\nEnter your key (note that the line will be consumed and only the first (%d) characters will be considered): ", sel);
		b = (char*)malloc(sizeof(char) * (sel + strlen(input) + 2));
		if (b == NULL){
			printf("No memory\n");
			goto closeCtl;
		}
		memset(b, 0, sel + strlen(input) + 2);
		sprintf(b, "%d;", sel);
		memset(input, 0, 100);
		fgets(b+strlen(b), sel+50, stdin);
		dev = ioctl(fileno(ctl), IOCTL_CREATE, b);
		if (dev < 0) {
			printf("Error encountered at %s:%d\n", __FILE__, __LINE__);
			free(b);
			goto closeCtl;
		}
		free(b);
		bigIndex = max(bigIndex, dev);
		printf("\nNewly created devices index: %d\n", dev);
		home:
		sel = -1;
		dev = -1;
		printf("\nWhat would you like to do next?");
		bad:
		printf("\n\t0 - create\n\t1 - encrypt\n\t2 - decrypt\n\t3 - destroy\n\t4 - change key\n\t5 - exit\n");
		memset(input, 0, 100);
		fgets(input, 30, stdin);
		sscanf(input, "%d", &sel);
		if (sel < 0 || sel > 5){
			printf("Bad input, try again\n");
			goto bad;
		}
		if (sel == 5)
			goto closeCtl;
		else if (sel == 4){
			// Change key
			printf("\nEnter index of device to change key of: ");
			trg:
			sel = -1;
			dev = -1;
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			sscanf(input, "%d", &sel);
			if (sel < 0 || sel > bigIndex){
				printf("\nThat device isn't created yet (Note that you can pass the index of an already destroyed device but it wont work)\nTry again:");
				goto trg;
			}
			printf("\nEnter the key length: ");
			pos:
			dev = -1;
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			sscanf(input, "%d", &dev);
			if (dev < 1){
				printf("Please enter a positive number:");
				goto pos;
			}
			sprintf(input, "%d", dev);
			sprintf(temp, "%d", sel);
			b = (char*)malloc(sizeof(char) * (dev + strlen(input) + strlen(temp) + 3));
			if (b == NULL){
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0,dev + strlen(input) + strlen(temp) + 3);
			sprintf(b, "%d;%d;", sel, dev);
			printf("\nEnter the new key: ");
			fgets(b + strlen(b), dev + 50, stdin);
			dev = ioctl(fileno(ctl), IOCTL_KEY, b);
			free(b);
			if (dev < 0){
				printf("Error occured at %s:%d\n", __FILE__, __LINE__);
				goto closeCtl;
			}
			printf("Key change successful\n");
			goto home;
		}
		else if (sel == 3) {
			three:
			sel = -1;
			printf("\nEnter the index of the file to destroy: ");
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			// sending stack data to kernel
			sscanf(input, "%d", &sel);
			if (sel < 0 || sel > bigIndex){
				printf("Try again\n");
				goto three;
			}
			strcat(input, ";");
			dev = ioctl(fileno(ctl), IOCTL_DESTROY, input);
			if (dev < 0) {
				printf("Error occured at %s:%d\n", __FILE__, __LINE__);
				goto closeCtl;	
			}
			printf("Device destroyed successfully\n");
			memset(input, 0, 100);
			goto home;
		}
		else if (sel == 2) {
			// Decrypt
			decrypt:
			sel = -1;
			printf("\nEnter the device index you wanna use to decrypt the data\n");
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			sscanf(input, "%d", &sel);
			if (sel < 0 || sel > bigIndex){
				printf("Try again\n");
				goto decrypt;
			}
			b = (char*)malloc(sizeof(char) * (strlen(DEC_NAME) + strlen(input) + 1));
			if (b == NULL){
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0, strlen(DEC_NAME) + strlen(input) + 1);
			sprintf(b, "%s%d", DEC_NAME, sel);
			dec = fopen(b, "r+");
			free(b);
			if (!dec){
				printf("Couldn't open file, maybe you entered an incorrect index\n");
				goto closeCtl;
			}
			sel = -1;
			printf("\nOpened successfully.\nEnter the length of the text you want to decrypt:");
			bwe:
			memset(input, 0, 100);
			fgets(input, 50, stdin);
			input[8] = '\0';
			sscanf(input, "%d", &sel);
			if (sel < 1) {
				printf("\nPlease enter a positive integer\n");
				goto bwe;
			}
			b = (char*)malloc(sizeof(char) * (sel + 1));
			if (b == NULL){
				fclose(dec);
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0, sel + 1);
            printf("\nEnter the data: ");
			fgets(b, sel + 10, stdin);
			b[sel] = '\0';
			sel = strlen(b);
			fwrite(b, sizeof(char), sel, dec);
			memset(b, 0, sel + 1);
			fread(b, sizeof(char), sel, dec);
			printf("\nDecrypted data: %s\n", b);
			fclose(dec);
			dec = NULL;
			goto home;
		}
		else if (sel == 1){
			// encrypt
			encrypt:
			sel = -1;
			printf("\nEnter the device index you wanna use to encrypt the data\n");
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			sscanf(input, "%d", &sel);
			if (sel < 0 || sel > bigIndex){
				printf("Try again\n");
				goto encrypt;
			}
			b = (char*)malloc(sizeof(char) * (strlen(ENC_NAME) + strlen(input) + 1));
			if (b == NULL){
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0, strlen(ENC_NAME) + strlen(input) + 1);
			sprintf(b, "%s%d", ENC_NAME, sel);
			enc = fopen(b, "r+");
			free(b);
			if (!enc){
				printf("Couldn't open file, maybe you entered an incorrect index\n");
				goto closeCtl;
			}
			sel = -1;
			printf("\nOpened successfully.\nEnter the length of the text you want to encrypt:");
			bweh:
			memset(input, 0, 100);
			fgets(input, 50, stdin);
			input[8] = '\0';
			sscanf(input, "%d", &sel);
			if (sel < 1) {
				printf("\nPlease enter a positive integer\n");
				goto bweh;
			}
			b = (char*)malloc(sizeof(char) * (sel + 1));
			if (b == NULL){
				fclose(enc);
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0, sel + 1);
            printf("\nEnter the data: ");
			fgets(b, sel + 50, stdin);
			b[sel] = '\0';
			sel = strlen(b);
			fwrite(b, sizeof(char), sel, enc);
			memset(b, 0, sel + 1);
			fread(b, sizeof(char), sel, enc);
			printf("Encrypted data: %s\n", b);
			fclose(enc);
			enc = NULL;
			goto home;
		}
		else if (sel == 0){
			// new device
			printf("\nEnter the key length for the new device: ");
			newDevice:
			sel = -1;
			memset(input, 0, 100);
			fgets(input, 30, stdin);
			sscanf(input, "%d", &sel);
			if (sel < 1){
				printf("Please enter a positive number\n");
				goto newDevice;
			}
			sprintf(input, "%d", sel);
			printf("\nEnter your key (note that the line will be consumed and only the first (%d) characters will be considered): ", sel);
			b = (char*)malloc(sizeof(char) * (sel + strlen(input) + 2));
			if (b == NULL){
				printf("No memory\n");
				goto closeCtl;
			}
			memset(b, 0, sel + strlen(input) + 2);
			sprintf(b, "%d;", sel);
			memset(input, 0, 100);
			fgets(b+strlen(b), sel + 50, stdin);
			dev = ioctl(fileno(ctl), IOCTL_CREATE, b);
			free(b);
			if (dev < 0){
				printf("Error occured at %s:%d\n", __FILE__, __LINE__);
				goto closeCtl; 	
			}
			bigIndex = max(bigIndex, dev);
			printf("\nNew device created successfully with index: %d\n", dev);
			goto home;
		}
	}
	else if (sel == 2){
		closeCtl:
		
		fclose(ctl);
		out:
		printf("Bye\n");
		return 0;
	}
}
