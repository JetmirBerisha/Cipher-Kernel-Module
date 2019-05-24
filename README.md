This is a Linux Kernel Module that enables encryption and decryption using the Vigenere cipher. It does that by creating ecryption/decryption character device pairs using ioctl commands.

How to load this module?
Run the makefile by typing "make" on a linux terminal. Note that you must have the linux headers installed before this can succeed. Then you can insert the module into the kernel by typing "sudo insmod enc_dec_module.ko". 

After that is done you want to "gcc user.c" and that will compile the user program that controls device creation, destruction, and key change. To perform any of these operations follow the instructions the program provides. 

Usage:
After running the compiled user.c, which expects the module to be loaded, you can create a new device pair and specify a key for that pair. Then /dev/cryptEncrypt0 and /dev/cryptDecrypt0 will appear. You may use the user program to encrypt and decrypt data but you may also use the devices directly. In order to encrypt data you can write to /dev/cryptEncrypt0 and then read back the encrypted data. In the same manner you can write the encrypted data to cryptDecrypt0 and read back the decrypted data.
In order to change encryption keys or destroy devices use the user program. 
Also note that once you terminate a session of the user program, all of the created character devices' unread data will be destroyed. This implies that you can use these devices in successive sessions but the data will be lost.
