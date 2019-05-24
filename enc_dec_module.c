#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/fcntl.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#define NAME "cryptctl"
#define ENC_NAME "cryptEncrypt"
#define DEC_NAME "cryptDecrypt"
#define ENC_QUANTUM 1000
#define ENC_QSET 1000
#define COUNT 255
#define IOCTL_CREATE 1000500
#define IOCTL_DESTROY 1000502
#define IOCTL_KEY 1000501

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jetmir Berisha");
MODULE_DESCRIPTION("Vigniere encryption decryption devices");
MODULE_VERSION("1.0");
// Structures to keep track of data and relevant pointers for a specific device (encDev/decDev)
typedef struct enc_qset_ {
    void** data;
    struct enc_qset_* next;
} enc_qset;
// device properties for cryptctl, encryptXX, decryptXX
typedef struct enc_devices_ {
    enc_qset *data;                 /* Pointer to first quantum set */
    int deviceNo;                   /* The number of the cipher device */
    loff_t readOffset;              /* The file offset for reading/writing ciphered data */ 
    loff_t writeOffset;
    char* key;                      /* The ciper key of the device for encrypting/decrypting */
    char* devName;                  /* The kmalloced device name */
    int quantum;                    /* The current quantum size */
    int qset;                       /* The current array size */
    unsigned long size;             /* Amount of data stored here */
    struct semaphore sem;           /* Mutex */
    struct cdev* c_dev;             /* Char device structure */
    dev_t dev;                      /* Major and minor */
    struct device* devPtr;          /* The device that shows up in /dev/ */
    struct class* my_class;         /* The class that represents this driver's devices */
    struct enc_devices_ *next;      /* Linked list of devices managed by this driver */
} enc_devices;

// Globals
static int devCounter = 0;      //Minor number
static enc_devices *head;   /* Linked list storing information for each device controlled by this driver. By convention the first node is the cryptctl device */
static enc_devices *end;

// function Prototypes
// File operations
static int chardev_uevent(struct device *dev, struct kobj_uevent_env *env);
static ssize_t enc_read (struct file *, char __user *, size_t, loff_t *);
static ssize_t enc_write (struct file *, const char __user *, size_t, loff_t *);
static long enc_ioctl (struct file *, unsigned int, unsigned long);
static int enc_open (struct inode *, struct file *);
static int enc_release (struct inode *, struct file *);
// Self defined funcs
static int getUserNum(char __user* b);
static int enc_trim(enc_devices*);
static enc_qset* enc_follow(enc_devices* dev, int item);
static void encrypt(char*, char*, int);
static void decrypt(char*, char*, int);

// File operations structure, keeps pointers that the OS uses to call the appropriate function in this driver
struct file_operations enc_fops = {
    .owner =            THIS_MODULE,
    .read =             enc_read,
    .write =            enc_write,
    .unlocked_ioctl =   enc_ioctl,
    .open =             enc_open,
    .release =          enc_release,
};

// Called upon insmod
static int hello_init(void) {
    unsigned int minor = 0;
    head = kmalloc(sizeof(enc_devices), GFP_KERNEL);        /* cryptctl */
    if (alloc_chrdev_region(&head->dev, minor, COUNT, NAME) < 0){
        printk(KERN_WARNING "encrypt: can't get major number at %s: %d\n", __FILE__, __LINE__);
        return -1;
    }
    printk(KERN_WARNING "Major: %u, Minor: %u\n", MAJOR(head->dev), MINOR(head->dev));
    // Obtaining a standalone cdev structure at runtime:
    // Or you can make your own structure and register it with a function call
    head->c_dev = cdev_alloc();
    if (head->c_dev == NULL){
        printk(KERN_WARNING "encrypt: can't allocate a cdev with cdev_alloc at %s: %d\n", __FILE__, __LINE__);
        unregister_chrdev_region(head->dev, COUNT);
        return -1;
    }
    head->c_dev->ops = &enc_fops;
    cdev_init(head->c_dev, &enc_fops);
    if (cdev_add(head->c_dev, head->dev, COUNT) < 0) {
        unregister_chrdev_region(head->dev, COUNT);
        printk(KERN_WARNING "failed to add cdev at %s: %d\n", __FILE__, __LINE__);
        return -1;
    }
    head->my_class = class_create(THIS_MODULE, "className");
    if (head->my_class == NULL){
        unregister_chrdev_region(head->dev, COUNT);
        cdev_del(head->c_dev);
        printk(KERN_WARNING "Failed to create device class at %s:%d\n", __FILE__, __LINE__);
        return -EEXIST;
    }
    head->my_class->dev_uevent = chardev_uevent;
    head->devPtr = device_create(head->my_class, NULL, head->dev, NULL, NAME);
    if (!head->devPtr) {
        class_destroy(head->my_class);
        unregister_chrdev_region(head->dev, COUNT);
        cdev_del(head->c_dev);
        printk(KERN_WARNING "Failed to create device at %s:%d\n", __FILE__, __LINE__);
        return -EINVAL;
    }
    /* Initialize the rest of the struct */
    head->devName = kmalloc(sizeof(char)*9, GFP_KERNEL);
    strcpy(head->devName, NAME);
    head->next =        NULL;
    head->deviceNo =    -1;
    head->readOffset =  -1;
    head->writeOffset = -1;
    head->data =        NULL;
    head->key =         NULL;
    head->quantum =     ENC_QUANTUM;
    head->qset =        ENC_QSET;
    head->size =        0;
    sema_init(&head->sem, 1);
    end = head;
    return 0;
}

/*
 *  Associated with the open("/dev/ecrypt") system call. 
 *  Maps the enc_device struct to the file struct 
 */
static int enc_open (struct inode* inode, struct file* filp) {
    enc_devices* dPtr;
    if (head->dev == inode->i_rdev)
        filp->private_data = head;
    else {
        // Gotta see which field of the device need to be initialized in ioctl anbd which fields need to be initialized here (probably all of them in ioctl)
        for(dPtr = head->next; dPtr; dPtr = dPtr->next) {
            if (dPtr->dev == inode->i_rdev){
                filp->private_data = dPtr;
                break;
            }
        }
    }
    return 0;
}

static ssize_t enc_read (struct file* filp, char __user* buff, size_t count, loff_t* off) {
    int quantum, qset;
    int itemsize;   /* Amount of bytes in the list item */
    int item, s_pos, q_pos, rest;
    ssize_t retval;
    enc_devices *dev;
    enc_qset *dptr;         /* The first item in the list */
    loff_t* offset;
    // Disallow reading/writing from cryptctl
    if (filp->private_data == head)
        return -1;
    printk(KERN_WARNING "enc_read called\n");
    dev = filp->private_data;
    quantum = dev->quantum;
    qset = dev->qset;
    itemsize = quantum * qset;
    retval = 0;
    offset = &dev->readOffset;

    printk(KERN_WARNING "1");
    if (down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    printk(KERN_WARNING "Offset in read: %lld, dev->size: %lu\n", *offset, dev->size);
    if (*offset >= dev->size)
        goto out;
    if (*offset + count > dev->size)
        count = dev->size - *offset;

    /* Find list item, qset index, and offset in the quantum */
    item = (long)*offset / itemsize;
    rest = (long)*offset % itemsize;
    s_pos = rest / quantum; q_pos = rest % quantum;
    printk(KERN_WARNING "3");
    /* Follow the linked list until this item is hit */
    dptr = enc_follow(dev, item);
    printk(KERN_WARNING "5");
    if (dptr == NULL || !dptr->data || !dptr->data[s_pos])
        goto out;       /*  Don't skip entries (don't fill holes) */
    printk(KERN_WARNING "dptr->data: %s\n", (char*)dptr->data[s_pos]);

    /* Read only up to the end of the quantum */
    if (count > quantum - q_pos)
        count = quantum - q_pos;
    if (copy_to_user(buff, dptr->data[s_pos] + q_pos, count)) {
        printk(KERN_WARNING "7");   
        retval = -EFAULT;
        goto out;
    }

    *offset += count;
    retval = count;
    dev->readOffset = *offset;
    out:
    up(&dev->sem);
    printk(KERN_WARNING "9");
    return retval;
}

static ssize_t enc_write (struct file* filp, const char __user* buff, size_t count, loff_t* off) {
    int quantum, qset;
    int itemsize;           /* Amount of bytes in the list item */
    int item, s_pos, q_pos, rest;
    ssize_t retval;
    enc_devices *dev;
    enc_qset *dptr;         /* The first item in the list */    // Disallow reading/writing from cryptctl
    loff_t *offset;
    if (filp->private_data == head)
        return -1;
    printk(KERN_WARNING "2");
    dev = filp->private_data;
    quantum = dev->quantum;
    qset = dev->qset;
    itemsize = quantum * qset;
    retval = -ENOMEM;
    offset = &dev->writeOffset;
    // Semaphore mutex
    printk(KERN_WARNING "4");
    if (down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    /* Find the item in the list, qset index and offset in the quantum */
    printk(KERN_WARNING "4-5: *offset %lld, itemsize %d, quantum %d, qset %d\n", *offset, itemsize, quantum, qset);
    item = (long)*offset / itemsize;
    rest = (long)*offset % itemsize;
    s_pos = rest / quantum;
    q_pos = rest % quantum;
    printk(KERN_WARNING "4-6: item %d, rest %d, s_pos %d, q_pos %d\n", item, rest, s_pos, q_pos);

    /* Follow the linked list up to the right position*/
    printk(KERN_WARNING "6");
    dptr = enc_follow(dev, item);
    printk(KERN_WARNING "8");
    if (!dptr)
        goto out;
    printk(KERN_WARNING "8-1");
    if (!dptr->data) {
        printk(KERN_WARNING "8-2");
        dptr->data = kmalloc(qset * sizeof(char*), GFP_KERNEL);
        printk(KERN_WARNING "8-3");
        if (!dptr->data){
            printk(KERN_WARNING "kmalloc failed at %s:%d\n", __FILE__, __LINE__);
            goto out;
        }
        printk(KERN_WARNING "8-4");
        memset(dptr->data, 0, qset * sizeof(char *));
        printk(KERN_WARNING "8-5");
    }
    printk(KERN_WARNING "8-6");
    if (!dptr->data[s_pos]) {
        printk(KERN_WARNING "8-7");
        dptr->data[s_pos] = kmalloc(quantum, GFP_KERNEL);
        printk(KERN_WARNING "8-8");
        if (!dptr->data[s_pos]){
            printk(KERN_WARNING "kmalloc failed at %s:%d\n", __FILE__, __LINE__);
            goto out;
        }
    }
    printk(KERN_WARNING "10");
    /* Only write one whole quantum */
    if (count > quantum - q_pos)
        count = quantum - q_pos;
    if (copy_from_user(dptr->data[s_pos] + q_pos, buff, count)){
        printk(KERN_WARNING "copy_from_user failed at %s:%d\n", __FILE__, __LINE__);
        retval = -EFAULT;
        goto out;
    }
    // Even = encryption
    if (dev->deviceNo % 2 == 0) 
        encrypt(dptr->data[s_pos] + q_pos, dev->key, count);
    else 
        decrypt(dptr->data[s_pos] + q_pos, dev->key, count);
    printk(KERN_WARNING "12. Wrote into /dev/encrypt: %s\n", (char*)dptr->data[s_pos]);
    *offset += count;
    retval = count;
    dev->writeOffset = *offset;

    // Update the size
    if (dev->size < *offset)
        printk(KERN_EMERG "12-2");
    dev->size = *offset;

    out:
    up(&dev->sem);
    printk(KERN_WARNING "14");
    return retval;
}


static long enc_ioctl (struct file* filp, unsigned int cmd, unsigned long b) {
    char *userPtr, *key, *decname, *encname, *newKey;
    char buf[2], krep[256];
    int err, keysize, pairDest, devNo, keyLen;
    enc_devices *devinfo, *previous, *decrypt, *devP, *nextEncrypt, *encryptX;
    printk(KERN_WARNING "Called ioctl on: %s", ((enc_devices*)(filp->private_data))->devName);
    if (filp->private_data != head)
        return -EBADF;
    switch(cmd){
        case IOCTL_CREATE:
            //Create enc_device for encrypt
            devinfo = kmalloc(sizeof(enc_devices), GFP_KERNEL);
            devinfo->dev = MKDEV(MAJOR(head->dev),devCounter+1);
            devinfo->c_dev = cdev_alloc();
            if (devinfo->c_dev == NULL){
                printk(KERN_WARNING "encrypt: can't allocate an  encrypt_cdev with cdev_alloc at %s: %d\n", __FILE__, __LINE__);
                kfree(devinfo);
                return -1;
            }

            devinfo->c_dev->ops = &enc_fops;
            cdev_init(devinfo->c_dev, &enc_fops);
            devinfo->c_dev->owner = THIS_MODULE;

            err = cdev_add(devinfo->c_dev, devinfo->dev,1);
            if(err){
                printk(KERN_WARNING "enc_ioctl: failed to add encrypt cdev to system @ THERES ONLY ONE FUCKING FILE");
                kfree(devinfo);
                return -EINVAL;
            }
            printk(KERN_WARNING "30");
            encname = kmalloc((sizeof(char)*strlen(ENC_NAME) + 6), GFP_KERNEL);
            encname = strcpy(encname, ENC_NAME);
            sprintf(encname+strlen(ENC_NAME), "%d", devCounter/2);
            devinfo->devName = encname;
            printk(KERN_WARNING "%s", encname);
            devinfo->devPtr = device_create(head->my_class, head->devPtr, devinfo->dev, "%s", devinfo->devName);
            devinfo->my_class = head->my_class;
            //if encrypt failed to be created
            if(!devinfo->devPtr){
                cdev_del(devinfo->c_dev);
                kfree(devinfo->devName);
                kfree(devinfo);
                printk(KERN_WARNING "Failed to create device at %s:%d\n", __FILE__,__LINE__);
                return -EINVAL;
            }

            //save encrypt dev to add to queue if successful creation of decrypt dev later
            encryptX = devinfo;

            //Add decrypt devinfo
            devinfo = NULL;
            printk(KERN_WARNING "31");
            devinfo = kmalloc(sizeof(enc_devices), GFP_KERNEL);
            devinfo->dev = MKDEV(MAJOR(head->dev), devCounter+2);
            devinfo->c_dev = cdev_alloc();
            //if cdev_alloc failed for decrypt free ecnryptX
            if(devinfo->c_dev == NULL){
                printk(KERN_WARNING "Failed to create c_dev for decrypt module in ioctl create\n");
                kfree(devinfo);
                kfree(encryptX->devName);
                cdev_del(encryptX->c_dev);
                device_destroy(encryptX->my_class, encryptX->dev);
                kfree(encryptX);
                return -EINVAL;
            }
                
            devinfo->c_dev->ops = &enc_fops;
            cdev_init(devinfo->c_dev, &enc_fops);
            devinfo->c_dev->owner = THIS_MODULE;


            err = cdev_add(devinfo->c_dev, devinfo->dev, 1);
            if(err){
                printk(KERN_WARNING "cdev_add failed for decrypt dev in IOCTL create\n");
                kfree(devinfo);
                kfree(encryptX->devName);
                cdev_del(encryptX->c_dev);
                device_destroy(encryptX->my_class, encryptX->dev);
                kfree(encryptX);
                return -EINVAL;
            }
            
            printk(KERN_WARNING "32");
            decname = kmalloc((sizeof(char)*strlen(DEC_NAME) + 6), GFP_KERNEL);
            decname = strcpy(decname, DEC_NAME);
            sprintf(decname+strlen(DEC_NAME), "%d", devCounter/2);
            devinfo->devName = decname;
            printk(KERN_WARNING "%s", decname);
            devinfo->devPtr = device_create(head->my_class, head->devPtr, devinfo->dev,  "%s", devinfo->devName);
            if (!devinfo->devPtr) {
                cdev_del(devinfo->c_dev);
                kfree(devinfo->devName);
                kfree(devinfo);
                kfree(encryptX->devName);
                cdev_del(encryptX->c_dev);
                device_destroy(encryptX->my_class, encryptX->dev);
                printk(KERN_WARNING "Failed to create device at %s:%d\n", __FILE__, __LINE__);
                return -EINVAL;
            }

            //Get Key from user - copy_from_user
            userPtr = (char*) b;
            printk(KERN_WARNING "33");
            keysize = getUserNum(userPtr);
            if (keysize < 0){
                printk(KERN_WARNING "failed at %s:%d", __FILE__, __LINE__);
                return -EINVAL;
            }
            memset(krep, 0, 255);
            sprintf(krep, "%d;", keysize);
            key = kmalloc(sizeof(char) * (keysize+1), GFP_KERNEL);
            if(copy_from_user(key, userPtr + strlen(krep), keysize)){
                printk(KERN_WARNING "failed at %s:%d", __FILE__, __LINE__);
                return -EFAULT;
            }
            key[keysize] = '\0';
            // localbuff = kmalloc((sizeof(char)*501), GFP_KERNEL);
            // if(copy_from_user(localbuff, userPtr, 500))
            //     return -EFAULT;

            // localbuff[500] = '\0';
            // buffholder = localbuff;
            // key = kmalloc((sizeof(char)*501), GFP_KERNEL);
            // keyholder = key;
            // printk(KERN_WARNING "34");

            // do{
            //     if(isalpha(*localbuff))
            //         *key++ = *localbuff;
            //     else
            //         break;
            //     localbuff++;
            // }while(*localbuff);
            // *key = '\0';
            // key = keyholder;  //set key back to initial position address
            // localbuff = buffholder; // " "
            // printk(KERN_WARNING "35");
            // kfree(localbuff);
            printk(KERN_WARNING "Key while creating: %s", key);
            keysize = 0;
            keysize = strlen(key);

            /* Initialize the rest of the struct */
            encryptX->deviceNo = devCounter++;
            encryptX->data = NULL;
            encryptX->key = kmalloc(sizeof(char)*(keysize+3), GFP_KERNEL);
            encryptX->key = strcpy(encryptX->key, key);
            encryptX->key = strcat(encryptX->key, "\0");
            encryptX->quantum = ENC_QUANTUM;
            encryptX->qset = ENC_QSET;
            encryptX->size = 0;
            encryptX->readOffset = 0;
            encryptX->writeOffset = 0;
            sema_init(&encryptX->sem, 1);
            encryptX->next = NULL;
            encryptX->my_class = head->my_class;

            devinfo->deviceNo = devCounter++;
            devinfo->data = NULL;
            devinfo->key = kmalloc(sizeof(char)*(keysize+3), GFP_KERNEL);
            devinfo->key = strcpy(devinfo->key, key);
            devinfo->key = strcat(devinfo->key, "\0");
            devinfo->quantum = ENC_QUANTUM;
            devinfo->qset = ENC_QSET;
            devinfo->size = 0;
            devinfo->readOffset = 0;
            devinfo->writeOffset = 0;
            sema_init(&devinfo->sem, 1);
            devinfo->my_class = head->my_class;
            devinfo->next = NULL;
            printk(KERN_WARNING "Keys at encrypt: '%s' decrypt: '%s'", encryptX->key, devinfo->key);
            printk(KERN_WARNING "enc entry %d, dec entry %d", encryptX->deviceNo, devinfo->deviceNo);
            kfree(key);
            //Add encrypt and decrypt devices to list
            end->next = encryptX;
            end->next->next = devinfo;
            end = devinfo;
            // Return the device number that was created
            printk(KERN_WARNING "return %d", (devCounter-1)/2);
            return (devCounter-1)/2;

        case IOCTL_DESTROY: ;
            pairDest = 0;
            nextEncrypt = NULL;
            pairDest = getUserNum((char*)b);
            printk(KERN_WARNING "destroy #%d", pairDest);
            if(pairDest < 0)
                return pairDest;
            if (!head){
                printk(KERN_WARNING "failed at %s:%d\n", __FILE__, __LINE__);
                return -EFAULT;
            }
            for (devP = head; devP; devP = devP->next){ //stops one short of the match
                if (devP->next)
                    if (devP->next->deviceNo == 2*pairDest)
                        break;
                printk(KERN_WARNING "head->next=%p", head->next);
            }
            if (devP == NULL){
                printk(KERN_WARNING "fault at %s:%d\n", __FILE__, __LINE__);
                return -1;
            }
            /* Need to connect the last dev (referred to after
             * the break in the for loop) to the dev 
             * which comes after the pair which we are going
             * to delete.
             */
            printk(KERN_WARNING "20--");
            previous = devP; //only needed to close the gap if there's more after decrypt
            devP = devP->next;
            decrypt = devP->next;
            if(decrypt->next != NULL) //get the next encrypt if there are any
                nextEncrypt = decrypt->next;
            printk(KERN_WARNING "20");
            enc_trim(devP);
            if(devP->key)
                kfree(devP->key);
            if(devP->devName)
                kfree(devP->devName);
            printk(KERN_WARNING "22");
            device_destroy(devP->my_class, devP->dev);
            cdev_del(devP->c_dev);
            printk(KERN_WARNING "24");
            kfree(devP);

            previous->next = NULL;

            enc_trim(decrypt);
            if(decrypt->key)
                kfree(decrypt->key);
            if(decrypt->devName)
                kfree(decrypt->devName);
            printk(KERN_WARNING "26");
            device_destroy(decrypt->my_class, decrypt->dev); 
            cdev_del(decrypt->c_dev);
            printk(KERN_WARNING "28");
            kfree(decrypt);

            previous->next = nextEncrypt;
            if (nextEncrypt == NULL)
			end = previous;
            break;

        case IOCTL_KEY:
            memset(buf, 0, 2);
            memset(krep, 0, 256);
            printk(KERN_WARNING "40");
            if ( (devNo = getUserNum((char*)b)) < 0 )
                return devNo;
            printk(KERN_WARNING "device: %d", devNo);
            sprintf(krep, "%d", devNo);
            if ( (keyLen = getUserNum((char*)b + strlen(krep) + 1)) < 0 ){
                printk(KERN_WARNING "failed at %s:%d\n", __FILE__, __LINE__);
                return keyLen;
            }
            printk(KERN_WARNING "keyLen: %d", keyLen);
            sprintf(krep, "%d;%d;", devNo, keyLen);
            newKey = kmalloc(sizeof(char) * (keyLen+1), GFP_KERNEL);
            if (!newKey){
                printk(KERN_WARNING "failed at %s:%d\n", __FILE__, __LINE__);
                return -EFAULT;
            }
            if (copy_from_user(newKey, (char*)b + strlen(krep), keyLen)){
                printk(KERN_WARNING "copy_from_user failed at %s:%d\n", __FILE__, __LINE__);
                return -EFAULT;
            }
            newKey[keyLen] = '\0';
            if (!head){
                printk(KERN_WARNING "failed at %s:%d\n", __FILE__, __LINE__);
                return -EFAULT;
            }
            printk(KERN_WARNING "Request=%d\nThe linked list\nhead %d\n  |\n  v", devNo, head->deviceNo);
            for (devinfo = head->next; devinfo; devinfo = devinfo->next) {
                printk(KERN_WARNING "node %d\n  |\n  v", devinfo->deviceNo);
            }
            for (devP = head->next; devP; devP = devP->next)
                if (devP->deviceNo == 2*devNo)
                    break;
            if (devP == NULL){
                printk(KERN_WARNING "failed at %s:%d", __FILE__, __LINE__);
                return -ENODEV;
            }
            kfree(devP->key);
            kfree(devP->next->key);
            devP->key = newKey;
            devP->next->key = kmalloc(sizeof(char)*(keyLen + 2), GFP_KERNEL);
            if (!devP->next->key){
                printk(KERN_WARNING "failed at %s:%d\n", __FILE__, __LINE__);
                return -EFAULT;
            }
            strcpy(devP->next->key, newKey);
            strcat(devP->next->key, "");
            break;
    }
    return 0;
}
//Automatically called when you close fd
static int enc_release (struct inode* inode, struct file* filp) {
    if (filp->private_data != head){
        enc_trim(filp->private_data);
    }
    return 0;
}

/* Trim the file to 0 length */
static int enc_trim(enc_devices* dev) {
    enc_qset *next, *dptr;
    int qset = dev->qset;       /* 'dev' is not-null*/
    int i;
    /* Go throgh the linked list of data points */
    for (dptr = dev->data; dptr; dptr = next) {
        if (dptr->data) {
            for (i = 0; i < qset; i++)
                if (dptr->data[i])
                    kfree(dptr->data[i]);
                else
                    break;
            kfree(dptr->data);
            dptr->data = NULL;
        }
        next = dptr->next;
        kfree(dptr);
    }
    dev->readOffset = 0;
    dev->writeOffset = 0;
    dev->size = 0;
    dev->quantum = ENC_QUANTUM;
    dev->qset = ENC_QSET;
    dev->data = NULL;
    return 0;
}

/* Follow the data structure to the desired location */
static enc_qset* enc_follow(enc_devices* dev, int item) {
    enc_qset* qs = dev->data;
    /* Allocate the first qset explicitly if need be*/
    if (!qs) {
        qs = dev->data = kmalloc(sizeof(enc_qset), GFP_KERNEL);
        if (qs == NULL)
            return NULL;
        //memset(qs, 0, sizeof(enc_qset));
        qs->data = NULL;
        qs->next = NULL;
    }

    /* Then follow the list */
    while (item--) {
        if (!qs->next) {
            qs->next = kmalloc(sizeof(enc_qset), GFP_KERNEL);
            if (qs->next == NULL)
                return NULL;
            qs->data = NULL;
            qs->next = NULL;
        }
        qs = qs->next;
        continue;               // Dunno why this is here
    }
    return qs;
}

// Called upon "rmmod [this module]"
static void hello_exit(void) {
    /*
     *  A little unclear on when to free stuff
     *  is it going to be freed on destroy?
     *  Should still check for outstanding devices
     */
    enc_devices *next, *dPtr = head;
    if (head) {
        for (head = head->next; head; head = next) {
            next = head->next;
            if (head) {
                enc_trim(head);
                if (head->devName)
                    kfree(head->devName);
                if (head->dev)
                    device_destroy(head->my_class, head->dev);
                if (head->c_dev)
                    cdev_del(head->c_dev);
                if (head->key)
                    kfree(head->key);
                kfree(head);
            }
            head = NULL;
        }
        unregister_chrdev_region(dPtr->dev, COUNT);
        device_destroy(dPtr->my_class, dPtr->dev);
        class_destroy(dPtr->my_class);
    }
    printk(KERN_WARNING "exit text\n");
}

module_init(hello_init);
module_exit(hello_exit);


static int chardev_uevent(struct device *dev, struct kobj_uevent_env *env) {
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}


static void encrypt(char* buff, char* key, int len) {
    int i = 0, j = 0;
    printk(KERN_WARNING "ENCRYPT Key: '%s', data: '%s'", key, buff);
    if (!buff || !key)
        return;
    while (i < len) {
        if (key[j] == '\0')
            j = 0;
        if (islower(buff[i])){
            buff[i] = (char)((toupper(buff[i]) + toupper(key[j])) % 26);
            buff[i] += 'A';
            buff[i] = (char)tolower(buff[i]);
            j++;
        }
        else if (isupper(buff[i])) {
            buff[i] = (char)((buff[i] + (char)toupper(key[j])) % 26);
            buff[i] += 'A';
            j++;
        }
        i++;
    }
}

static void decrypt(char* buff, char* key, int len) {
    int i = 0, j = 0;
    printk(KERN_WARNING "DECRYPT Key: '%s', data: '%s'", key, buff);
    if (!buff || !key)
        return;
    while (i < len) {
        if (key[j] == '\0')
            j = 0;
        if (islower(buff[i])){
            buff[i] = (char)((toupper(buff[i]) - (char)toupper(key[j]) + 26) % 26);
            buff[i] += 'A';
            buff[i] = (char)tolower(buff[i]);
            j++;
        }
        else if (isupper(buff[i])) {
            buff[i] = (char)((buff[i] - (char)toupper(key[j]) + 26) % 26);
            buff[i] += 'A';
            j++;
        }
        i++;
    }
}


static int getUserNum(char __user* b) {
    int i = 0;
    char buff[10] = {0};
    if (copy_from_user(buff, b, 1)){
        printk(KERN_WARNING "copy_from_user failed at %s:%d\n", __FILE__, __LINE__);
        return -EFAULT;
    }
    while (isdigit(buff[i])) {
        i++;
        if (copy_from_user(buff + i, b + i, 1)){
            printk(KERN_WARNING "copy_from_user failed at %s:%d\n", __FILE__, __LINE__);
            return -EFAULT;
        }
    }
    if (!isdigit(buff[i]))
        buff[i] = '\0';
    i = 0;
    sscanf(buff, "%d", &i);
    return i;
}
