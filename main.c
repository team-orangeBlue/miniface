/*
        BootMii - a Free Software replacement for the Nintendo/BroadOn bootloader.
        Requires mini.

Copyright (C) 2008, 2009        Haxx Enterprises <bushing@gmail.com>
Copyright (C) 2009              Andre Heider "dhewg" <dhewg@wiibrew.org>
Copyright (C) 2008, 2009        Hector Martin "marcan" <marcan@marcansoft.com>
Copyright (C) 2008, 2009        Sven Peter <svenpeter@gmail.com>
Copyright (C) 2009              John Kelley <wiidev@kelley.ca>

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <stdbool.h>
#include "bootmii_ppc.h"
#include "string.h"
#include "ipc.h"
#include "mini_ipc.h"
#include "nandfs.h"
#include "otp.h"
#include "fat.h"
#include "malloc.h"
#include "diskio.h"
#include "printf.h"
#include "video_low.h"
#include "input.h"
#include "console.h"
#include "sha1.h"
#include "es.h"
#include "wad.h"
#include "aes.h"

#define MINIMUM_MINI_VERSION 0x00010004

seeprom_t seeprom;
bool lockstate = true;

#ifdef MSPACES
mspace mem2space;
#endif

static void dsp_reset(void)
{
	write16(0x0c00500a, read16(0x0c00500a) & ~0x01f8);
	write16(0x0c00500a, read16(0x0c00500a) | 0x0010);
	write16(0x0c005036, 0);
}

s32 testAES(void)
{
	printf("testAES: ");
	static u8 somedata[128] ALIGNED(64);
	static u8 data2[128] ALIGNED(64);
	static u8 data3[128] ALIGNED(64);
	u8 key[16], iv[16];
	/*printf("somedata:\n");
	hexdump(somedata, 128);
	printf("key:\n");
	hexdump(key, 16);
	printf("iv:\n");
	hexdump(iv, 16);
	printf("\n");*/

	memset(data2, 0, 128);
	aes_reset();
	aes_set_key(key);
	aes_set_iv(iv);
	aes_encrypt(somedata, data2, 128/16, 0);

/*	hexdump(data2, 128);

	printf("...\n");
	printf("iv:\n");
	hexdump(iv, 16);
	printf("--\n");*/
	
	aes_reset();
	aes_set_key(key);
	aes_set_iv(iv);
	aes_decrypt(data2, data3, 128/16, 0);
    s32 ret = memcmp(somedata, data3, 128) ? -1 : 0;
    printf("%d\n", ret); 
	if(ret) return ret;

	memset(data3, 0, 128);
	my_aes_set_key(key);
	my_aes_decrypt(iv, data2, data3, 128);

    ret = memcmp(somedata, data3, 128) ? -1 : 0;
    printf("aes test 2: %d\n", ret); 
    
	return ret;
}

u32 lolcrypt(u8 *stuff)
{
	u32 key = 0x73b5dbfa;
	while(*stuff) {
		*stuff ^= (key & 0xff);
		stuff++;
		key = ((key<<1) | (key>>31));
	}
	return key;
}

int zone = 0; // to keep track of which menu the user is in.
int option = 0;
#define listsize 9 // simplifies updates
int oldprintx = 0;
int oldprinty = 0; // to unprint the old arrow when updating.
bool printedz = false; // to keep track if we explained to the user when things changed.
bool printedo = false;

char options[listsize][40] = {
	"Backup OTP and SEEPROM", 
	"Backup NAND ", 
	"Print system information",
	"Restore SEEPROM",
	"Restore NAND (without bootblocks)", 
	"Boot system menu", 
	"Boot homebrew channel (LULZ)",
	"Load BootMii IOS",
	"Load sd/bootmii/ppcboot.elf"
};


int zoneprinter(int zone){
	switch(zone){
		case 0:
			for (unsigned int i = 0; i<27; ++i){gfx_printf("");}
			gfx_printf("Main menu");
			for (unsigned int i = 0; i<listsize; ++i){
				gfx_printf("> %s", options[i]);
			}
			printedz = true;
			break;
	}
	return 0;
}

int micromemorybackup(bool addcsum){
	/*
		Here you can see the function to back up the OTP and SEEPROM. 
		Despite the fact that this is literally the core part of keys.bin, we don't make it and give you 2 separate files! :D

		For differentiation, we will record a SHA-1 of the dump if we are asked to.
		I have tested saving with FatFs LFN enabled. That required me to add a 60KB magic table and it didn't work properly anyway.
		As such SHA1 appended will be 3 bytes in size.
	*/
	gfx_printf("Starting to dump OTP and SEEPROM");
	// initial wizardry
	FATFS fs; FIL fatf; UINT a; FRESULT ret;
	f_mount(0, NULL); //unmount sd
	disk_initialize(0); // start sd
	f_mount(0, &fs); // mount sd
	unsigned char* buf = (unsigned char*)malloc(0x80);
	gfx_printf("Reading OTP");
	*(vu32*)0xCD8000C0 = 0x20; // light on
	// get otp
	otp_init();
	memcpy(buf, &otp, 0x80);
	if (addcsum){ // here we will add a sha1
		SHA1Context check;
		SHA1Reset(&check);
		SHA1Input(&check, &buf[0], 0x40);
		SHA1Input(&check, &buf[0x40], 0x40);
		if (SHA1Result(&check) == 0) {
			gfx_printf("Error: could not compute OTP SHA-1");
			return 1;
    	}
		char otpname[13];
		sprintf(otpname, "/O_");
		for (int i = 0; i < 3; i++) {
        	sprintf((otpname+3)+i*2, "%02x", check.Message_Digest[i]);
    	}
		sprintf(otpname+9, ".bin");
		gfx_printf("Saving OTP with SHA1");
		ret = f_open(&fatf, otpname, FA_WRITE | FA_CREATE_NEW);
	} else {
		// save otp
		gfx_printf("Saving OTP");
		ret = f_open(&fatf, "/otp.bin", FA_WRITE | FA_CREATE_NEW);
	}

	if(ret){
		gfx_printf("Error: cannot use otp.bin (f_open error %i)", ret);
		*(vu32*)0xCD8000C0 = 0x0; // light off
		return 1;
	}
	ret = f_write(&fatf, buf, 0x80, &a);
	if(ret){
		gfx_printf("Error: cannot write otp.bin (f_write error %i)", ret);
		*(vu32*)0xCD8000C0 = 0x0; // light off
		return 1;
	}
	f_close(&fatf);
    free(buf);

	gfx_printf("Reading SEEPROM");
	getseeprom(&seeprom);
	buf = (unsigned char*)malloc(0x100);
	memcpy(buf, &seeprom, 0x100);
	if (addcsum){ // here we will add a sha1
		SHA1Context check;
		SHA1Reset(&check);
		SHA1Input(&check, &buf[0], 0x40);
		SHA1Input(&check, &buf[0x40], 0x40);
		SHA1Input(&check, &buf[0x80], 0x40);
		SHA1Input(&check, &buf[0xc0], 0x40);
		if (SHA1Result(&check) == 0) {
			gfx_printf("Error: could not compute SEEPROM SHA-1");
			return 1;
    	}
		char seepromname[13];
		sprintf(seepromname, "/S_");
		for (int i = 0; i < 3; i++) {
        	sprintf((seepromname+3)+i*2, "%02x", check.Message_Digest[i]);
    	}
		sprintf(seepromname+9, ".bin");
		gfx_printf("Saving SEEPROM with SHA1");
		ret = f_open(&fatf, seepromname, FA_WRITE | FA_CREATE_NEW);
	} else {
		// save seeprom
		gfx_printf("Saving SEEPROM");
		ret = f_open(&fatf, "/seeprom.bin", FA_WRITE | FA_CREATE_NEW);
	}
	
	if(ret){
		gfx_printf("Error: cannot use seeprom.bin (f_open error %i)", ret);
		*(vu32*)0xCD8000C0 = 0x0; // light off
		return 1;
	}
	ret = f_write(&fatf, buf, 0x100, &a);
	if(ret){
		gfx_printf("Error: cannot write seeprom.bin (f_write error %i)", ret);
		*(vu32*)0xCD8000C0 = 0x0; // light off
		return 1;
	}
	f_close(&fatf);
    free(buf);

	*(vu32*)0xCD8000C0 = 0x0; // light off
	gfx_printf("Backed up successfully");
	return 0;
}

int printinfo(){
	/* 	
		This is the function to show info about the system.
		Currently you can find out info about boot1, boot2 TMD and SEEPROM, as well as serial number, menu, BC and MIOS versions, alongside NAND FS usage.
		I have an idea to view info about some IOS, but this sounds a bit stupid. So maybe not. Plus I'm not sure how to list directories with NAND FS right now.
		How this works:
		 * boot1: get OTP hash, and check with preset values. Easiest way.
		 * boot2: check TMD using mini's "IPC_BOOT2_TMD" call, which gives us a memory address, which we can turn into the version value itself.
		 * boot2 (2nd method): check SEEPROM.
		 * system menu: mount NAND FS, read tmd if present, then use lookup table to convert.
		 * serial: decrypt setting.txt from nand and decipher it.
	*/ 
	// make note of everything we have got
	u8 boot1hashes[4][20] = { // boot1 OTP SHA-1 hashes. from wiibrew
		{0xb3, 0x0c, 0x32, 0xb9, 0x62, 0xc7, 0xcd, 0x08, 0xab, 0xe3, 0x3d, 0x01, 0x5b, 0x9b, 0x8b, 0x1d, 0xb1, 0x09, 0x75, 0x44}, // boot1a
		{0xef, 0x3e, 0xf7, 0x81, 0x09, 0x60, 0x8d, 0x56, 0xdf, 0x56, 0x79, 0xa6, 0xf9, 0x2e, 0x13, 0xf7, 0x8b, 0xbd, 0xdf, 0xdf}, // boot1b
		{0xd2, 0x20, 0xc8, 0xa4, 0x86, 0xc6, 0x31, 0xd0, 0xdf, 0x5a, 0xdb, 0x31, 0x96, 0xec, 0xbc, 0x66, 0x87, 0x80, 0xcc, 0x8d}, // boot1c
		{0xf7, 0x93, 0x06, 0x8a, 0x09, 0xe8, 0x09, 0x86, 0xe2, 0xa0, 0x23, 0xc0, 0xc2, 0x3f, 0x06, 0x14, 0x0e, 0xd1, 0x69, 0x74}  // boot1d
	};
	char boot1vercode[4][1] = {"a", "b", "c", "d"};
	char menuverlist[17][3] = {
		"0.0", // insert startup disc
		"1.0", // unlabeled ones from startup disc
		"3.5", // because someone thought that 3.4K is not cool enough
		"TMD", // if we get an error in opening 
		"2.0",
		"2.1", // eu only
		"2.2",
		"3.0",
		"3.1",
		"3.2",
		"?.?", // there is a gap?!
		"3.3",
		"3.4", // 3.5K is hidden...
		"4.0",
		"4.1",
		"4.2",
		"4.3"
	};
	char menureg[7][1] = {"J", "U", "E", "?", "?", "?", "K"}; // WHY???
	struct nandfs_fp fp;
	u32 boot2_tmd = ipc_exchange(IPC_BOOT2_TMD, 0)->args[0]; // this will be the ram address for the boot2 tmd
	u16 menuver, realmenu, bcver, miosver;
	char sernopref[4], serno[10]; // read serial number with prefix from setting.txt

	otp_init(); // learn info about boot1
	getseeprom(&seeprom); // learn info about boot2
	nandfs_initialize(); // learn info about titles
	u32 usage = nandfs_get_usage(); // get usage
	// who thought that the read buffer pointer must be a u8?!
	// thanks comex for giving an example, I guess...
	if (nandfs_open(&fp, "/title/00000001/00000002/content/title.tmd") == -1){menuver = 101;} else {
		u8* menutmd = (u8 *) memalign(32, fp.size);
		nandfs_read(menutmd, fp.size, 1, &fp);
		switch (*(vu16*)(menutmd+0x1DC)){ // we will fix the version and put it into a corrected variant for seeking
			default:
				menuver = *(vu16*)(menutmd+0x1DC);
				realmenu = *(vu16*)(menutmd+0x1DC);
				break;
			case 390: // 3.5K
				menuver = 70;
				realmenu = *(vu16*)(menutmd+0x1DC);
				break;
			case 97: // 2.0U
				menuver = 129;
				realmenu = *(vu16*)(menutmd+0x1DC);
				break;
			case 64: // 1.0J
				menuver = 32;
				realmenu = *(vu16*)(menutmd+0x1DC);
				break;
		}
	}
	if (nandfs_open(&fp, "/title/00000001/00000100/content/title.tmd") == -1){bcver = 37707;} else {; //leetspeech "ERROR"
		u8* bctmd = (u8 *) memalign(32, fp.size);
		nandfs_read(bctmd, fp.size, 1, &fp);
		bcver = *(vu16*)(bctmd+0x1DC);
	}
	if (nandfs_open(&fp, "/title/00000001/00000101/content/title.tmd") == -1){miosver = 37707;} else {;
		u8* miostmd = (u8 *) memalign(32, fp.size);
		nandfs_read(miostmd, fp.size, 1, &fp);
		miosver = *(vu16*)(miostmd+0x1DC);
	}
	if (nandfs_open(&fp, "/title/00000001/00000002/data/setting.txt") == -1){strlcpy(sernopref, "ERR\0", 4); strlcpy(serno, ", NO FILE\0", 10);} else {
		u8* setting = (u8 *) memalign(32, fp.size);
		nandfs_read(setting, fp.size, 1, &fp);
		lolcrypt(setting); // decrypt setting.txt and discover serial number
		// time for extremely unreadable computations
		char *start, *end; // to separate the serial out
		start = strstr((char *)setting, "CODE="); // find prefix
		if (start != NULL) { // if present
			start += strlen("CODE="); // mark
			end = strchr(start, '\r'); // find CR
			if (end != NULL) { // if present
				*end = '\0'; // edit out real quick (not dangerous, this is a memory area and not fatfs)
				memcpy(sernopref, start, strlen(start)+1); // take out
				*end = '\r'; // fix buffer
			}
		} // same deal as above
		start = strstr((char *)setting, "SERNO=");
		if (start != NULL) {
			start += strlen("SERNO=");
			end = strchr(start, '\r');
			if (end != NULL) {
				*end = '\0';
				memcpy(serno, start, strlen(start)+1);
				*end = '\r';
			}
		}
	}
	gfx_printf("Provisioning info:");
	for (int i = 0; i<4; ++i){
		if (!(memcmp(&otp.boot1_hash, boot1hashes[i], 20))){ // I'm not you nintendo, I use memcmp for my bytes, not strncmp... lol
			//if res is 0, aka strings match
			gfx_printf("boot1%c; s_boot2 v%X; serial %s%s", boot1vercode[i][0], seeprom.counters->boot2version+1, sernopref, serno);
		}
	}

	gfx_printf("Software info:");
	// unfortunately nintendo did not make the lists on a template from day 1. so we need exceptions.
	gfx_printf("NAND usage %i/1000; t_boot2 v%X", usage, *(vu8*)((0x80000000|boot2_tmd)+0x1DD));
	gfx_printf("Menu Ver. %c%c%c%c v%i; BackCompat v%i; MIOS v%i", menuverlist[(menuver >> 4)/2][0], menuverlist[(menuver >> 4)/2][1], menuverlist[(menuver >> 4)/2][2], menureg[menuver & 0xf][0], realmenu, bcver, miosver);
	return 0;
	// todo: find out about installed IOS.
	// issues: how do you list directories with nandfs driver?

}

int seepromrestore(){
	/*
		Here you can see the SEEPROM restore function.
		This is the only part of miniface that requires the custom-made MINI 1.4, because of a custom IPC call to write the SEEPROM.
		It operates pretty simple:
		1. Open seeprom.bin, and say what we see inside of it.
		2. Query the user. As we know, SEEPROM stores boot2 version, so if this is done incorrectly, the system may get bricked to a hardmod level.
		3. Restore... this was easy.

		As said above, some safeguards should be added. I would only care about checking the boot2 version.
	*/
	gfx_printf("Starting to restore SEEPROM");
	// initial wizardry
	FATFS fs;
	FIL fatf; UINT a;
	f_mount(0, NULL); //unmount sd
	disk_initialize(0); // start sd
	f_mount(0, &fs); // mount sd
	char* buf = (char*)malloc(0x100);
	gfx_printf("Accessing seeprom.bin from SD");
	FRESULT ret = f_open(&fatf, "/seeprom.bin", FA_READ);
	if(ret){
		gfx_printf("Error: cannot use seeprom.bin (f_open error)");
		return 1;
	}
	gfx_printf("Reading seeprom.bin from SD");
	ret = f_read(&fatf, buf, 0x100, &a);
	if(ret){
		gfx_printf("Error: cannot use seeprom.bin (f_read error)");
		return 1;
	}
	if (lockstate){
		// check boot2 version in dump against current data
		getseeprom(&seeprom);
		if (seeprom.counters[0].boot2version != buf[0x48]){
			gfx_printf("STOP! Your boot2 versions are different!");
			gfx_printf("You will brick your console!");
			return 2;
		}
	}
	gfx_printf("Will write this into SEEPROM (ngsig): %02X%02X%02X%02X", buf[12], buf[13], buf[14], buf[15]);
	gfx_printf("OK to proceed? Y = yes, X = no");
	switch(input_wait()){
		case PAD_X:
			return 255;
			break;
		case PAD_Y:
			break;
	}
	// write seeprom
	gfx_printf("Writing SEEPROM");
	*(vu32*)0xCD8000C0 = 0x20; // light on
	sync_before_read(buf, 256);
	for (int i = 0; i<256; i+=4){
		gfx_printf("Writing bytes %i - %i", i, i+4);
		ipc_exchange(IPC_KEYS_SETEEP, 3, virt_to_phys(&buf[i]), i, 4); // this requires a custom version of MINI
	}
	// WARNING: DO NOT. PASS THE SEEPROM. AS IS.
	// WiiBrew warns you that MINI IPC takes 6 !!!UINT32!!! arguments. We need to send 256 bytes.
	// If you do this, you will write only the first 4 bytes, AND ERASE THE OTHER PARTS OF THE SEEPROM. Reboot, and boot1 will lock up, hardbricking the Wii.

	// Oh my..
	
	f_close(&fatf);
    free(buf);

	*(vu32*)0xCD8000C0 = 0x0; // light off
	gfx_printf("Restored SEEPROM successfully");
	return 0;
}

int nandbackup(){
	gfx_printf("Starting to back up NAND");
	*(vu32*)0xCD8000C0 = 0x20; // light on
	FATFS fs;
	f_mount(0, NULL); // unmount sd
	disk_initialize(0); // init sd
	f_mount(0, &fs); // mount sd
	char* nandbuf = (char*)malloc(0x850);
	FIL fatf; UINT a;
	int pg;
	char zeroes[0x840] = {0};
				
	FRESULT ret = f_open(&fatf, "/nand.bin", FA_WRITE | FA_CREATE_NEW);
	if (ret){
		gfx_printf("Error: nand.bin cannot be used - %i", ret);
		return 1;
	}
	for(pg = 0; pg < 4096 * 64; pg++){ // For all pages
		int res = nand_read(pg, nandbuf, nandbuf+0x800);
		if (res){
			gfx_printf("Error reading page %d", pg);
			f_write(&fatf, zeroes, 0x840, &a);
		} else {
			ret = f_write(&fatf, nandbuf, 0x840, &a);
			if (ret){
				gfx_printf("Error: cannot write - %i", ret);
				return 1;
			}
		}
	
		if(pg % 64 == 0)
    		gfx_printf("Read block %d", pg/64);
	}
	gfx_printf("Writing keys");
	char* buf = (char*)malloc(0x100);
	ret = f_write(&fatf, zeroes, 0x100, &a);
	if (ret){
		gfx_printf("Error: cannot write padding - %i", ret);
		return 1;
	}
	otp_init();
	memcpy(buf, &otp, 0x80);
	ret = f_write(&fatf, buf, 0x80, &a);
	if (ret){
		gfx_printf("Error: cannot write OTP - %i", ret);
		return 1;
	}
	ret = f_write(&fatf, zeroes, 0x80, &a);
	if (ret){
		gfx_printf("Error: cannot write padding - %i", ret);
		return 1;
	}
	getseeprom(&seeprom);
	memcpy(buf, &seeprom, 0x100);
	ret = f_write(&fatf, buf, 0x100, &a);
	if (ret){
		gfx_printf("Error: cannot write SEEPROM - %i", ret);
		return 1;
	}
	free(buf);
	ret = f_write(&fatf, zeroes, 0x100, &a);
	if (ret){
		gfx_printf("Error: cannot write padding - %i", ret);
		return 1;
	}
	gfx_printf("Finalizing write");
	f_close(&fatf);
	*(vu32*)0xCD8000C0 = 0; // light off
    //free(nandbuf); // So here's the deal. I am either dumb or there's no good reason that this free locks up. So screw everything and hope it doesnt leak
	gfx_printf("NAND saved to sd/nand.bin");
	return 0;
}

int nandrestore(){
	/*
		This is the NAND restore function.
		It finds a NAND.bin on the SD card, sized 840h*40h*4096h+1024 bytes (bytes/page, pages/block, blocks/nand plus keys.bin)
		It checks if you disabled godmode, and then:
		1. the keys.bin of your nand are checked against your current OTP NAND encryption and NAND HMAC keys
		2. a compare is executed to save write cycles.
		3. we confirm if the write is OK to be done, and then load in the backup.

		problems: our verification takes a whopping 19min55s. when you use ceil1ng_cat, you spend only 4min30s. WTF???
		I have tried some things, like changing how much I `memcmp()` at a time, `memcmp()`ing 16 megabytes of data in RAM. So on.
		Why isn't CEIL1NG_CAT open source? Defense against desperate users, which don't know the hiding dangers behind bypassing NAND restore checks?
	*/
	// ideas: can we increase verification speed anyhow? bootmii does all checks in less than 5 minutes.
	gfx_printf("Starting to restore NAND");

    FATFS fs;
	f_mount(0, NULL);
	disk_initialize(0);
	f_mount(0, &fs);
    FIL fatf; UINT a;
    int pg, block;
	char* buf = (char*)malloc(0x850);
	*(vu32*)0xCD8000C0 = 0x20; // light on
    FRESULT ret = f_open(&fatf, "/nand.bin", FA_READ);
    if(ret){
        gfx_printf("Error: cannot find nand.bin");
		free(buf); // this has to be done
        return 1;
    }
	if (lockstate){
		gfx_printf("Checking NAND against OTP...");
		f_lseek(&fatf, 0x21000144); // jump to keys.bin->otp->nand hmac key
		otp_init(); // check nand keys
		char* keybuf = (char*)malloc(0x24); // bufferize
		ret = f_read(&fatf, keybuf, 0x24, &a);
		if (ret){
			gfx_printf("Error: cannot read keys from file - %i", ret);
			gfx_printf("Is your backup old?");
			f_close(&fatf);
			free(buf);
			free(keybuf);
			return 1;
		}
		char* otpbuf = (char*)malloc(0x80);
		memcpy(otpbuf, &otp, 0x80);
		if (memcmp(keybuf, &otpbuf[0x44], 0x24)){ // if otp key isnt the same as backup key
			gfx_printf("Error: your backup keys don't match OTP!");
			gfx_printf("Is this the right console?");
			f_close(&fatf);
			free(buf);
			free(keybuf);
			free(otpbuf);
			return 1;
		}
		gfx_printf("Check passed!");
		free(keybuf);
		free(otpbuf);
	}
	/*gfx_printf("Starting restore simulation");
	bool program[4096] = {false}; // we will make an array to check whatever blocks should be programmed
	u16 programcount = 0; // keep track of how many blocks will be updated
	char* workcount = (char*)malloc(0x10);
	for(pg = 0x200; pg < 4064 * 64; pg++){ // USE CEIL1NG_CAT! how do they get faster speeds..?
		sprintf(workcount, "%i/4063", pg/0x40);
		print_str_noscroll(510, 450, workcount);
		f_lseek(&fatf, pg*0x840); // seek to next block in file
        ret = f_read(&fatf, buf, 0x800, &a); 
		if (ret){
			gfx_printf("Could not access backup! %i", ret);
			goto giveup;
		}
        nand_read(pg, nandbuf, nandbuf+0x800);
		// DO NOT CHECK ECC DATA! otherwise all blocks will be considered different
		if(memcmp(buf, nandbuf, 0x800)){ // if a discrepancy is found
			++programcount; // increment counter
			program[pg/64] = true; // note the page
			gfx_printf("Will program block %i", pg/0x40);
			pg+=(64-(pg%64)); // jump to next block			
		}
    }
	for (int i = 4063; i<4096; ++i){program[i]=true;} // last 32 blocks must be written!
	programcount+=32;
	free(nandbuf);
	memset(workcount, 0x20, 0xa);
	print_str_noscroll(510, 450, workcount);
	free(workcount);
	gfx_printf("%i blocks will be programmed", programcount);
	gfx_printf("EJECT/START to start, other to give up.");
	if(input_wait()!=GPIO_EJECT){goto giveup;}

    for(block = 8; block < 4096; block++){
		if (program[block]){
        	nand_erase(block*64); // erase block starting at the correct page
			gfx_printf("Erased block %d", block);
			f_lseek(&fatf, block*0x40*0x840); // jump to block start 
			for (int i = 0; i<63; ++i){ // program block (64 pages)
				f_read(&fatf, buf, 0x840, &a);
				nand_write(block*0x40+i, buf, buf+0x800); // slightly difficult calculation to jump to next page (i was making this at midnight while watchig 99999cc mkwii)
			}
			gfx_printf("Programmed block %d", block);
		}
    }*/
   	gfx_printf("Restore NAND?");
	gfx_printf("EJECT/START to start, other to give up.");
	if(input_wait()!=GPIO_EJECT){goto giveup;}
   	u8 NANDStatus = nand_status();
	char* reporter = (char*)malloc(0x18);
    //gfx_printf("NAND Status: %d\n", nand_status());

    for(block = 8; block < 4096; block++){
        nand_erase(block*64);
        if(block%256 == 0){
			sprintf(reporter, "Erased block %d", block);
			print_str_noscroll(280, 420, reporter);
		}
    }

    f_lseek(&fatf, 0x200 * 0x840); // go to beginning of file
    for(pg = 0x200; pg < 4096 * 64; pg++){
        f_read(&fatf, buf, 0x840, &a);
        nand_write(pg, buf, buf+0x800);

        while(nand_status() != NANDStatus);

        if(pg % 64 == 0)
        	sprintf(reporter, "Flashed block %d", pg/64);
			print_str_noscroll(280, 420, reporter);
    }
	memset(reporter, 0x20, 0x18);
	print_str_noscroll(280, 420, reporter);
	free(reporter);
    f_close(&fatf);
	*(vu32*)0xCD8000C0 = 0x0; // light off
    free(buf);
	gfx_printf("NAND restored successfully");
	return 0;
giveup:
	f_close(&fatf);
	*(vu32*)0xCD8000C0 = 0x0; // light off
    free(buf);
	gfx_printf("Better luck next time! Wrote nothing...");
	return 255;
}

int executer(int option){
	/*
		Here you can see the function to wrap all of our system hacking calls.
		This is in my opinion much cleaner than calling the functions separately. Also I don't have to explain to you what all of this does.
	*/
	switch(option){
		case 0:
			micromemorybackup(false);
			break;
		case 1:
			nandbackup();
			break;
		case 2:
			printinfo();
			break;
		case 3:
			seepromrestore(); // be careful!
			break;
		case 4:
			nandrestore(); // TODO for all 3 above: parse the function result.
			break;
		case 5:
			gfx_printf("Launching system menu");
			boot2_run(1, 2); // sysmenu
			break;
		case 6: 
			gfx_printf("Launching HBC (LULZ)");
			boot2_run(0x10001, 0x4C554C5A); // hbc "LULZ"
			break;
		case 7:
			gfx_printf("Launching IOS 254");
			boot2_run(1, 254); // bootmii ios stub loader default location
			break;
		case 8:
			gfx_printf("Launching executable");
			FATFS fs; // make filesystem container
			f_mount(0, NULL); // unmount sd
			disk_initialize(0); // init sd
			f_mount(0, &fs); // mount sd
			FIL fatf; UINT a; // for tracking
			FRESULT ret = f_open(&fatf, "/bootmii/ppcboot.elf", FA_READ);
			u32 len = fatf.fsize;
			if (ret){gfx_printf("That file does not exist."); break;}
			char* buf = (char*)malloc(len); // bufferize the read
			ret = f_read(&fatf, buf, len, &a); // read out binary to RAM
			if (ret){gfx_printf("That file is unreadable."); break;}
			f_close(&fatf);
			free(buf); // not exactly safe, but we control all instructions.
			int res = ipc_powerpc_boot(buf, len);
			if (res){gfx_printf("Error! PPC_BOOT Result: %i - press any key", res); input_wait();}
			
			// I have no idea why, but apparently IPC_PPC_BOOT_FILE does not exist..? how tf does IPC work and how did I add the SEEPROM write call?
			// CEIL1ING_CAT uses IPC_PPC_BOOT, not IPC_PPC_BOOT_FILE. Sure...
			// Calling the commands below locks up MINI. You get a 1 short, 1 long, 1 short (which afaict means "IPC call arugments malformed", no usb gecko, sorry)
			//char path[]="/bootmii/ppcboot.elf";
			//int res = ipc_exchange(IPC_PPC_BOOT_FILE, 2, 0, &path)->args[0];
			//if (res){gfx_printf("Error! PPC_BOOT_FILE Result: %i", res);}
			break;
	}
	if (option != 5 || option != 6 || option != 7 || option != 8){gfx_printf("Press any key...");}
	input_wait();
	printedz = false;
	printedo = false;
	return 0;
}

int main(void)
{
	exception_init();
	dsp_reset();

	// clear interrupt mask
	write32(0x0c003004, 0);

	ipc_initialize();
	ipc_slowping();

	gecko_init();
	input_init();

	FATFS fs; FIL fatf; UINT a; // make filesystem container
	f_mount(0, NULL); // unmount sd
	disk_initialize(0); // init sd
	f_mount(0, &fs); // mount sd
    unsigned char* buf;
	char *start, *end, autoboot[64], s_vmode[11], s_tid_high[9], s_tid_low[9];
	u32 tid_high, tid_low;
	int bootdelay, vmode;
	buf = (unsigned char*)malloc(0x1000); // for files. this also goes without saying that bootmii.ini must be under 4kib
    FRESULT ret = f_open(&fatf, "/bootmii/bootmii.ini", FA_READ); // access configuration file
    if(ret){
		vmode = -1;
		bootdelay=255;
		f_close(&fatf);
		free(buf);
        goto nosdinit; // if no file exists, just dont do anything.
    }
	ret = f_read(&fatf, buf, 0x1000, &a);
	if(ret){
		vmode = -1;
		bootdelay=255;
		f_close(&fatf);
		free(buf);
        goto nosdinit; // file unreadable. welp.
    }
	/*
		Check 1: define the video output mode
	*/
	start = strstr((char *)buf, "VIDEO=");
	if (start != NULL) { // if present
		start += strlen("VIDEO="); // mark
		end = strchr(start, '\n'); // find LF
		if (end != NULL) { // if present
			*end = '\0'; // edit out real quick (not dangerous, this is a memory area and not sd)
			memcpy(s_vmode, start, strlen(start)+1); // take out
			*end = '\n'; // fix buffer
		}
		switch(s_vmode[3]){
			case 0x43: // NTSC
				vmode = 0;
				break;
			case 0x35: // PAL50
				vmode = 1;
				break;
			case 0x36: // PAL60
				vmode = 2;
				break;
			case 0x47: // PROGRESSIVE
				vmode = 3;
				break;
		}
	} else {vmode = -1;}
	/*
		Check 2: do a boot time check 
	*/
	start = strstr((char *)buf, "BOOTDELAY="); // find prefix
	if (start != NULL) { // if present
		start += strlen("BOOTDELAY="); // mark
		end = strchr(start, '\n'); // find LF
		if (end != NULL) { // if present
			*end = '\0'; // edit out real quick (not dangerous, this is a memory area and not sd)
			bootdelay = my_atoi(start); // take out
			*end = '\n'; // fix buffer
			if (bootdelay>10){bootdelay=255;} // as usual, comply with format of bootmii.ini
		}
	} else {bootdelay=255;} // otherwise make a flag that nothing was found.
	/*
		Check 3: define what to autoboot
	*/
	start = strstr((char *)buf, "AUTOBOOT="); // find prefix
	if (start != NULL) { // if present
		start += strlen("AUTOBOOT="); // mark
		end = strchr(start, '\n'); // find LF
		if (end != NULL) { // if present
			*end = '\0'; // edit out real quick (not dangerous, this is a memory area and not sd)
			memcpy(autoboot, start, strlen(start)+1); // take out
			*end = '\n'; // fix buffer
		}
	} else {bootdelay=255;} // or skip autobooting logic
	f_close(&fatf);
	free(buf);

	/* TODO: mount SD card and check bootmii.ini for:
	 * video init mode
	 * coldboot target (both SYSMENU, HBC, as well as a title ID or a MINI-compatible ELF file on SD)
	 * boot delay (if 0, dont start any code execution at all; and if not, then just idle on the welcome screen.)
	 * whatever else... oh of course, the godmode unlock.
	*/
nosdinit:
#ifdef MSPACES
	mem2space = create_mspace_with_base((void *)0x90000000, 64*1024*1024, 0);
#endif
	if (!bootdelay){goto autorun;} // jump to autoboot and do not spend time initializing video output if bootdelay is 0
	init_fb(vmode);

	VIDEO_Init(vmode);
	VIDEO_SetFrameBuffer(get_xfb());
	VISetupEncoder();
	
	// begin OTP+SEEPROM autodump
	buf = (unsigned char*)malloc(0x80);
	otp_init();
	memcpy(buf, &otp, 0x80);
	SHA1Context bootcheck;
	SHA1Reset(&bootcheck);
	SHA1Input(&bootcheck, &buf[0], 0x40);
	SHA1Input(&bootcheck, &buf[0x40], 0x40);
	if (SHA1Result(&bootcheck) == 0) {micromemorybackup(true);} // better safe than sorry!
	char otpname[13];
	sprintf(otpname, "/O_");
	for (int i = 0; i < 3; i++) {
       	sprintf((otpname+3)+i*2, "%02X", bootcheck.Message_Digest[i]);
    }
	sprintf(otpname+9, ".bin");
	if(f_open(&fatf, otpname, FA_READ)){ // file doesn't exist, back up things immediately!
		gfx_printf("Please wait while we dump OTP");
		micromemorybackup(true);
	}else{f_close(&fatf);} 
	// end OTP+SEEPROM autodump

	u32 version = ipc_getvers();
	u16 mini_version_major = version >> 16 & 0xFFFF;
	u16 mini_version_minor = version & 0xFFFF;
	gfx_printf("Welcome to miniface! Ver. 0F");
	if (bootdelay!=255){
		char count[15];
		gfx_printf("Detected autoboot for %s!", (autoboot[0] == 0x53) ? "system menu" : ((autoboot[0] == 0x48) ? "homebrew channel" : ((autoboot[0] == 0x30) ? "title" : "ELF")));
		gfx_printf("Press EJECT/START now or wait to load.");
		for (bootdelay = bootdelay; bootdelay>0; --bootdelay){
			sprintf(count, "%i seconds left", bootdelay);
			print_str_noscroll(280, 100, count);
			for (int i=10; i>0; --i){ // clock cycles are valuable! always listen for input.
				if(input_read() == GPIO_EJECT){goto undo_run;}
				udelay(100000);
			}
		}
	}
autorun:
	switch(autoboot[0]){
			case 0x53: // SYSMENU
				executer(5);
				break;
			case 0x48: // HBC
				executer(6);
				break;
			case 0x30: // title ID
				// step 1: split
				strlcpy(s_tid_high, autoboot, 9);
				s_tid_high[8] = '\0'; // for atoi_hex
				strlcpy(s_tid_low, autoboot+8, 9);
				s_tid_low[8] = '\0'; // for atoi_hex

				// step 3: convert to u32
				tid_high = my_atoi_hex(s_tid_high, 8);
				tid_low = my_atoi_hex(s_tid_low, 8);
				// step 4: run boot2
				boot2_run(tid_high, tid_low);
				break;
			case 0x2F: // mini executable
				//ipc_exchange(IPC_PPC_BOOT_FILE, 2, true, &autoboot); // does not work sadly. maybe we need to send a pointer with the string..?
				FRESULT ret = f_open(&fatf, autoboot, FA_READ);
				u32 len = fatf.fsize;
				if (ret){gfx_printf("Given file does not exist - press any key"); input_wait(); break;}
				char* buf = (char*)malloc(len); // bufferize the read
				gfx_printf("Uploading %d bytes", len);
				ret = f_read(&fatf, buf, len, &a); // read out binary to RAM
				if (ret){gfx_printf("Given file is unreadable - press any key"); input_wait(); break;}
				gfx_printf("Memory address: %08X", &buf);
				f_close(&fatf);
				free(buf); // not exactly safe, but we control all instructions.
				int res = ipc_powerpc_boot(buf, len);
				if (res){gfx_printf("Error! PPC_BOOT result: %i - press any key", res); input_wait();}
				break;
		}
	//print_str_noscroll(5, 37, "Mini version: %d.%0d", mini_version_major, mini_version_minor);
undo_run:
	gfx_printf("When disc LED is lit, DO NOT POWER OFF!");
	udelay(1450000);
	/*
		Below you can observe the halt that we call if the user for some reason did not use a compatible MINI.
		This is designed to be fail-proof for the most part. You already know that to load miniface, you are required to load the BootMii stub loader.
		If you had the loader in boot2, you should not care at all.
		If you had the loader in IOS254, the approach below should be pretty resilient to things like accidental bricking.
		An example would be after breaking the system, for example when using boot1c and installing a stub menu IOS.

		The idea is the following:
		When we detect an unsuitable armboot.bin, we do not let you do anything and stop execution. You then get 20 seconds to either load HBC, or go to IOS 254.
		Because you entered from those 2, there is no way that you didn't have access to them.

		This provides an easy brick-resistant safeguard. Although in reality, we only need the custom MINI for SEEPROM write support. But who cares.
	*/
	if (version < MINIMUM_MINI_VERSION) {
		gfx_printf("");
		gfx_printf("");
		gfx_printf("!!!  SSSSS TTTTTTT  OOOOO  PPPPPP  !!!");
		gfx_printf("!!!  SSSSS TTTTTTT OO   OO PPPPPPP !!!");
		gfx_printf("!!! SS       TTT   OO   OO PP   PP !!!");
		gfx_printf("!!! SS       TTT   OO   OO PP   PP !!!");
		gfx_printf("!!! SS       TTT   OO   OO PP   PP !!!");
		gfx_printf("!!!  SSSSS   TTT   OO   OO PP   PP !!!");
		gfx_printf("!!!  SSSSS   TTT   OO   OO PPPPPP  !!!");
		gfx_printf("!!!      SS  TTT   OO   OO PPPPPP  !!!");
		gfx_printf("!!!      SS  TTT   OO   OO PP      !!!");
		gfx_printf("         SS  TTT   OO   OO PP         ");
		gfx_printf("!!!  SSSSS   TTT   OO   OO PP      !!!");
		gfx_printf("!!!  SSSSS   TTT    OOOOO  PP      !!!");
		gfx_printf("");
		gfx_printf("");
		gfx_printf("This MINI version is INCOMPATIBLE");
		gfx_printf("with miniface. You need %d.%0d, but you have %d.%0d.", (MINIMUM_MINI_VERSION >> 16), (MINIMUM_MINI_VERSION & 0xFFFF), mini_version_major, mini_version_minor);
		gfx_printf("We distribute a compatible armboot.bin.");
		gfx_printf("You can add it while we wait, or press EJECT/START");
		gfx_printf("to open HBC (LULZ). Otheriwse, IOS 254 will be loaded.");
		char count[3];
		for (int i = 20; i>0;){ 
			if ((*(vu32*)0xCD8000C0)&0x20){
                *(vu32*)0xCD8000C0 = 0x0;
            } else {
                *(vu32*)0xCD8000C0 = 0x20;
            } // light toggle
			sprintf(count, "%i seconds", i);
			print_str_noscroll(300, 30, count);
			udelay(1000000); // wait 1 second
			if (input_read() == GPIO_EJECT){executer(6);};
			--i;
		}
		gfx_printf("Press any key to run IOS 254.");
		input_wait();
		boot2_run(1, 254); // launch bootmii IOS
		udelay(5000000); // dont show the menu
	}

	for (;;){
		switch(zone){
			case 0:
				if (!printedz){zoneprinter(zone);}
				if (!printedo){
					// warning: there is a bug. if your string is shorter than 12 characters, you will bug the print. add spaces please.
					print_str_noscroll(oldprintx, oldprinty, "      "); // clear old arrow
					print_str_noscroll(2+12*strlen(options[option]), 441-(17*listsize)+17*option, "<<<---"); // print new arrow
					oldprintx = 2+12*strlen(options[option]);
					//oldprinty = 322+17*option;
					oldprinty = 441-(17*listsize)+17*option;
					printedo = true;
				}
				switch (input_read()){
					case PAD_RIGHT:
					case PAD_DOWN:
						if (option==listsize-1) {option = 0;} else {++option;}
						printedo = false;
						break;
					case PAD_LEFT:
					case PAD_UP: // impossible to press without a gc controller
						if (option==0) {option = listsize-1;} else {--option;}
						printedo = false;
						break;
					case GPIO_EJECT:
					case PAD_A:
						executer(option);
						break;
				}
			break;
		}
	}

	return 0;
}

