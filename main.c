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

#define MINIMUM_MINI_VERSION 0x00010001

seeprom_t seeprom;

#ifdef MSPACES
mspace mem2space;
#endif

static void dsp_reset(void)
{
	write16(0x0c00500a, read16(0x0c00500a) & ~0x01f8);
	write16(0x0c00500a, read16(0x0c00500a) | 0x0010);
	write16(0x0c005036, 0);
}

static char ascii(char s) {
  if(s < 0x20) return '.';
  if(s > 0x7E) return '.';
  return s;
}

void hexdump(void *d, int len) {
  u8 *data;
  int i, off;
  data = (u8*)d;
  for (off=0; off<len; off += 16) {
    printf("%08x  ",off);
    for(i=0; i<16; i++)
      if((i+off)>=len) printf("   ");
      else printf("%02x ",data[off+i]);

    printf(" ");
    for(i=0; i<16; i++)
      if((i+off)>=len) printf(" ");
      else printf("%c",ascii(data[off+i]));
    printf("\n");
  }
}
	
void testOTP(void)
{
	printf("reading OTP...\n");
	printf("OTP:\n");
	otp_init();
	hexdump(&otp, sizeof(otp_t));

	printf("reading SEEPROM...\n");
	getseeprom(&seeprom);
	printf("read SEEPROM!\n");
	printf("SEEPROM:\n");
	hexdump(&seeprom, sizeof(seeprom));
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

int main(void)
{
	int vmode = -1;
#ifdef MSPACES
	mem2space = create_mspace_with_base((void *)0x90000000, 64*1024*1024, 0);
#endif
	exception_init();
	dsp_reset();

	// clear interrupt mask
	write32(0x0c003004, 0);

	ipc_initialize();
	ipc_slowping();

	gecko_init();
    input_init();
	init_fb(vmode);

	VIDEO_Init(vmode);
	VIDEO_SetFrameBuffer(get_xfb());
	VISetupEncoder();

	u32 version = ipc_getvers();
	u16 mini_version_major = version >> 16 & 0xFFFF;
	u16 mini_version_minor = version & 0xFFFF;
	printf("Mini version: %d.%0d\n", mini_version_major, mini_version_minor);

	if (version < MINIMUM_MINI_VERSION) {
		printf("Sorry, this version of MINI (armboot.bin)\n"
			"is too old, please update to at least %d.%0d.\n", 
			(MINIMUM_MINI_VERSION >> 16), (MINIMUM_MINI_VERSION & 0xFFFF));
		for (;;) 
			; // better ideas welcome!
	}

    gfx_printf("NAND Backup Restorer!\n");

    FATFS fs;
	f_mount(0, NULL);
	disk_initialize(0);
	f_mount(0, &fs);
    FIL fatf; UINT a;
    int pg, block;
    char* buf = (char*)malloc(0x840);

    FRESULT ret = f_open(&fatf, "/nand.bin", FA_READ);
    if(ret){
        gfx_printf("Error: cannot find nand.bin\n");
        for(;;);
    }

    u8 NANDStatus = nand_status();

    //gfx_printf("NAND Status: %d\n", nand_status());

    for(block = 8; block < 4096; block++){
        nand_erase(block*64);
        gfx_printf("Erased block %d\n", block);
    }

    f_lseek(&fatf, 0x200 * 0x840);
    for(pg = 0x200; pg < 4096 * 64; pg++){
        f_read(&fatf, buf, 0x840, &a);
        nand_write(pg, buf, buf+0x800);

        while(nand_status() != NANDStatus);

        if(pg % 64 == 0)
            
        gfx_printf("Flashed block %d\n", pg/64);
    }

    f_close(&fatf);
    free(buf);
	boot2_run(1, 2);
	gfx_printf("Done\n");

	return 0;
}

