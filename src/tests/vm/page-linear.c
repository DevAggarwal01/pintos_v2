/* Encrypts, then decrypts, 2 MB of memory and verifies that the
   values are as they should be. */

#include <string.h>
#include "tests/arc4.h"
#include "tests/lib.h"
#include "tests/main.h"

#define SIZE (2 * 1024 * 1024)

static char buf[SIZE];

void test_main (void)
{
  struct arc4 arc4;
  size_t i;

  /* Initialize to 0x5a. */
  msg ("initialize");
  memset (buf, 0x5a, sizeof buf);

  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail ("byte %zu != 0x5a", i);

  /* Encrypt zeros. */
  msg ("read/modify/write pass one");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Decrypt back to zeros. */
  msg ("read/modify/write pass two");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail ("byte %zu != 0x5a", i);
}

// /* Encrypts, then decrypts, 2 MB of memory and verifies that the
//    values are as they should be. */

// #include <string.h>
// #include "tests/arc4.h"
// #include "tests/lib.h"
// #include "tests/main.h"

// #define SIZE (2 * 1024 * 1024)

// static char buf[SIZE];

// void test_main (void)
// {
//   struct arc4 arc4;
//   size_t i;

//   /* Initialize to 0x5a. */
//   msg ("initialize");
//   msg ("ANY SWAP ACTIVITY AFTER HERE IS FOR MEMSET PASS\n");
//   memset (buf, 0x5a, sizeof buf);

//   for (i = 0; i < 64; i++)
//     printf("after initialize: byte %zu is 0x%02x\n", i, (unsigned char) buf[i]);

//   /* Check that it's all 0x5a. */
//   msg ("read pass");
//   msg ("ANY SWAP ACTIVITY AFTER HERE IS FOR ONLY FIRST READ PASS\n");
//   for (i = 0; i < SIZE; i++)
//     if (buf[i] != 0x5a)
//       printf("first pass: byte %zu != 0x5a\n", i);

//   for (i = 0; i < 64; i++)
//     printf("after read pass: byte %zu is 0x%02x\n", i, (unsigned char) buf[i]);

//   /* Encrypt zeros. */
//   msg ("read/modify/write pass one");
//   msg ("ANY SWAP ACTIVITY AFTER HERE IS FOR ONLY ENCRYPTION PASS\n");
//   arc4_init (&arc4, "foobar", 6);
//   arc4_crypt (&arc4, buf, SIZE/2048);

//   for (i = 0; i < 64; i++)
//     printf("after init/crypt first: byte %zu is 0x%02x\n", i, (unsigned char) buf[i]);

//   /* Decrypt back to zeros. */
//   msg ("read/modify/write pass two");
//   msg ("ANY SWAP ACTIVITY AFTER HERE IS FOR ONLY DECRYPTION PASS\n");
//   arc4_init (&arc4, "foobar", 6);
//   arc4_crypt (&arc4, buf, SIZE/4096);

//   for (i = 0; i < 64; i++)
//     if (buf[i] != 0x5a)
//       printf("after init/crypt second: byte %zu is 0x%02x\n, which is not 0x5a", i, (unsigned char) buf[i]);

//   /* Check that it's all 0x5a. */
//   msg ("read pass");
//   for (i = 0; i < SIZE; i++) {
//     if (buf[i] != 0x5a) {
//       printf("last pass: failed at byte %zu 0x%x != 0x5a\n", i, buf[i]);
//       break;
//     }
//   }
// }
