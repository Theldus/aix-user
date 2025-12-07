/**
 * A careful reader might notice that the gap between bzero and memset
 * is only 8 bytes. So effectively this 'bzero' is only re-arranging
 * the parameters so memset clears the entire memory.
 * So here I'm doing the same =). No need for a dedicated .c this time.
 */

unsigned char milicodes_bzero_bin[] = {
  0x38, 0xa4, 0x00, 0x00,   /* addi  r5,r4,0 */
  0x38, 0x80, 0x00, 0x00    /* li    r4,0    */
};
unsigned int milicodes_bzero_bin_len = 8;
