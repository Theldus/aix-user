/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef GDB_H
#define GDB_H

	#include <ctype.h>
	#include "util.h"

	/* Macros. */

	/*
	 * Expects a single char, and if match, increase the buffer
	 * and decrease the length.
	 */
	#define expect_char(c,buf,len) \
		do { \
			if ((c) != *(buf)) { \
				warn("Expected '%c', got '%c'\n", (c), *(buf)); \
				send_gdb_error(); \
				return (-1); \
			} \
			buf++; \
			len--; \
		} while(0)

	/*
	 * Expects a char range, and if match, increase the buffr
	 * and decreases the length.
	 */
	#define expect_char_range(c_start,c_end,buf,len) \
		do { \
			if (*(buf) < c_start || *(buf) > c_end) { \
				warn("Expected range %c-%c, got '%c'\n", \
					(c_start), (c_end), *(buf)); \
				send_gdb_error(); \
				return (-1); \
			} \
			buf++; \
			len--; \
		} while(0)

	/* Math macros. */
	#define ABS(N) (((N)<0)?(-(N)):(N))
	#define MIN(x, y) ((x) < (y) ? (x) : (y))

#ifdef VERBOSE
	#define LOG_CMD_REC(...) \
		do { \
			fprintf(stderr, __VA_ARGS__); \
		} while (0)
#else
	#define LOG_CMD_REC(...)
#endif

	/**
	 * @brief Reads a given integer encoded in hex and returns it.
	 *
	 * @param buffer Buffer containing the integer to be read.
	 * @param len    Buffer length. This variable is updated.
	 *
	 * @param endptr If not NULL, the position for the first non-hex digit
	 *               character is saved.
	 *
	 * @param base   Number base, whether 10 or 16.
	 *
	 * @return Returns the integer read.
	 */
	static inline uint32_t read_int(const char *buff, size_t *len,
		const char **endptr, int base)
	{
		int32_t ret;
		char c;
		int v;

		ret = 0;
		for (size_t i = 0; i < *len; i++) {
			c = tolower(buff[i]);

			if (c >= '0' && c <= '9')
				v = (c - '0');
			else if (base == 16 && (c >= 'a' && c <= 'f'))
				v = (c - 'a' + 10);
			else {
				if (endptr) {
					*endptr = buff + i;
					*len = *len - i;
				}
				goto out;
			}
			ret = ret * base + v;
		}
	out:
		return (ret);
	}

	/**
	 * @brief Same behavior as read_int(), but do not updates @len nor returns
	 * where next non-digit char is.
	 *
	 * @param buf  Buffer to be read.
	 * @param len  Buffer length.
	 * @param base Number base, whether 10 or 16.
	 *
	 * @return Returns the integer read.
	 */
	static inline uint32_t simple_read_int(const char *buf, size_t len, int base)
	{
		size_t l = len;
		return read_int(buf, &l, NULL, base);
	}

	/* Embedded PowerPC target description XML. */
	static const char gdb_target_xml[] =
		"<?xml version=\"1.0\"?>"
		"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
		"<target version=\"1.0\">"
		"  <architecture>powerpc:common</architecture>"
		"  <feature name=\"org.gnu.gdb.power.core\">"
		"    <reg name=\"r0\" bitsize=\"32\" type=\"uint32\" regnum=\"0\"/>"
		"    <reg name=\"r1\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r2\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r3\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r4\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r5\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r6\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r7\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r8\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r9\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r10\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r11\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r12\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r13\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r14\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r15\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r16\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r17\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r18\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r19\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r20\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r21\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r22\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r23\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r24\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r25\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r26\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r27\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r28\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r29\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r30\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"r31\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\" regnum=\"32\"/>"
		"    <reg name=\"msr\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"cr\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"lr\" bitsize=\"32\" type=\"code_ptr\"/>"
		"    <reg name=\"ctr\" bitsize=\"32\" type=\"uint32\"/>"
		"    <reg name=\"xer\" bitsize=\"32\" type=\"uint32\"/>"
		"  </feature>"
		"</target>";

	extern int gdb_init(uc_engine *uc, u16 port);

#endif /* GDH_H */
