/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>

static int err_int(int res, const char *file, int line)
{
	if (res < 0) {
		fprintf(stderr, "Error at %s:%d, aborting...\n", file, line);
		fprintf(stderr, "  -> (%s)\n", strerror(errno));
		exit(1);
	}
	return res;
}

#define ERR(x) err_int((x), __FILE__, __LINE__)

int main(int argc, char **argv)
{
	struct timeval  tv;
	struct timespec tp_real;
	struct timespec tp_mono;
	time_t t;
	char *end;
	intmax_t ref;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <reference-epoch-in-secs>\n", argv[0]);
		return 1;
	}

	/* Parse reference epoch robustly */
	errno = 0;
	ref    = strtoimax(argv[1], &end, 10);
	if (errno || *end != '\0') {
		fprintf(stderr, "Invalid reference epoch: %s\n", argv[1]);
		return 1;
	}

	ERR(time(&t));
	ERR(gettimeofday(&tv, NULL));
	ERR(clock_gettime(CLOCK_REALTIME,  &tp_real));
	ERR(clock_gettime(CLOCK_MONOTONIC, &tp_mono));

	printf("time:                           sec(%jd)\n",
		(intmax_t)t);

	printf("gettimeofday:                   sec(%jd), usec(%ld)\n",
		(intmax_t)tv.tv_sec,
		(long)tv.tv_usec);

	printf("clock_gettime(CLOCK_REALTIME):  sec(%jd), nsec(%ld)\n",
		(intmax_t)tp_real.tv_sec,
		tp_real.tv_nsec);

	printf("clock_gettime(CLOCK_MONOTONIC): sec(%jd), nsec(%ld)\n",
		(intmax_t)tp_mono.tv_sec,
		tp_mono.tv_nsec);

	printf("Current time: %s\n", asctime(localtime(&t)));

	/* Invariant 1: time() vs reference epoch */
	printf("== Comparison ref(%jd) vs time(%jd) ==\n",
		ref, (intmax_t)t);

	if (imaxabs((intmax_t)t - ref) <= 10)
		printf("  -> OK (within tolerance)\n");
	else {
		printf("  -> MISMATCH (epoch off)\n");
		return 1;
	}

	/* Invariant 2: CLOCK_REALTIME vs gettimeofday */
	{
		intmax_t sec_diff = imaxabs((intmax_t)tp_real.tv_sec -
			(intmax_t)tv.tv_sec);

		printf("== CLOCK_REALTIME vs gettimeofday ==\n");

		if (sec_diff <= 2)
			printf("  -> OK (sec diff = %jd)\n", sec_diff);
		else {
			printf("  -> MISMATCH (sec diff = %jd)\n", sec_diff);
			return 1;
		}
	}

	/* Invariant 3: Sub-second consistency */
	{
		intmax_t usec_from_nsec = tp_real.tv_nsec / 1000;
		intmax_t usec_diff      = imaxabs(usec_from_nsec - (intmax_t)tv.tv_usec);

		printf("== Sub-second precision check ==\n");

		if (usec_diff <= 1000)
			printf("  -> OK (usec diff = %jd)\n", usec_diff);
		else {
			printf("  -> MISMATCH (usec diff = %jd)\n", usec_diff);
			return 1;
		}
	}

	printf("All time checks passed.\n");
	return 0;
}
