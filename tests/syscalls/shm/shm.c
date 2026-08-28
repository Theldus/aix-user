/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>

/* Same segment size used by 'restbyname'. */
#define SEG_SIZE 40960

#define errx(code,...) \
	do {\
		fprintf(stderr, "%s:%d ", __func__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);\
		exit((code));\
	} while (0)

/**
 * @brief Fills the memory pointed to by @p buff with a position-dependent
 * pattern, so that an aliased/wrong mapping is not able to pass the
 * check made by @ref check_pattern.
 *
 * @param buff Buffer to be filled.
 * @param size Buffer size.
 * @param seed Pattern seed.
 */
static void fill_pattern(char *buff, int size, int seed)
{
	int i;
	for (i = 0; i < size; i++)
		buff[i] = (char)((i + seed) & 0xFF);
}

/**
 * @brief Checks if the memory pointed to by @p buff matches the pattern
 * previously written by @ref fill_pattern.
 *
 * @param buff Buffer to be checked.
 * @param size Buffer size.
 * @param seed Pattern seed.
 *
 * @return Returns 1 if the buffer matches, 0 otherwise.
 */
static int check_pattern(const char *buff, int size, int seed)
{
	int i;
	for (i = 0; i < size; i++)
		if ((unsigned char)buff[i] != ((i + seed) & 0xFF))
			return 0;
	return 1;
}

/**
 * @brief Creates a new (private) shared memory segment and attaches it.
 *
 * @param size Segment size.
 * @param id   Returned segment identifier.
 *
 * @return Returns the attached address.
 */
static char *create_and_attach(int size, int *id)
{
	char *buff;

	*id = shmget(IPC_PRIVATE, size, 0600);
	if (*id < 0)
		errx(1, "Unable to shmget: %d (%s)\n", errno, strerror(errno));

	buff = shmat(*id, 0, 0);
	if (buff == (char*)-1)
		errx(1, "Unable to shmat: %d (%s)\n", errno, strerror(errno));

	return buff;
}

int main(void)
{
	char *buff, *buff2;
	int id, id2;
	int wstatus;
	pid_t pid;
	int i;

	/* ================================================================
	 * Create, attach and check if the segment is zero-filled, as a
	 * brand new segment should always be.
	 * ================================================================*/
	buff = create_and_attach(SEG_SIZE, &id);

	for (i = 0; i < SEG_SIZE; i++)
		if (buff[i])
			errx(1, "Failed: byte %d is not zeroed: 0x%x!\n", i, buff[i]);

	printf(" -> Attach + zero-fill: [PASS]\n");

	/* ================================================================
	 * Read/write within the very same process.
	 * ================================================================*/
	fill_pattern(buff, SEG_SIZE, 0);
	if (!check_pattern(buff, SEG_SIZE, 0))
		errx(1, "Failed: unable to read back what was written!\n");

	printf(" -> Read/write: [PASS]\n");

	/* ================================================================
	 * Sharing across a fork(): this is what 'restbyname' (and friends)
	 * actually rely upon: attach *before* the fork and then use the
	 * segment as a two-way channel between parent and child.
	 *
	 * Note that a fork()ed child inherits the attachment, there is no
	 * shmat() on the child side.
	 * ================================================================*/
	fill_pattern(buff, SEG_SIZE, 1);

	if ((pid = fork()) < 0)
		errx(1, "Unable to fork: %d (%s)\n", errno, strerror(errno));

	/*
	 * Child: check whether the parent writes are visible here and, if
	 * so, answer back with a new pattern.
	 *
	 * Beware to *not* use exit()/printf() here: stdout is block-buffered
	 * and the buffer inherited from the parent would be flushed twice.
	 */
	if (!pid) {
		if (!check_pattern(buff, SEG_SIZE, 1))
			_exit(1);
		fill_pattern(buff, SEG_SIZE, 2);
		_exit(0);
	}

	if (waitpid(pid, &wstatus, 0) != pid)
		errx(1, "Unable to waitpid: %d (%s)\n", errno, strerror(errno));
	if (!WIFEXITED(wstatus))
		errx(1, "Failed: child has not exited normally: 0x%x!\n", wstatus);
	if (WEXITSTATUS(wstatus))
		errx(1, "Failed: child does not see the parent writes!\n");

	printf(" -> Child sees parent writes: [PASS]\n");

	if (!check_pattern(buff, SEG_SIZE, 2))
		errx(1, "Failed: parent does not see the child writes!\n");

	printf(" -> Parent sees child writes: [PASS]\n");

	/* ================================================================
	 * Detach: the segment must stay alive until an explicit IPC_RMID,
	 * so it must be possible to attach it again.
	 *
	 * Note: the segment *contents* are not checked after the re-attach:
	 * a detach/attach cycle preserves them on AIX, but aix-user does not
	 * keep a backing store for detached segments (see syscalls/shm.c).
	 * ================================================================*/
	if (shmdt(buff))
		errx(1, "Unable to shmdt: %d (%s)\n", errno, strerror(errno));

	printf(" -> Detach: [PASS]\n");

	buff = shmat(id, 0, 0);
	if (buff == (char*)-1)
		errx(1, "Failed: segment is gone after a shmdt: %d (%s)\n",
			errno, strerror(errno));

	printf(" -> Re-attach after detach: [PASS]\n");

	/* ================================================================
	 * Two segments at once: they must be independent from each other.
	 * ================================================================*/
	buff2 = create_and_attach(SEG_SIZE, &id2);
	if (id == id2)
		errx(1, "Failed: shmget returned a duplicated id: %d!\n", id);
	if (buff == buff2)
		errx(1, "Failed: both segments are attached at the same address!\n");

	fill_pattern(buff,  SEG_SIZE, 3);
	fill_pattern(buff2, SEG_SIZE, 4);

	if (!check_pattern(buff, SEG_SIZE, 3) || !check_pattern(buff2, SEG_SIZE, 4))
		errx(1, "Failed: segments are aliasing each other!\n");

	printf(" -> Multiple segments: [PASS]\n");

	/* ================================================================
	 * Removal.
	 * ================================================================*/
	if (shmdt(buff) || shmdt(buff2))
		errx(1, "Unable to shmdt: %d (%s)\n", errno, strerror(errno));

	if (shmctl(id, IPC_RMID, NULL) || shmctl(id2, IPC_RMID, NULL))
		errx(1, "Unable to shmctl: %d (%s)\n", errno, strerror(errno));

	printf(" -> Remove (IPC_RMID): [PASS]\n");

	/* ================================================================
	 * Invalid operations.
	 * ================================================================*/

	/* Attaching an already removed segment. */
	if (shmat(id, 0, 0) != (char*)-1)
		errx(1, "Failed: attached an already removed segment!\n");

	/* Removing it twice. */
	if (shmctl(id, IPC_RMID, NULL) != -1)
		errx(1, "Failed: removed the same segment twice!\n");

	/* Detaching an address that was never attached. */
	if (shmdt((char*)0x1234) != -1)
		errx(1, "Failed: detached a bogus address!\n");

	printf(" -> Invalid operations: [PASS]\n");
	return 0;
}
