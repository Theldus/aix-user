/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unicorn/unicorn.h>

#include "gdb.h"

/* GDB handle states. */
#define GDB_STATE_START   0x1
#define GDB_STATE_CMD     0x2
#define GDB_STATE_CSUM_D1 0x4
#define GDB_STATE_CSUM_D2 0x8

/* Single-step hook. */
static uc_hook ss;

/* aix-user gdb stub. */
static int sv_fd;
static int cl_fd = -1;

/* The registers are cached, so this flag signals
 * if the cache is updated or not. */
static int have_ppc_regs = 0;

/* Memory dump helpers. */
static uint8_t *dump_buffer;

/*
 * Keeps all the variables for the GDB state machine here
 */
struct gdb_handle
{
	int  state;
	int  csum;
	int  cmd_idx;
	char buff[32];
	char csum_read[3];
	char cmd_buff[512];
} gdb_handle = {
	.state = GDB_STATE_START
};

/**
 * @brief Write @p len bytes from @p buf to @p conn.
 *
 * Contrary to send(2)/write(2) that might return with
 * less bytes written than specified, this function
 * attempts to write the entire buffer, because...
 * thats the most logical thing to do...
 *
 * @param conn Target file descriptor.
 * @param buf Buffer to be sent.
 * @param len Amount of bytes to be sent.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
ssize_t send_all(
	int conn, const void *buf, size_t len)
{
	const char *p;
	ssize_t ret;

	if (conn < 0)
		return (-1);

	p = buf;
	while (len)
	{
		ret = write(conn, p, len);
		if (ret == -1)
			return (-1);
		p += ret;
		len -= ret;
	}
	return (0);
}

/**
 * @brief Configure a TCP server to listen to the
 * specified port @p port.
 *
 * @param srv_fd Returned server fd.
 * @param port Port to listen.
 */
void setup_server(int *srv_fd, uint16_t port)
{
	struct sockaddr_in server;
	int reuse = 1;

	*srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*srv_fd < 0)
		errx(1, "Unable to open socket!\n");

	setsockopt(*srv_fd, SOL_SOCKET, SO_REUSEADDR,
		(const char *)&reuse, sizeof(reuse));

	/* Prepare the sockaddr_in structure. */
	memset((void*)&server, 0, sizeof(server));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);

	/* Bind. */
	if (bind(*srv_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
		errx(1, "Bind failed");

	/* Listen. */
	listen(*srv_fd, 1);
}

/* ------------------------------------------------------------------*
 * MISC                                                              *
 * ------------------------------------------------------------------*/
/**
 * Global buffer, responsible to handle dynamic allocations
 * from/to GDB messages.
 */
static char  *gbuffer      = NULL;
static size_t gbuffer_size = 0;

/**
 * @brief Increase the global buffer size to a new value
 * if needed.
 *
 * @param new_size New buffer size.
 */
static void increase_buffer(size_t new_size)
{
	char *tmp;
	if (gbuffer_size < new_size) {
		tmp = realloc(gbuffer, new_size);
		if (!tmp)
			errx(1, "Unable to allocate %zu bytes!\n", new_size);
		gbuffer = tmp;
		gbuffer_size = new_size;
	}
}

/**
 * @brief For a given nibble, to converts to its
 * ascii representative form, ie: 10 -> a.
 *
 * @param nibble Nibble input value to be converted.
 *
 * @return Returns the converted value.
 */
static inline char to_digit(int nibble) {
	static const char digits[] = "0123456789abcdef";
	return (digits[nibble]);
}

/**
 * @brief For a given nibble (in its char form),
 * convert to the decimal representation, i.e:
 * 'b' -> 11.
 *
 * @param ch Char nibble to be converted.
 *
 * @return Returns the converted value.
 */
static inline int to_value(int ch)
{
	int c = tolower(ch);

	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'a' && c <= 'f')
		return (0xA + c - 'a');
	else
		return (-1);
}

/**
 * @brief Encodes a binary data inside @p data to its representative form in
 * ascii hex value.
 *
 * @param data Data to be encoded in ascii-hex form.
 * @param len  Length of @p data.
 *
 * @return Returns a buffer containing the encoded buffer.
 *
 * @note Please note that the size of the output
 * buffer is twice bigger than the input buffer.
 */
char *encode_hex(const char *data, size_t len)
{
	char *tmp;
	size_t i;

	increase_buffer(len * 2);
	for (i = 0, tmp = gbuffer; i < len; i++) {
		*tmp++ = to_digit((data[i] >> 4) & 0xF);
		*tmp++ = to_digit((data[i]     ) & 0xF);
	}
	return (gbuffer);
}

/**
 * @brief Converts an input buffer containing an ascii hex-value representation
 * into the equivalent binary form.
 *
 * @param data Input buffer to be decoded to binary.
 * @param len  Input buffer length.
 *
 * @return Returns the buffer containing the binary representation of the data.
 */
char *decode_hex(const char *data, size_t len)
{
	char *ptr;
	size_t i;

	increase_buffer(len);
	for (i = 0, ptr = gbuffer; i < len * 2; i += 2, ptr++) {
		*ptr =  to_value(data[i]);
		*ptr <<= 4;
		*ptr |= to_value(data[i+1]);
	}
	return (gbuffer);
}

/* ------------------------------------------------------------------*
 * GDB commands                                                      *
 * ------------------------------------------------------------------*/

/**
 * @brief Send a GDB command/packet in the format:
 * $data#NN, where NN is the checksum modulo 256.
 *
 * All GDB commands follows the same structure.
 *
 * @param buff Buffer containing the data to be
 * sent.
 * @param len Buffer length.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static ssize_t send_gdb_cmd(const char *buff, size_t len)
{
	size_t i;
	int csum;
	ssize_t ret;
	char csum_str[3];

	/* Calculate checksum. */
	for (i = 0, csum = 0; i < len; i++)
		csum += buff[i];
	csum &= 0xFF;

	send_all(cl_fd, "$", 1);
	send_all(cl_fd, buff, len);
	send_all(cl_fd, "#", 1);
	snprintf(csum_str, 3, "%02x", csum);
	ret = send_all(cl_fd, csum_str, 2);

	if (ret < 0)
		errx(1, "Unable to send command to GDB!\n");

	return (0);
}

/**
 * @brief Acks a previous message/packet sent from GDB
 */
static inline void send_gdb_ack(void) {
	send_all(cl_fd, "+", 1);
}

/**
 * @brief Tells GDB that we do not support the
 * receive message/packet.
 */
static inline void send_gdb_unsupported_msg(void) {
	send_gdb_cmd(NULL, 0);
}

/**
 * @brief Confirms that the previous command was
 * successfully executed.
 *
 * The 'OK' command is generally sent by the serial,
 * and then forwarded to GDB, as the serial device is
 * the only one that knows if the command succeeded
 * or not.
 */
static inline void send_gdb_ok(void) {
	send_gdb_cmd("OK", 2);
}

/**
 * @brief Tells GDB that something went wrong with
 * the latest command.
 */
static inline void send_gdb_error(void) {
	send_gdb_cmd("E00", 3);
}

/**
 * @brief Send the halt reason to GDB.
 */
static inline void send_gdb_halt_reason(void) {
	send_gdb_cmd("S05", 3);
}

/**/
static const int regs_to_be_read[] = {
	UC_PPC_REG_0,  UC_PPC_REG_1,  UC_PPC_REG_2,   UC_PPC_REG_3,
	UC_PPC_REG_4,  UC_PPC_REG_5,  UC_PPC_REG_6,   UC_PPC_REG_7,
	UC_PPC_REG_8,  UC_PPC_REG_9,  UC_PPC_REG_10,  UC_PPC_REG_11,
	UC_PPC_REG_12, UC_PPC_REG_13, UC_PPC_REG_14,  UC_PPC_REG_15,
   	UC_PPC_REG_16, UC_PPC_REG_17, UC_PPC_REG_18,  UC_PPC_REG_19,
   	UC_PPC_REG_20, UC_PPC_REG_21, UC_PPC_REG_22,  UC_PPC_REG_23,
	UC_PPC_REG_24, UC_PPC_REG_25, UC_PPC_REG_26,  UC_PPC_REG_27,
	UC_PPC_REG_28, UC_PPC_REG_29, UC_PPC_REG_30,  UC_PPC_REG_31,
	UC_PPC_REG_PC,
	UC_PPC_REG_MSR,
	UC_PPC_REG_CR,
	UC_PPC_REG_LR,
	UC_PPC_REG_CTR,
	UC_PPC_REG_XER
};
#define PPC_REGS_AMNT (sizeof(regs_to_be_read)/sizeof(int))
union ppc_regs {
	u32 u32_vals[PPC_REGS_AMNT];
	u8   u8_vals[PPC_REGS_AMNT*4];
} ppcregs = {0};

/**
 * @brief Handle he 'read registers (g)' command from GDB.
 *
 * @param uc Unicorn engine context.
 */
static void handle_gdb_read_registers(uc_engine *uc)
{
	void *ptr_vals[PPC_REGS_AMNT] = {0};
	char *buff;
	int   i;

	for (i = 0; i < PPC_REGS_AMNT; i++)
		ptr_vals[i] = &ppcregs.u32_vals[i];

	if (uc_reg_read_batch(uc, regs_to_be_read, ptr_vals, PPC_REGS_AMNT) < 0) {
		warn("Unable to read GPRs...\n");
		return;
	}

	printf("Regs:\n");
	for (i = 0; i < PPC_REGS_AMNT; i++)
		printf("r%02d: %08x\n", i, ppcregs.u32_vals[i]);

	/* Convert registers to big-endian for GDB. */
	for (i = 0; i < PPC_REGS_AMNT; i++)
		ppcregs.u32_vals[i] = htonl(ppcregs.u32_vals[i]);

	buff = encode_hex((const char*) ppcregs.u8_vals, sizeof ppcregs);
	send_gdb_cmd(buff, sizeof(ppcregs) * 2);
}

/**
 * @brief Handles the 'read memory (m)' command from GDB.
 *
 * @param uc   Unicorn engine context.
 * @param buff Message buffer to be parsed.
 * @param len  Buffer length.
 *
 * @return Returns 0 if the request is valid, -1 otherwise.
 *
 * @note Please note that the actual memory read is
 * done by the serial device. This routine only parses
 * the command and forward the request to the serial
 * device.
 */
static int handle_gdb_read_memory(uc_engine *uc, const char *mbuff, size_t len)
{
	static u8 *dump_buffer;
	uint32_t addr, amnt;
	const char *ptr;
	char *dump_buff;
	char *hexa_buff;

	ptr = mbuff;

	/* Skip first 'm'. */
	expect_char('m', ptr, len);
	addr = read_int(ptr, &len, &ptr, 16);
	expect_char(',', ptr, len);

	/* Get amount. */
	amnt = simple_read_int(ptr, len, 16);

	/* */
	dump_buff = malloc(amnt);
	if (!dump_buff)
		errx(1, "GDBStub: Unable to alloc %u bytes!\n", amnt);

	if (uc_mem_read(uc, addr, dump_buff, amnt)) {
		warn("Unable to read from VM memory: %x\n", addr);
		free(dump_buff);
		return -1;
	}

	hexa_buff = encode_hex(dump_buff, amnt);
	send_gdb_cmd(hexa_buff, amnt * 2);
	free(dump_buff);

	return 0;
}

/**
 * @brief Handle GDB query packets (commands starting with 'q').
 *
 * @param uc       Unicorn engine context.
 * @param cmd_buff Command buffer to parse.
 * @param len      Command buffer length.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int handle_gdb_query_packets(uc_engine *uc, const char *cmd_buff,
	size_t len)
{
	uint32_t offset, length, chunk_size;
	char *response_buff;
	const char *ptr;
	size_t xml_size;

	/* Handle 'qSupported' - advertise our capabilities. */
	if (strncmp(cmd_buff, "qSupported", 10) == 0) {
		send_gdb_cmd("qXfer:features:read+", 20);
		return 0;
	}

	/* Handle 'qXfer:features:read:target.xml:offset,length'. */
	if (strncmp(cmd_buff, "qXfer:features:read:target.xml:", 31) == 0) {
		ptr = cmd_buff + 31;
		len -= 31;

		/* Parse offset. */
		offset = read_int(ptr, &len, &ptr, 16);
		expect_char(',', ptr, len);

		/* Parse length. */
		length = simple_read_int(ptr, len, 16);

		/* Calculate chunk size. */
		xml_size = sizeof(gdb_target_xml) - 1;
		if (offset >= xml_size) {
			send_gdb_error();
			return -1;
		}

		chunk_size = MIN(length, xml_size - offset);

		/* Allocate response buffer: 'm'/'l' prefix + chunk. */
		response_buff = malloc(chunk_size + 1);
		if (!response_buff)
			errx(1, "GDBStub: Unable to alloc %u bytes!\n", chunk_size + 1);

		/* Build response: 'm' for more data, 'l' for last chunk. */
		if (offset + chunk_size < xml_size)
			response_buff[0] = 'm';
		else
			response_buff[0] = 'l';

		/* Copy XML chunk. */
		memcpy(response_buff + 1, gdb_target_xml + offset, chunk_size);

		/* Send via standard function. */
		send_gdb_cmd(response_buff, chunk_size + 1);
		free(response_buff);
		return 0;
	}

	/* Unsupported query. */
	send_gdb_unsupported_msg();
	return 0;
}

/**
 * @brief Generic handler for all GDB commands/packets.
 *
 * This routine handles all messages and dispatches each
 * of them for the appropriated handler, if any. If not
 * supported, a not-supported packet is sent to GDB.
 *
 * @param uc   Unicorn engine context.
 * @param gh   GDB state machine data.
 * @param cont If <> 0, signals that the execution should proceed.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int handle_gdb_cmd(uc_engine *uc, struct gdb_handle *gh, int *cont)
{
	int csum_chk;

	if (!cont)
		return -1;

	*cont    = 0;
	csum_chk = (int) simple_read_int(gh->csum_read, 2, 16);
	if (csum_chk != gh->csum)
		warn("Checksum for message: %s (%d) doesn't match: %d!\n",
			gh->cmd_buff, csum_chk, gh->csum);

	/* Ack received message. */
	send_gdb_ack();

	/* Handle single-char messages. */
	switch (gh->cmd_buff[0]) {
	/* Read registers. */
	case 'g':
		handle_gdb_read_registers(uc);
		break;
	/* Read memory. */
	case 'm':
		handle_gdb_read_memory(uc, gh->cmd_buff, sizeof gh->cmd_buff);
		break;
	/* Halt reason. */
	case '?':
		send_gdb_halt_reason();
		break;
	/* Query packets. */
	case 'q':
		handle_gdb_query_packets(uc, gh->cmd_buff, sizeof gh->cmd_buff);
		break;
	/* Not-supported messages. */
	default:
		send_gdb_unsupported_msg();
		break;
	}
}

/* ------------------------------------------------------------------*
 * GDB handling state machine                                        *
 * ------------------------------------------------------------------*/

/**
 * @brief Handle the start of state for a GDB command.
 *
 * If any non-valid start of command is received, the char
 * is silently ignored.
 *
 * @param gh GDB state machine data.
 * @param curr_byte Current byte read.
 */
static void handle_gdb_state_start(struct gdb_handle *gh,
	uint8_t curr_byte)
{
	/*
	 * If Ctrl+C.
	 *
	 * Ctrl+C/break is a special command that doesn't need
	 * to be ack'ed nor anything
	 */
	if (curr_byte == 3)
		return;

	/* Skip any char before a start of command. */
	if (curr_byte != '$')
		return;

	gh->state   = GDB_STATE_CMD;
	memset(gh->cmd_buff, 0, sizeof gh->cmd_buff);
	gh->csum    = 0;
	gh->cmd_idx = 0;
}

/**
 * @brief Handle the receipt of the first checksum digit.
 *
 * @param gh GDB state machine data.
 * @param curr_byte Current byte read.
 */
static inline void handle_gdb_state_csum_d1(struct gdb_handle *gh,
	uint8_t curr_byte)
{
	gh->csum_read[0] = curr_byte;
	gh->state = GDB_STATE_CSUM_D2;
}

/**
 * @brief Handle the receipt of the last checksum digit.
 *
 * This also marks the end of the command, so the command in this stage is
 * completely received and ready to be parsed.
 *
 * @param uc        Unicorn engine context.
 * @param gh        GDB state machine data.
 * @param curr_byte Current byte read.
 * @param cont      Signals if execution should continue or not.
 */
static
inline void handle_gdb_state_csum_d2(uc_engine *uc, struct gdb_handle *gh,
	uint8_t curr_byte, int *cont)
{
	gh->csum_read[1] = curr_byte;
	gh->state        = GDB_STATE_START;
	gh->csum        &= 0xFF;

	/* Handles the command. */
	handle_gdb_cmd(uc, gh, cont);

	LOG_CMD_REC("Command: (%s), csum: %x, csum_read: %s\n",
		gh->cmd_buff, gh->csum, gh->csum_read);
}

/**
 * @brief Handle the command data.
 *
 * While already received a command, this routine saves its content until the
 * marker of end-of-command (#).
 *
 * @param gh GDB state machine data.
 * @param curr_byte Current byte read.
 */
static
inline void handle_gdb_state_cmd(struct gdb_handle *gh, uint8_t curr_byte)
{
	if (curr_byte == '#') {
		gh->state = GDB_STATE_CSUM_D1;
		return;
	}
	gh->csum += curr_byte;

	/* Emit a warning if command exceeds buffer size. */
	if ((size_t)gh->cmd_idx > sizeof gh->cmd_buff - 2)
		errx(1, "Command exceeds buffer size (%zu): %s\n",
			sizeof gh->cmd_buff, gh->cmd_buff);

	gh->cmd_buff[gh->cmd_idx++] = curr_byte;
}

/**
 * @brief For each byte received, calls the appropriate handler, accordingly
 * with the byte and the current state.
 *
 * @param uc   Unicorn engine context.
 * @param addr GDB message bufer.
 * @param size GDB message buffer size.
 * @param cont Signals if execution should continue or not.
 */
void handle_gdb_msg(uc_engine *uc, uint32_t addr, uint32_t size, int *cont)
{
	int i;
	ssize_t ret;
	uint8_t curr_byte;

	ret = recv(cl_fd, gdb_handle.buff, sizeof gdb_handle.buff, 0);
	if (ret <= 0)
		errx(1, "GDB closed!\n");

	for (i = 0; i < ret; i++) {
		curr_byte = gdb_handle.buff[i] & 0xFF;

		switch (gdb_handle.state) {
		/* Decide which state to go. */
		case GDB_STATE_START:
			handle_gdb_state_start(&gdb_handle, curr_byte);
			break;
		/* First digit checksum. */
		case GDB_STATE_CSUM_D1:
			handle_gdb_state_csum_d1(&gdb_handle, curr_byte);
			break;
		/* Second digit checsum. */
		case GDB_STATE_CSUM_D2:
			handle_gdb_state_csum_d2(uc, &gdb_handle, curr_byte, cont);
			break;
		/* Inside a command. */
		case GDB_STATE_CMD:
			handle_gdb_state_cmd(&gdb_handle, curr_byte);
			break;
		}
	}
}

/**
 *
 */
static void single_step(uc_engine *uc, uint32_t addr, uint32_t size,
	void *user_data)
{
	int cont = 0;
	fprintf(stderr, "Inside-GDB single-step!!: %x\n", addr);
	
	while (!cont) {
		if (cl_fd < 0) {
			cl_fd = accept(sv_fd, NULL, NULL);
			if (cl_fd < 0)
				errx(1, "Failed to accept client connection!\n");
		}
		else {
			handle_gdb_msg(uc, addr, size, &cont);
		}
	}
}

/**
 *
 */
int gdb_init(uc_engine *uc, u16 port)
{
	setup_server(&sv_fd, port);

	/*
	 * Enable single-step, i.e.: add a hook code for the entire 4GiB.
	 * so our handler stop at each instruction.
	 */
	if (uc_hook_add(uc, &ss, UC_HOOK_CODE, single_step, NULL, 0, (1ULL<<32)-1))
		return -1;

	return 0;
}
