#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string>
#include <vector>

const size_t k_max_msg = 32 << 20;  // likely larger than the kernel buffer

static void msg(const char *msg) {
	fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
	int err = errno;
	fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static int32_t read_full(int fd, uint8_t *buf, size_t n) {
	while (n > 0) {
		ssize_t res = read(fd, buf, n);
		if (res <= 0) {
			return -1; // error or unexpected EOF
		}
		assert((size_t)res <= n);
		n -= (size_t)res;
		buf += res;
	}
	return 0;
}

static int32_t write_all(int fd, uint8_t *buf, size_t n) {
	while (n > 0) {
		ssize_t res = write(fd, buf, n); // we request to write n bytes, but in reality we might face a short count
		if (res <= 0) {
			return -1; // error
		}
		assert((size_t)res <= n);
		n -= (size_t)res;
		buf += res;
	}
	return 0;
}

// note: '&' in function parameter list doesn't mean address, rather it means that buf is an alias/reference for the buffer passed in
static void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len) {
	buf.insert(buf.end(), data, data + len);
}

static int32_t send_req(int fd, const uint8_t *text, size_t len) {
	if (len > k_max_msg) {
		return -1;
	}

	std::vector<uint8_t> wbuf;
	buf_append(wbuf, (const uint8_t *)&len, 4);
	buf_append(wbuf, text, len);
	return write_all(fd, wbuf.data(), wbuf.size());
}

static int32_t read_res(int fd) {
	// 4 byte header
	std::vector<uint8_t> rbuf;
	rbuf.resize(4);

	errno = 0;
	ssize_t err = read_full(fd, &rbuf[0], 4);
	if (err) {
		if (errno == 0) {
			msg("EOF");
		}
		else {
			msg("read() error");
		}
	}

	uint32_t len = 0;
	memcpy(&len, rbuf.data(), 4); // assuming little endian
	if (len > k_max_msg) {
		msg("too long");
		return -1;
	}

	// reply body
	rbuf.resize(4 + len);
	err = read_full(fd, &rbuf[4], len);
	if (err) {
		msg("read() error");
		return -1;
	}

	// do something

	printf("len:%u data:%.*s\n", len, len < 100 ? len : 100, &rbuf[4]);
	return 0;

}

int main() {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		die("socket()");
	}

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(1234);
	addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK); // 127.0.0.1

	int res = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (res) {
		die("connect");
	}

	// multiple pipelined requests
	std::vector<std::string> query_list = {
		"hello1", "hello2", "hello3",
		std::string(k_max_msg, 'z'), // a large message requires multiple event loop iterations
		"hello5"
	};
	for (const std::string &s : query_list) {
		int32_t err = send_req(fd, (uint8_t *)s.data(), s.size());
		if (err) {
			goto L_DONE;
		}
	}
	for (size_t i = 0; i < query_list.size(); i++) {
		int32_t err = read_res(fd);
		if (err) {
			goto L_DONE;
		}
	}

	L_DONE:
		close(fd);
		return 0;
}

