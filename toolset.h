#ifndef _toolset_h
#define _toolset_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define CHUNK_SIZE 1024
int read_file(const char* file, char* buffer, int max_length) {
	int f = open(file, O_RDONLY);
	if (f == -1)
		return -1;
	int bytes_read = 0;
	while (true) {
		int bytes_to_read = CHUNK_SIZE;
		if (bytes_to_read > max_length - bytes_read)
			bytes_to_read = max_length - bytes_read;
		int rv = read(f, &buffer[bytes_read], bytes_to_read);
		if (rv == -1)
			return -1;
		bytes_read += rv;
		if (rv == 0)
			return bytes_read;
	}
}

static bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void raw_input() {
  int i;
  printf("> ");
  read(0, (char*)&i, 4);
}

#endif