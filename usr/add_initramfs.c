// SPDX-License-Identifier: GPL-2.0
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <asm/bootparam.h>
#include <linux/pe.h>

static void
usage(const char *name, FILE * output)
{
	fprintf(output, "Usage:\n"
		"\t%s <kernel> <cpio_0> [... <cpio_N>]\n"
		"\n"
		"<kernel> is the kernel to append to.\n"
		"<cpio_N> is an initramfs to append.\n", name);
	exit(output == stderr ? 2 : 0);
}

struct file {
	char *data;
	size_t size;
};

static void
update_kernel_initrd_section(FILE * kernel, unsigned int size)
{

}

static void
append_initrds(FILE * kernel, struct file *initrds, int n_initrds)
{
	int pos;
	int pad = 0;
	uint8_t space = (uint8_t) ' ';

	pos = fseek(kernel, 0, SEEK_END);
	if (pos < 0)
		err(9, "fseek() failed");

	if (pos % 4096 != 0)
		pad = 4096 - (pos % 4096);

	while (pad--) {
		size_t sz;

		sz = fwrite(&space, 1, 1, kernel);
		if (sz != 1)
			err(10, "Could not write to kernel");
	}

	for (int i = 0; i < n_initrds; i++) {
		size_t sz;

		sz = fwrite(initrds[i].data, initrds[i].size, 1, kernel);
		if (sz != 1)
			err(11, "Could not write to kernel");
	}
}

static void
read_file(const char *const filename, struct file *file, int do_close)
{
	FILE *input;
	char *buf;
	int n = 0;

	input = fopen(filename, "r");
	if (!input)
		err(3, "Could not open initrd \"%s\"", filename);

	buf = calloc(1, 1024);
	if (!buf)
		err(4, "Could not allocate buffer");

	while (1) {
		size_t sz;
		char *newbuf;

		sz = fread(&buf[n * 1024], 1, 1024, input);
		if (sz < 1024 && feof(input)) {
			fclose(input);
			file->size = n * 1024 + sz;
			file->data = realloc(buf, file->size);
			if (!file->data)
				err(4, "Could not allocate buffer");
			break;
		}

		newbuf = reallocarray(buf, ++n, 1024);
		if (!newbuf)
			err(4, "Could not allocate buffer");
	}

	if (do_close)
		fclose(input);
}

int
main(int argc, char *argv[])
{
	struct file *initrds = NULL;
	char *kernelpath = NULL;
	int n_initrds = 0;
	unsigned int total_initrd_size = 0;
	off_t initrd_offset;
	FILE *kernel;

	struct option options[] = {
		{"kernel", 1, NULL, 'k'},
		{"initramfs", 1, NULL, 'i'},
		{"help", 1, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (1) {
		int opt = getopt_long(argc, argv, "k:i:", options, NULL);
		struct file *initrds_new;

		if (opt == -1)
			break;

		switch (opt) {
		case 'k':
			kernelpath = optarg;
			break;
		case 'i':
			initrds_new =
			    reallocarray(initrds, sizeof *initrds,
					 n_initrds + 1);
			if (!initrds_new)
				err(1, "Could not reallocate array");
			initrds = initrds_new;
			read_file(optarg, &initrds[n_initrds], 1);
			total_initrd_size += initrds[n_initrds].size;
			n_initrds++;
			break;
		case 'h':
		case '?':
			usage(argv[0], opt == 'h' ? stdout : stderr);
			break;
		}
	}

	if (kernelpath == NULL)
		errx(5, "kernel not specified");

	if (n_initrds == 0)
		errx(6, "initramfs not specified");

	if (total_initrd_size == 0)
		errx(7, "initrd size cannot be zero");

	total_initrd_size = ALIGN_UP(total_initrd_size, 4096);

	kernel = fopen(kernelpath, "r+");
	if (!kernel)
		err(8, "Could not open kernel \"%s\"", kernelpath);

	update_kernel_initrd_section(kernel, total_initrd_size);

	append_initrds(kernel, initrds, n_initrds);

	fflush(kernel);
	fclose(kernel);

	return 0;
}
