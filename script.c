/* Run script when a (*,G) group is matched and installed in the kernel
 *
 * Copyright (c) 2011-2017  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "mroute.h"

char *script_exec = NULL;

int run_script(struct mroute *mroute)
{
	int status;
	pid_t pid;

	char *argv[] = {
		script_exec,
		"reload",
		NULL,
	};

	if (!script_exec)
		return 0;

	if (mroute) {
		char source[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];

		if (mroute->version == 4) {
			inet_ntop(AF_INET, &mroute->u.mroute4.sender.s_addr, source, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &mroute->u.mroute4.group.s_addr, group, INET_ADDRSTRLEN);
		} else {
			inet_ntop(AF_INET6, &mroute->u.mroute6.sender.sin6_addr, source, INET_ADDRSTRLEN);
			inet_ntop(AF_INET6, &mroute->u.mroute6.group.sin6_addr, group, INET_ADDRSTRLEN);
		}

		setenv("source", source, 1);
		setenv("group", group, 1);
		argv[1] = "install";
	} else {
		unsetenv("source");
		unsetenv("group");
	}

	pid = fork();
	if (-1 == pid)
		return -1;
	if (0 == pid)
		_exit(execv(argv[0], argv));
	waitpid(pid, &status, 0);

	if (WIFEXITED(status))
		return 0;

	return WEXITSTATUS(status);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */

