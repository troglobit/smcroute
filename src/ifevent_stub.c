/* No-op fallback for platforms without a kernel link-event listener.
 *
 * Reload-driven activation (SIGHUP / `smcroutectl reload`) and the
 * `-d SEC` startup delay remain the recommended workaround on these
 * platforms.  A BSD route-socket equivalent is tracked separately.
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "ifevent.h"

void ifevent_init(void) { }
void ifevent_exit(void) { }

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
