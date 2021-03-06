/* signal-glib.h
 *
 * Copyright (C) 2016 Patrick Griffis <tingping@tingping.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "signal-address.h"
#include "signal-identity.h"
#include "signal-session.h"
#include "signal-session-manager.h"
#include "signal-storage.h"
#include "signal-storage-keyfile.h"

G_BEGIN_DECLS

void signal_init (void);
void signal_deinit (void);

G_END_DECLS
