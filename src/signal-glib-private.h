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

#include "signal-glib.h"

#include <axolotl.h>
#include <key_helper.h>
#include <session_builder.h>
#include <session_cipher.h>

#include "crypto-provider.h"
#include "identity-key-store.h"
#include "pre-key-store.h"
#include "signed-pre-key-store.h"
#include "sender-key-store.h"
#include "session-store.h"

#include "key-utils.h"

extern axolotl_context *global_ctx;
