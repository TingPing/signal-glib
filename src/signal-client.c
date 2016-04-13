/* signal-client.c
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

#include <glib.h>
#include <axolotl/axolotl.h>

#include "crypto-provider.h"

static axolotl_context *global_ctx;
static GRecMutex global_ctx_mutex;

static void
unlock_ctx (void *user_data)
{
  g_rec_mutex_unlock (&global_ctx_mutex);
}

static void
lock_ctx (void *user_data)
{
  g_rec_mutex_lock (&global_ctx_mutex);
}

static inline int
ax_to_glib_loglevel (const int level)
{
  switch(level)
    {
    case AX_LOG_ERROR:
      return G_LOG_LEVEL_ERROR;
    case AX_LOG_WARNING:
      return G_LOG_LEVEL_WARNING;
    case AX_LOG_NOTICE:
      return G_LOG_LEVEL_MESSAGE;
    case AX_LOG_INFO:
      return G_LOG_LEVEL_INFO;
    case AX_LOG_DEBUG:
      return G_LOG_LEVEL_DEBUG;
    default:
      return G_LOG_LEVEL_DEBUG;
    }
}

static void
log_func (int level, const char *message, size_t len, void *user_data)
{
  g_log("SignalGlib", ax_to_glib_loglevel(level), "%s\n", message);
}

int
main(void)
{
  g_autofree axolotl_crypto_provider *provider = sg_crypto_provider_new ();

  axolotl_context_create (&global_ctx, NULL);
  axolotl_context_set_log_function (global_ctx, log_func);
  axolotl_context_set_crypto_provider (global_ctx, provider);
  g_assert(axolotl_context_set_locking_functions (global_ctx, lock_ctx, unlock_ctx) == 0);

  g_clear_pointer(&global_ctx, axolotl_context_destroy);
  return 0;
}
