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

#include <string.h>
#include <glib.h>
#include <axolotl/axolotl.h>
#include <axolotl/key_helper.h>
#include <time.h>

#include "crypto-provider.h"
#include "identity-key-store.h"

axolotl_context *global_ctx;
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
  g_log(G_LOG_DOMAIN, ax_to_glib_loglevel(level), "%s", message);
}

static void
generate_keys (ratchet_identity_key_pair **identity_key_pair,
          uint32_t *registration_id)
{
  axolotl_key_helper_pre_key_list_node *pre_keys_head;
  session_pre_key *last_resort_key;
  session_signed_pre_key *signed_pre_key;

  g_info("Generating identity key pair");
  g_assert(axolotl_key_helper_generate_identity_key_pair(identity_key_pair, global_ctx) == 0);
  g_assert(axolotl_key_helper_generate_registration_id(registration_id, 0, global_ctx) == 0);
  g_assert(axolotl_key_helper_generate_pre_keys(&pre_keys_head, 0, 100, global_ctx) == 0);
  g_assert(axolotl_key_helper_generate_last_resort_pre_key(&last_resort_key, global_ctx) == 0);
  g_info("Signing pre key");
  g_assert(axolotl_key_helper_generate_signed_pre_key(&signed_pre_key, *identity_key_pair, 5, (uint64_t)time(NULL), global_ctx) == 0);

  /* Store identity_key_pair somewhere durable and safe. */
  /* Store registration_id somewhere durable and safe. */

  /* Store pre keys in the pre key store. */
  /* Store signed pre key in the signed pre key store. */
}



int
main(void)
{
  g_autofree axolotl_crypto_provider *provider = sg_crypto_provider_new ();
  g_autoptr(GKeyFile) keystore = g_key_file_new ();

  g_info("Creating context");
  axolotl_context_create (&global_ctx, NULL);
  axolotl_context_set_log_function (global_ctx, log_func);
  axolotl_context_set_crypto_provider (global_ctx, provider);
  g_assert(axolotl_context_set_locking_functions (global_ctx, lock_ctx, unlock_ctx) == 0);

  if (!g_key_file_load_from_file (keystore, "keys.ini", G_KEY_FILE_NONE, NULL))
    g_debug("Failed to load keys.ini");

#if 0
  if (identity_key_pair == NULL)
    {
      axolotl_buffer *key_buffer;
      generate_keys (&identity_key_pair, &registration_id);
      g_key_file_set_uint64 (keystore, "identity", "registration-id", registration_id);
      g_assert(ratchet_identity_key_pair_serialize (&key_buffer, identity_key_pair) == 0);
      key_file_set_data (keystore, "identity", "key-pair", axolotl_buffer_data(key_buffer), axolotl_buffer_len(key_buffer));
      axolotl_buffer_free (key_buffer);
    }
#endif

  axolotl_store_context *store_ctx;
  g_autofree axolotl_identity_key_store *identity_store = sg_identity_key_store_new (keystore);
  g_assert (axolotl_store_context_create (&store_ctx, global_ctx) == 0);
  g_assert (axolotl_store_context_set_identity_key_store (store_ctx, identity_store) == 0);

  if (!g_key_file_save_to_file (keystore, "keys.ini", NULL))
    g_debug("Failed to save keys.ini");

  g_clear_pointer(&store_ctx, axolotl_store_context_destroy);
  g_clear_pointer(&global_ctx, axolotl_context_destroy);
  return 0;
}
