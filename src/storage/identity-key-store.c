/* identity-key-store.c
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

#define LOCAL_KEY_GROUP "identity"
#define REMOTE_KEY_GROUP "remote-identities"

#include "identity-key-store.h"
#include "key-utils.h"

extern axolotl_context *global_ctx;

static int
get_identity_key_pair (axolotl_buffer **public_data,
                       axolotl_buffer **private_data,
                       void            *user_data)
{
  GKeyFile *file = user_data;
  ratchet_identity_key_pair *identity_key_pair;
  ec_public_key *pub_key;
  ec_private_key *priv_key;
  size_t data_len;
  g_autofree uint8_t *data;

  data = key_file_get_data (file, LOCAL_KEY_GROUP, "key-pair", &data_len);
  if (!data)
    {
      g_debug ("Failed to get identity key pair");
      return -77; // Random number..
    }

  if (ratchet_identity_key_pair_deserialize (&identity_key_pair, data, data_len, global_ctx))
    {
      g_warning ("Failed to deserialize identity key pair");
      return AX_ERR_UNKNOWN;
    }

  pub_key = ratchet_identity_key_pair_get_public (identity_key_pair);
  priv_key = ratchet_identity_key_pair_get_private (identity_key_pair);

  // Leaving them unset is not fatal
  ec_public_key_serialize (public_data, pub_key);
  ec_private_key_serialize (private_data, priv_key);

  return AX_SUCCESS;
}

static int
get_local_registration_id (void     *user_data,
                           uint32_t *registration_id)
{
  GKeyFile *file = user_data;
  uint64_t id = g_key_file_get_uint64 (file, LOCAL_KEY_GROUP, "registration-id", NULL);

  if (id == 0 || id > 16380)
    {
      g_warning("invalid registration id number found");
      return AX_ERR_UNKNOWN;
    }

  *registration_id = (uint32_t)id;
  return AX_SUCCESS;
}

static int
save_identity (const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
{
  GKeyFile *file = user_data;

  if (key_data == NULL)
    {
      if (!g_key_file_remove_key (file, REMOTE_KEY_GROUP, name, NULL))
        {
          g_warning ("Failed to remove identity %s", name);
          return AX_ERR_UNKNOWN;
        }
      return AX_SUCCESS;
    }

  // TODO: Verify `name` is a valid key name
  key_file_set_data (file, REMOTE_KEY_GROUP, name, key_data, key_len);
  return AX_SUCCESS;
}


extern int axolotl_constant_memcmp(const void *s1, const void *s2, size_t n);

static int
is_trusted_identity (const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree uint8_t *data = NULL;
  size_t data_len;
  g_autoptr(GError) err = NULL;

  // Trust on first use
  if (!g_key_file_has_key (file, REMOTE_KEY_GROUP, name, &err) &&
      (err == NULL || err->code == G_KEY_FILE_ERROR_GROUP_NOT_FOUND))
    {
      g_info ("First use of identiy %s, trusting", name);
      key_file_set_data (file, REMOTE_KEY_GROUP, name, key_data, key_len);
      return 1;
    }
  else if (err)
    {
      g_warning("Error checking for key: %s", err->message);
      return AX_ERR_UNKNOWN;
    }

  data = key_file_get_data (file, REMOTE_KEY_GROUP, name, &data_len);
  if (!data)
    return AX_ERR_UNKNOWN;

  return axolotl_constant_memcmp (key_data, data, key_len) == 0;
}

static void
destroy_func (void *user_data)
{
  g_key_file_unref (user_data);
}

axolotl_identity_key_store *
sg_identity_key_store_new (GKeyFile *keystore)
{
  axolotl_identity_key_store *store = g_new (axolotl_identity_key_store, 1);

  store->get_identity_key_pair = get_identity_key_pair;
  store->get_local_registration_id = get_local_registration_id;
  store->save_identity = save_identity;
  store->is_trusted_identity = is_trusted_identity;
  store->destroy_func = destroy_func;
  store->user_data = g_key_file_ref (keystore);

  return store;
}
