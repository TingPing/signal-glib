/* session-store.c
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

#define KEY_GROUP "sessions"

#include <string.h>
#include "session-store.h"
#include "key-utils.h"

static char *
address_to_key (const axolotl_address *address)
{
  // We assume these are C strings
  return g_strdup_printf ("%s%c%d",
                          address->name, ';',
                          address->device_id);
  // FIXME TODO: Properly escape addresses so they are all valid keys
}

static int
load_session_func (axolotl_buffer **record,
                   const axolotl_address *address,
                   void *user_data)
{
  GKeyFile *file = user_data;
  size_t data_len;
  g_autofree char *key = address_to_key (address);
  g_autofree uint8_t *data = key_file_get_data (file, KEY_GROUP, key, &data_len);

  if (!data)
    return 0;

  if ((*record = axolotl_buffer_create (data, data_len)))
    return 1;
  else
    return AX_ERR_NOMEM;
}

static int
get_sub_device_sessions_func (axolotl_int_list **sessions,
                              const char *name,
                              size_t name_len,
                              void *user_data)
{
  GKeyFile *file = user_data;
  size_t keys_len;
  int count = 0;
  g_auto(GStrv) keys = g_key_file_get_keys (file, KEY_GROUP, &keys_len, NULL);

  if (!keys)
    return 0;

  *sessions = axolotl_int_list_alloc ();
  if (!*sessions)
    return AX_ERR_NOMEM;

  for (size_t i = 0; i < keys_len; ++i)
    {
      // TODO: Choose more efficient solution?
      g_autofree char *sess = (char*)g_base64_decode (keys[i], NULL);

      if (!strcmp (name, sess))
        {
          int device_id = atoi (sess + name_len + 1);
          axolotl_int_list_push_back (*sessions, device_id);
          ++count;
        }
    }

  return count;
}

static int
store_session_func (const axolotl_address *address,
                    uint8_t *record,
                    size_t record_len,
                    void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree char *key = address_to_key (address);

  key_file_set_data (file, KEY_GROUP, key, record, record_len);
  return AX_SUCCESS;
}

static int
contains_session_func (const axolotl_address *address,
                       void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree char *key = address_to_key (address);

  return g_key_file_has_key (file, KEY_GROUP, key, NULL);
}

static int
delete_session_func (const axolotl_address *address,
                     void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree char *key = address_to_key (address);

  return g_key_file_remove_key (file, KEY_GROUP, key, NULL);
}

static int
delete_all_sessions_func (const char *name,
                          size_t name_len,
                          void *user_data)
{
  GKeyFile *file = user_data;
  size_t keys_len;
  int count = 0;
  g_auto(GStrv) keys = g_key_file_get_keys (file, KEY_GROUP, &keys_len, NULL);

  if (!keys)
    return 0;

  for (size_t i = 0; i < keys_len; ++i)
    {
      g_autofree char *sess = (char*)g_base64_decode (keys[i], NULL);

      if (!strcmp (name, sess))
        {
          g_key_file_remove_key (file, KEY_GROUP, keys[i], NULL);
          ++count;
        }
    }

  return count;
}

static void
destroy_func (void *user_data)
{
  g_key_file_unref (user_data);
}

axolotl_session_store *
sg_session_store_new (GKeyFile *keystore)
{
  axolotl_session_store *store = g_new (axolotl_session_store, 1);

  store->load_session_func = load_session_func;
  store->get_sub_device_sessions_func = get_sub_device_sessions_func;
  store->store_session_func = store_session_func;
  store->contains_session_func = contains_session_func;
  store->delete_session_func = delete_session_func;
  store->delete_all_sessions_func = delete_all_sessions_func;
  store->destroy_func = destroy_func;
  store->user_data = g_key_file_ref (keystore);

  return store;
}
