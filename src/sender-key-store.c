/* sender-key-store.c
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

#define KEY_GROUP "senders"

#include "sender-key-store.h"
#include "key-utils.h"

static char *
sender_to_b64 (const axolotl_sender_key_name *sender_key_name)
{
  g_autofree char *data;
  int data_len;

  // We assume these are C strings
  data = g_strdup_printf ("%s%c%s%c%d%n",
                          sender_key_name->group_id, '\0',
                          sender_key_name->sender.name, '\0',
                          sender_key_name->sender.device_id,
                          &data_len);

  g_assert (data_len >= 0);
  return g_base64_encode ((uint8_t*)data, (size_t)data_len);
}

static int
store_sender_key (const axolotl_sender_key_name *sender_key_name,
                  uint8_t *record,
                  size_t record_len,
                  void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree char *key = sender_to_b64 (sender_key_name);

  key_file_set_data (file, KEY_GROUP, key, record, record_len);

  return AX_SUCCESS;
}

static int
load_sender_key (axolotl_buffer **record,
                 const axolotl_sender_key_name *sender_key_name,
                 void *user_data)
{
  GKeyFile *file = user_data;
  g_autofree char *key = sender_to_b64 (sender_key_name);
  size_t data_len;
  g_autofree uint8_t *data = key_file_get_data (file, KEY_GROUP, key, &data_len);

  if (!data)
    return 0;

  if ((*record = axolotl_buffer_create (data, data_len)))
    return 1;
  else
    return AX_ERR_NOMEM;
}

static void
destroy_func (void *user_data)
{
  g_key_file_unref (user_data);
}

axolotl_sender_key_store *
sg_sender_key_store_new (GKeyFile *keystore)
{
  axolotl_sender_key_store *store = g_new (axolotl_sender_key_store, 1);

  store->store_sender_key = store_sender_key;
  store->load_sender_key = load_sender_key;
  store->destroy_func = destroy_func;
  store->user_data = g_key_file_ref (keystore);

  return store;
}
