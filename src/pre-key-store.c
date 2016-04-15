/* pre-key-store.c
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

#define KEY_GROUP "pre-keys"

#include "pre-key-store.h"
#include "key-utils.h"

static int
load_pre_key (axolotl_buffer **record, uint32_t pre_key_id, void *user_data)
{
  GKeyFile *file = user_data;
  char key[16];
  size_t data_len;
  g_autofree uint8_t *data;

  g_snprintf (key, sizeof(key), "%"G_GUINT32_FORMAT, pre_key_id);
  data = key_file_get_data (file, KEY_GROUP, key, &data_len);
  if (!data)
    return AX_ERR_INVALID_KEY_ID;

  if ((*record = axolotl_buffer_create (data, data_len)))
    return AX_SUCCESS;
  else
    return AX_ERR_NOMEM;
}

static int
store_pre_key (uint32_t pre_key_id,
               uint8_t *record,
               size_t record_len,
               void *user_data)
{
  GKeyFile *file = user_data;
  char key[16];

  g_snprintf (key, sizeof(key), "%"G_GUINT32_FORMAT, pre_key_id);
  key_file_set_data (file, KEY_GROUP, key, record, record_len);

  return AX_SUCCESS;
}

static int
contains_pre_key (uint32_t pre_key_id, void *user_data)
{
  GKeyFile *file = user_data;
  char key[16];

  g_snprintf (key, sizeof(key), "%"G_GUINT32_FORMAT, pre_key_id);
  return g_key_file_has_key (file, KEY_GROUP, key, NULL);
}

static int
remove_pre_key (uint32_t pre_key_id, void *user_data)
{
  GKeyFile *file = user_data;
  char key[16];

  g_snprintf (key, sizeof(key), "%"G_GUINT32_FORMAT, pre_key_id);
  if (!g_key_file_remove_key (file, KEY_GROUP, key, NULL))
    return AX_ERR_UNKNOWN; // TODO: Ignore non existant keys?

  return AX_SUCCESS;
}

static void
destroy_func (void *user_data)
{
  g_key_file_unref (user_data);
}

axolotl_pre_key_store *
sg_pre_key_store_new (GKeyFile *keystore)
{
  axolotl_pre_key_store *store = g_new (axolotl_pre_key_store, 1);

  store->load_pre_key = load_pre_key;
  store->store_pre_key = store_pre_key;
  store->contains_pre_key = contains_pre_key;
  store->remove_pre_key = remove_pre_key;
  store->destroy_func = destroy_func;
  store->user_data = g_key_file_ref (keystore);

  return store;
}
