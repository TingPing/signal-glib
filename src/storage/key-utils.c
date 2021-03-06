/* key-utils.c
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

#include "key-utils.h"

uint8_t *
key_file_get_data (GKeyFile *file, const char *group, const char *key, size_t *out_len)
{
  g_autofree char *data = g_key_file_get_value (file, group, key, NULL);
  return data ? g_base64_decode (data, out_len) : NULL;
}

void
key_file_set_data (GKeyFile *file, const char *group, const char *key, const uint8_t *data, size_t data_len)
{
  g_autofree char *value = g_base64_encode (data, data_len);
  g_key_file_set_value (file, group, key, value);
}

