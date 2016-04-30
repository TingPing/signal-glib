/* signal-storage.c
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

#include "signal-storage.h"
#include "signal-storage-private.h"

G_DEFINE_INTERFACE (SignalStorage, signal_storage, G_TYPE_OBJECT)

axolotl_store_context *
signal_storage_get_axolotl_store (SignalStorage *storage)
{
  return SIGNAL_STORAGE_GET_IFACE (storage)->get_axolotl_store (storage);
}

ratchet_identity_key_pair *
signal_storage_get_identity_key (SignalStorage *storage)
{
  return SIGNAL_STORAGE_GET_IFACE (storage)->get_identity_key (storage);
}

guint64
signal_storage_get_registration_id (SignalStorage *storage)
{
  return SIGNAL_STORAGE_GET_IFACE (storage)->get_registration_id (storage);
}

static void
signal_storage_default_init (SignalStorageInterface *iface)
{
}
