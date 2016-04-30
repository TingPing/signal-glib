/* signal-address.c
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

#include "signal-address.h"

G_DEFINE_BOXED_TYPE (SignalAddress, signal_address, signal_address_copy, signal_address_free)

SignalAddress *
signal_address_new (const char *name,
                    gint32      device_id)
{
  SignalAddress *addr = g_new (SignalAddress, 1);
  addr->name = g_strdup (name);
  addr->device_id = device_id;
  return addr;
}

SignalAddress *
signal_address_copy (SignalAddress *address)
{
  g_return_val_if_fail (address != NULL, NULL);

  return signal_address_new (address->name, address->device_id);
}

void
signal_address_free (SignalAddress *address)
{
  if (address)
    {
      g_free (address->name);
      g_free (address);
    }
}
