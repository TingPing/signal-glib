/* signal-address.h
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

#include <glib-object.h>

G_BEGIN_DECLS

typedef struct
{
  char *name;
  gint32 device_id;
} SignalAddress;


#define SIGNAL_TYPE_ADDRESS (signal_address_get_type())
GType          signal_address_get_type (void) G_GNUC_CONST;

SignalAddress *signal_address_new (const char *name,
                                   gint32      device_id);

SignalAddress *signal_address_copy (SignalAddress *address);

void           signal_address_free (SignalAddress *address);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(SignalAddress, signal_address_free)

G_END_DECLS
