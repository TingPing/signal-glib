/* test-client.c
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
#include "signal-glib.h"

static void
test_client (void)
{
  g_autoptr (SignalIdentity) alice, bob;

  alice = signal_identity_new_from_file ("keys-1.ini");
  bob = signal_identity_new_from_file ("keys-2.ini");
  g_assert_nonnull (alice);
  g_assert_nonnull (bob);
}

int
main (int    argc,
      char **argv)
{
  int ret;

  g_test_init (&argc, &argv, NULL);
  signal_init ();

  g_test_add_func ("/signal/client", test_client);

  ret = g_test_run ();

  signal_deinit ();
  return ret;
}
