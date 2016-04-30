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

  g_autoptr(SignalAddress) alices_address, bobs_address;

  alices_address = signal_address_new ("Alice", 0);
  bobs_address = signal_address_new ("Bob", 0);

  SignalSessionManager *a_mgr, *b_mgr;

  a_mgr = signal_identity_get_session_manager (alice);
  b_mgr = signal_identity_get_session_manager (bob);

  g_autoptr (GBytes) initial_message, response_message;

  initial_message = signal_session_manager_new_exchange (a_mgr, bobs_address);
  g_assert_nonnull (initial_message);
  response_message = signal_session_manager_new_response (b_mgr, initial_message,
                                                          alices_address, NULL);
  g_assert_nonnull (response_message);

  g_autoptr(SignalSession) alice_session = signal_session_manager_new_session (a_mgr, response_message, NULL);
  g_assert_nonnull (alice_session);
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
