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
#include "signal-glib-private.h"

static void
new_keys (axolotl_store_context *store_ctx,
          ratchet_identity_key_pair **identity_key_pair,
          uint32_t *registration_id)
{

  axolotl_key_helper_pre_key_list_node *pre_keys_head, *node;
  session_pre_key *last_resort_key;
  session_pre_key *pre_key;
  session_signed_pre_key *signed_pre_key;
  int ret;

  g_info("Generating identity key pair");
  ret = axolotl_key_helper_generate_identity_key_pair(identity_key_pair, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_key_helper_generate_registration_id(registration_id, 0, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_key_helper_generate_pre_keys(&pre_keys_head, 0, 100, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_key_helper_generate_last_resort_pre_key(&last_resort_key, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  g_info("Signing pre key");
  // FIXME: Time
  ret = axolotl_key_helper_generate_signed_pre_key(&signed_pre_key, *identity_key_pair, 1,
                                                   (uint64_t)time(NULL), global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = axolotl_signed_pre_key_store_key (store_ctx, signed_pre_key);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  // TODO: last resort
  node = pre_keys_head;
  while (node && (pre_key = axolotl_key_helper_key_list_element (node)))
    {
      ret = axolotl_pre_key_store_key (store_ctx, pre_key);
      g_assert_cmpint (ret, ==, AX_SUCCESS);
      node = axolotl_key_helper_key_list_next (node);
    }
  axolotl_key_helper_key_list_free (pre_keys_head);
}

static axolotl_store_context *
new_store (const char *filename)
{
  axolotl_store_context *store_ctx;
  int ret;
  g_autoptr(GKeyFile) keystore = g_key_file_new ();
  g_autofree axolotl_identity_key_store *identity_store = sg_identity_key_store_new (keystore);
  g_autofree axolotl_pre_key_store *pre_key_store = sg_pre_key_store_new (keystore);
  g_autofree axolotl_signed_pre_key_store *signed_pre_key_store = sg_signed_pre_key_store_new (keystore);
  g_autofree axolotl_sender_key_store *sender_key_store = sg_sender_key_store_new (keystore);
  g_autofree axolotl_session_store *session_store = sg_session_store_new (keystore);
  ret = axolotl_store_context_create (&store_ctx, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_identity_key_store (store_ctx, identity_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_pre_key_store (store_ctx, pre_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_signed_pre_key_store (store_ctx, signed_pre_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_sender_key_store (store_ctx, sender_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_session_store (store_ctx, session_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ratchet_identity_key_pair *identity_key_pair;
  uint32_t registration_id;
  axolotl_buffer *data;

  new_keys (store_ctx, &identity_key_pair, &registration_id);
  g_key_file_set_uint64 (keystore, "identity", "registration-id", registration_id);
  ret = ratchet_identity_key_pair_serialize (&data, identity_key_pair);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  key_file_set_data (keystore, "identity", "key-pair", axolotl_buffer_data (data), axolotl_buffer_len (data));

  if (!g_key_file_save_to_file (keystore, filename, NULL))
    g_debug("Failed to save keys-1.ini");

  return store_ctx;
}

static session_pre_key_bundle *
get_pre_key_bundle (axolotl_store_context *store_ctx)
{
  session_pre_key_bundle *bundle;
  uint32_t registration_id;
  int device_id = 1;
  uint32_t pre_key_id = 1;
  ec_public_key *pre_key_public;
  uint32_t signed_pre_key_id = 1;
  ec_public_key *identity_key;
  ratchet_identity_key_pair *identity_key_pair;
  session_pre_key *pre_key;
  session_signed_pre_key *signed_pre_key;
  ec_public_key *signed_pre_key_public;

  int ret;
  ret = axolotl_identity_get_local_registration_id (store_ctx, &registration_id);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_pre_key_load_key (store_ctx, &pre_key, pre_key_id);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  pre_key_public = ec_key_pair_get_public (session_pre_key_get_key_pair (pre_key));
  g_assert_nonnull (pre_key_public);
  ret = axolotl_identity_get_key_pair (store_ctx, &identity_key_pair);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  identity_key = ratchet_identity_key_pair_get_public (identity_key_pair);
  g_assert_nonnull (identity_key);

  ret = axolotl_signed_pre_key_load_key (store_ctx, &signed_pre_key, signed_pre_key_id);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  signed_pre_key_public = ec_key_pair_get_public (session_signed_pre_key_get_key_pair (signed_pre_key));
  g_assert_nonnull (signed_pre_key_public);

  ret = session_pre_key_bundle_create (&bundle,
    registration_id, device_id,
    pre_key_id, pre_key_public,
    signed_pre_key_id, signed_pre_key_public,
    session_signed_pre_key_get_signature (signed_pre_key),
    session_signed_pre_key_get_signature_len (signed_pre_key),
    identity_key
  );
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  return bundle;
}

static void
test_client (void)
{
  axolotl_store_context *store_ctx = new_store("keys-1.ini"), *other_person_store = new_store("keys-2.ini");
  axolotl_address address = {
    "test", 4, 1,
  };
  session_builder *builder;
  session_cipher *cipher;
  ciphertext_message *encrypted_message;
  const char *message = "Hello World";
  session_pre_key_bundle *other_bundle = get_pre_key_bundle (other_person_store);
  int ret;

  ret = session_builder_create (&builder, store_ctx, &address, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = session_builder_process_pre_key_bundle (builder, other_bundle);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = session_cipher_create (&cipher, store_ctx, &address, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = session_cipher_encrypt (cipher, (guchar*)message, strlen(message), &encrypted_message);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  g_clear_pointer(&encrypted_message, axolotl_buffer_free);
  g_clear_pointer(&cipher, session_cipher_free);
  g_clear_pointer(&builder, session_builder_free);
  g_clear_pointer(&store_ctx, axolotl_store_context_destroy);
  g_clear_pointer(&other_person_store, axolotl_store_context_destroy);
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