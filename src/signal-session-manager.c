/* signal-session-manager.c
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
#include "signal-session-manager.h"
#include "signal-storage-private.h"

struct _SignalSessionManager
{
  GObject parent_instance;
};

typedef struct
{
  session_builder *builder;
  SignalStorage *storage;
} SignalSessionManagerPrivate;

enum
{
  PROP_0,
  PROP_STORAGE,
  N_PROPS
};

G_DEFINE_TYPE_WITH_PRIVATE (SignalSessionManager, signal_session_manager, G_TYPE_OBJECT)

static inline GBytes *
buffer_to_bytes (axolotl_buffer *buffer)
{
  GBytes *bytes = g_bytes_new (axolotl_buffer_data (buffer), axolotl_buffer_len (buffer));
  axolotl_buffer_free (buffer);
  return bytes;
}

static ec_public_key *
create_public_key (axolotl_buffer **signature)
{
  int ret;
  ec_key_pair *key_pair;
  ec_public_key *public_key;

  ret = curve_generate_key_pair (global_ctx, &key_pair);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  public_key = ec_key_pair_get_public(key_pair);

  if (signature)
    {
      axolotl_buffer *public_buf;

      ret = ec_public_key_serialize (&public_buf, public_key);
      g_assert_cmpint (ret, ==, AX_SUCCESS);

      ret = curve_calculate_signature (global_ctx, signature,
                                ec_key_pair_get_private (key_pair),
                                axolotl_buffer_data (public_buf),
                                axolotl_buffer_len (public_buf));

      g_assert_cmpint (ret, ==, AX_SUCCESS);
      AXOLOTL_UNREF(public_buf);
    }

  AXOLOTL_REF (public_key);
  AXOLOTL_UNREF (key_pair);
  return public_key;
}

static key_exchange_message *
create_exchange_message (axolotl_store_context *store_ctx)
{
  key_exchange_message *message;
  axolotl_buffer *base_key_signature;
  ec_public_key *base_key = create_public_key (&base_key_signature);
  ec_public_key *ratchet_key = create_public_key (NULL);
  ratchet_identity_key_pair *identity_key_pair;
  ec_public_key *identity_key;
  int ret;

  ret = axolotl_identity_get_key_pair (store_ctx, &identity_key_pair);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  identity_key = ratchet_identity_key_pair_get_public (identity_key_pair);
  g_assert_nonnull (identity_key);

  g_debug ("Creating key exchange message");

  ret = key_exchange_message_create (&message,
          CIPHERTEXT_CURRENT_VERSION, 0, KEY_EXCHANGE_INITIATE_FLAG,
          base_key, axolotl_buffer_data (base_key_signature), ratchet_key, identity_key);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  axolotl_buffer_free (base_key_signature);
  return message;
}

GBytes *
signal_session_manager_new_exchange (SignalSessionManager *self,
                                     SignalAddress        *address)
{
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);
  axolotl_address addr;
  axolotl_store_context *store_ctx;
  key_exchange_message *initial_message;
  axolotl_buffer *buffer;
  GBytes *bytes;
  int ret;

  g_return_val_if_fail (address != NULL, NULL);

  addr.name = address->name;
  addr.name_len = strlen (address->name) + 1;
  addr.device_id = address->device_id;

  store_ctx = signal_storage_get_axolotl_store (priv->storage);
  initial_message = create_exchange_message (store_ctx);

  g_clear_pointer (&priv->builder, session_builder_free);
  ret = session_builder_create (&priv->builder, store_ctx, &addr, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = session_builder_process (priv->builder, &initial_message);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  buffer = key_exchange_message_get_serialized (initial_message);
  bytes = buffer_to_bytes (buffer);
  //g_clear_pointer (&initial_message, key_exchange_message_destroy);

  return bytes;
}

GBytes *
signal_session_manager_new_response (SignalSessionManager *self,
                                     GBytes               *exchange,
                                     SignalAddress        *address,
                                     GError              **error)
{
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);
  key_exchange_message *message, *response;
  axolotl_address addr;
  axolotl_store_context *store_ctx;
  axolotl_buffer *buffer;
  GBytes *bytes;
  gsize data_size;
  gconstpointer data;
  int ret;

  g_return_val_if_fail (address != NULL, NULL);

  data = g_bytes_get_data (exchange, &data_size);

  // TODO: Errors
  ret = key_exchange_message_deserialize (&message, data, data_size, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  addr.name = address->name;
  addr.name_len = strlen (address->name) + 1;
  addr.device_id = address->device_id;

  store_ctx = signal_storage_get_axolotl_store (priv->storage);

  g_clear_pointer (&priv->builder, session_builder_free);
  ret = session_builder_create (&priv->builder, store_ctx, &addr, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = session_builder_process_key_exchange_message (priv->builder, message, &response);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  buffer = key_exchange_message_get_serialized (response);
  bytes = buffer_to_bytes (buffer);
  //g_clear_pointer (&response, key_exchange_message_destroy);

  return bytes;
}

SignalSession *
signal_session_manager_new_session (SignalSessionManager *self,
                                    GBytes               *response,
                                    GError              **error)
{
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);
  key_exchange_message *message, *message_response;
  gsize data_size;
  gconstpointer data;
  int ret;

  data = g_bytes_get_data (response, &data_size);

  // TODO: Errors
  ret = key_exchange_message_deserialize (&message, data, data_size, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);

  ret = session_builder_process_key_exchange_message (priv->builder, message, &message_response);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  g_assert_null (message_response);

  g_clear_pointer (&message, key_exchange_message_destroy);
  g_clear_pointer (&priv->builder, session_builder_free);

  return NULL; // TODO
}

static void
signal_session_manager_get_property (GObject *obj,
                                     guint prop_id,
                                     GValue *val,
                                     GParamSpec *pspec)
{
  SignalSessionManager *self = SIGNAL_SESSION_MANAGER(obj);
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_STORAGE:
      g_value_set_object (val, priv->storage);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
      break;
    }
}

static void
signal_session_manager_set_property (GObject *obj,
                                     guint prop_id,
                                     const GValue *val,
                                     GParamSpec *pspec)
{
  SignalSessionManager *self = SIGNAL_SESSION_MANAGER(obj);
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_STORAGE:
      priv->storage = g_value_dup_object (val);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
      break;
    }
}

static void
signal_session_manager_finalize (GObject *object)
{
  SignalSessionManager *self = SIGNAL_SESSION_MANAGER(object);
  SignalSessionManagerPrivate *priv = signal_session_manager_get_instance_private (self);

  g_clear_pointer (&priv->builder, session_builder_free);
  G_OBJECT_CLASS (signal_session_manager_parent_class)->finalize (object);
}

static void
signal_session_manager_class_init (SignalSessionManagerClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = signal_session_manager_finalize;
  object_class->get_property = signal_session_manager_get_property;
  object_class->set_property = signal_session_manager_set_property;

  g_object_class_install_property (object_class, PROP_STORAGE,
                                   g_param_spec_object ("storage", "Storage", "Storage for keys",
                                   SIGNAL_TYPE_STORAGE, G_PARAM_READWRITE |
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_STATIC_STRINGS));
}

static void
signal_session_manager_init (SignalSessionManager *self)
{
}
