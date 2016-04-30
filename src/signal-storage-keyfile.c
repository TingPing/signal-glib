/* signal-storage-keyfile.c
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

#include "signal-storage-keyfile.h"
#include "signal-storage.h"
#include "identity-key-store.h"
#include "pre-key-store.h"
#include "signed-pre-key-store.h"
#include "sender-key-store.h"
#include "session-store.h"
#include "key-utils.h"

#include "signal-glib-private.h"

struct _SignalStorageKeyfile
{
  GObject parent_instance;
};

typedef struct
{
  axolotl_store_context *store_ctx;
  GKeyFile *keystore;
  char *filename;
} SignalStorageKeyfilePrivate;

enum
{
  PROP_0,
  PROP_FILENAME,
  N_PROPS
};

static void signal_storage_keyfile_iface_init (SignalStorageInterface *);

G_DEFINE_TYPE_WITH_CODE (SignalStorageKeyfile, signal_storage_keyfile, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (SIGNAL_TYPE_STORAGE, signal_storage_keyfile_iface_init)
                         G_ADD_PRIVATE (SignalStorageKeyfile))

SignalStorageKeyfile *
signal_storage_keyfile_new (const char *filename)
{
	return g_object_new (SIGNAL_TYPE_STORAGE_KEYFILE, "filename", filename, NULL);
}

static void
signal_storage_keyfile_get_property (GObject *obj,
                                     guint prop_id,
                                     GValue *val,
                                     GParamSpec *pspec)
{
  SignalStorageKeyfile *self = SIGNAL_STORAGE_KEYFILE(obj);
  SignalStorageKeyfilePrivate *priv = signal_storage_keyfile_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_FILENAME:
      g_value_set_string (val, priv->filename);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
      break;
    }
}

static void
signal_storage_keyfile_set_property (GObject *obj,
                                     guint prop_id,
                                     const GValue *val,
                                     GParamSpec *pspec)
{
  SignalStorageKeyfile *self = SIGNAL_STORAGE_KEYFILE(obj);
  SignalStorageKeyfilePrivate *priv = signal_storage_keyfile_get_instance_private (self);
  GError *err = NULL;

  switch (prop_id)
    {
    case PROP_FILENAME:
      priv->filename = g_value_dup_string (val);
      // FIXME: Local file encoding
      if (!g_key_file_load_from_file (priv->keystore, priv->filename, G_KEY_FILE_NONE, &err))
        {
          g_warning ("%s", err->message);
          g_error_free (err);
        }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
      break;
    }
}

static void
signal_storage_keyfile_save (SignalStorageKeyfile *self)
{
  SignalStorageKeyfilePrivate *priv = signal_storage_keyfile_get_instance_private (self);
  GError *err = NULL;

  if (!g_key_file_save_to_file (priv->keystore, priv->filename, &err))
    {
      g_warning ("%s", err->message);
      g_error_free (err);
    }
}

static void
signal_storage_keyfile_finalize (GObject *object)
{
  SignalStorageKeyfile *self = (SignalStorageKeyfile *)object;
  SignalStorageKeyfilePrivate *priv = signal_storage_keyfile_get_instance_private (self);

  signal_storage_keyfile_save (self);
  g_clear_pointer (&priv->keystore, g_key_file_unref);
  g_clear_pointer (&priv->filename, g_free);
  g_clear_pointer (&priv->store_ctx, axolotl_store_context_destroy);
  G_OBJECT_CLASS (signal_storage_keyfile_parent_class)->finalize (object);
}

static void
signal_storage_keyfile_class_init (SignalStorageKeyfileClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = signal_storage_keyfile_finalize;
	object_class->get_property = signal_storage_keyfile_get_property;
	object_class->set_property = signal_storage_keyfile_set_property;

  g_object_class_install_property (object_class, PROP_FILENAME,
                                   g_param_spec_string ("filename", "Filename", "File to load/save",
                                                        NULL, G_PARAM_READWRITE |
                                                              G_PARAM_CONSTRUCT_ONLY |
                                                              G_PARAM_STATIC_STRINGS));
}

static void
signal_storage_keyfile_iface_init (SignalStorageInterface *iface)
{
}

static void
signal_storage_keyfile_init (SignalStorageKeyfile *self)
{
  SignalStorageKeyfilePrivate *priv = signal_storage_keyfile_get_instance_private (self);
  g_autofree axolotl_identity_key_store *identity_store;
  g_autofree axolotl_pre_key_store *pre_key_store;
  g_autofree axolotl_signed_pre_key_store *signed_pre_key_store;
  g_autofree axolotl_sender_key_store *sender_key_store;
  g_autofree axolotl_session_store *session_store;
  int ret;

  priv->keystore = g_key_file_new ();
  identity_store = sg_identity_key_store_new (priv->keystore);
  pre_key_store = sg_pre_key_store_new (priv->keystore);
  signed_pre_key_store = sg_signed_pre_key_store_new (priv->keystore);
  sender_key_store = sg_sender_key_store_new (priv->keystore);
  session_store = sg_session_store_new (priv->keystore);

  // If any of these fail nothing we can do anyway..
  ret = axolotl_store_context_create (&priv->store_ctx, global_ctx);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_identity_key_store (priv->store_ctx, identity_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_pre_key_store (priv->store_ctx, pre_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_signed_pre_key_store (priv->store_ctx, signed_pre_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_sender_key_store (priv->store_ctx, sender_key_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
  ret = axolotl_store_context_set_session_store (priv->store_ctx, session_store);
  g_assert_cmpint (ret, ==, AX_SUCCESS);
}
