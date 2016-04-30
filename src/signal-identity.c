/* signal-identity.c
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

#include "signal-identity.h"
#include "signal-storage.h"
#include "signal-storage-keyfile.h"

struct _SignalIdentity
{
  GObject parent_instance;
};

enum
{
  PROP_0,
  PROP_STORAGE,
  N_PROPS
};

typedef struct
{
  SignalStorage *storage;
} SignalIdentityPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (SignalIdentity, signal_identity, G_TYPE_OBJECT)

SignalIdentity *
signal_identity_new_from_file (const char *file)
{
  g_autoptr (SignalStorage) storage = SIGNAL_STORAGE(signal_storage_keyfile_new (file));
  return g_object_new (SIGNAL_TYPE_IDENTITY, "storage", storage, NULL);
}

static void
signal_identity_get_property (GObject *obj,
                              guint prop_id,
                              GValue *val,
                              GParamSpec *pspec)
{
  SignalIdentity *self = SIGNAL_IDENTITY(obj);
  SignalIdentityPrivate *priv = signal_identity_get_instance_private (self);

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
signal_identity_set_property (GObject *obj,
                              guint prop_id,
                              const GValue *val,
                              GParamSpec *pspec)
{
  SignalIdentity *self = SIGNAL_IDENTITY(obj);
  SignalIdentityPrivate *priv = signal_identity_get_instance_private (self);
  GError *err = NULL;

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
signal_identity_finalize (GObject *object)
{
  SignalIdentity *self = (SignalIdentity *)object;
  SignalIdentityPrivate *priv = signal_identity_get_instance_private (self);

  g_clear_object (&priv->storage);
  G_OBJECT_CLASS (signal_identity_parent_class)->finalize (object);
}

static void
signal_identity_class_init (SignalIdentityClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = signal_identity_finalize;
  object_class->set_property = signal_identity_set_property;
  object_class->get_property = signal_identity_get_property;

  g_object_class_install_property (object_class, PROP_STORAGE,
                                   g_param_spec_object ("storage", "Storage", "Storage for keys",
                                   SIGNAL_TYPE_STORAGE, G_PARAM_READWRITE |
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_STATIC_STRINGS));
}

static void
signal_identity_init (SignalIdentity *self)
{
}
