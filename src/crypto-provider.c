/* crypto-provider.c
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

#include "crypto-provider.h"
#include <string.h>
#include <gio/gio.h>
#include <nettle/hmac.h>
#include <nettle/aes.h>
#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/yarrow.h>

static struct yarrow256_ctx yarrow_ctx;

static gboolean
seed_random (struct yarrow256_ctx *ctx)
{
  g_autoptr(GFile) random_device = g_file_new_for_path("/dev/random");
  g_autoptr(GFileInputStream) istream = g_file_read (random_device, NULL, NULL);
  uint8_t random_bytes[YARROW256_SEED_FILE_SIZE];
  size_t bytes_read;

  g_debug("Seeding random number");

  if (!istream)
    {
      g_debug("Failed to read from /dev/random");
      return FALSE;
    }


  if (!g_input_stream_read_all (G_INPUT_STREAM(istream), random_bytes, YARROW256_SEED_FILE_SIZE, &bytes_read,
                                NULL, NULL))
    {
      g_debug("Failed to get random bytes");
      return FALSE;
    }
  else if (bytes_read != YARROW256_SEED_FILE_SIZE)
    {
      g_debug("Failed to get enough random bytes: %zu", bytes_read);
      return FALSE;
    }

  g_debug("Seeded random number");
  yarrow256_seed (ctx, YARROW256_SEED_FILE_SIZE, random_bytes);

  return TRUE;
}

#define MAYBE_SEED() G_STMT_START \
  if (G_UNLIKELY(!yarrow256_is_seeded (&yarrow_ctx))) \
    { \
      yarrow256_init (&yarrow_ctx, 0, NULL); \
      if (!seed_random (&yarrow_ctx)) \
        return AX_ERR_UNKNOWN; \
    } \
G_STMT_END

static int
random_func (uint8_t *data,
             size_t   len,
             void    *user_data)
{
  MAYBE_SEED();

  yarrow256_random (&yarrow_ctx, len, data);
  return AX_SUCCESS;
}

static int
sha256_init_func (void         **hmac_context,
                  const uint8_t *key,
                  size_t         key_len,
                  void          *user_data)
{
  struct hmac_sha256_ctx *ctx = g_new (struct hmac_sha256_ctx, 1);

  hmac_sha256_set_key (ctx, key_len, key);

  *hmac_context = ctx;
  return AX_SUCCESS;
}


static int
sha256_update_func (void          *hmac_context,
                    const uint8_t *data,
                    size_t         data_len,
                    void          *user_data)
{
  struct hmac_sha256_ctx *ctx = hmac_context;

  hmac_sha256_update (ctx, data_len, data);

  return AX_SUCCESS;
}


static int
sha256_final_func (void            *hmac_context,
                   axolotl_buffer **output,
                   void            *user_data)
{
  struct hmac_sha256_ctx *ctx = hmac_context;
  uint8_t digest[SHA256_DIGEST_SIZE];

  hmac_sha256_digest (ctx, SHA256_DIGEST_SIZE, (uint8_t*)&digest);


  if ((*output = axolotl_buffer_create (digest, SHA256_DIGEST_SIZE)))
    return AX_SUCCESS;
  else
    return AX_ERR_NOMEM;
}

static void
sha256_cleanup_func (void *hmac_context,
                     void *user_data)
{
  g_free (hmac_context);
}

static int
sha512_digest_func (axolotl_buffer **output,
                    const uint8_t   *data,
                    size_t           data_len,
                    void            *user_data)
{
  struct sha512_ctx ctx;
  uint8_t digest[SHA512_DIGEST_SIZE];

  sha512_init (&ctx);
  sha512_update (&ctx, data_len, data);
  sha512_digest (&ctx, SHA512_DIGEST_SIZE, digest);

  if ((*output = axolotl_buffer_create (digest, SHA512_DIGEST_SIZE)))
    return AX_SUCCESS;
  else
    return AX_ERR_NOMEM;
}

static nettle_cipher_func *
get_cipher_func (size_t   key_len,
                 gboolean encrypt)
{
  switch (key_len)
  {
  case AES128_KEY_SIZE:
    return (nettle_cipher_func*)(encrypt ? aes128_encrypt : aes128_decrypt);
  case AES192_KEY_SIZE:
    return (nettle_cipher_func*)(encrypt ? aes192_encrypt : aes192_decrypt);
  case AES256_KEY_SIZE:
    return (nettle_cipher_func*)(encrypt ? aes256_encrypt : aes256_decrypt);
  default:
    return NULL;
  }
}

static void *
get_cipher_context (const uint8_t *key,
                    size_t         key_len,
                    gboolean       encrypt)
{
  switch (key_len)
  {
  case AES128_KEY_SIZE:
    {
      struct aes128_ctx *ctx = g_new(struct aes128_ctx, 1);
      if (encrypt)
        aes128_set_encrypt_key (ctx, key);
      else
        aes128_set_decrypt_key (ctx, key);
      return ctx;
    }

  case AES192_KEY_SIZE:
    {
      struct aes192_ctx *ctx = g_new(struct aes192_ctx, 1);
      if (encrypt)
        aes192_set_encrypt_key (ctx, key);
      else
        aes192_set_decrypt_key (ctx, key);
      return ctx;
    }

  case AES256_KEY_SIZE:
    {
      struct aes256_ctx *ctx = g_new(struct aes256_ctx, 1);
      if (encrypt)
        aes256_set_encrypt_key (ctx, key);
      else
        aes256_set_decrypt_key (ctx, key);
      return ctx;
    }

  default:
    return NULL;
  }
}

static gboolean
pad_message (const uint8_t *message,
             size_t message_len,
             uint8_t **padded_out,
             size_t *padded_len_out)
{
  uint8_t *padded;
  size_t padded_len;
  uint8_t padding = (uint8_t)(AES_BLOCK_SIZE - (message_len % AES_BLOCK_SIZE));
  if (!padding)
    return FALSE;

  padded_len = message_len + padding;
  padded = g_new(uint8_t, padded_len);

  memcpy (padded, message, message_len);

  // PKCS#7
  for (uint8_t i = 0; i < padding; ++i)
    padded[message_len + i] = padding;

  g_debug ("Padded message with %u bytes", padding);

  *padded_out = padded;
  *padded_len_out = padded_len;
  return TRUE;
}

static inline size_t
get_padded_len (const uint8_t *data,
                size_t data_len)
{
  // Remove padding (PKCS#7)
  uint8_t padding_byte = data[data_len - 1];
  if (padding_byte < AES_BLOCK_SIZE)
    {
      for (uint8_t i = 1; i <= padding_byte; ++i)
        if (data[data_len - i] != padding_byte)
          return data_len;

      return data_len - padding_byte;
    }
  return data_len;
}


static int
aes_encrypt_func (axolotl_buffer **output,
                  int              cipher,
                  const uint8_t   *key,
                  size_t           key_len,
                  const uint8_t   *iv,
                  size_t           iv_len,
                  const uint8_t   *plaintext,
                  size_t           plaintext_len,
                  void            *user_data)
{
  g_autofree void *ctx = get_cipher_context (key, key_len, TRUE);
  nettle_cipher_func *func = get_cipher_func (key_len, TRUE);
  g_autofree uint8_t *dest = g_new (uint8_t, plaintext_len + AES_BLOCK_SIZE);
  g_autofree uint8_t *iv_copy = g_new (uint8_t, iv_len);
  memcpy(iv_copy, iv, iv_len);

  g_return_val_if_fail (func != NULL, AX_ERR_UNKNOWN);
  g_return_val_if_fail (iv_len == 16, AX_ERR_UNKNOWN);
  g_return_val_if_fail (ctx != NULL, AX_ERR_UNKNOWN);

  if (cipher == AX_CIPHER_AES_CBC_PKCS5)
    {
      g_autofree uint8_t *padded = NULL;
      size_t padded_len;

      if (pad_message (plaintext, plaintext_len, &padded, &padded_len))
        cbc_encrypt (ctx, func, AES_BLOCK_SIZE, iv_copy, padded_len, dest, padded);
      else
        cbc_encrypt (ctx, func, AES_BLOCK_SIZE, iv_copy, plaintext_len, dest, plaintext);
    }
  else if (cipher == AX_CIPHER_AES_CTR_NOPADDING)
    {
      ctr_crypt (ctx, func, AES_BLOCK_SIZE, iv_copy, plaintext_len, dest, plaintext);
    }
  else
    return AX_ERR_UNKNOWN;

  if ((*output = axolotl_buffer_create (dest, plaintext_len))) // Correct size?
    return AX_SUCCESS;
  else
    return AX_ERR_NOMEM;
}

static int
aes_decrypt_func (axolotl_buffer **output,
                  int              cipher,
                  const uint8_t   *key,
                  size_t           key_len,
                  const uint8_t   *iv,
                  size_t           iv_len,
                  const uint8_t   *ciphertext,
                  size_t           ciphertext_len,
                  void            *user_data)
{
  g_autofree void *ctx = get_cipher_context (key, key_len, FALSE);
  nettle_cipher_func *func = get_cipher_func (key_len, FALSE);
  g_autofree uint8_t *dest = g_new (uint8_t, ciphertext_len);
  g_autofree uint8_t *iv_copy = g_new (uint8_t, iv_len);
  size_t dest_len = ciphertext_len;
  memcpy(iv_copy, iv, iv_len);

  g_return_val_if_fail (func != NULL, AX_ERR_UNKNOWN);
  g_return_val_if_fail (iv_len == 16, AX_ERR_UNKNOWN);
  g_return_val_if_fail (ctx != NULL, AX_ERR_UNKNOWN);

  if (cipher == AX_CIPHER_AES_CBC_PKCS5)
    {
      cbc_decrypt (ctx, func, AES_BLOCK_SIZE, iv_copy, ciphertext_len, dest, ciphertext);
      dest_len = get_padded_len (dest, dest_len);
    }
  else if (cipher == AX_CIPHER_AES_CTR_NOPADDING)
    {
      ctr_crypt (ctx, func, AES_BLOCK_SIZE, iv_copy, ciphertext_len, dest, ciphertext);
    }
  else
    return AX_ERR_UNKNOWN;

  if ((*output = axolotl_buffer_create (dest, dest_len)))
    return AX_SUCCESS;
  else
    return AX_ERR_NOMEM;
}

axolotl_crypto_provider *
sg_crypto_provider_new (void)
{
  axolotl_crypto_provider *provider = g_new (axolotl_crypto_provider, 1);

  provider->random_func = random_func;
  provider->hmac_sha256_init_func = sha256_init_func;
  provider->hmac_sha256_update_func = sha256_update_func;
  provider->hmac_sha256_final_func = sha256_final_func;
  provider->hmac_sha256_cleanup_func = sha256_cleanup_func;
  provider->sha512_digest_func = sha512_digest_func;
  provider->encrypt_func = aes_encrypt_func;
  provider->decrypt_func = aes_decrypt_func;
  provider->user_data = NULL;

  return provider;
}

