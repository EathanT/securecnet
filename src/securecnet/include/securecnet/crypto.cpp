#include "securecnet/crypto.hpp"

#include <algorithm>
#include <cstring>

#include <sodium.h>

namespace scn {

    namespace {
        Result ensure_crypto_ready() {
            static const int init_result = sodium_init();
            if (init_result < 0) {
                return Result::fail(Errc::Internal, "libsodium init failed");
            }
            return Result::success();
        }
    }

    void KeyPair::clear() {
        crypto_secure_zero(secret_key.data(), secret_key.size());
        std::fill(public_key.begin(), public_key.end(), 0);
    }

    void SessionKeys::clear() {
        crypto_secure_zero(rx.data(), rx.size());
        crypto_secure_zero(tx.data(), tx.size());
    }

    bool SessionKeys::empty() const {
        U8 accum = 0;
        for (U8 byte : rx) accum |= byte;
        for (U8 byte : tx) accum |= byte;
        return accum == 0;
    }

    Result crypto_runtime_status() {
        return ensure_crypto_ready();
    }

    void crypto_random_bytes(void* dst, ST len) {
        if (!dst || len == 0) {
            return;
        }
        (void)ensure_crypto_ready();
        randombytes_buf(dst, len);
    }

    void crypto_secure_zero(void* p, ST len) {
        if (!p || len == 0) {
            return;
        }
        (void)ensure_crypto_ready();
        sodium_memzero(p, len);
    }

    bool crypto_constant_time_equal(const U8* a, const U8* b, ST len) {
        if ((!a || !b) && len != 0) {
            return false;
        }
        U8 diff = 0;
        for (ST i = 0; i < len; ++i) {
            diff |= static_cast<U8>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

    Result crypto_generate_keypair(KeyPair& out) {
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if (crypto_kx_keypair(out.public_key.data(), out.secret_key.data()) != 0) {
            return Result::fail(Errc::Internal, "crypto_kx_keypair failed");
        }
        return Result::success();
    }

    Result crypto_derive_client_session_keys(const KeyPair& client_ephemeral,
                                             const U8* server_public_key, ST server_public_key_len,
                                             SessionKeys& out) {
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if (!server_public_key || server_public_key_len != NetConfig::KeyExchangePublicKeyBytes) {
            return Result::fail(Errc::InvalidArg, "bad server public key");
        }
        if (crypto_kx_client_session_keys(out.rx.data(), out.tx.data(),
                                          client_ephemeral.public_key.data(),
                                          client_ephemeral.secret_key.data(),
                                          server_public_key) != 0) {
            return Result::fail(Errc::AuthFailed, "client session key derivation failed");
        }
        return Result::success();
    }

    Result crypto_derive_server_session_keys(const KeyPair& server_ephemeral,
                                             const U8* client_public_key, ST client_public_key_len,
                                             SessionKeys& out) {
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if (!client_public_key || client_public_key_len != NetConfig::KeyExchangePublicKeyBytes) {
            return Result::fail(Errc::InvalidArg, "bad client public key");
        }
        if (crypto_kx_server_session_keys(out.rx.data(), out.tx.data(),
                                          server_ephemeral.public_key.data(),
                                          server_ephemeral.secret_key.data(),
                                          client_public_key) != 0) {
            return Result::fail(Errc::AuthFailed, "server session key derivation failed");
        }
        return Result::success();
    }

    void crypto_make_packet_nonce(U64 conn_id, U64 seq,
                                  std::array<U8, NetConfig::AeadNonceBytes>& out) {
        out.fill(0);
        for (int i = 0; i < 8; ++i) {
            out[8 + i] = static_cast<U8>((conn_id >> ((7 - i) * 8)) & 0xFFu);
            out[16 + i] = static_cast<U8>((seq >> ((7 - i) * 8)) & 0xFFu);
        }
    }

    Result crypto_aead_encrypt(const U8* key, ST key_len,
                               const U8* nonce, ST nonce_len,
                               const U8* aad, ST aad_len,
                               const U8* plaintext, ST plaintext_len,
                               U8* out, ST out_cap, ST& out_len) {
        out_len = 0;
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if (!key || key_len != NetConfig::AeadKeyBytes) {
            return Result::fail(Errc::InvalidArg, "bad AEAD key");
        }
        if (!nonce || nonce_len != NetConfig::AeadNonceBytes) {
            return Result::fail(Errc::InvalidArg, "bad AEAD nonce");
        }
        if (aad_len > 0 && !aad) {
            return Result::fail(Errc::InvalidArg, "AAD is null");
        }
        if (plaintext_len > 0 && !plaintext) {
            return Result::fail(Errc::InvalidArg, "plaintext is null");
        }
        if (out_cap < plaintext_len + NetConfig::AeadTagBytes) {
            return Result::fail(Errc::Truncated, "ciphertext buffer too small");
        }

        unsigned long long written = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                out, &written,
                plaintext, static_cast<unsigned long long>(plaintext_len),
                aad, static_cast<unsigned long long>(aad_len),
                nullptr, nonce, key) != 0) {
            return Result::fail(Errc::Internal, "AEAD encrypt failed");
        }
        out_len = static_cast<ST>(written);
        return Result::success();
    }

    Result crypto_aead_decrypt(const U8* key, ST key_len,
                               const U8* nonce, ST nonce_len,
                               const U8* aad, ST aad_len,
                               const U8* ciphertext, ST ciphertext_len,
                               U8* out, ST out_cap, ST& out_len) {
        out_len = 0;
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if (!key || key_len != NetConfig::AeadKeyBytes) {
            return Result::fail(Errc::InvalidArg, "bad AEAD key");
        }
        if (!nonce || nonce_len != NetConfig::AeadNonceBytes) {
            return Result::fail(Errc::InvalidArg, "bad AEAD nonce");
        }
        if (aad_len > 0 && !aad) {
            return Result::fail(Errc::InvalidArg, "AAD is null");
        }
        if (ciphertext_len < NetConfig::AeadTagBytes) {
            return Result::fail(Errc::BadPacket, "ciphertext too short");
        }
        if (!ciphertext) {
            return Result::fail(Errc::InvalidArg, "ciphertext is null");
        }
        if (out_cap < ciphertext_len - NetConfig::AeadTagBytes) {
            return Result::fail(Errc::Truncated, "plaintext buffer too small");
        }

        unsigned long long written = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                out, &written,
                nullptr,
                ciphertext, static_cast<unsigned long long>(ciphertext_len),
                aad, static_cast<unsigned long long>(aad_len),
                nonce, key) != 0) {
            return Result::fail(Errc::AuthFailed, "AEAD decrypt failed");
        }
        out_len = static_cast<ST>(written);
        return Result::success();
    }

    Result crypto_keyed_hash(const U8* key, ST key_len,
                             const U8* data, ST data_len,
                             U8* out, ST out_len) {
        auto rc = ensure_crypto_ready();
        if (!rc.ok()) return rc;
        if ((!key || key_len == 0) || !out || out_len == 0) {
            return Result::fail(Errc::InvalidArg, "bad keyed hash args");
        }
        if (data_len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "hash input is null");
        }
        if (crypto_generichash(out, out_len, data,
                               static_cast<unsigned long long>(data_len),
                               key, key_len) != 0) {
            return Result::fail(Errc::Internal, "keyed hash failed");
        }
        return Result::success();
    }

} 
