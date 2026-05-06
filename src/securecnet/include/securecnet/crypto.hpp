#pragma once
#include <array>
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

namespace scn {

    struct KeyPair {
        std::array<U8, NetConfig::KeyExchangePublicKeyBytes> public_key{};
        std::array<U8, NetConfig::KeyExchangeSecretKeyBytes> secret_key{};

        void clear();
    };

    struct SessionKeys {
        std::array<U8, NetConfig::SessionKeyBytes> rx{};
        std::array<U8, NetConfig::SessionKeyBytes> tx{};

        void clear();
        bool empty() const;
    };

    Result crypto_runtime_status();
    void crypto_random_bytes(void* dst, ST len);
    void crypto_secure_zero(void* p, ST len);
    bool crypto_constant_time_equal(const U8* a, const U8* b, ST len);

    Result crypto_generate_keypair(KeyPair& out);
    Result crypto_derive_client_session_keys(const KeyPair& client_ephemeral,
                                             const U8* server_public_key, ST server_public_key_len,
                                             SessionKeys& out);
    Result crypto_derive_server_session_keys(const KeyPair& server_ephemeral,
                                             const U8* client_public_key, ST client_public_key_len,
                                             SessionKeys& out);

    void crypto_make_packet_nonce(U64 conn_id, U64 seq,
                                  std::array<U8, NetConfig::AeadNonceBytes>& out);

    Result crypto_aead_encrypt(const U8* key, ST key_len,
                               const U8* nonce, ST nonce_len,
                               const U8* aad, ST aad_len,
                               const U8* plaintext, ST plaintext_len,
                               U8* out, ST out_cap, ST& out_len);

    Result crypto_aead_decrypt(const U8* key, ST key_len,
                               const U8* nonce, ST nonce_len,
                               const U8* aad, ST aad_len,
                               const U8* ciphertext, ST ciphertext_len,
                               U8* out, ST out_cap, ST& out_len);

    Result crypto_keyed_hash(const U8* key, ST key_len,
                             const U8* data, ST data_len,
                             U8* out, ST out_len);

} 
