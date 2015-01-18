# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "openssl"
require "httparty"
require "json"

# A hack/fix to make the gem work.
# TODO: Fix upstream code and then remove this.
module SJCL; end; require "sjcl"

module PasswordBox
    class Vault
        class HTTP
            include HTTParty
        end

        attr_reader :accounts

        # Fetches a blob from the server and creates a vault
        def self.open_remote username, password
            session = login username, password
            accounts = fetch_accounts session

            new accounts
        end

        # TODO: Move these functions out to separate classes!
        def self.login username, password
            hash = compute_password_hash username, password
            response = HTTP.post "https://api0.passwordbox.com/api/0/api_login.json",
                                 query: {member: {email: username, password: hash}}

            # TODO: Handle errors!
            key = parse_response response.parsed_response, password
            session = response.headers["Set-Cookie"][/_pwdbox_session=(.*?);/, 1]

            {id: session, key: key}
        end

        # Computes password hash that is sent to the PB server instead of the plain text password.
        def self.compute_password_hash username, password
            salt = Digest::SHA1.hexdigest username
            pbkdf2_sha256 password, salt, 10_000, 256
        end

        def self.parse_response response, password
            salt = response["salt"]
            if salt.nil? || salt.size < 32
                raise "Legacy user is not supported"
            end

            derivation_rules = JSON.parse response["dr"] rescue \
                raise "Failed to parse derivation rules"

            kek = compute_kek password, salt, derivation_rules

            decrypt response["k_kek"], kek
        end

        # Computes the KEK (key encryption key) which is used to encrypt/decrypt the actual key
        # with which all the data is encrypted.
        def self.compute_kek password, salt, derivation_rules
            client_iterations = [0, derivation_rules.fetch("client_iterations", 0).to_i].max
            server_iterations = [1, derivation_rules.fetch("iterations", 1).to_i].max

            step1 = pbkdf2_sha1 password, salt, 1, 512
            step2 = pbkdf2_sha256 step1, salt, client_iterations, 512
            step3 = pbkdf2_sha256 step2, salt, server_iterations, 256
            step4 = pbkdf2_sha1 step3 + password, salt, 1, 512

            step4
        end

        def self.pbkdf2_sha1 password, salt, iterations, bits
            pbkdf2 password, salt, iterations, bits, "sha1"
        end

        def self.pbkdf2_sha256 password, salt, iterations, bits
            pbkdf2 password, salt, iterations, bits, "sha256"
        end

        def self.pbkdf2 password, salt, iterations, bits, sha
            if iterations > 0
                Digest.hexencode OpenSSL::PKCS5.pbkdf2_hmac password, salt, iterations, bits / 8, sha
            else
                password
            end
        end

        # Decrypts a piece of data. Encrypted data is base64 encoded.
        # The key is hex encoded. Only first 256 of key are used.
        # Decrypted data is encoded in plain binary.
        #
        # Encrypted data is made up of the following parts:
        # 1 byte at 0: ignored
        # 1 byte at 1: format version (only 4 is supported)
        # 16 bytes at 2: IV - initialized vector for AES-CCM encryption
        # the rest at 18: cipher text (encrypted data)
        def self.decrypt encrypted_base64, key_hex
            # Decode to binary
            encrypted = SJCL::Codec::Base64.toBits encrypted_base64
            key = SJCL::Codec::Hex.toBits key_hex

            # Version byte is at offset 1
            version = SJCL::BitArray.extract encrypted, 8, 8
            if version != 4
                raise "Unsupported cipher format version: #{version}"
            end

            # We use AES-256-CCM not matter how long the key is
            key = SJCL::BitArray.clamp key, 256

            # Split encrypted into IV and cipher
            iv = SJCL::BitArray.bitSlice encrypted, 16, 16 + 128
            cipher = SJCL::BitArray.bitSlice encrypted, 16 + 128

            # Decrypt
            aes = SJCL::Cipher::AES.new key
            decrypted = SJCL::Mode::CCM.decrypt aes, cipher, iv

            # Decrypted data is in SJCL.bitArray format. Convert it to binary string.
            SJCL::Codec::UTF8String.fromBits decrypted
        end

        def self.fetch_accounts session
            []
        end

        # This is internal and it's not supposed to be called directly
        def initialize accounts
            @accounts = []
            @accounts = parse_accounts accounts
        end

        def parse_accounts accounts
            accounts.map { |i| {} }
        end
    end
end
