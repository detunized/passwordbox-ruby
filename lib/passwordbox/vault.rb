# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "openssl"
require "httparty"

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
            hash = password_hash username, password
            response = HTTP.post "https://api0.passwordbox.com/api/0/api_login.json",
                                 query: {member: {email: username, password: hash}}

            # TODO: Handle errors!
            response.parsed_response
        end

        def self.password_hash username, password
            salt = Digest::SHA1.hexdigest username
            Digest.hexencode OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 10000, 32, "sha256")
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
