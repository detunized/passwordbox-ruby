# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module PasswordBox
    class Vault
        attr_reader :accounts

        # Fetches a blob from the server and creates a vault
        def self.open_remote username, password
            session = login username, password
            accounts = fetch_accounts session

            new accounts
        end

        def self.login username, password
            {}
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
