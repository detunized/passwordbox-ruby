# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

# Run via top level rake file:
# $ rake example

require "passwordbox"

vault = PasswordBox::Vault.open_remote "username", "password"

vault.accounts.each_with_index do |i, index|
    puts "#{index + 1}: #{i}"
end
