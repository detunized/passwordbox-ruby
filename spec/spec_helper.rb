# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "passwordbox"
require "rspec/its"

class Hash
    def without key
        delete_if { |i| i == key }
    end
end
