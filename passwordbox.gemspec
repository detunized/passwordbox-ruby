# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

$:.push File.expand_path("../lib", __FILE__)
require "passwordbox/version"

Gem::Specification.new do |s|
    s.name        = "passwordbox"
    s.version     = PasswordBox::VERSION
    s.licenses    = ["MIT"]
    s.authors     = ["Dmitry Yakimenko"]
    s.email       = "detunized@gmail.com"
    s.homepage    = "https://github.com/detunized/passwordbox-ruby"
    s.summary     = "Unofficial PasswordBox API"
    s.description = "Unofficial PasswordBox API"

    s.required_ruby_version = ">= 2.0.0"

    s.add_dependency "httparty", "~> 0.13.0"

    s.add_development_dependency "rake", "~> 10.4.0"
    s.add_development_dependency "rspec", "~> 3.1.0"
    s.add_development_dependency "rspec-its", "~> 1.1.0"

    s.files         = `git ls-files`.split "\n"
    s.test_files    = `git ls-files spec`.split "\n"
    s.require_paths = ["lib"]
end
