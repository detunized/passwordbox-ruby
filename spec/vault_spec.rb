# Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe PasswordBox::Vault do
    let(:vault) { PasswordBox::Vault.new [] }

    describe "#accounts" do
        context "returned accounts" do
            it { expect(vault.accounts).to be_instance_of Array }
        end
    end

    describe ".parse_response" do
        it "raises an exception on missing salt" do
            expect {
                PasswordBox::Vault.parse_response Hash.new
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on short salt" do
            expect {
                PasswordBox::Vault.parse_response "salt" => "too short"
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on non-string salt" do
            expect {
                PasswordBox::Vault.parse_response "salt" => -1
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end
    end
end
