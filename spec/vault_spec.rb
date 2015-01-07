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
        let(:valid_response) { {"salt" => "0" * 32, "dr" => "{}"} }
        let(:session) { PasswordBox::Vault.parse_response valid_response }

        it "parses server response and returns session" do
            expect(session).to be_instance_of Hash
        end

        it "raises an exception on missing salt" do
            expect {
                PasswordBox::Vault.parse_response valid_response.without("salt")
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on short salt" do
            expect {
                PasswordBox::Vault.parse_response valid_response.update("salt" => "too short")
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on non-string salt" do
            expect {
                PasswordBox::Vault.parse_response valid_response.update("salt" => -1)
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on missing derivation rules" do
            expect {
                PasswordBox::Vault.parse_response valid_response.without("dr")
            }.to raise_error RuntimeError, "Invalid response: derivation rules are missing"
        end

        it "raises an exception on non-JSON derivation rules" do
            expect {
                PasswordBox::Vault.parse_response valid_response.update("dr" => "not json")
            }.to raise_error RuntimeError, "Invalid response: derivation rules are not valid JSON"
        end
    end
end
