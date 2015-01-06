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
end
