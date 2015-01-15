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

        it "raises an exception on missing derivation rules" do
            expect {
                PasswordBox::Vault.parse_response valid_response.without("dr")
            }.to raise_error RuntimeError, "Failed to parse derivation rules"
        end

        it "raises an exception on non-JSON derivation rules" do
            expect {
                PasswordBox::Vault.parse_response valid_response.update("dr" => "not json")
            }.to raise_error RuntimeError, "Failed to parse derivation rules"
        end
    end

    describe ".compute_key" do
        let(:password) { "password" }
        let(:salt) { "salt" }

        let(:tests) {
            {
                [ 0,  0] => "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                            "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef",

                [ 1,  0] => "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                            "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac",

                [ 0,  1] => "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                            "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef",

                [ 1,  1] => "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                            "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac",

                [10,  0] => "76ea6ae400308d72ceb56f223a44a31a552bdf03598f5fd39387467b618ce245" +
                            "ecb1877528ca94f3e9e720dfdbd9f85af68f13346c3f9dfaed7417a4ea2dbeba",

                [ 0, 10] => "57ffc1876b96dab3f8d3daed9455547f3f7c692de3684d34ea27f7b36143e2d2" +
                            "03480a01370ba30ea03f6b1cb8fe89db63f1adec34913a7def56e194ed1b0a6a",

                [13, 42] => "3f64e210cb30e46672e74a6c63e73201183a4fec4279480df4163882dd4ac1b2" +
                            "6fd1333ba819dfb4f97381b93c65ba6b768034019113470db0356206f1bb9708",
            }
        }

        it "computes key" do
            tests.each do |rules, key|
                expect(
                    PasswordBox::Vault.compute_key password, salt, {
                        "client_iterations" => rules[0],
                        "iterations" => rules[1]
                    }
                ).to eq key
            end
        end
    end
end
