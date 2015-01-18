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

    describe ".compute_password_hash" do
        # Generated with the PasswordBox JS sources
        let(:username) { "username" }
        let(:password) { "password" }
        let(:hash) { "bb5eeb368dd3d7ba5ab371c76ba5073e0a91f55697b81790bb34846d3e25f8e4" }

        it "computes password hash" do
            expect(
                PasswordBox::Vault.compute_password_hash username, password
            ).to eq hash
        end
    end

    describe ".parse_response" do
        let(:password) { "password" }
        let(:encryption_key) { "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562" }
        let(:valid_response) {
            {
                "salt"  => "1095d8447adfdba215ea3dfd7dbf029cc8cf09c6fade18c76a356c908f48175b",
                "dr"    => "{\"client_iterations\":\"500\"," +
                           "\"iterations\":\"9498\",\"algo\":\"sha256\"}",
                "k_kek" => "AAR6fDOLfXJKRxiYYhm4u/OgQw3tIWtPUFutlF55RgshUagCtR3WXiZGG52m" +
                           "2RutxUrKcrJj7ZdTHVWukvYH2MveKbKuljwVv0zWnSwHqQSf0aRzJhyl0JWB"
            }
        }

        def parse response
            PasswordBox::Vault.parse_response response, password
        end

        it "parses server response and returns session" do
            expect(
                parse valid_response
            ).to eq encryption_key
        end

        it "raises an exception on missing salt" do
            expect {
                parse valid_response.without("salt")
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on short salt" do
            expect {
                parse valid_response.update("salt" => "too short")
            }.to raise_error RuntimeError, "Legacy user is not supported"
        end

        it "raises an exception on missing derivation rules" do
            expect {
                parse valid_response.without("dr")
            }.to raise_error RuntimeError, "Failed to parse derivation rules"
        end

        it "raises an exception on non-JSON derivation rules" do
            expect {
                parse valid_response.update("dr" => "not json")
            }.to raise_error RuntimeError, "Failed to parse derivation rules"
        end
    end

    describe ".compute_kek" do
        let(:password) { "password" }
        let(:salt) { "salt" }

        # Tests generated with the PasswordBox JS sources
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

        it "computes kek" do
            tests.each do |rules, key|
                expect(
                    PasswordBox::Vault.compute_kek password, salt, {
                        "client_iterations" => rules[0],
                        "iterations" => rules[1]
                    }
                ).to eq key
            end
        end
    end

    describe ".decrypt" do
        # Generated with the PasswordBox JS sources
        let(:encrypted) { "AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==" }
        let(:decrypted) { "password" }
        let(:encryption_key) { "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562" }

        it "decrypts cipher text" do
            expect(
                PasswordBox::Vault.decrypt encrypted, encryption_key
            ).to eq decrypted
        end

        it "uses first 256 bits of the key only" do
            expect(
                PasswordBox::Vault.decrypt encrypted, encryption_key + "deadbeef" * 8
            ).to eq decrypted
        end
    end
end
