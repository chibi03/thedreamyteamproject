#include "../secrets.h"
#include "../tls-record-layer.h"

#include "../../utils/tests.h"
#include "../../utils/utils.h"

#include <boost/asio.hpp>
#include <string>

#include <check.h>

using boost::asio::ip::tcp;
using util::operator""_x;

namespace
{
  const std::vector<uint8_t> some_messages =
      "010000c5030359f38fc78fd64ef8e8aec2c486ef2247b7c2416ca9f421aff5505ef505d7698b01000004ff011301"
      "010000970033004700450017004104c0d645154c89c3b3725dfc4884a35d25406e100bff63392e7a406f2624d220"
      "b9c9776a3a81fd538ae41b38b0616de06b937cd9b447960ef5c137fbff03a51a1a002b0003020304002d00020101"
      "000a00040002001700290033000e00086964656e7469747900000000002120cbefc811e3e2fdae06abf5c8adcd92"
      "b2db375fc11828a9f811c6529f0b13c43c0200007e030359f3902e975920bd7bb7544e495129953837631e598b63"
      "a20f91c84b17c960120100130100005500330045001700410499484aed20b35a570d06af3f84194eee23a1af4318"
      "00c52e0c9356f123ffdc0588ae598e18bd9ff892fd3251fe4bea0a5512ac7da7fcb474656f59ab3ad9684e002b00"
      "020304002900020000"_x;
  const std::vector<uint8_t> psk = "abab"_x;
  const std::vector<uint8_t> dhe =
      "86e94ce15c700d63c13433f73839bdfb23617c631a149e395aa646ac762da770"_x;
} // namespace

START_TEST(record_layer_compute_early_secrets)
{
  boost::asio::io_service io_service;
  const std::vector<uint8_t> expected_early_secret =
      "7b363255bc0c920c99638156f99e8fc462922ec80db84e4d34181cac1d7e7c54"_x;

  for (connection_end c : {connection_end::CLIENT, connection_end::SERVER})
  {
    tcp::socket socket(io_service);
    tls_record_layer record_layer(c, std::forward<tcp::socket>(socket));
    record_layer.set_cipher_suite(TLS_ASCON_128_SHA256);

    const auto early_secret = record_layer.compute_early_secrets(psk, {});

    ck_assert_array_split_eq(early_secret, expected_early_secret);
  }
}
END_TEST


START_TEST(record_layer_compute_handshake_traffic_keys)
{
  boost::asio::io_service io_service;
  const std::vector<uint8_t> expected_client_finished_key =
      "f62efc0fb6c705a5f26aea2258b7b977714fced584ee9c41527fa5e2b8c21709"_x;
  const std::vector<uint8_t> expected_server_finished_key =
      "ec63586da077b97377b8475907c1addb681d34bde7a82dbfeba174843e968e0b"_x;

  for (connection_end c : {connection_end::CLIENT, connection_end::SERVER})
  {
    tcp::socket socket(io_service);
    tls_record_layer record_layer(c, std::forward<tcp::socket>(socket));
    record_layer.set_cipher_suite(TLS_ASCON_128_SHA256);
    record_layer.compute_early_secrets(psk, some_messages);
    record_layer.compute_handshake_traffic_keys(dhe, some_messages);

    const auto client_finished_key = record_layer.get_finished_key(connection_end::CLIENT);
    const auto server_finished_key = record_layer.get_finished_key(connection_end::SERVER);
    ck_assert_array_split_eq(client_finished_key, expected_client_finished_key);
    ck_assert_array_split_eq(server_finished_key, expected_server_finished_key);
  }
}
END_TEST


START_TEST(record_layer_compute_handshake_derived_key)
{
  boost::asio::io_service io_service;
  const std::vector<uint8_t> expected_derived_key =
      "1ab3f3b0c93af7c9ab834a1258299ea3d8ca077455a6ff16f479cdc834ce0161"_x;

  for (connection_end c : {connection_end::CLIENT, connection_end::SERVER})
  {
    tcp::socket socket(io_service);
    tls_record_layer record_layer(c, std::forward<tcp::socket>(socket));
    record_layer.set_cipher_suite(TLS_ASCON_128_SHA256);
    record_layer.compute_early_secrets(psk, some_messages);
    const auto derived_key = record_layer.compute_handshake_traffic_keys(dhe, some_messages);

    ck_assert_array_split_eq(derived_key, expected_derived_key);
  }
}
END_TEST

namespace
{
  const std::array<std::vector<uint8_t>, 16> expected_ciphertexts{
      "1b90db4dfe6d42069eb5255e5259c917051f"_x, "1d78d428f90289e0b1458d8d727b2591c702"_x,
      "e359caad9c907ab79666aadcda9b57a32f14"_x, "d9ad6ff0bc22207879f1bd13d06352f6f2f0"_x,
      "d9dfc5b8affd560af0f66d7631ef736c67f4"_x, "1f595e895b4e7d0d7bbc9dc05627b4d0f419"_x,
      "e1d342cea7dd6b3d527722818bd3fdd78be7"_x, "750f95dfbc589c33b9147f4d27b2f4651e7d"_x,
      "61081c1d9cd0fd5c05a65ed021335eaab723"_x, "31dcb55e5e5e9bc9cacca175a37991eb8d02"_x,
      "55f648235e3c97ebc601df1ce10dccbd5a8f"_x, "ec792e5fd3714587c486ccd59a7f78359655"_x,
      "c175c723b1d6ace7ce2fb687f4272348c5bc"_x, "f67a8213fe068f8623e66417d68f23d40def"_x,
      "cf21c17709586f952c20cd5a43af06715ff0"_x, "6b860b005f9c694d13238c738144ccd473d5"_x};

  void encrypted_message(const content_type type, bool test_header_type,
                         bool check_expected_ciphertext)
  {
    size_t ecc = type == TLS_HANDSHAKE ? 0 : 8;

    boost::asio::io_service io_service;
    for (const cipher_suite cs : {TLS_ASCON_128_SHA256, TLS_AES_128_GCM_SHA256})
    {
      tcp::socket client_socket{io_service}, server_socket{io_service};
      tls_record_layer client_record_layer{connection_end::CLIENT,
                                           std::forward<tcp::socket>(client_socket)};
      tls_record_layer server_record_layer{connection_end::SERVER,
                                           std::forward<tcp::socket>(server_socket)};

      // compute keys and set up read/write states
      auto activate = [&cs, &type](tls_record_layer& layer) {
        layer.set_cipher_suite(cs);
        layer.compute_early_secrets(psk, some_messages);
        layer.compute_handshake_traffic_keys(dhe, some_messages);
        if (type == TLS_APPLICATION_DATA)
          layer.compute_application_traffic_keys(some_messages);
        layer.update_read_key();
        layer.update_write_key();
      };
      activate(client_record_layer);
      activate(server_record_layer);

      for (unsigned int r = 0; r < 2; ++r, ecc += 2)
      {
        // encrypt
        tls13_cipher::record record1, record2;
        bool ret = client_record_layer.encrypt(type, "ab"_x, record1);
        ck_assert_uint_eq(ret, true);
        ck_assert_uint_ne(record1.ciphertext.size(), 1);
        if (test_header_type)
          ck_assert_uint_eq(record1.header.type, TLS_APPLICATION_DATA);
        if (check_expected_ciphertext)
          ck_assert_array_split_eq(record1.ciphertext, expected_ciphertexts[ecc]);

        ret = server_record_layer.encrypt(type, "cd"_x, record2);
        ck_assert_uint_eq(ret, true);
        ck_assert_uint_ne(record2.ciphertext.size(), 1);
        if (test_header_type)
          ck_assert_uint_eq(record2.header.type, TLS_APPLICATION_DATA);
        if (check_expected_ciphertext)
          ck_assert_array_split_eq(record2.ciphertext, expected_ciphertexts[ecc + 1]);

        // decrypt
        std::vector<uint8_t> plain1, plain2;
        content_type type1, type2;
        ret = client_record_layer.decrypt(record2, plain1, type1);
        ck_assert_uint_eq(ret, true);
        ck_assert_uint_eq(type1, type);
        ck_assert_array_split_eq(plain1, "cd"_x);

        ret = server_record_layer.decrypt(record1, plain2, type2);
        ck_assert_uint_eq(ret, true);
        ck_assert_uint_eq(type2, type);
        ck_assert_array_split_eq(plain2, "ab"_x);
      }
    }
  }
} // namespace

START_TEST(record_layer_handshake_encrypted)
{
  encrypted_message(TLS_HANDSHAKE, false, false);
}
END_TEST

START_TEST(record_layer_application_data_encrypted)
{
  encrypted_message(TLS_APPLICATION_DATA, false, false);
}
END_TEST

START_TEST(record_layer_handshake_encrypted_type)
{
  encrypted_message(TLS_HANDSHAKE, true, false);
}
END_TEST

START_TEST(record_layer_application_data_encrypted_type)
{
  encrypted_message(TLS_APPLICATION_DATA, true, false);
}
END_TEST

START_TEST(record_layer_handshake_encrypted_expected)
{
  encrypted_message(TLS_HANDSHAKE, false, true);
}
END_TEST

START_TEST(record_layer_application_data_encrypted_expected)
{
  encrypted_message(TLS_APPLICATION_DATA, false, true);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("TLS");

  // Test cases for the record layer
  TCase* tcase = tcase_create("Record layer");
  tcase_add_test(tcase, record_layer_compute_early_secrets);
  tcase_add_test(tcase, record_layer_compute_handshake_traffic_keys);
  tcase_add_test(tcase, record_layer_compute_handshake_derived_key);
  tcase_add_test(tcase, record_layer_handshake_encrypted);
  tcase_add_test(tcase, record_layer_application_data_encrypted);
  tcase_add_test(tcase, record_layer_handshake_encrypted_type);
  tcase_add_test(tcase, record_layer_application_data_encrypted_type);
  tcase_add_test(tcase, record_layer_handshake_encrypted_expected);
  tcase_add_test(tcase, record_layer_application_data_encrypted_expected);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
