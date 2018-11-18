#ifndef TLS_H
#define TLS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <vector>
#include <string>

typedef std::map<std::string, std::vector<uint8_t>> psk_map;

enum connection_end
{
  SERVER,
  CLIENT
};

/// TLS version constants
enum version_constants : uint8_t
{
  TLSv1_2_MAJOR = 3,
  TLSv1_2_MINOR = 3,
  TLSv1_3_MAJOR = 3,
  TLSv1_3_MINOR = 4
};

/// TLS content type constants
enum content_type : uint8_t
{
  TLS_ALERT            = 21,
  TLS_HANDSHAKE        = 22,
  TLS_APPLICATION_DATA = 23
};

/// The protocol version.
struct protocol_version
{
  /// Major protocol version.
  uint8_t major;
  /// Minor protocol version.
  uint8_t minor;

  bool operator==(const protocol_version& b) const
  {
    return major == b.major && minor == b.minor;
  }

  bool operator!=(const protocol_version& b) const
  {
    return major != b.major || minor != b.minor;
  }
} __attribute__((packed));

constexpr protocol_version TLSv1_2{TLSv1_2_MAJOR, TLSv1_2_MINOR};
constexpr protocol_version TLSv1_3{TLSv1_3_MAJOR, TLSv1_3_MINOR};

/// The header of the record layer consisting of type, version and length.
struct record_layer_header
{
  /// Record type
  content_type type;
  /// Protocol version
  protocol_version version;
  /// Size of the transmitted payload, e.g. the size of the cipher text.
  uint16_t length;
} __attribute__((packed));

enum handshake_types : uint8_t
{
  HELLO_REQUEST       = 0,
  CLIENT_HELLO        = 1,
  SERVER_HELLO        = 2,
  SERVER_HELLO_DONE   = 14,
  CLIENT_KEY_EXCHANGE = 16,
  FINISHED            = 20
};

struct handshake_message_header
{
  handshake_types msg_type;
  uint8_t length[3];
} __attribute__((packed));

struct random_struct
{
  uint8_t random_bytes[32];
} __attribute__((packed));

struct cipher_suite
{
  bool operator==(const cipher_suite& b) const
  {
    return type[0] == b.type[0] && type[1] == b.type[1];
  }

  bool operator!=(const cipher_suite& b) const
  {
    return type[0] != b.type[0] || type[1] != b.type[1];
  }

  uint8_t type[2];
} __attribute__((packed));

constexpr cipher_suite TLS_AES_128_GCM_SHA256 = {0x13, 0x01};
constexpr cipher_suite TLS_ASCON_128_SHA256   = {0xFF, 0x01};
typedef std::vector<cipher_suite> cipher_suites;

enum AlertLevel : uint8_t
{
  warning = 1,
  fatal   = 2
};

enum AlertDescription : uint8_t
{
  close_notify                    = 0,
  unexpected_message              = 10,
  bad_record_mac                  = 20,
  record_overflow                 = 22,
  handshake_failure               = 40,
  bad_certificate                 = 42,
  unsupported_certificate         = 43,
  certificate_revoked             = 44,
  certificate_expired             = 45,
  certificate_unknown             = 46,
  illegal_parameter               = 47,
  unknown_ca                      = 48,
  access_denied                   = 49,
  decode_error                    = 50,
  decrypt_error                   = 51,
  protocol_version                = 70,
  insufficient_security           = 71,
  internal_error                  = 80,
  inappropriate_fallback          = 86,
  user_canceled                   = 90,
  missing_extension               = 109,
  unsupported_extension           = 110,
  unrecognized_name               = 112,
  bad_certificate_status_response = 113,
  unknown_psk_identity            = 115,
  certificate_required            = 116,
  no_application_protocol         = 120,

  ok = 255,
};

enum Location
{
  local,
  remote
};

/// An alert with a location.
/// "Remote" alerts where received as TLS_ALERT messages.
/// "Local" alerts where generated locally.
struct alert_location
{
  Location location;
  AlertDescription alert;

  operator bool() const
  {
    return alert == ok;
  }
};

std::ostream& operator<<(std::ostream& os, const alert_location& alert);

struct Alert
{
  AlertLevel level;
  AlertDescription description;
} __attribute__((packed));

enum ExtensionType : uint16_t
{
  SUPPORTED_GROUPS          = 10,
  PRE_SHARED_KEY            = 41,
  EARLY_DATA                = 42,
  SUPPORTED_VERSIONS        = 43,
  COOKIE                    = 44,
  PSK_KEY_EXCHANGE_MODES    = 45,
  CERTIFICATE_AUTHORITIES   = 47,
  OID_FILTERS               = 48,
  POST_HANDSHAKE_AUTH       = 49,
  SIGNATURE_ALGORITHMS_CERT = 50,
  KEY_SHARE                 = 51
};

enum PskKeyExchangeMode : uint8_t
{
  PSK_KE     = 0,
  PSK_DHE_KE = 1
};

enum NamedGroup : uint16_t
{
  SECP_256_R1 = 0x0017
};

struct Extension
{
  ExtensionType type;
  std::vector<uint8_t> data;
};

struct HandshakePayload
{
  uint16_t legacy_version;
  struct random_struct random;
  std::vector<uint8_t> legacy_session_id;
  std::vector<cipher_suite> cipher_suites;
  std::vector<uint8_t> legacy_compression_methods;
  std::vector<Extension> extentions;
};

struct HandshakePackage
{
  handshake_message_header message_header;
  HandshakePayload payload;
};

struct KeyShareEntry
{
  NamedGroup group;
  std::vector<uint8_t> data;
};

struct PskIdentity
{
  std::string identity;
  uint32_t obfuscated_ticket_age;
};

struct OfferedPsks
{
  std::vector<PskIdentity> identities;
  std::vector<uint8_t> binders;
};

#endif
