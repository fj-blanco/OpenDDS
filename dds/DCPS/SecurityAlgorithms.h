/*
 * Distributed under the OpenDDS License.
 * See: http://www.opendds.org/license.html
 */

#ifndef OPENDDS_DCPS_SECURITY_ALGORITHMS_H
#define OPENDDS_DCPS_SECURITY_ALGORITHMS_H

#include <dds/OpenDDSConfigWrapper.h>

#if OPENDDS_CONFIG_SECURITY

#include <dds/DdsSecurityCoreC.h>
#include <dds/Versioned_Namespace.h>

OPENDDS_BEGIN_VERSIONED_NAMESPACE_DECL

namespace OpenDDS {
namespace DCPS {

inline bool check_crypto_algorithm_compatibility(
  DDS::Security::CryptoAlgorithmSet supported_mask,
  DDS::Security::CryptoAlgorithmSet required_mask)
{
  using namespace DDS::Security;
  return (required_mask & supported_mask) == required_mask ||
    ((required_mask & supported_mask) != 0 &&
     (required_mask & CRYPTO_ALGORITHM_COMPATIBILITY_MODE) != 0);
}

inline bool compatible(const DDS::Security::CryptoAlgorithmRequirements& lhs,
                       const DDS::Security::CryptoAlgorithmRequirements& rhs)
{
  return check_crypto_algorithm_compatibility(rhs.supported_mask, lhs.required_mask) &&
    check_crypto_algorithm_compatibility(lhs.supported_mask, rhs.required_mask);
}

inline bool compatible(
  const DDS::Security::ParticipantSecurityDigitalSignatureAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityDigitalSignatureAlgorithmInfo& rhs)
{
  return compatible(lhs.trust_chain, rhs.trust_chain) &&
    compatible(lhs.message_auth, rhs.message_auth);
}

inline bool compatible(
  const DDS::Security::ParticipantSecurityKeyEstablishmentAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityKeyEstablishmentAlgorithmInfo& rhs)
{
  return compatible(lhs.shared_secret, rhs.shared_secret);
}

inline bool compatible(
  const DDS::Security::ParticipantSecuritySymmetricCipherAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecuritySymmetricCipherAlgorithmInfo& rhs)
{
  return check_crypto_algorithm_compatibility(
           rhs.supported_mask, lhs.builtin_endpoints_required_mask) &&
    check_crypto_algorithm_compatibility(
           rhs.supported_mask, lhs.builtin_kx_endpoints_required_mask) &&
    check_crypto_algorithm_compatibility(
           lhs.supported_mask, rhs.builtin_endpoints_required_mask) &&
    check_crypto_algorithm_compatibility(
           lhs.supported_mask, rhs.builtin_kx_endpoints_required_mask);
}

inline bool authentication_algorithms_compatible(
  const DDS::Security::ParticipantSecurityAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityAlgorithmInfo& rhs)
{
  return compatible(lhs.digital_signature, rhs.digital_signature) &&
    compatible(lhs.key_establishment, rhs.key_establishment);
}

inline bool participant_algorithms_compatible(
  const DDS::Security::ParticipantSecurityAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityAlgorithmInfo& rhs)
{
  return authentication_algorithms_compatible(lhs, rhs) &&
    compatible(lhs.symmetric_cipher, rhs.symmetric_cipher);
}

inline bool has_vendor_specific_authentication_requirements(
  const DDS::Security::ParticipantSecurityAlgorithmInfo& value)
{
  const DDS::Security::CryptoAlgorithmSet vendor_mask = 0x7fff0000;
  return (value.digital_signature.trust_chain.required_mask & vendor_mask) != 0 ||
    (value.digital_signature.message_auth.required_mask & vendor_mask) != 0 ||
    (value.key_establishment.shared_secret.required_mask & vendor_mask) != 0;
}

inline bool has_vendor_specific_requirements(
  const DDS::Security::ParticipantSecurityAlgorithmInfo& value)
{
  const DDS::Security::CryptoAlgorithmSet vendor_mask = 0x7fff0000;
  return has_vendor_specific_authentication_requirements(value) ||
    (value.symmetric_cipher.builtin_endpoints_required_mask & vendor_mask) != 0 ||
    (value.symmetric_cipher.builtin_kx_endpoints_required_mask & vendor_mask) != 0;
}

inline void default_participant_security_algorithm_info(
  DDS::Security::ParticipantSecurityAlgorithmInfo& value)
{
  using namespace DDS::Security;
  value.digital_signature.trust_chain.supported_mask =
    CBIT_RSASSA_PSS_MGF1SHA256_2048_SHA256 |
    CBIT_RSASSA_PKCS1_V15_2048_SHA256 |
    CBIT_ECDSA_P256_SHA256;
  value.digital_signature.trust_chain.required_mask = CBIT_ECDSA_P256_SHA256;
  value.digital_signature.message_auth.supported_mask =
    CBIT_RSASSA_PSS_MGF1SHA256_2048_SHA256 | CBIT_ECDSA_P256_SHA256;
  value.digital_signature.message_auth.required_mask = CBIT_ECDSA_P256_SHA256;
  value.key_establishment.shared_secret.supported_mask =
    CBIT_DHE_MODP_2048_256 | CBIT_ECDHE_CEUM_P256;
  value.key_establishment.shared_secret.required_mask = CBIT_ECDHE_CEUM_P256;
  value.symmetric_cipher.supported_mask = CBIT_AES128_GCM | CBIT_AES256_GCM;
  value.symmetric_cipher.builtin_endpoints_required_mask = CBIT_AES256_GCM;
  value.symmetric_cipher.builtin_kx_endpoints_required_mask = CBIT_AES256_GCM;
  value.symmetric_cipher.user_endpoints_default_required_mask = CBIT_AES256_GCM;
}

inline void participant_security_config_from_attributes(
  DDS::Security::ParticipantSecurityConfig& config,
  const DDS::Security::ParticipantSecurityAttributes& attributes)
{
  using namespace DDS::Security;
  config.allow_unauthenticated_participants = attributes.allow_unauthenticated_participants;
  config.is_access_protected = attributes.is_access_protected;
  config.is_rtps_axk_protected = attributes.is_rtps_protected;
  config.is_rtps_psk_protected = false;
  config.is_discovery_protected = attributes.is_discovery_protected;
  config.is_liveliness_protected = attributes.is_liveliness_protected;
  config.is_key_revision_enabled = false;
  config.plugin_participant_attributes = attributes.plugin_participant_attributes;
  config.ac_endpoint_properties = attributes.ac_endpoint_properties;

  default_participant_security_algorithm_info(config.algorithm_info);
  config.algorithm_info.digital_signature.trust_chain.supported_mask =
    CRYPTO_ALGORITHM_SET_ALL;
  config.algorithm_info.digital_signature.trust_chain.required_mask =
    CRYPTO_ALGORITHM_SET_EMPTY;
  config.algorithm_info.digital_signature.message_auth.supported_mask =
    CRYPTO_ALGORITHM_SET_ALL;
  config.algorithm_info.digital_signature.message_auth.required_mask =
    CRYPTO_ALGORITHM_SET_EMPTY;
  config.algorithm_info.key_establishment.shared_secret.supported_mask =
    CRYPTO_ALGORITHM_SET_ALL;
  config.algorithm_info.key_establishment.shared_secret.required_mask =
    CRYPTO_ALGORITHM_SET_EMPTY;
}

inline bool equal(const DDS::Security::CryptoAlgorithmRequirements& lhs,
                  const DDS::Security::CryptoAlgorithmRequirements& rhs)
{
  return lhs.supported_mask == rhs.supported_mask &&
    lhs.required_mask == rhs.required_mask;
}

inline bool equal(
  const DDS::Security::ParticipantSecurityDigitalSignatureAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityDigitalSignatureAlgorithmInfo& rhs)
{
  return equal(lhs.trust_chain, rhs.trust_chain) && equal(lhs.message_auth, rhs.message_auth);
}

inline bool equal(
  const DDS::Security::ParticipantSecurityKeyEstablishmentAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecurityKeyEstablishmentAlgorithmInfo& rhs)
{
  return equal(lhs.shared_secret, rhs.shared_secret);
}

inline bool equal(
  const DDS::Security::ParticipantSecuritySymmetricCipherAlgorithmInfo& lhs,
  const DDS::Security::ParticipantSecuritySymmetricCipherAlgorithmInfo& rhs)
{
  return lhs.supported_mask == rhs.supported_mask &&
    lhs.builtin_endpoints_required_mask == rhs.builtin_endpoints_required_mask &&
    lhs.builtin_kx_endpoints_required_mask == rhs.builtin_kx_endpoints_required_mask &&
    lhs.user_endpoints_default_required_mask == rhs.user_endpoints_default_required_mask;
}

} // namespace DCPS
} // namespace OpenDDS

OPENDDS_END_VERSIONED_NAMESPACE_DECL

#endif // OPENDDS_CONFIG_SECURITY

#endif // OPENDDS_DCPS_SECURITY_ALGORITHMS_H
