/*
 * Distributed under the OpenDDS License.
 * See: http://www.opendds.org/license.html
 */

#include <dds/OpenDDSConfigWrapper.h>

#if OPENDDS_CONFIG_SECURITY

#include <dds/DCPS/SecurityAlgorithms.h>

#include <gtest/gtest.h>

namespace {

using namespace DDS::Security;
using namespace OpenDDS::DCPS;

TEST(dds_DCPS_SecurityAlgorithms, RequiredAlgorithmsMustBeSupported)
{
  EXPECT_TRUE(check_crypto_algorithm_compatibility(0x7, 0x3));
  EXPECT_FALSE(check_crypto_algorithm_compatibility(0x1, 0x3));
  EXPECT_TRUE(check_crypto_algorithm_compatibility(
    0x1, 0x3 | CRYPTO_ALGORITHM_COMPATIBILITY_MODE));
  EXPECT_FALSE(check_crypto_algorithm_compatibility(
    0x4, 0x3 | CRYPTO_ALGORITHM_COMPATIBILITY_MODE));
}

TEST(dds_DCPS_SecurityAlgorithms, CompatibilityIsBilateral)
{
  CryptoAlgorithmRequirements lhs = {0x3, 0x1};
  CryptoAlgorithmRequirements rhs = {0x1, 0x1};
  EXPECT_TRUE(compatible(lhs, rhs));

  rhs.required_mask = 0x4;
  EXPECT_FALSE(compatible(lhs, rhs));
}

TEST(dds_DCPS_SecurityAlgorithms, Version11Defaults)
{
  ParticipantSecurityAlgorithmInfo value;
  default_participant_security_algorithm_info(value);

  EXPECT_EQ(CBIT_ECDSA_P256_SHA256,
            value.digital_signature.message_auth.required_mask);
  EXPECT_EQ(CBIT_ECDHE_CEUM_P256,
            value.key_establishment.shared_secret.required_mask);
  EXPECT_EQ(CBIT_AES256_GCM,
            value.symmetric_cipher.builtin_endpoints_required_mask);
  EXPECT_FALSE(has_vendor_specific_requirements(value));

  value.key_establishment.shared_secret.required_mask = 0x00010000;
  EXPECT_TRUE(has_vendor_specific_requirements(value));
}

} // namespace

#endif // OPENDDS_CONFIG_SECURITY
