from pyYubitool.yubikeyutil import Yubikey, OTPInvalid

__author__ = 'Hans Hoerberg'

import unittest


class RuleRoleTest(unittest.TestCase):


    def __init__(self, methodName='runTest'):
        unittest.TestCase.__init__(self, methodName)

        self.correct_yubikey = [
            {
                "comment": "Verifying a correct OTP.",
                "yubikeyprefix": "vvbiughhdfeh",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "vvbiughhdfehjleruetelhfvurjrhebceghdttujduef",
                "useCtr": 1,
                "sessionCtr": 0,
                "tstp": 12013883,
                "rnd": 45743,
            },
            {
                "comment": "Verifying a correct OTP.",
                "yubikeyprefix": "vvbiughhdfeh",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "vvbiughhdfehdfflhhtlbuudcuulbnedgkdvubcurnfi",
                "useCtr": 1,
                "sessionCtr": 1,
                "tstp": 12070661,
                "rnd": 3170,
            },
            {
                "comment": "Verifying a short yubikey prefix.",
                "yubikeyprefix": "abc",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "abcdfflhhtlbuudcuulbnedgkdvubcurnfi",
                "useCtr": 1,
                "sessionCtr": 1,
                "tstp": 12070661,
                "rnd": 3170,
            }
        ]

        self.wrong_crc_yubikey = {
                "comment": "Validate crc.",
                "yubikeyprefix": "abc",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "fffffflhhtlbuudcuulbnedgkdvubcurnfi",
                "useCtr": 1,
                "sessionCtr": 1,
                "tstp": 12070661,
                "rnd": 3170,
            }
        
        self.invalid_otp = [
            {
                "comment": "Too long yubikeyprefix.",
                "yubikeyprefix": "vvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfeh",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "vvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehvvbiughhdfehdfflhhtlbuudcuulbnedgkdvubcurnfi",
            },
            {
                "comment": "To short OTP",
                "yubikeyprefix": "abc",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "abcdfflhhtlbuudcuulbnedgkdvub",
            },
            {
                "comment": "Invalid modhex in OTP.",
                "yubikeyprefix": "abc",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4ca",
                "otp": "abcdfflhhtlbuudcuulbnedgkdvubcurqqq",
            }
        ]

        self.invalid_aes_key =             \
            {
                "comment": "Verifying a correct OTP.",
                "yubikeyprefix": "vvbiughhdfeh",
                "internalidentity": "1f4d3b25740b",
                "aeskey": "2e1e8c40248a4a2102ac780ba79ac4cb",
                "otp": "vvbiughhdfehjleruetelhfvurjrhebceghdttujduef",
            }

    def testInvalidOTP(self):
        for testkey in self.invalid_otp:
            try:
                yubikey = Yubikey(testkey["otp"], testkey["aeskey"])
            except OTPInvalid:
                pass
            else:
                self.fail("OTPInvalid exception should occur!")

    def testCorrectOTP(self):
        for testkey in self.correct_yubikey:
            try:
                yubikey = Yubikey(testkey["otp"], testkey["aeskey"])
            except:
                self.fail("No exception should occur!")
            else:
                self.assertTrue(yubikey.validateCrc())
                self.assertTrue(yubikey.public_id() == testkey["yubikeyprefix"])
                self.assertTrue(yubikey.uid() == testkey["internalidentity"])
                self.assertTrue(yubikey.useCtr() == testkey["useCtr"])
                self.assertTrue(yubikey.sessionCtr() == testkey["sessionCtr"])
                self.assertTrue(yubikey.tstp() == testkey["tstp"])
                self.assertTrue(yubikey.rnd()== testkey["rnd"])

    def testWrongCrc(self):
            try:
                yubikey = Yubikey(self.wrong_crc_yubikey["otp"], self.wrong_crc_yubikey["aeskey"])
            except:
                self.fail("No exception should occur!")
            else:
                self.assertFalse(yubikey.validateCrc())

    def testInvalidAesKey(self):
            try:
                yubikey = Yubikey(self.invalid_aes_key["otp"], self.invalid_aes_key["aeskey"])
            except:
                self.fail("No exception should occur!")
            else:
                self.assertFalse(yubikey.validateCrc())
                self.assertTrue(yubikey.public_id() == self.invalid_aes_key["yubikeyprefix"])
                self.assertFalse(yubikey.uid() == self.invalid_aes_key["internalidentity"])


if __name__ == '__main__':
    unittest.main()



