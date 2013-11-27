from time import sleep
from unittest import TestSuite
import logging
import sys
from pyYubitool.yubikeyutil import YubikeyUrl, YubikeyValidation, YubikeyDb

__author__ = 'Hans Hoerberg'

import unittest
import copy

testlogger = logging.getLogger()

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
testlogger.addHandler(ch)
testlogger.setLevel(logging.DEBUG)
testlogger.info('sadfsdf')

class VerifyYubikeyClientTest(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        unittest.TestCase.__init__(self, methodName)
        self.server = "http://130.239.201.5:8000/wsapi/2.0/verify"
        self.correctKey = \
            {
                "yubikeyprefix": "vvbiughhdfeh",
                "otp": "vvbiughhdfehjleruetelhfvurjrhebceghdttujduef",
            }

        #Adress to local server
        self.localServer = "https://localhost:8181/wsapi/2.0/verify"

        #Address to the yubico server
        self.yubicoServer = "http://api2.yubico.com/wsapi/2.0/verify"

        self.server = "http://130.239.201.5:8000/wsapi/2.0/verify"

        #Test api key
        self.api_key = "whatevermykeyis"

        #You have to configure this database yourself, to work with Yubico and/or your own yubikey server.
        self.mydb = "../../../db/yubikeyconf.db"


        self.testDatabase = "../../../db/yubikeylocaltest.db"

        self.correctpayload = {
                            'nonce': 'mytestnounce',
                            'otp': 'vvbiughhdfehjleruetelhfvurjrhebceghdttujduef',
                            'timestamp': '1',
                            'timeout': '2',
                            'sl': '100',
                            'h': "Zk5CIaoULnSBq6AFDrVnVKwCSTI=",
                            'id': 5}


    def test_configuration_localserver_your_otp_yubico(self):
        """
        This test will verify that the yubico implementation of a server and client still works.
        You can run this test as many times as you like and need no configurations.
        """
        print "Performing test test_configuration_localserver_your_otp_yubico."
        print "Testing the local server and client!"
        validator = YubikeyValidation(None)

        username = "testuser1"

        db = YubikeyDb(self.testDatabase)
        db.clear_all_logs()

        otplist = [
            {"otp": "vvghndudfdbtrjnvehrjllnncdirbcegjghnhugtrkre", "time": 4},
            {"otp": "vvghndudfdbtknuvbrkhhrubulhciilkbtjuiktkiflj", "time": 5},
            {"otp": "vvghndudfdbtfiungirtikiketnhrdlljhjkjungunfc", "time": 8},
            {"otp": "vvghndudfdbthriturtfendvthgluebtbvbinukuuknk", "time": 12},
            {"otp": "vvghndudfdbtlfleblhiuveuiibcfejlgukicnrcnbir", "time": 0}
        ]

        result = validator.validate_opt(username, otplist[4]["otp"], self.testDatabase, 1)
        self.assertTrue(result)

        result = validator.validate_opt(username, otplist[0]["otp"], self.testDatabase, 1)
        self.assertFalse(result)

        db.clear_all_logs()

        for otp in otplist:
            print "Testing otp " + otp["otp"] + "."
            result = validator.validate_opt(username, otp["otp"], self.testDatabase, 1)
            self.assertTrue(result)
            print "Sleep for " + str(otp["time"]) + "seconds."
            sleep(otp["time"])

        result = validator.validate_opt(username, otplist[1]["otp"], self.testDatabase, 1)
        self.assertFalse(result)
        print "Test test_configuration_localserver_your_otp_yubico done."

    def test_configuration_localhost_server(self):
        """
        This test will verify that the yubikey validation server works.
        To get a correct result you first have to start the server.

        Command: python yubikeyserver.py yubikeyserver_conf

        You must use the default configuration and the testdatabase yubikeylocaltest.db
        """
        print "Performing test test_configuration_localhost_server."
        validator = YubikeyValidation(self.localServer)

        print "Testing server " + self.localServer
        user = "testuser1"

        otplist = [
            {"otp": "vvghndudfdbtrjnvehrjllnncdirbcegjghnhugtrkre", "time": 4},
            {"otp": "vvghndudfdbtknuvbrkhhrubulhciilkbtjuiktkiflj", "time": 5},
            {"otp": "vvghndudfdbtfiungirtikiketnhrdlljhjkjungunfc", "time": 8},
            {"otp": "vvghndudfdbthriturtfendvthgluebtbvbinukuuknk", "time": 12},
            {"otp": "vvghndudfdbtlfleblhiuveuiibcfejlgukicnrcnbir", "time": 0}
        ]

        db = YubikeyDb(self.testDatabase)
        db.clear_all_logs()

        for otp in otplist:
            result = validator.validate_opt(user, otp["otp"], self.testDatabase,
                         timestamp = 1,
                         timestamp_error_margin = 40,
                         allow_duplicated_nonce=False,
                         verifyssl=False)
            self.assertTrue(result)
            print "Sleep for " + str(otp["time"]) + "seconds."
            sleep(otp["time"])
        print "Test test_configuration_localhost_server done."

    def test_configuration_realserver_your_otp_yubico(self):
        """
        To run this test you have to create and configure the database yubikeyconf.db with a yubikey
        that is active on yubico's servers.
        http://www.yubico.com/products/services-software/personalization-tools/use/

        You also have to obtains an api_key/id that is active at yubico.
        https://upgrade.yubico.com/getapikey/yubi
        """
        print "Performing test test_configuration_realserver_your_otp_yubico."

        #db = YubikeyDb(self.mydb)
        #db.clear_all_logs()

        validator = YubikeyValidation(self.yubicoServer)

        print "Testing server " + self.yubicoServer
        user = raw_input("Your username:")
        otp = raw_input("Your otp:")

        #This server support timestamp=1.
        result = validator.validate_opt(user, otp, self.mydb, 1)
        self.assertTrue(result)
        print "Test test_configuration_realserver_your_otp_yubico done."


    def test_configuration_realserver_your_otp_other_server(self):
        """
        To run this test you have to create and configure the database with a yubikey
        that is active on your own yubikey validation server.

        For example: http://code.google.com/p/yubico-yubiserve/
        (This server do not allow timestamp verifications.)

        You also have to obtains an api_key/id for your server and add it to the database.:

        """
        print "Performing test test_configuration_realserver_your_otp_other_server."

        #db = YubikeyDb(self.mydb)
        #db.clear_all_logs()

        validator = YubikeyValidation(self.server)

        print "Testing server " + self.server
        user = raw_input("Your username:")
        otp = raw_input("Your otp:")

        #Test the server without timestamp verification.
        result = validator.validate_opt(user, otp, self.mydb, 0)
        self.assertTrue(result)
        print "Test test_configuration_realserver_your_otp_other_server done."


    def test_validate_signature_in_payload(self):
        """
        Validates that the hash algorithm works.
        """
        print "Performing test test_validate_signature_in_payload."
        api_key = self.api_key
        yubikeyurl = YubikeyUrl()
        self.assertTrue(yubikeyurl.validate_signature_in_payload(self.correctpayload, api_key))
        payload = copy.deepcopy(self.correctpayload)
        payload.pop("otp", None)
        self.assertFalse(yubikeyurl.validate_signature_in_payload(payload, api_key))
        payload = copy.deepcopy(self.correctpayload)
        payload["otp"] = "vvecbvudnvcilfuncbkvfekkbluuikfthgutgvrehnuk"
        self.assertFalse(yubikeyurl.validate_signature_in_payload(payload, api_key))
        payload = copy.deepcopy(self.correctpayload)
        payload.pop("h", None)
        self.assertFalse(yubikeyurl.validate_signature_in_payload(payload, api_key))
        payload = copy.deepcopy(self.correctpayload)
        payload["nonce"] = "theevildude"
        self.assertFalse(yubikeyurl.validate_signature_in_payload(payload, api_key))
        print "Test test_validate_signature_in_payload done."

    def test_create_request_payload(self):
        """
        Validates that the payload is created correctly.
        """
        print "Performing test test_create_request_payload."
        yubikeyurl = YubikeyUrl()
        requestpayload = yubikeyurl.create_request_payload(self.api_key, self.correctpayload["id"],
                                                             self.correctpayload["nonce"],self.correctKey["otp"])
        self.assertDictContainsSubset(self.correctpayload, requestpayload)
        self.assertTrue(yubikeyurl.validate_signature_in_payload(requestpayload, self.api_key))
        print "Test test_create_request_payload done."


if __name__ == '__main__':
    #unittest.main()
    suite  = TestSuite()
    #suite.addTest(VerifyYubikeyClientTest('test_create_request_payload'))
    #suite.addTest(VerifyYubikeyClientTest('test_validate_signature_in_payload'))
    #suite.addTest(VerifyYubikeyClientTest('test_configuration_localserver_your_otp_yubico'))
    #The tests below demands actions from the testers side.
    #suite.addTest(VerifyYubikeyClientTest('test_configuration_localhost_server'))
    suite.addTest(VerifyYubikeyClientTest('test_configuration_realserver_your_otp_yubico'))
    #suite.addTest(VerifyYubikeyClientTest('test_configuration_realserver_your_otp_other_server'))

    unittest.TextTestRunner().run(suite)

