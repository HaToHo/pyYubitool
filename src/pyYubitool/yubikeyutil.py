import hmac
import hashlib
import random
import base64
import sqlite3
import math
import logging
import requests
import string
import time
from pyYubitool import yubikeyconf
from datetime import datetime

__author__ = 'haho0032'

import Crypto.Cipher.AES

#Add a logger for this class.
logger = logging.getLogger("yubikeyutil")


class OTPInvalid(Exception):
    pass


class OTPServerError(Exception):
    pass


class YubikeyDb:

    def __init__(self, database):
        self.database = database

    def connect(self):
        conn = sqlite3.connect(self.database)
        return conn

#CLIENT METHODS
    def public_id_exists(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM client_yubikey_users cyu where cyu.public_id=?', (public_id, ))
        response = c.fetchone()
        count = response[0]
        conn.close()
        return count > 0

    def user_from_public_id(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT cyu.user_name FROM client_yubikey_users cyu where cyu.public_id=?', (public_id, ))
        response = c.fetchone()
        user = response[0]
        conn.close()
        return user

    def user_exists(self, user):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM client_yubikey_users cyu where cyu.user=?', (user, ))
        response = c.fetchone()
        count = response[0]
        conn.close()
        return count > 0

    def id_from_server(self, server):
        if server is None:
            server = ""
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT cs.id FROM client_servers cs where cs.server_url=?', (server, ))
        response = c.fetchone()
        id = response[0]
        conn.close()
        return id

    def api_key_from_server(self, server):
        if server is None:
            server = ""
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT cs.api_key FROM client_servers cs where cs.server_url=?', (server, ))
        response = c.fetchone()
        api_key = response[0]
        conn.close()
        return base64.b64decode(api_key)

    def addClientSessionLog(self, public_id, utc_timestamp, seconds19700101, yubikey_timestamp,
                            yubikey_session_counter, yubikey_sessionuse):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM client_session_log csl where csl.public_id=?', (public_id, ))
        response = c.fetchone()
        count = response[0]

        if count > 0:
            c.execute('DELETE FROM client_session_log where public_id = ?', (public_id,))


        c.execute("INSERT INTO client_session_log VALUES (?,?,?,?,?,?)", (public_id ,utc_timestamp,
        seconds19700101, yubikey_timestamp, yubikey_session_counter, yubikey_sessionuse))

        conn.commit()
        conn.close()

    def lastClientSessionLog(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT * FROM client_session_log csl where csl.public_id=?', (public_id, ))
        db_response = c.fetchmany()
        if db_response is None or len(db_response) == 0:
            return None
        response = {}
        response["public_id"] = db_response[0][0]
        response["utc_timestamp"] = db_response[0][1]
        response["seconds19700101"] = db_response[0][2]
        response["yubikey_timestamp"] = db_response[0][3]
        response["yubikey_session_counter"] = db_response[0][4]
        response["yubikey_sessionuse"] = db_response[0][5]
        return response



#SERVER METHODS

    def id_from_api_key(self, api_key):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT lsak.id FROM local_server_api_key lsak where lsak.api_key=?', (api_key, ))
        response = c.fetchone()
        id = response[0]
        conn.close()
        return id

    def api_key_from_id(self, id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT lsak.api_key FROM local_server_api_key lsak where lsak.id=?', (id, ))
        response = c.fetchone()
        api_key = response[0]
        conn.close()
        return base64.b64decode(api_key)

    def aes_from_public_id(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT lsy.aes FROM local_server_yubikey lsy where lsy.public_id=?', (public_id, ))
        response = c.fetchone()
        aes = response[0]
        conn.close()
        return aes

    def private_id_from_public_id(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT lsy.private_id FROM local_server_yubikey lsy where lsy.public_id=?', (public_id, ))
        response = c.fetchone()
        private_id = response[0]
        conn.close()
        return private_id

    def add_server_sessionLog(self, public_id, utc_timestamp, seconds19700101, yubikey_timestamp,
                            yubikey_session_counter, yubikey_sessionuse):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM local_server_session_log lssl where lssl.public_id=?', (public_id, ))
        response = c.fetchone()
        count = response[0]

        if count > 0:
            c.execute('DELETE FROM local_server_session_log where public_id = ?', (public_id,))


        c.execute("INSERT INTO local_server_session_log VALUES (?,?,?,?,?,?)", (public_id ,utc_timestamp,
        seconds19700101, yubikey_timestamp, yubikey_session_counter, yubikey_sessionuse))

        conn.commit()
        conn.close()

    def last_server_sessionLog(self, public_id):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT * FROM local_server_session_log lssl where lssl.public_id=?', (public_id, ))
        db_response = c.fetchmany()
        if db_response is None or len(db_response) == 0:
            return None
        response = {}
        response["public_id"] = db_response[0][0]
        response["utc_timestamp"] = db_response[0][1]
        response["seconds19700101"] = db_response[0][2]
        response["yubikey_timestamp"] = db_response[0][3]
        response["yubikey_session_counter"] = db_response[0][4]
        response["yubikey_sessionuse"] = db_response[0][5]
        return response

    def addOTP(self, otp):
        conn = self.connect()
        c = conn.cursor()
        c.execute("INSERT INTO local_server_replay_log VALUES (?)", (otp,))
        conn.commit()
        conn.close()

    def otp_exists(self, otp):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM local_server_replay_log lsrl where lsrl.otp=?', (otp, ))
        response = c.fetchone()
        count = response[0]
        conn.close()
        return count > 0

    def addNONCE(self, public_id, nonce):
        conn = self.connect()
        c = conn.cursor()
        c.execute("INSERT INTO local_server_replay_log_nonce VALUES (? ,?)", (public_id, nonce))
        conn.commit()
        conn.close()

    def nonce_exists(self, public_id, nonce):
        conn = self.connect()
        c = conn.cursor()
        c.execute('SELECT count(*) FROM local_server_replay_log_nonce lsrln where lsrln.public_id=? and lsrln.nonce=?',
                  (public_id, nonce))
        response = c.fetchone()
        count = response[0]
        conn.close()
        return count > 0

    def clear_all_logs(self):
        conn = self.connect()
        c = conn.cursor()
        c.execute('DELETE FROM local_server_session_log')
        c.execute('DELETE FROM local_server_replay_log_nonce')
        c.execute('DELETE FROM local_server_replay_log')
        c.execute('DELETE FROM client_session_log')
        conn.commit()
        conn.close()


class YubikeyValidation:

    def __init__(self, server):
        self.server = server

    def log_opt_user(self, otp, user):
        logger.warn("OTP: " + otp + " USER: " + user)

    def validate_opt(self, userid, otp, database, timestamp = 1, timestamp_error_margin = 900,
                     allow_duplicated_nonce=False, verifyssl=True):
        try:
            logger.info("--YubikeyValidation--")
            logger.info("OTP: " + otp + " USER: " + userid)

            db = YubikeyDb(database)
            key = Yubikey(otp, None)
            tmpuser = db.user_from_public_id(key.public_id())
            if tmpuser is None:
                return False
            if tmpuser != userid:
                return False
            yubikeyurl = YubikeyUrl()

            id = db.id_from_server(self.server)
            nonce = ''. join(random.choice(string.ascii_uppercase + string.digits) for x in range(30))
            api_key = db.api_key_from_server(self.server)
            payload = yubikeyurl.create_request_payload(api_key, id, nonce, otp, timestamp=timestamp)
            if not yubikeyurl.validate_signature_in_payload(payload, api_key):
                logger.warn("Signature not valid in the created payload. You have a problem with your configuration.")
                self.log_opt_user(otp, userid)
                return False
            if self.server is not None:
                response_payload = self.server_validate_otp(payload, verifyssl)
            else:
                response_payload = self.local_validate_otp(payload, database,timestamp_error_margin,
                                                           allow_duplicated_nonce)

            if not yubikeyurl.validate_signature_in_payload(response_payload, api_key):
                logger.warn("The signature in the server response is not valid.")
                self.log_opt_user(otp, userid)
                return False

            response_key = Yubikey(payload["otp"], None)
            if response_key.public_id() != key.public_id():
                logger.warn("The public id from the server is not the same as the sent public id. Possible man "
                            "in the middle attack")
                self.log_opt_user(otp, userid)
                return False

            #If not the correct parameters is returned from the server, the OTP cannot be considered validated.
            for param in yubikeyconf.RESPONSE_MANDATORY:
                if param not in response_payload:
                    logger.warn("The server is not responding correct. Missing parameter " + param + " in response.")
                    self.log_opt_user(otp, userid)
                    return False

            dt = datetime.now()
            secondssince197001 = int(time.mktime(dt.timetuple()))
            #If not the correct parameters is returned from the server, the OTP cannot be considered validated.
            if timestamp == 1:
                for param in yubikeyconf.RESPONSE_TIMESTAMP_MANDATORY:
                    if param not in response_payload:
                        logger.warn("The server is not responding correct. Missing parameter " + param + " in response.")
                        self.log_opt_user(otp, userid)
                        return False
                session_log = db.lastClientSessionLog(key.public_id())
                if session_log is not None:
                    if unicode(session_log["utc_timestamp"]) > response_payload["t"]:
                        logger.warn("UTC timestamp from the server is wrong. Previous timestamp" +
                        session_log["utc_timestamp"] + ". Timestamp from server: " + response_payload["t"])
                        self.log_opt_user(otp, userid)
                        return False
                    if int(session_log["yubikey_session_counter"]) > int(response_payload["sessioncounter"]):
                        logger.warn("The sessioncounter for the yubikey is lesser then last time. Possible attack!" +
                            "Last session counter: " + str(session_log["yubikey_session_counter"]) +
                            ". Session counter from server: " + str(response_payload["sessioncounter"]))
                        self.log_opt_user(otp, userid)
                        return False
                    elif int(session_log["yubikey_session_counter"]) == int(response_payload["sessioncounter"]):
                        if int(session_log["yubikey_sessionuse"]) > int(response_payload["sessionuse"]):
                            logger.warn("The session use for the yubikey is lesser then last time. Possible attack!" +
                            "Last session use: " + str(session_log["yubikey_sessionuse"]) +
                            ". Session use from server: " + str(response_payload["sessionuse"]))
                            self.log_opt_user(otp, userid)
                            return False
                        #The validation can only be performed during the same session.
                        yubikey_time1 = int(session_log["yubikey_timestamp"])
                        yubikey_time2 = int(response_payload["timestamp"])
                        if yubikey_time1 >= yubikey_time2:
                            logger.warn("The internal timestamp for the yubikey is not greater then last time. " +
                                        "Possible attack!" + "Last timestamp: " + str(yubikey_time1) +
                                        ". Timestamp from server: " + str(yubikey_time2))
                            self.log_opt_user(otp, userid)
                            return False
                        elapsedTime = secondssince197001-int(float(session_log["seconds19700101"]))
                        try:
                            self.validateTimeStamp(elapsedTime, timestamp_error_margin,
                                                   yubikey_time1, yubikey_time2)
                        except OTPInvalid:
                            logger.warn("The internal time since last use of the yubikey do not match with the saved value!")
                            self.log_opt_user(otp, userid)
                            return False

            if response_payload[yubikeyconf.STATUS_RESPONSE_PARAM] != yubikeyconf.OK:
                logger.warn("The yubikey validation server did not respond status OK. STATUS: " +
                            response_payload[yubikeyconf.STATUS_RESPONSE_PARAM])
                self.log_opt_user(otp, userid)
                return False

            if nonce != response_payload[yubikeyconf.NONCE_RESPONSE_PARAM]:
                logger.warn("The yubikey validation server responded with wrong nonce. Possible attack!" +
                " Expected nonce: " + nonce + " Retrieved nonce: " + response_payload[yubikeyconf.NONCE_RESPONSE_PARAM])
                self.log_opt_user(otp, userid)
                return False

            if yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.SECURITYLEVEL_REQUEST_PARAM] != \
                    response_payload[yubikeyconf.SECURITYLEVEL_RESPONSE_PARAM]:
                logger.warn("The server responded with the wrong security level." +
                " Expected sl: " + yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.SECURITYLEVEL_REQUEST_PARAM]
                + " Retrieved sl: " + response_payload[yubikeyconf.SECURITYLEVEL_RESPONSE_PARAM])
                self.log_opt_user(otp, userid)
                return False

            #if not self.validate_response(key.public_id(), otp, nonce, response_payload):
            #    return False

            if timestamp == 1:
                db.addClientSessionLog(key.public_id(), response_payload['t'], secondssince197001,
                                       response_payload['timestamp'], response_payload['sessioncounter'],
                                       response_payload['sessionuse'])

            return True
        except Exception as ex:
            self.log_opt_user(otp, userid)
            logger.error("A uknown error has occured! Message: " + ex.message)
            return False

    def parse_server_response(self, response):
        response_payload = {}
        response = response.split("\r\n")
        for value in response:
            keyvalue = value.split("=", 1)
            if (len(keyvalue) == 2):
                response_payload[keyvalue[0]] = keyvalue[1]
        return response_payload

    def server_validate_otp(self, payload, verify=True):
        try:
            response_payload = {}
            response = requests.get(self.server, params=payload, verify=verify)
            if response.status_code == 200:
                return self.parse_server_response(response.content)
            raise OTPServerError()
        except Exception as ex:
            raise OTPServerError(ex.message)

    def local_validate_otp(self, payload, databas, timestamp_error_margin = 900, allow_duplicated_nonce=False):
        """

        :param payload:
        :return: :raise:
        """
        logger.info("--local_validate_otp--")
        payloadlog = "Payload: "
        for key, value in payload.iteritems():
            payloadlog += str(key) + "=" + str(value) + ", "
        logger.info(payloadlog)
        yubikeyurl = YubikeyUrl()
        db = YubikeyDb(databas)
        public_id = None
        api_key = None
        otp = None
        response_payload = {}
        dt = datetime.now()
        secondssince197001 = int(time.mktime(dt.timetuple()))

        if yubikeyconf.OTP_REQUEST_PARAM in payload:
            id = payload[yubikeyconf.ID_REQUEST_PARAM]
            try:
                if db.api_key_from_id(id) is None:
                    logger.info("No api key is registered for the id in the payload.")
                    logger.info("Return: OPERATION_NOT_ALLOWED")
                    return self.create_yubikey_response_with_hash(response_payload,None,
                                                                  yubikeyconf.OPERATION_NOT_ALLOWED)
            except Exception as ex:
                logger.info("The id in the payload is causing an error. Message = " + ex.message)
                logger.info("Return: NO SUCH CLIENT")
                return self.create_yubikey_response_with_hash(response_payload,None, yubikeyconf.NO_SUCH_CLIENT)
            api_key = db.api_key_from_id(id)
        else:
            logger.info("No id in the payload.")
            logger.info("Return: NO SUCH CLIENT")
            return self.create_yubikey_response_with_hash(response_payload,None, yubikeyconf.NO_SUCH_CLIENT)

        if yubikeyconf.OTP_REQUEST_PARAM in payload:
            response_payload[yubikeyconf.OTP_RESPONSE_PARAM] = payload[yubikeyconf.OTP_REQUEST_PARAM]
            try:
                otp = response_payload[yubikeyconf.OTP_RESPONSE_PARAM]
                tmp_yubikey = Yubikey(response_payload[yubikeyconf.OTP_RESPONSE_PARAM], None)
                public_id = tmp_yubikey.public_id()
            except:
                public_id = None
        if public_id is None or otp is None:
            logger.info("No public id can be parsed from the OTP.")
            logger.info("Return: BAD_OTP")
            return self.create_yubikey_response_with_hash(response_payload, api_key, yubikeyconf.BAD_OTP)
        if yubikeyconf.NONCE_REQUEST_PARAM in payload:
            response_payload[yubikeyconf.NONCE_RESPONSE_PARAM] = payload[yubikeyconf.NONCE_REQUEST_PARAM]
        response_payload[yubikeyconf.SECURITYLEVEL_RESPONSE_PARAM] = "100"

        #Handle all optional parameters
        if yubikeyconf.TIMEOUT_REQUEST_PARAM in payload:
            #Timeout while performing requests to other servers. Not used by this server, since everythin is performed
            #localy. Status NOT_ENOUGH_ANSWER can never occur.
            pass
        if not yubikeyconf.TIMESTAMP_REQUEST_PARAM in payload:
            payload[yubikeyconf.TIMESTAMP_REQUEST_PARAM] = \
                yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.TIMESTAMP_REQUEST_PARAM]
        if yubikeyconf.SECURITYLEVEL_REQUEST_PARAM not in payload:
            pass
            #No extarnal validation server will be used, so the response will always be 100. No check needed.

        utc_time = str(datetime.utcnow())
        response_payload[yubikeyconf.UTC_TIMESTAMP_RESPONSE_PARAM] = utc_time


        #Verify mandatory parameters
        for param in yubikeyconf.REQUEST_MANDATORY:
            if param not in payload:
                logger.info("Missing the mandatory parameter " + param + ".")
                logger.info("Return: MISSING_PARAMETER")
                return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.MISSING_PARAMETER)

        if db.otp_exists(otp):
            logger.info("The OTP has already been used!")
            logger.info("Return: REPLAYED_OTP")
            return self.create_yubikey_response_with_hash(response_payload, api_key, yubikeyconf.REPLAYED_OTP)


        if not allow_duplicated_nonce:
            if db.nonce_exists(public_id, payload[yubikeyconf.NONCE_REQUEST_PARAM]):
                logger.info("The nonce have already been used for this OTP.")
                logger.info("Return: REPLAYED_REQUEST")
                return self.create_yubikey_response_with_hash(response_payload, api_key, yubikeyconf.REPLAYED_REQUEST)

        if not yubikeyurl.validate_signature_in_payload(payload, api_key):
            logger.info("The client signature is wrong!")
            logger.info("Return: BAD_SIGNATURE")
            return self.create_yubikey_response_with_hash(response_payload, api_key, yubikeyconf.BAD_SIGNATURE)

        aes = db.aes_from_public_id(public_id)

        try:
            yubikey = Yubikey(otp, aes)
            public_id = yubikey.public_id()
            if not yubikey.validateCrc():
                logger.info("The crc validation fails for the OTP.")
                logger.info("Return: BAD_OTP")
                return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.BAD_OTP)

            if yubikey.uid() != db.private_id_from_public_id(public_id):
                logger.info("The private id is wrong in the OTP.")
                logger.info("Return: BAD_OTP")
                return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.BAD_OTP)

            session_log = db.last_server_sessionLog(public_id)
            if session_log is not None:
                if unicode(session_log["utc_timestamp"]) > response_payload["t"]:
                    logger.info("The UTC timestamp in the response is earlier then the last response in the log.")
                    logger.info("Response UTC timestamp: " + response_payload["t"])
                    logger.info("Log UTC timestamp: " + session_log["utc_timestamp"])
                    logger.info("Return: BACKEND_ERROR")
                    return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.BACKEND_ERROR)
                if int(session_log["yubikey_session_counter"]) > int(yubikey.sessionCtr()):
                    logger.info("The session counter for the yubikey is lesser then in the log.")
                    logger.info("Session counter in response: " + str(yubikey.sessionCtr()))
                    logger.info("Session counter in log: " + str(session_log["yubikey_session_counter"]))
                    logger.info("Return: REPLAYED_REQUEST")
                    return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.REPLAYED_REQUEST)
                elif int(session_log["yubikey_session_counter"]) == int(yubikey.sessionCtr()):
                    if int(session_log["yubikey_sessionuse"]) > int(yubikey.useCtr()):
                        logger.info("The session use for the yubikey is lesser then in the log.")
                        logger.info("Session use in response: " + str(yubikey.useCtr()))
                        logger.info("Session use in log: " + str(session_log["yubikey_sessionuse"]))
                        logger.info("Return: REPLAYED_REQUEST")
                        return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.REPLAYED_REQUEST)

                    yubikey_time1 = int(session_log["yubikey_timestamp"])
                    yubikey_time2 = int(yubikey.tstp())
                    if yubikey_time1 >= yubikey_time2:
                        logger.info("The yubikey internal timestamp is lesser then in the log.")
                        logger.info("Timestamp in response: " + str(yubikey_time2))
                        logger.info("Session use in log: " + str(yubikey_time1))
                        logger.info("")
                        logger.info("Return: REPLAYED_REQUEST")
                        return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.REPLAYED_REQUEST)
                    elapsedTime = secondssince197001-int(float(session_log["seconds19700101"]))
                    self.validateTimeStamp(elapsedTime, timestamp_error_margin,
                                           yubikey_time1, yubikey_time2)

            if str(payload[yubikeyconf.TIMESTAMP_REQUEST_PARAM]) == "1":
                response_payload[yubikeyconf.SESSIONCOUNTER_RESPONSE_PARAM] = str(yubikey.sessionCtr())
                response_payload[yubikeyconf.SESSIONUSE_RESPONSE_PARAM] = str(yubikey.useCtr())
                response_payload[yubikeyconf.YUBIIKEY_TIMESTAMP_RESPONSE_PARAM] = str(yubikey.tstp())

            db.add_server_sessionLog(public_id, utc_time,
                                     secondssince197001, yubikey.tstp(), yubikey.sessionCtr(), yubikey.useCtr())

            db.addOTP(otp)

            db.addNONCE(public_id, response_payload[yubikeyconf.NONCE_RESPONSE_PARAM])

            logger.info("The OTP is correct!")
            return self.create_yubikey_response_with_hash(response_payload, api_key, yubikeyconf.OK)

        except OTPInvalid as ex:
            logger.info("The OTP is invalid due to the message: " + ex.message)
            return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.BAD_OTP)
        except Exception as ex:
            logger.error("An unknown exception occured. Message = " + ex.message)
            return self.create_yubikey_response_with_hash(response_payload,api_key, yubikeyconf.BACKEND_ERROR)

    def validateTimeStamp(self, elapsed_time, error_margin, yubikey_tstp1, yubikey_tstp2):
        """

        :param elapsed_time: Database timestamp for last call for this OTP, compared with the current timestamp.
        :param error_margin: The amount of cycles that is allowed to be off.
        :raise:
        """
        max_size = 16777215
        cycles_per_second=8

        elapsed_cycles = elapsed_time*cycles_per_second

        amount_of_roundtrips = int(float(elapsed_cycles) / float(max_size))

        current_value = elapsed_cycles - amount_of_roundtrips * max_size

        if (current_value + yubikey_tstp1) > max_size:
            current_value = (yubikey_tstp1+current_value) - max_size
        else:
            current_value = (yubikey_tstp1+current_value)

        seconds_off = math.fabs(float(current_value - yubikey_tstp2) / float(cycles_per_second))
        if seconds_off > error_margin or seconds_off < 0:
            logger.warn("The internal time in the yubikey and the time saved in the database missmatch with " +
            str(seconds_off) + " seconds. Accepted missmatch is " + str(error_margin) + ".")
            raise OTPInvalid('The internal timestamp for the OTP is not within an acceptable error margin.')
        return True

    def validateChallange(self, private_id, challenge):
        #ONLY USED FOR CHALLENGE RESPONSE MODE.
        #NOT IMPLEMENTED FOR THIS SERVER YET!
        #uid xor private_id == challenge
        #See http://www.yubico.com/wp-content/uploads/2013/07/YubiKey-Manual-v3_1.pdf
        raise OTPInvalid('Invalid OTP.')


    def create_yubikey_response_with_hash(self, payload, api_key, status):
        yubikeyurl = YubikeyUrl()
        payload[yubikeyconf.STATUS_RESPONSE_PARAM] = status
        h = yubikeyurl.create_get_params(payload)
        h = yubikeyurl.signature(api_key, h)
        payload[yubikeyconf.HMACSHA1_SIGNATURE_RESPONSE_PARAM] = h
        return payload


class YubikeyUrl:

    def __init__(self):
        pass

    def validate_signature_in_payload(self, payload, api_key):
        if yubikeyconf.HASH_REQUEST_PARAM not in payload:
            return False
        if yubikeyconf.OTP_REQUEST_PARAM not in payload:
            return False
        params = self.create_get_params(payload)
        otp = payload[yubikeyconf.OTP_REQUEST_PARAM]
        signature = self.signature(api_key, params)
        return payload[yubikeyconf.HASH_REQUEST_PARAM] == signature

    def create_get_params(self, payload):
        value = ""
        first = True
        for key in sorted(payload.iterkeys()):
            if key != yubikeyconf.HASH_REQUEST_PARAM:
                tmpvalue = key + "=" + str(payload[key])
                if first:
                    first = False
                else:
                    tmpvalue = "&" + tmpvalue
                value += tmpvalue
        return value


    def create_request_payload(self, api_key, id, nonce, opt,
                             sl=yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.SECURITYLEVEL_REQUEST_PARAM],
                             timeout=yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.TIMEOUT_REQUEST_PARAM],
                             timestamp=yubikeyconf.REQUEST_DEFAULT_VALUES[yubikeyconf.TIMESTAMP_REQUEST_PARAM]):
        payload = {}
        payload[yubikeyconf.ID_REQUEST_PARAM] = id
        payload[yubikeyconf.NONCE_REQUEST_PARAM] = nonce
        payload[yubikeyconf.OTP_REQUEST_PARAM] = opt
        payload[yubikeyconf.SECURITYLEVEL_REQUEST_PARAM] = sl
        payload[yubikeyconf.TIMEOUT_REQUEST_PARAM] = timeout
        payload[yubikeyconf.TIMESTAMP_REQUEST_PARAM] = timestamp
        h = self.create_get_params(payload)
        h = self.signature(api_key, h)
        payload[yubikeyconf.HASH_REQUEST_PARAM] = h
        return payload

    def signature (self, public_id, value):
        return hmac.new(str(public_id), msg=str(value), digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()

class Yubikey:
    MODHEXCONVERT = {
                    'c': '0',
                    'b': '1',
                    'd': '2',
                    'e': '3',
                    'f': '4',
                    'g': '5',
                    'h': '6',
                    'i': '7',
                    'j': '8',
                    'k': '9',
                    'l': 'a',
                    'n': 'b',
                    'r': 'c',
                    't': 'd',
                    'u': 'e',
                    'v': 'f',
                    }

    def __init__(self, token, aes_key):
        self._aes_key = aes_key
        self._public_id, self._otp, self._decoded_otp = self.decode_yubikey(token, aes_key)

    def public_id(self):
        return self._public_id
    def uid(self):
        return self._decoded_otp[0:6].encode('hex')

    def useCtr(self):
        return int("0x" + self._decoded_otp[7].encode('hex') + self._decoded_otp[6].encode('hex'), 0)

    def tstp(self):
        return int("0x" + self._decoded_otp[10].encode('hex')
                   + self._decoded_otp[9].encode('hex') + self._decoded_otp[8].encode('hex'), 0)

    def sessionCtr(self):
        return int("0x" + self._decoded_otp[11].encode('hex'), 0)

    def rnd(self):
        return int("0x" + self._decoded_otp[12].encode('hex') + self._decoded_otp[13].encode('hex'), 0)

    def _crc(self):
        return int("0x" + self._decoded_otp[15].encode('hex') + self._decoded_otp[14].encode('hex'), 0)



    def validateUid(self, private_id):
        if self.uid() == private_id:
            return True
        return False

    def validateCrc(self):
        crc = 0xffff;
        for val in self._decoded_otp:
            crc ^= int("0x" + val.encode('hex'), 0)
            for i in range(0, 8):
                j = crc & 1
                crc >>= 1
                if j:
                    crc ^= 0x8408
        return crc == 0xf0b8

    def decode_yubikey(self, yubikey, aes=None):
        try:
            l = len(yubikey)
            if l < 32:
                raise OTPInvalid('Invalid OTP.')
            otp = yubikey[l-32:l]
            public_id = None
            try:
                public_id = yubikey[0:l-32]
                if len(public_id) > 32:
                    raise OTPInvalid('Invalid OTP.')
            except OTPInvalid as e:
                raise e
            except:
                #public_id is optional.
                pass
            hex = ""
            if aes is None:
                return (public_id, otp, None)
            for c in otp:
                hex += self.MODHEXCONVERT[c]
            decoded_otp = self.decrypt(hex.decode('hex'), aes.decode('hex'))
            return (public_id, otp, decoded_otp)
        except:
            raise OTPInvalid('Invalid OTP.')

    def decrypt(self, data, key):
       return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB).decrypt(data)

