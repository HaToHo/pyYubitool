import importlib
from logging.handlers import BufferingHandler
from urlparse import parse_qs
import argparse
import logging
from cherrypy import wsgiserver
from cherrypy.wsgiserver import ssl_pyopenssl
from pyYubitool.yubikeyutil import YubikeyValidation

__author__ = 'haho0032'

def create_logger(filename):
    """
    Creates a logger with a given filename.
    :param filename: File name for the log
    :return: A logger class.
    """
    logger = logging.getLogger("")
    LOGFILE_NAME = filename
    hdlr = logging.FileHandler(LOGFILE_NAME)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    CPC = ('%(asctime)s %(name)s:%(levelname)s '
           '[%(client)s,%(path)s,%(cid)s] %(message)s')
    cpc_formatter = logging.Formatter(CPC)
    hdlr.setFormatter(base_formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)
    _formatter = logging.Formatter(CPC)
    fil_handl = logging.FileHandler(LOGFILE_NAME)
    fil_handl.setFormatter(_formatter)

    buf_handl = BufferingHandler(10000)
    buf_handl.setFormatter(_formatter)
    return logger

def application(environ, start_response):
    headers = []
    headers.append(('Content-type', "text/plain"))
    if environ["PATH_INFO"] == config.PATH:
        validator = YubikeyValidation(None)

        payload = dict((k, v if len(v) > 1 else v[0]) for k, v in  parse_qs(environ["QUERY_STRING"]).iteritems())

        response_payload = validator.local_validate_otp(payload, config.DATABASE,config.TIMESTAMP_ERROR_MARGIN,
                                     config.ALLOW_DUPLICATED_NONCE)

        response = ""

        for key, value in response_payload.iteritems():
            response += key + "=" + value +"\r\n"

        start_response("200 OK", headers)
        return response
    start_response("404 NOT FOUND", [])
    return "404 NOT FOUND"

if __name__ == '__main__':
    #This is equal to a main function in other languages. Handles all setup and starts the server.

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    args = parser.parse_args()
    global config
    config = importlib.import_module(args.config)

    global logger
    logger = create_logger(config.LOG_FILE)

    serverpath = ""

    global SRV
    SRV = wsgiserver.CherryPyWSGIServer((config.HOST, config.PORT), application)
    if config.HTTPS:
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)
        serverpath += "https://"
    else:
        serverpath += "https://"
    serverpath += config.HOST + ":" + str(config.PORT) + config.PATH
    logger.info("Starting server " + serverpath)

    print "Yubikey server listing on: " + serverpath
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
