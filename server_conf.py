#The host for the server
HOST="localhost"
#Port for the webserver.
PORT=8181
#Path the server listen to.
PATH="/wsapi/2.0/verify"
#Log file
LOG_FILE="yubikeyserver.log"
#True if HTTPS should be used instead of HTTP.
HTTPS=True
#If HTTPS is true you have to assign the server cert, key and certificate chain.
SERVER_CERT = "httpsCert/server.crt"
SERVER_KEY = "httpsCert/server.key"
#CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None


#Amount of seconds that your OTP will be valid.
TIMESTAMP_ERROR_MARGIN = 40
#True if a nonce may be used multiple times by the same OTP's public id.
ALLOW_DUPLICATED_NONCE=False
#The database the server is using
DATABASE="db/yubikeylocaltest.db"