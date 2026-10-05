import random
import string
import base64
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import (
    MSSQL,
    DummyPrint,
    TDS_ENCRYPT_REQ,
    TDS_ENCRYPT_OFF,
    TDS_PRE_LOGIN,
    TDS_LOGIN,
    TDS_INIT_LANG_FATAL,
    TDS_ODBC_ON,
    TDS_INTEGRATED_SECURITY_ON,
    TDS_LOGIN7,
    TDS_SSPI,
    TDS_LOGINACK_TOKEN,
)

from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenResp

try:
    from OpenSSL import SSL
except Exception:
    LOG.critical("pyOpenSSL is not installed, can't continue")

PROTOCOL_CLIENT_CLASS = "MSSQLRelayClient"


class MYMSSQL(MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        MSSQL.__init__(self, address, port, rowsPrinter)
        self.resp = None
        self.sessionData = {}

    def initConnection(self, authdata, kdc=None):
        self.connect()
        self.resp = self._negotiate_encryption()
        return self.doInitialActions(authdata, kdc)

    def doInitialActions(self, authdata, kdc=None):
        # Also partly copied from tds.py
        login = TDS_LOGIN()

        login["HostName"] = (
            "".join([random.choice(string.ascii_letters) for _ in range(8)])
        ).encode("utf-16le")
        login["AppName"] = (
            "".join([random.choice(string.ascii_letters) for _ in range(8)])
        ).encode("utf-16le")
        login["ServerName"] = self.server.encode("utf-16le")
        login["CltIntName"] = login["AppName"]
        login["ClientPID"] = random.randint(0, 1024)
        login["PacketSize"] = self.packetSize
        login["OptionFlags2"] = (
            TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON
        )

        login["SSPI"] = authdata["krbauth"]
        login["Length"] = len(login.getData())

        # send the auth
        self.sendTDS(TDS_LOGIN7, login.getData())

        # According to the specs, if encryption is not required, we must encrypt just
        # the first Login packet :-o
        if self.resp["Encryption"] == TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds = self.recvTDS()
        self.replies = self.parseReply(tds["Data"])
        return TDS_LOGINACK_TOKEN in self.replies

    def close(self):
        return self.disconnect()


class MSSQLRelayClient(ProtocolClient):

    PLUGIN_NAME = "MSSQL"

    def __init__(
        self, serverConfig, targetHost, targetPort=1433, extendedSecurity=True
    ):
        ProtocolClient.__init__(
            self, serverConfig, targetHost, targetPort, extendedSecurity
        )

        self.extendedSecurity = extendedSecurity

        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None

    def initConnection(self, authdata, kdc=None):
        self.session = MYMSSQL(self.targetHost, self.targetPort)
        self.session.initConnection(authdata, kdc)
        return True

    def keepAlive(self):
        # Don't know yet what needs to be done for TDS
        pass

    def killConnection(self):
        if self.session is not None:
            self.session.disconnect()
            self.session = None
