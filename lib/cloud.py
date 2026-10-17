#################################################################################
"""
OpenEO Module: Cloud Proxy Server


"""
#################################################################################
from __future__ import annotations

import logging, threading, socket, ssl
import time
from typing import Any
import globalState, util
from lib.PluginSuperClass import PluginSuperClass
from lib import cloud_tls, cloudproxy

# logging for use in this module
_LOGGER = logging.getLogger(__name__)


_OPENER = cloudproxy.build_default_opener()

#################################################################################
class cloudClassPlugin(PluginSuperClass):
    PRETTY_NAME = "OpenEO Cloud"
    CORE_PLUGIN = False # Can't be disabled from the UI
    
    # The cloud module is OFF unless the owner explicitly enables it.
    pluginParamSpec={   "enabled":      {"type": "bool","default": False},
                        "authtoken":    {"type": "str","default":""},
                        "server":       {"type": "str","default":"ssl.openeo.uk"},
                        "port":         {"type": "int","default":8381}
                        }

    proxythread: threading.Thread | None = None
    failurecount: int = 0
    looptime: int = 15
    maxfailurecount: int = int((24*60*60)/looptime) # about 24h
    ssl_sock: Any = None


    def poll(self) -> int:

        # Have we had too many failures? - if so, we should probably autodisable
        if self.failurecount>self.maxfailurecount:
            globalState.configDB.set("cloud","enabled",False)
            self.failurecount=0
            _LOGGER.error(f"OpenEO Cloud - Given up connecting to server. Module disabled")
        else:
            # Check to see if we are running a thread, and if we are supposed to be
            if self.pluginConfig["enabled"] and (self.proxythread is None or not self.proxythread.is_alive()):
                # Enabled, but not running, so best we try starting
                self._thread_start()

            if (not self.pluginConfig["enabled"]) and (self.ssl_sock is not None):
                self.ssl_sock.close()
                self.ssl_sock=None

        return(0)

    def configure(self, configParam: Any) -> None:
        # Run a poll(), just in case we have been switched on or off
        super().configure(configParam)
        self.failurecount=0
        self.poll()

    def _thread_start(self) -> None:
        _LOGGER.info(f"Starting OpenEO Cload thread")
        self.proxythread = threading.Thread(target=self._proxythread, name='_proxythread', daemon=True)
        self.proxythread.start()

    def _thread_stop(self) -> None:
        _LOGGER.info(f"Stopping OpenEO Cload thread")
        self.killflag=True


    def _proxythread(self) -> None:
        """Connect to a TCP socket with AUTH handshake and receive commands."""

        while self.pluginConfig["enabled"]:
            
            client_id=globalState.stateDict["eo_serial_number"]

            if client_id=="" or client_id is None:
                _LOGGER.warning(f"OpenEO Cloud - waiting for EO serial comms to be established before Cloud Connection can begin")
                time.sleep(self.looptime)
                continue
            
            if self.pluginConfig['authtoken']=="" or self.pluginConfig['authtoken'] is None:
                _LOGGER.warning(f"OpenEO Cloud module enabled, but authorisation token not defined in module settings. Not Connecting.")

                self.failurecount+=1
                time.sleep(self.looptime)
                continue

            try:
                _LOGGER.warning(f"OpenEO Cloud - Connecting to {self.pluginConfig['server']}:{self.pluginConfig['port']}. Attempt {self.failurecount}/{self.maxfailurecount}")

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)  # type: ignore[attr-defined,unused-ignore]
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

                # Certificate verification is mandatory: only the pinned certificate
                # for ssl.openeo.uk is trusted (see lib/cloud_tls.py).
                context = cloud_tls.make_ssl_context()
                self.ssl_sock = context.wrap_socket(s, server_hostname=self.pluginConfig['server'])
                self.ssl_sock.settimeout(30.0)
                self.ssl_sock.connect((self.pluginConfig['server'], self.pluginConfig['port']))
                cloud_tls.verify_pinned_peer(self.ssl_sock.getpeercert(binary_form=True))
                self.ssl_sock.settimeout(None)
                
                #self.ssl_sock.settimeout(15.0)  # 5 seconds
                f = self.ssl_sock.makefile('rw', encoding='utf-8', newline='\n')

                # Send AUTH
                connectionstr=f"AUTH {client_id} {self.pluginConfig['authtoken']} {globalState.stateDict['app_version']} {globalState.stateDict['app_deploy_directory']}\n"

                self.ssl_sock.sendall(bytearray(connectionstr,'utf-8'))

                # Wait for OK
                response=f.readline().rstrip('\n')
                if response != "OK":
                    _LOGGER.warning(f"OpenEO Cloud Connection unauthorised. Cannot connect.")
                    self.ssl_sock.close()
                    self.failurecount+=1
                    time.sleep(self.looptime)
                    continue

                _LOGGER.warning(f"OpenEO Cloud Connection - Sucessfully Authorised.")
                self.failurecount=0

                # Command loop
                while True:
                    if not self.pluginConfig["enabled"]:
                        self.failurecount+=1
                        _LOGGER.warning(f"OpenEO Cloud Connection - Module unexpectedly disabled.")
                        break

                    command=f.readline().rstrip('\n')

                    if command=="ACK":
                        # ACK message used for detecting dead connections
                        self.ssl_sock.sendall(bytearray(f"ACK\n",'utf-8'))
                    else:
                        r=self.get_output(command)

                        for x in r['headers']:
                            (a,b)=x
                            self.ssl_sock.sendall(bytearray(f"HDR {a} {b}\n",'utf-8'))

                        self.ssl_sock.sendall(bytearray(f"LEN {r['bodylen']}\n",'utf-8'))
                        self.ssl_sock.sendall(r['body'])

            except Exception as e:
                _LOGGER.error(f"OpenEO Cloud Connection error: {e}")
                self.failurecount+=1

            finally:
                try:
                    self.ssl_sock.close()
                except:
                    pass

        _LOGGER.warning(f"OpenEO Cloud - closed comms")


    @staticmethod
    def _local_port() -> int:
        """Port the local web UI listens on."""
        try:
            return int(globalState.stateDict["_moduleDict"]["configserver"].pluginConfig["port"])
        except Exception:
            return 80

    def get_output(self, command: str) -> dict[str, Any]:
        """Proxy one cloud command to the local web UI (see lib/cloudproxy.py)."""
        result = cloudproxy.proxy_request(command, self._local_port(), _OPENER)
        return {"headers": result.headers, "body": result.body, "bodylen": result.bodylen}

    # def get_user_settings(self):
    #     settings = []
    #     util.add_simple_setting(self.pluginConfig, settings, 'textinput', "cloud", ("authtoken",), f'Authorisation Code (Charger ID: {globalState.stateDict["eo_serial_number"]})',pattern='([A-Za-z0-9]{5})')
    #     return settings

    def get_user_settings(self) -> list[dict[str, Any]]:
        return [{"type": "textinput", "name": "authtoken", "label": f'Authorisation Code (Charger ID: {globalState.stateDict["eo_serial_number"]})', "default":self.pluginConfig.get("authtoken",False), "pattern":'([A-Za-z0-9]{5})', "note":""}];
