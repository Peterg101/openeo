#################################################################################
"""
OpenEO Module: Config Server
Spawns a webserver thread which hosts the (FastAPI) web interface for setting the timer 
schedule. All routes live in lib/webapp/app.py and require a login. Note that this will only ever update the first schedule in the scheduler
list of "on" periods for the charger.

I expect this module could be integrated to the webserver module to reduce the 
number of threads running.

Configuration example:
"configserver": {"port": 80}

"""
#################################################################################
import logging, threading

from lib.PluginSuperClass import PluginSuperClass

# logging for use in this module
_LOGGER = logging.getLogger(__name__)


def _make_server(app, port):
    """uvicorn server that can run in a non-main thread, single worker, no reload."""
    import contextlib
    import uvicorn

    class _ThreadServer(uvicorn.Server):
        # Signal handlers can only be installed from the main thread; the main
        # thread belongs to openeo's control loop. Older uvicorn calls
        # install_signal_handlers(), newer ones use capture_signals().
        def install_signal_handlers(self):
            pass

        @contextlib.contextmanager
        def capture_signals(self):
            yield

    config = uvicorn.Config(app, host="0.0.0.0", port=int(port), log_level="warning",
                            access_log=False, log_config=None, loop="asyncio",
                            http="h11", ws="none", lifespan="off", workers=1,
                            # No reverse proxy in front of us: the client address must be
                            # the real socket peer (rate limiting, loopback-only internal token).
                            proxy_headers=False, server_header=False)
    return _ThreadServer(config)


#################################################################################
class configserverClassPlugin(PluginSuperClass):
    PRETTY_NAME = "Config Server"
    CORE_PLUGIN = True # Can't be disabled from the UI

    pluginParamSpec={   "enabled":      {"type": "bool","default": True},
                        "port":  {"type": "int","default":80},
                        "update_start": {"type": "int","default":0},
                        "update_finish": {"type": "int","default":0},
                        "update_log": {"type": "str","default":""}}

    def __init__(self,configParam):
        super().__init__(configParam)

        self.serverthread = threading.Thread(target=self.webserver, name='serverthread', daemon=True)
        self.serverthread.start()

    def webserver(self):
        try:
            from lib.webapp.app import create_app
            from lib.webapp.providers import build_deps
            deps = build_deps()
            deps.auth.import_pending()
            if not deps.auth.has_password():
                _LOGGER.warning("No admin password is set: all web UI logins are refused. "
                                "Edit openeo-setup.txt on the SD card boot partition and reboot.")
            server = _make_server(create_app(deps), self.pluginConfig["port"])
            _LOGGER.info("Serving Configuration webserver on port {}".format(self.pluginConfig["port"]))
            server.run()
        except Exception:
            _LOGGER.exception("Config server failed")
