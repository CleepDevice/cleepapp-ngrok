#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import requests
import time
from cleep.exception import CommandError, CommandInfo
from cleep.core import CleepModule
from cleep.common import CATEGORIES
from cleep.libs.internals.console import Console
from threading import Timer


class Ngrok(CleepModule):
    """
    Ngrok application
    """

    MODULE_AUTHOR = "Cleep"
    MODULE_VERSION = "1.0.1"
    MODULE_DEPS = []
    MODULE_DESCRIPTION = "Ngrok service connector"
    MODULE_LONGDESCRIPTION = (
        "Allow your device to be accessible outside from your local network"
    )
    MODULE_TAGS = ["outside", "external", "remote"]
    MODULE_CATEGORY = CATEGORIES.SERVICE
    MODULE_URLINFO = "https://ngrok.com/"
    MODULE_URLSITE = "https://github.com/CleepDevice/cleepapp-ngrok"
    MODULE_URLHELP = "https://github.com/CleepDevice/cleepapp-ngrok/wiki"
    MODULE_URLBUGS = "https://github.com/CleepDevice/cleepapp-ngrok/issues"

    MODULE_CONFIG_FILE = "ngrok.conf"
    DEFAULT_CONFIG = {"authkey": None, "autostart": True}

    AGENT_NAME = "ngrok"
    AGENT_BIN = "ngrok"
    AGENT_CONFIG = "ngrok.yml"
    AGENT_SERVICE = "/etc/systemd/system/ngrok.service"
    AGENT_CLI_BASE_URL = "http://localhost:4040/api"
    AGENT_CLI_HEADERS = {"content-type": "application/json"}
    CLEEP_TUNNEL_NAME = "cleep"
    TUNNEL_STARTUP_DELAY = 10.0

    TUNNEL_STOPPED = "STOPPED"
    TUNNEL_STARTED = "STARTED"
    TUNNEL_STARTING = "STARTING"
    TUNNEL_ERROR = "ERROR"

    def __init__(self, bootstrap, debug_enabled):
        """
        Constructor

        Args:
            bootstrap (dict): bootstrap objects
            debug_enabled: debug status
        """
        CleepModule.__init__(self, bootstrap, debug_enabled)

        self.__tunnel_status = Ngrok.TUNNEL_STOPPED
        self.__agent_bin = os.path.join(self.APP_BIN_PATH, self.AGENT_BIN)
        self.__agent_config = os.path.join(self.APP_BIN_PATH, self.AGENT_CONFIG)
        self.tunnel_update_event = self._get_event("ngrok.tunnel.update")

    def _on_start(self):
        """
        Start app
        """
        # install agent
        if not self.__install_agent():
            self.logger.error("Unable to install ngrok agent. Can't continue.")
            return

        # start ngrok agent
        if not self.__start_agent():
            return

        # start cleep tunnel
        auto_start = self._get_config_field("autostart")
        if auto_start:
            if not self.__is_tunnel_established():
                self.__tunnel_status = Ngrok.TUNNEL_STARTING
                add_tunnel = Timer(self.TUNNEL_STARTUP_DELAY, self.__add_cleep_tunnel)
                add_tunnel.start()
            else:
                self.logger.info("Ngrok cleep tunnel is already started")

    def _on_stop(self):
        """
        Stop app
        """
        try:
            self.__remove_cleep_tunnel(send_event=False)
            self.__stop_agent()
        except:
            pass

    def get_module_config(self):
        """
        Return module config

        returns:
            dict: app config::

                {
                    authkey (str): ngrok auth key,
                    autostart (bool): start tunnel automatically
                    publicurl (str): device public url,
                    tunnelstatus (str): tunnel status (STARTED|STARTING|STOPPED|ERROR),
                }

        """
        tunnel_info = self.__get_tunnel_info() or {}

        config = super().get_module_config()
        config.update(
            {
                "publicurl": tunnel_info.get("publicurl"),
                "tunnelstatus": self.__tunnel_status,
            }
        )
        return config

    def set_auto_start(self, auto_start):
        """
        Set auto start

        Args:
            auto_start (bool): True to start tunnel when app starts

        Raises:
            CommandError: if error saving config
        """
        self._check_parameters(
            [{"name": "auto_start", "value": auto_start, "type": bool}]
        )

        if not self._set_config_field("autostart", auto_start):
            raise CommandError("Unable to save config")

    def set_auth_key(self, auth_key):
        """
        Set ngrok agent auth key

        Args:
            auth_key (str): ngrok auth key

        Raises:
            CommandError: if authorization failed or error saving config
        """
        self._check_parameters([{"name": "auth_key", "value": auth_key}])

        if not self.__authorize_agent(auth_key):
            raise CommandError("Can't authorize with specified key")
        if not self._set_config_field("authkey", auth_key):
            raise CommandError("Unable to save config")
        
    def get_tunnel_info(self):
        """
        Returns cleep tunnel info

        Returns:
            dict: tunnel info or None if tunnel does not exist::

            {
                id (str): tunnel identifier,
                publicurl (str) : tunnel public url
                proto (str): tunnel protocal (http|https)
                metrics (dict): tunnel metrics (see https://ngrok.com/docs/agent/api/#request-2),
            }

        """
        tunnel_info = self.__get_tunnel_info()
        if tunnel_info is None:
            raise CommandError("Unable to get tunnel info")
        return tunnel_info

    def __get_tunnel_info(self):
        """
        Returns cleep tunnel info

        Returns:
            dict: tunnel info or None if tunnel does not exist::

            {
                id (str): tunnel identifier,
                publicurl (str) : tunnel public url
                proto (str): tunnel protocal (http|https)
                metrics (dict): tunnel metrics (see https://ngrok.com/docs/agent/api/#request-2),
            }

        """
        # check we can get tunnel info
        auth_key = self._get_config_field("authkey")
        if not auth_key:
            return None
        if not self.__is_tunnel_established():
            return None

        try:
            # GET http://localhost:4040/api/tunnels/cleep
            url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
            resp = requests.get(url)

            if resp.status_code == 200:
                resp_json = resp.json()
                return {
                    "id": resp_json.get("ID"),
                    "publicurl": resp_json.get("public_url"),
                    "proto": resp_json.get("proto"),
                    "metrics": resp_json.get("metrics"),
                }
            return None
        except Exception as error:
            self.logger.error(
                f"Error getting cleep tunnel info from {url}: {str(error)}"
            )
            return None

    def __is_tunnel_established(self):
        """
        Check if tunnel is established between provider and device

        Returns:
            bool: True if tunnel established, False otherwise
        """
        try:
            url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
            resp = requests.head(url)
            if resp.status_code == 200:
                return True
            return False
        except Exception as error:
            return False

    def start_tunnel(self):
        """
        Start tunnel manually

        Raises:
            CommandError: if command failed
            CommandInfo: if tunnel already exists
        """
        if not self.__start_agent():
            raise CommandError('Unable to start ngrok agent service')
        if not self.__is_agent_running():
            # maybe agent is just running and need some time to connect to ngrok services
            time.sleep(self.TUNNEL_STARTUP_DELAY)
            if not self.__is_agent_running():
                raise CommandError('Unable to start ngrok agent service')
        if self.__is_tunnel_established():
            raise CommandInfo("Tunnel already started")

        if not self.__add_cleep_tunnel():
            raise CommandError("Error starting tunnel")

    def stop_tunnel(self):
        """
        Stop manually tunnel

        Raises:
            CommandError: if command failed
        """
        if not self.__remove_cleep_tunnel():
            raise CommandError("Error stoping tunnel")

    def __add_cleep_tunnel(self):
        """
        Register cleep tunnel on agent
        """
        # POST http://localhost:4040/api/tunnels {"name": "cleep", "proto":"http", "addr": "https://localhost"}
        url = f"{self.AGENT_CLI_BASE_URL}/tunnels"
        body = {
            "name": self.CLEEP_TUNNEL_NAME,
            "proto": "http",
            "addr": "https://localhost",
        }
        resp = requests.post(url, json=body, headers=self.AGENT_CLI_HEADERS)

        if resp.status_code == 201:
            self.__tunnel_status = Ngrok.TUNNEL_STARTED
            self.logger.info("Ngrok Cleep tunnel started")
            self.__send_tunnel_event(delayed=True)
            return True

        self.__tunnel_status = Ngrok.TUNNEL_ERROR
        self.logger.error(
            f"Error registering cleep tunnel on ngrock agent: {resp.text}"
        )
        self.__send_tunnel_event()
        return False

    def __remove_cleep_tunnel(self, send_event=True):
        """
        Remove cleep tunnel to avoid sharing device access when app is stopped

        Args:
            send_event (bool): True to send event (default True)
        """
        # DELETE http://localhost:4040/api/tunnels/cleep
        url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
        resp = requests.delete(url)

        if resp.status_code == 204:
            self.__tunnel_status = Ngrok.TUNNEL_STOPPED
            self.logger.info("Ngrok Cleep tunnel stopped")
            self.__send_tunnel_event(send_event)
            return True

        self.logger.warning("Ngrock Cleep tunnel failed to stop (not started?)")
        self.__send_tunnel_event(send_event)
        return False

    def __authorize_agent(self, auth_key):
        """
        Authorize local service to ngrok account. Load auth_key from configuration.

        Returns:
            bool: True if agent authorized successfully, False otherwise
        """
        console = Console()
        # ngrok config add-authtoken <key>
        cmd = [
            self.__agent_bin,
            "config",
            "add-authtoken",
            auth_key,
            "--config",
            self.__agent_config,
        ]
        try:
            self.cleep_filesystem.enable_write()
            resp = console.command(cmd, timeout=5, opts={"env": self.get_env()})

            self.logger.debug("Authorize agent cmd: %s, resp: %s", cmd, resp)
            if resp["returncode"] != 0:
                self.logger.error(
                    "Unable to authorize ngrok agent: %s", '\n'.join(resp["stdout"] + resp["stderr"])
                )
                return False

        except Exception:
            self.logger.exception('Unable to add auth token to ngrok')

        finally:
            self.cleep_filesystem.disable_write()

        self.logger.info("Ngrok agent authorized successfully")
        return True

    def __is_agent_running(self):
        """
        Check if ngrok service is running

        Returns:
            bool: True if service is running
        """
        console = Console()

        service = os.path.basename(self.AGENT_SERVICE)
        cmd = ['systemctl', 'is-active', '--quiet', service]
        self.logger.debug('Is agent running cmd: %s', cmd)
        resp = console.command(cmd)
        self.logger.debug('Is agent running resp: %s', resp)

        return resp["returncode"] == 0

    def __install_agent(self):
        """
        Install ngrok service. It creates systemd service and needs to write on fs

        Returns:
            bool: True if service has been installed successfully
        """
        # check service not already installed
        if os.path.exists(self.AGENT_SERVICE):
            self.logger.info('Ngrok agent service already installed')
            return True

        console = Console()
        # ngrok service install --config <config>
        cmd = [
            self.__agent_bin,
            "service",
            "install",
            "--config",
            self.__agent_config,
        ]
        try:
            self.cleep_filesystem.enable_write()

            # create default empty config file
            if not os.path.exists(self.__agent_config):
                conf = 'version: "3"'
                self.cleep_filesystem.write_data(self.__agent_config, conf)
                self.logger.info("Ngrok agent default config file written")

            resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
            self.logger.debug("Start ngrok agent cmd: %s, resp: %s", cmd, resp)

            if resp["returncode"] != 0:
                self.logger.error(
                    "Unable to install ngrok agent service: %s", '\n'.join(resp["stdout"] + resp["stderr"])
                )
                return False
        finally:
            self.cleep_filesystem.disable_write()

        self.logger.info("Ngrok agent service installed successfully")
        return True

    def __start_agent(self):
        """
        Start ngrok service

        Returns:
            bool: True if agent started successfully, False otherwise
        """
        auth_key = self._get_config_field("authkey")
        if not auth_key:
            # can't start agent without auth key
            self.logger.info('Can\'t start ngrok agent service without auth key')
            return False

        if self.__is_agent_running():
            # agent already running, no need to start it again
            self.logger.info('Ngrok agent service already running')
            return True

        console = Console()
        # ngrok service start --config <config>
        cmd = [
            self.__agent_bin,
            "service",
            "start",
            "--config",
            self.__agent_config,
        ]
        resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
        self.logger.debug("Start agent cmd: %s, resp: %s", cmd, resp)

        if resp["returncode"] != 0:
            self.logger.error(
                "Unable to start ngrok agent: %s", '\n'.join(resp["stdout"] + resp["stderr"])
            )
            return False

        self.logger.info("Ngrok agent started successfully")
        return True

    def __stop_agent(self):
        """
        Stop ngrok service

        Returns:
            bool: True if agent stopped successfully, False otherwise
        """
        if not self.__is_agent_running():
            return True

        console = Console()
        # ngrok service stop --config <config>
        cmd = [
            self.__agent_bin,
            "service",
            "stop",
            "--config",
            self.__agent_config,
        ]
        resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
        self.logger.debug("Stop agent cmd: %s, resp: %s", cmd, resp)

        if resp["returncode"] != 0:
            self.logger.error(
                "Unable to stop ngrok agent: %s", '\n'.join(resp["stdout"] + resp["stderr"])
            )
            return False

        self.logger.info("Ngrok agent stopped successfully")
        return True

    def __send_tunnel_event(self, send_event=True, delayed=False):
        """
        Send tunnel event

        Args:
            send_event (bool): True to send event (default True)
            delayed (bool): Defer event sent. Useful to wait public url to be set (default False)
        """
        if not send_event:
            return

        def timer_send_event():
            tunnel_info = self.__get_tunnel_info() or {}
            self.logger.debug('Send event, tunnel info: %s', tunnel_info)
            params = {
                "status": self.__tunnel_status,
                "publicurl": tunnel_info.get("publicurl"),
            }
            self.tunnel_update_event.send(params=params)

        if delayed:
            timer = Timer(2.0, timer_send_event)
            timer.start()
        else:
            timer_send_event()
