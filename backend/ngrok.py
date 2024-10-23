#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import psutil
import requests
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
    MODULE_VERSION = "1.0.0"
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
    AGENT_BIN = "./ngrok"
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
        self.tunnel_update_event = self._get_event("ngrok.tunnel.update")

    def _on_start(self):
        """
        Start app
        """
        # start ngrok agent
        agent_started = False
        auth_key = self._get_config_field("authkey")
        if auth_key:
            agent_started = self.__is_agent_running()
            if not agent_started:
                if self.__authorize_agent(auth_key):
                    agent_started = self.__start_agent()
            else:
                self.logger.info("Ngrok agent is already started")

        # launch cleep tunnel
        auto_start = self._get_config_field("autostart")
        if agent_started and auto_start:
            if not self.__get_tunnel_info():
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

        if self.__authorize_agent(auth_key):
            if self._set_config_field("authkey", auth_key):
                return
            else:
                raise CommandError("Unable to save config")

        raise CommandError("Can't authorize with specified key")

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

    def start_tunnel(self):
        """
        Start tunnel manually

        Raises:
            CommandError: if command failed
            CommandInfo: if tunnel already exists
        """
        # check tunnel exists
        tunnel = self.__get_tunnel_info()
        if tunnel:
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
        Authorize local service to ngrok account

        Args:
            auth_key (str): ngrok auth key

        Returns:
            bool: True if agent authorized successfully, False otherwise
        """
        console = Console()
        # ngrok config add-authtoken <key>
        cmd = [
            self.AGENT_BIN,
            "config",
            "add-authtoken",
            auth_key,
        ]
        resp = console.command(cmd, timeout=5, opts={"env": self.get_env()})
        self.logger.debug("Authorize agent cmd: %s, resp: %s", cmd, resp)

        if resp["returncode"] == 0:
            self.logger.info("Ngrok agent authorized successfully")
            return True

        self.logger.error(
            "Unable to authorize ngrok agent: %s", resp["stdout"] + resp["stderr"]
        )
        return False

    def __is_agent_running(self):
        """
        Check if ngrok service is running

        Returns:
            bool: True if service is running
        """
        for proc in psutil.process_iter():
            if proc.name() == self.AGENT_NAME:
                return True

        return False

    def __start_agent(self):
        """
        Start ngrok service

        Returns:
            bool: True if agent started successfully, False otherwise
        """
        console = Console()
        # ngrok service start --config /root/.config/ngrok/ngrok.yml
        cmd = [
            self.AGENT_BIN,
            "service",
            "start",
        ]
        resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
        self.logger.debug("Start agent cmd: %s, resp: %s", cmd, resp)

        if resp["returncode"] == 0:
            self.logger.info("Ngrok agent started successfully")
            return True

        self.logger.error(
            "Unable to start ngrok agent: %s", resp["stdout"] + resp["stderr"]
        )
        return False

    def __stop_agent(self):
        """
        Stop ngrok service

        Returns:
            bool: True if agent stopped successfully, False otherwise
        """
        console = Console()
        # ngrok service stop
        cmd = [
            self.AGENT_BIN,
            "service",
            "stop",
        ]
        resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
        self.logger.debug("Stop agent cmd: %s, resp: %s", cmd, resp)

        if resp["returncode"] == 0:
            self.logger.info("Ngrok agent stopped successfully")
            return True

        self.logger.error(
            "Unable to stop ngrok agent: %s", resp["stdout"] + resp["stderr"]
        )
        return False

    def __send_tunnel_event(self, send_event=True, delayed=False):
        """
        Send tunnel event

        Args:
            send_event (bool): True to send event (default True)
            delayed (bool): Defer event sent. Useful to wait public url to be set (default False)
        """
        if not send_event:
            return

        def send_event():
            tunnel_info = self.__get_tunnel_info() or {}
            params = {
                "status": self.__tunnel_status,
                "publicurl": tunnel_info.get("publicurl"),
            }
            self.tunnel_update_event.send(params=params)

        if delayed:
            timer = Timer(2.0, send_event)
            timer.start()
        else:
            send_event()
