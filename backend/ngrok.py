#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import requests
import time
from cleep.exception import CommandError, CommandInfo
from cleep.core import CleepRemoteAccessModule
from cleep.common import CATEGORIES
from cleep.libs.configs.cleepconf import CleepConf
from cleep.libs.internals.console import Console, EndlessConsole


class Ngrok(CleepRemoteAccessModule):
    """
    Ngrok application
    """

    MODULE_AUTHOR = "Cleep"
    MODULE_VERSION = "1.2.0"
    MODULE_DEPS = []
    MODULE_DESCRIPTION = "Ngrok service connector"
    MODULE_LONGDESCRIPTION = "Make this device reachable from outside the local network"
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
    AGENT_WEB_ADDR = "127.0.0.1:4040"
    AGENT_CONFIG_HEADER = 'version: "3"\nagent:\n  web_addr: 127.0.0.1:4040\n'
    AGENT_CLI_BASE_URL = "http://localhost:4040/api"
    AGENT_CLI_HEADERS = {"content-type": "application/json"}
    AGENT_API_TIMEOUT = 5.0
    AGENT_LOG_REGEX = r"(\S+)=(\"[^=]*\"|\S+)(?:\s|$)"
    CLEEP_TUNNEL_NAME = "cleep"
    TUNNEL_STARTUP_DELAY = 10.0
    TUNNEL_STARTUP_INTERVAL = 120.0

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
        CleepRemoteAccessModule.__init__(self, bootstrap, debug_enabled)

        self.__tunnel_status = Ngrok.TUNNEL_STOPPED
        self.__agent_bin = os.path.join(self.APP_BIN_PATH, self.AGENT_BIN)
        self.__agent_config = os.path.join(self.APP_BIN_PATH, self.AGENT_CONFIG)
        self.__start_tunnel_task = None
        self.__agent_bootstrap_task = None
        self.__last_agent_error = None
        self.__binary_update_std = []
        self.__binary_update_running = False

        self.tunnel_update_event = self._get_event("ngrok.tunnel.update")

    def _on_start(self):
        """
        Start app — defer agent/tunnel work so blocking Console calls do not
        starve the gevent hub during inventory startup.
        """
        self.__agent_bootstrap_task = self.task_factory.create_task(
            None, self.__bootstrap_agent_and_tunnel
        )
        self.__agent_bootstrap_task.start()

    def __bootstrap_agent_and_tunnel(self):
        """Install/start agent and optionally schedule tunnel autoconnect."""
        if not self.__install_agent():
            return

        if not self.__start_agent():
            return

        auto_start = self._get_config_field("autostart")
        if not auto_start:
            return

        if self.__is_tunnel_established():
            self.__tunnel_status = Ngrok.TUNNEL_STARTED
            self.logger.info("Ngrok cleep tunnel is already started")
            tunnel_info = self.__get_tunnel_info() or {}
            self.__publish_public_url(tunnel_info.get("publicurl"))
            return

        if not self.__is_cleep_auth_ready():
            self.__last_agent_error = "Cleep authentication is disabled"
            self.logger.error(
                "Cleep authentication is disabled, tunnel will not start"
            )
            return

        self.__tunnel_status = Ngrok.TUNNEL_STARTING
        self.__start_tunnel_task = self.task_factory.create_task(
            self.TUNNEL_STARTUP_INTERVAL, self.__autoconnect_cleep_tunnel
        )
        self.__start_tunnel_task.start()

    def _on_stop(self):
        """
        Stop app
        """
        self.__stop_autoconnect_task()
        try:
            self.__remove_cleep_tunnel(send_event=False)
            self.__stop_agent()
        except Exception:
            self.logger.exception("Error while stopping ngrok")
        finally:
            self.unregister_remote_access_url()

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
                    agenterror (str): last agent error, or None,
                    agentrunning (bool): True when the ngrok service is active,
                    cleepauth (bool): True when Cleep authentication can protect a tunnel,
                }

        """
        self.__refresh_tunnel_status()
        agent_running = self.__is_agent_running()
        if agent_running:
            self.__last_agent_error = self.__read_recent_agent_error()

        tunnel_info = self.__get_tunnel_info() or {}
        self.__publish_public_url(tunnel_info.get("publicurl"))
        config = super().get_module_config()
        config.update(
            {
                "publicurl": tunnel_info.get("publicurl"),
                "tunnelstatus": self.__tunnel_status,
                "agenterror": self.__last_agent_error,
                "agentrunning": agent_running,
                "cleepauth": self.__is_cleep_auth_ready(),
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
        Set ngrok agent auth key.

        A running agent keeps its previous token until it is restarted.

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

        if self.__is_agent_running() and not self.__restart_agent():
            raise CommandError("Auth key saved but ngrok agent failed to restart")

    def update_binary(self):
        """
        Update ngrok binary using binary self update

        Raises:
            CommandError: if an update is already running or the update command failed to start
        """
        if self.__binary_update_running:
            raise CommandError("Binary update already running")

        self.__binary_update_running = True
        self.__binary_update_std = []
        cmd = [self.__agent_bin, "update"]
        try:
            self.cleep_filesystem.enable_write()
            console = EndlessConsole(
                cmd, self.__update_binary_callback, self.__update_binary_end_callback
            )
            console.start()
        except Exception:
            self.__binary_update_running = False
            self.cleep_filesystem.disable_write()
            self.logger.exception("Unable to start ngrok binary update")
            raise CommandError("Unable to start binary update")

    def __update_binary_callback(self, stdout, stderr):
        """
        Binary update callback

        Args:
            stdout (str): stdout message
            stderr (str): stderr message
        """
        if stdout:
            self.__binary_update_std.append(stdout)
        if stderr:
            self.__binary_update_std.append("ERR: " + stderr)

    def __update_binary_end_callback(self, return_code, killed):
        """
        Binary update end callback

        Args:
            return_code (int): command return code
            killed (bool): killed status
        """
        try:
            self.logger.info(
                "Ngrok binary update return code=%s: %s",
                return_code,
                "\n".join(self.__binary_update_std),
            )
            if return_code == 0 and not killed and self.__is_agent_running():
                self.__restart_agent()
        finally:
            self.cleep_filesystem.disable_write()
            self.__binary_update_running = False

    def get_tunnel_info(self):
        """
        Returns cleep tunnel info

        Returns:
            dict: tunnel info or None if tunnel does not exist::

            {
                id (str): tunnel identifier,
                publicurl (str) : tunnel public url
                proto (str): tunnel protocol (http|https)
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
                proto (str): tunnel protocol (http|https)
                metrics (dict): tunnel metrics (see https://ngrok.com/docs/agent/api/#request-2),
            }

        """
        auth_key = self._get_config_field("authkey")
        if not auth_key:
            return None

        url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
        try:
            resp = requests.get(url, timeout=self.AGENT_API_TIMEOUT)
            if resp.status_code != 200:
                return None

            resp_json = resp.json()
            return {
                "id": resp_json.get("ID"),
                "publicurl": resp_json.get("public_url"),
                "proto": resp_json.get("proto"),
                "metrics": resp_json.get("metrics"),
            }
        except Exception as error:
            self.logger.debug("Error getting cleep tunnel info from %s: %s", url, error)
            return None

    def __is_tunnel_established(self):
        """
        Check if tunnel is established between provider and device

        Returns:
            bool: True if tunnel established, False otherwise
        """
        url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
        try:
            resp = requests.head(url, timeout=self.AGENT_API_TIMEOUT)
            return resp.status_code == 200
        except Exception as error:
            self.logger.debug("Ngrok tunnel is not established: %s", error)
            return False

    def __refresh_tunnel_status(self):
        """
        Align the stored tunnel status with the agent when the tunnel is up or has dropped.
        """
        if self.__is_tunnel_established():
            self.__tunnel_status = Ngrok.TUNNEL_STARTED
        elif self.__tunnel_status == Ngrok.TUNNEL_STARTED:
            self.__tunnel_status = Ngrok.TUNNEL_STOPPED

    def __is_cleep_auth_ready(self):
        """
        Return True when Cleep authentication is enabled and an account exists.

        A public tunnel must not open while the device login is off.
        """
        try:
            conf = CleepConf(self.cleep_filesystem)
            accounts = conf.get_auth_accounts() or {}
            return bool(conf.is_auth_enabled() and len(accounts) > 0)
        except Exception:
            self.logger.exception("Unable to read Cleep authentication")
            return False

    def start_tunnel(self):
        """
        Start tunnel manually

        Raises:
            CommandError: if command failed
            CommandInfo: if tunnel already exists
        """
        if not self.__is_cleep_auth_ready():
            raise CommandError(
                "Cleep authentication must be enabled before opening a tunnel"
            )
        if not self.__start_agent():
            raise CommandError("Unable to start ngrok agent")
        if not self.__wait_for_agent():
            raise CommandError("Unable to start ngrok agent")
        if self.__is_tunnel_established():
            self.__tunnel_status = Ngrok.TUNNEL_STARTED
            tunnel_info = self.__get_tunnel_info() or {}
            self.__publish_public_url(tunnel_info.get("publicurl"))
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
            raise CommandError("Error stopping tunnel")

    def __wait_for_agent(self):
        """
        Wait until the agent API answers, after a service start.

        Returns:
            bool: True when the agent is active before the deadline
        """
        if self.__is_agent_running():
            return True

        time.sleep(self.TUNNEL_STARTUP_DELAY)
        return self.__is_agent_running()

    def __autoconnect_cleep_tunnel(self):
        """
        Function called during application startup to autoconnect cleep tunnel
        """
        try:
            if self.__is_tunnel_established():
                self.__tunnel_status = Ngrok.TUNNEL_STARTED
                self.logger.info("Ngrok cleep tunnel is already started")
                self.__stop_autoconnect_task()
                return

            if not self.__is_cleep_auth_ready():
                self.__last_agent_error = "Cleep authentication is disabled"
                self.logger.error(
                    "Cleep authentication is disabled, tunnel will not start"
                )
                self.__stop_autoconnect_task()
                return

            self.logger.info("Trying to create Ngrok Cleep tunnel")
            if self.__add_cleep_tunnel():
                self.__stop_autoconnect_task()
        except Exception:
            self.logger.exception("Error while autoconnecting Ngrok tunnel")

    def __stop_autoconnect_task(self):
        """
        Stop the startup tunnel task when the tunnel is up or the app stops.
        """
        if not self.__start_tunnel_task:
            return

        self.logger.info("Stop startup tunnel task")
        self.__start_tunnel_task.stop()
        self.__start_tunnel_task = None

    def __add_cleep_tunnel(self):
        """
        Register cleep tunnel on agent

        Returns:
            bool: True if the tunnel was created
        """
        url = f"{self.AGENT_CLI_BASE_URL}/tunnels"
        body = {
            "name": self.CLEEP_TUNNEL_NAME,
            "proto": "http",
            "addr": "https://localhost",
            "schemes": ["https"],
            "inspect": False,
        }
        try:
            resp = requests.post(
                url,
                json=body,
                headers=self.AGENT_CLI_HEADERS,
                timeout=self.AGENT_API_TIMEOUT,
            )
        except Exception:
            self.logger.exception("Error registering cleep tunnel on ngrok agent")
            self.__tunnel_status = Ngrok.TUNNEL_ERROR
            self.__send_tunnel_event()
            return False

        if resp.status_code == 201:
            self.__tunnel_status = Ngrok.TUNNEL_STARTED
            self.logger.info("Ngrok Cleep tunnel started")
            self.__send_tunnel_event(delayed=True)
            return True

        self.__tunnel_status = Ngrok.TUNNEL_ERROR
        self.logger.error(
            "Error registering cleep tunnel on ngrok agent: %s", resp.text
        )
        self.__send_tunnel_event()
        return False

    def __remove_cleep_tunnel(self, send_event=True):
        """
        Remove cleep tunnel to avoid sharing device access when app is stopped

        Args:
            send_event (bool): True to send event (default True)

        Returns:
            bool: True if the tunnel was removed
        """
        url = f"{self.AGENT_CLI_BASE_URL}/tunnels/{self.CLEEP_TUNNEL_NAME}"
        try:
            resp = requests.delete(url, timeout=self.AGENT_API_TIMEOUT)
        except Exception:
            self.logger.exception("Ngrok cleep tunnel failed to stop")
            return False

        if resp.status_code == 204:
            self.__tunnel_status = Ngrok.TUNNEL_STOPPED
            self.logger.info("Ngrok Cleep tunnel stopped")
            self.__send_tunnel_event(send_event)
            return True

        self.logger.warning("Ngrok cleep tunnel failed to stop (not started?)")
        return False

    def __authorize_agent(self, auth_key):
        """
        Authorize local service to ngrok account.

        Args:
            auth_key (str): ngrok auth token

        Returns:
            bool: True if agent authorized successfully, False otherwise
        """
        console = Console()
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
                    "Unable to authorize ngrok agent: %s",
                    "\n".join(resp["stdout"] + resp["stderr"]),
                )
                return False
        except Exception:
            self.logger.exception("Unable to add auth token to ngrok")
            return False
        finally:
            self.cleep_filesystem.disable_write()

        self.logger.info("Ngrok agent authorized successfully")
        return True

    def __is_agent_running(self):
        """
        Check if the ngrok systemd service is active.

        A recent error in the journal does not mean the service is stopped.

        Returns:
            bool: True if service is active
        """
        console = Console()
        service = os.path.basename(self.AGENT_SERVICE)
        cmd = ["systemctl", "is-active", "--quiet", service]
        self.logger.debug("Is agent running cmd: %s", cmd)
        resp = console.command(cmd)
        self.logger.debug("Is agent running resp: %s", resp)
        return resp.get("returncode") == 0

    def __read_recent_agent_error(self):
        """
        Read the latest ngrok error logged during the last minute.

        Returns:
            str: error text, or None when no recent error is found
        """
        console = Console()
        error = self.__get_agent_error_log(console)
        if not error:
            return None
        return error.get("err") or error.get("msg")

    def __get_agent_error_log(self, console):
        """
        Parse journalctl output to get last ngrok agent error within last minute

        args:
            console (Console): existing console instance

        Returns:
            dict: key-value dict from last error::

                {
                    t (str): datetime (str)
                    lvl (str): error level (str)
                    msg (str): error message (str)
                    err (str): error details (str)
                    ...
                }

            None: if no error found
        """
        cmd = [
            "journalctl",
            "-u",
            "ngrok",
            "-p",
            "3",
            "-n",
            "1",
            "--no-pager",
            "--since",
            "1 minutes ago",
            "-r",
            "--quiet",
            "-o",
            "cat",
        ]
        self.logger.trace("Is agent connected cmd: %s", cmd)
        resp = console.command(cmd)
        self.logger.debug("Is agent connected resp: %s", resp)

        stdout = resp.get("stdout", [])
        if len(stdout) == 0:
            return None

        return self.__parse_agent_log_line(stdout[0])

    def __parse_agent_log_line(self, line):
        """
        Parse one ngrok key=value log line.

        Args:
            line (str): raw journal line

        Returns:
            dict: parsed fields, or the raw line under "msg" when the format does not match
        """
        parsed_line = [
            item.replace('"', "")
            for item in re.split(self.AGENT_LOG_REGEX, line)
            if len(item.strip()) > 0
        ]
        if len(parsed_line) < 2 or len(parsed_line) % 2 != 0:
            return {"msg": line}

        line_iter = iter(parsed_line)
        return dict(zip(line_iter, line_iter))

    def __install_agent(self):
        """
        Install ngrok service. It creates systemd service and needs to write on fs

        Returns:
            bool: True if service has been installed successfully
        """
        if os.path.exists(self.AGENT_SERVICE):
            self.logger.info("Ngrok agent already installed")
            return True

        cmd = [
            self.__agent_bin,
            "service",
            "install",
            "--config",
            self.__agent_config,
        ]
        try:
            self.cleep_filesystem.enable_write()

            if not os.path.exists(self.__agent_config):
                self.cleep_filesystem.write_data(
                    self.__agent_config, self.AGENT_CONFIG_HEADER
                )
                self.logger.info("Ngrok agent default config file written")

            console = Console()
            resp = console.command(cmd, timeout=10, opts={"env": self.get_env()})
            self.logger.debug("Install ngrok agent cmd: %s, resp: %s", cmd, resp)

            if resp["returncode"] != 0:
                self.logger.error(
                    "Unable to install ngrok agent: %s",
                    self.__format_agent_command_error("install", resp),
                )
                self.__remove_broken_service_unit()
                return False
        except Exception:
            self.logger.exception("Error occurred installing agent")
            self.__remove_broken_service_unit()
            return False
        finally:
            self.cleep_filesystem.disable_write()

        self.logger.info("Ngrok agent installed successfully")
        return True

    def __remove_broken_service_unit(self):
        """
        Drop a unit file left by a failed install so the next start can try again.
        """
        if not os.path.exists(self.AGENT_SERVICE):
            return

        try:
            os.remove(self.AGENT_SERVICE)
        except OSError:
            self.logger.exception("Unable to remove broken ngrok service unit")

    @staticmethod
    def _config_with_localhost_web_addr(lines):
        """
        Bind the agent web interface to localhost without dropping the authtoken.

        Args:
            lines (list): current config lines, or empty when the file is missing

        Returns:
            list: config lines ending with a newline
        """
        if not lines:
            return [
                'version: "3"\n',
                "agent:\n",
                "  web_addr: %s\n" % Ngrok.AGENT_WEB_ADDR,
            ]

        normalized = [line if line.endswith("\n") else line + "\n" for line in lines]
        web_addr_pattern = re.compile(r"^(\s*)web_addr\s*:\s*(\S+)\s*$")
        for index, line in enumerate(normalized):
            match = web_addr_pattern.match(line.rstrip("\n"))
            if not match:
                continue
            if match.group(2) in (Ngrok.AGENT_WEB_ADDR, "localhost:4040"):
                return normalized
            indent = match.group(1) or "  "
            normalized[index] = "%sweb_addr: %s\n" % (indent, Ngrok.AGENT_WEB_ADDR)
            return normalized

        web_addr_line = "  web_addr: %s\n" % Ngrok.AGENT_WEB_ADDR
        for index, line in enumerate(normalized):
            if line.rstrip("\n") == "agent:":
                normalized.insert(index + 1, web_addr_line)
                return normalized

        normalized.extend(["agent:\n", web_addr_line])
        return normalized

    def __ensure_localhost_web_addr(self):
        """
        Write web_addr on localhost when the agent config does not already bind there.

        Returns:
            bool: True when the config file was updated
        """
        current = []
        if os.path.exists(self.__agent_config):
            current = self.cleep_filesystem.read_data(self.__agent_config)
            if current is None:
                self.logger.error("Unable to read ngrok agent config")
                return False

        updated = self._config_with_localhost_web_addr(current)
        if current == updated:
            return False

        self.cleep_filesystem.enable_write()
        try:
            written = self.cleep_filesystem.write_data(
                self.__agent_config, "".join(updated)
            )
        finally:
            self.cleep_filesystem.disable_write()
        return bool(written)

    def __start_agent(self):
        """
        Start ngrok service

        Returns:
            bool: True if the agent is running
        """
        auth_key = self._get_config_field("authkey")
        if not auth_key:
            self.logger.warning("Can't start ngrok agent without auth key")
            self.__last_agent_error = "No auth key"
            return False

        config_updated = self.__ensure_localhost_web_addr()
        if self.__is_agent_running():
            if config_updated:
                self.logger.info("Ngrok agent config updated, restarting")
                return self.__restart_agent()
            self.logger.info("Ngrok agent already running")
            return True

        console = Console()
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
            message = self.__format_agent_command_error("start", resp)
            self.__last_agent_error = message
            self.logger.error("Unable to start ngrok agent: %s", message)
            return False

        self.__last_agent_error = None
        self.logger.info("Ngrok agent started successfully")
        return True

    def __format_agent_command_error(self, action, resp):
        """
        Build a non-empty error string from a failed agent Console command.

        ``ngrok service …`` often exits non-zero with empty stdout/stderr; fall
        back to the journal then to the return code.

        Args:
            action (str): failed action label (start, stop, install)
            resp (dict): Console.command result

        Returns:
            str: error message suitable for logs and UI
        """
        parts = list(resp.get("stdout") or []) + list(resp.get("stderr") or [])
        message = "\n".join(parts).strip()
        if message:
            return message
        journal = self.__read_recent_agent_error()
        if journal:
            return journal
        returncode = resp.get("returncode")
        return "Unable to %s ngrok agent (returncode=%s)" % (action, returncode)

    def __stop_agent(self):
        """
        Stop ngrok service

        Returns:
            bool: True if agent stopped successfully, False otherwise
        """
        if not self.__is_agent_running():
            return True

        console = Console()
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
                "Unable to stop ngrok agent: %s",
                self.__format_agent_command_error("stop", resp),
            )
            return False

        self.logger.info("Ngrok agent stopped successfully")
        return True

    def __restart_agent(self):
        """
        Restart the ngrok service so it reloads its config and binary.

        Returns:
            bool: True if the agent is running after the restart
        """
        if not self.__stop_agent():
            self.logger.error("Unable to stop ngrok agent before restart")
            return False
        return self.__start_agent()

    def __publish_public_url(self, public_url):
        """
        Publish or clear this device public address.

        Args:
            public_url (str): public address, or empty when the tunnel is down
        """
        if self.__tunnel_status == Ngrok.TUNNEL_STARTED and public_url:
            self.register_remote_access_url(public_url)
            return

        self.unregister_remote_access_url()

    def __send_tunnel_event(self, send_event=True, delayed=False):
        """
        Send tunnel event

        Args:
            send_event (bool): True to send event (default True)
            delayed (bool): Defer event sending. Useful to wait public url to be set (default False)
        """
        if not send_event:
            return

        def timer_send_event():
            tunnel_info = self.__get_tunnel_info() or {}
            self.logger.debug("Send event, tunnel info: %s", tunnel_info)
            public_url = tunnel_info.get("publicurl")
            self.__publish_public_url(public_url)
            params = {
                "status": self.__tunnel_status,
                "publicurl": public_url,
            }
            self.tunnel_update_event.send(params=params)

        if delayed:
            timer = self.task_factory.create_timer(2.0, timer_send_event)
            timer.start()
        else:
            timer_send_event()
