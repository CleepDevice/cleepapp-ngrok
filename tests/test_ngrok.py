#!/usr/bin/env python
# -*- coding: utf-8 -*-
from cleep.libs.tests import session
import unittest
import logging
import sys
import time

sys.path.append("../")
from backend.ngrok import Ngrok
from backend.ngroktunnelupdateevent import NgrokTunnelUpdateEvent
from cleep.exception import (
    InvalidParameter,
    MissingParameter,
    CommandError,
    CommandInfo,
    Unauthorized,
)
from cleep.libs.tests.common import get_log_level
from unittest.mock import Mock, patch
import responses

LOG_LEVEL = get_log_level()


# TODO remove when Cleep v1.0.0 will be available
class AnyArg:
    def __eq__(self, a):
        return True


@patch("backend.ngrok.Console")
class TestNgrok(unittest.TestCase):
    TUNNEL_INFO = {
        "ID": "02a5fb59c6e79b784792608f7e118e9c",
        "public_url": "https://dummy-82-64-200-227.ngrok-free.app",
        "proto": "https",
        "metrics": {
            "conns": {
                "count": 0,
                "gauge": 0,
                "rate1": 0,
                "rate5": 0,
                "rate15": 0,
                "p50": 0,
                "p90": 0,
                "p95": 0,
                "p99": 0,
            },
            "http": {
                "count": 0,
                "rate1": 0,
                "rate5": 0,
                "rate15": 0,
                "p50": 0,
                "p90": 0,
                "p95": 0,
                "p99": 0,
            },
        },
    }

    def setUp(self):
        self.maxDiff = None
        logging.basicConfig(
            level=LOG_LEVEL,
            format="%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s",
        )
        self.session = session.TestSession(self)
        self.resp_mock = responses.RequestsMock(assert_all_requests_are_fired=False)
        self.resp_mock.start()

    def tearDown(self):
        self.session.clean()
        self.resp_mock.stop()
        self.resp_mock.reset()

    def init(self, start=True, mock_on_start=True, mock_on_stop=True):
        self.module = self.session.setup(
            Ngrok, mock_on_start=mock_on_start, mock_on_stop=mock_on_stop
        )

        self.tunnels_url = f"{Ngrok.AGENT_CLI_BASE_URL}/tunnels"
        self.tunnel_get_url = f"{self.tunnels_url}/{Ngrok.CLEEP_TUNNEL_NAME}"
        self.tunnel_head_url = f"{self.tunnels_url}/{Ngrok.CLEEP_TUNNEL_NAME}"
        self.tunnel_post_url = f"{self.tunnels_url}"
        self.tunnel_delete_url = f"{self.tunnels_url}/{Ngrok.CLEEP_TUNNEL_NAME}"
        self.resp_mock.get(self.tunnel_get_url, None)
        self.resp_mock.delete(self.tunnel_delete_url, None)
        self.resp_mock.post(self.tunnel_post_url, json={}, status=201)
        self.resp_mock.head(self.tunnel_head_url, status=200)

        if start:
            self.session.start_module(self.module)

    def test_on_start_should_start_tunnel(self, console_mock):
        self.init(start=False, mock_on_start=False)
        self.module._Ngrok__install_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._get_config_field = Mock(side_effect=[True])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=False)
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_called_with(120.0, AnyArg())

    def test_on_start_should_not_start_tunnel_if_agent_not_installed(
        self, console_mock
    ):
        self.init(start=False, mock_on_start=False)
        self.module._Ngrok__install_agent = Mock(return_value=False)
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_not_called()

    def test_on_start_should_not_start_tunnel_if_agent_is_not_started(
        self, console_mock
    ):
        self.init(start=False, mock_on_start=False)
        self.module._Ngrok__install_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=False)
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_not_called()

    def test_on_start_should_not_start_tunnel_if_autostart_is_false(self, console_mock):
        self.init(start=False, mock_on_start=False)
        self.module._Ngrok__install_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._get_config_field = Mock(side_effect=[False])
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_not_called()

    def test_on_start_should_not_start_tunnel_if_agent_fails_to_start(
        self, console_mock
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=False)
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_not_called()

    def test_on_start_should_not_start_tunnel_if_tunnel_already_started(
        self, console_mock
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__install_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)
        self.session.task_factory.create_task = Mock()

        self.module._on_start()

        self.session.task_factory.create_task.assert_not_called()

    def test_on_stop(self, console_mock):
        self.init(start=False, mock_on_stop=False)
        self.module._Ngrok__remove_cleep_tunnel = Mock()

        self.module._on_stop()

        self.module._Ngrok__remove_cleep_tunnel.assert_called()

    def test_on_stop_shoud_not_fail_if_remove_cleep_tunnel_call_failed(
        self, console_mock
    ):
        self.init(start=False, mock_on_stop=False)
        self.module._Ngrok__remove_cleep_tunnel = Mock(
            side_effect=Exception("Test error")
        )

        try:
            self.module._on_stop()
        except:
            self.fail("Should not trigger exception")

    def test_get_module_with_tunnel_info(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        config = self.module.get_module_config()

        self.assertDictEqual(
            config,
            {
                "authkey": None,
                "autostart": True,
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "tunnelstatus": "STOPPED",
                "agenterror": None,
            },
        )

    def test_get_module_without_tunnel_info(self, console_mock):
        self.init()

        config = self.module.get_module_config()

        self.assertDictEqual(
            config,
            {
                "authkey": None,
                "autostart": True,
                "publicurl": None,
                "tunnelstatus": "STOPPED",
                "agenterror": None,
            },
        )

    def test_set_auto_start_ok(self, console_mock):
        self.init()
        self.module._set_config_field = Mock(return_value=True)

        self.module.set_auto_start(True)

        self.module._set_config_field.assert_called_with("autostart", True)

    def test_set_auto_start_error_saving_config(self, console_mock):
        self.init()
        self.module._set_config_field = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.set_auto_start(False)

        self.assertEqual(cm.exception.message, "Unable to save config")
        self.module._set_config_field.assert_called_with("autostart", False)

    def test_set_auto_start_check_params(self, console_mock):
        self.init()

        with self.assertRaises(InvalidParameter) as cm:
            self.module.set_auto_start("test")

        self.assertEqual(
            cm.exception.message, 'Parameter "auto_start" must be of type "bool"'
        )

    def test_set_auth_key(self, console_mock):
        self.init()
        self.module._set_config_field = Mock(return_value=True)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)

        result = self.module.set_auth_key("a-key")

        self.module._set_config_field.assert_called_with("authkey", "a-key")

    def test_set_auth_key_auth_failed(self, console_mock):
        self.init()
        self.module._set_config_field = Mock(return_value=True)
        self.module._Ngrok__authorize_agent = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            result = self.module.set_auth_key("a-key")

        self.assertEqual(cm.exception.message, "Can't authorize with specified key")
        self.module._set_config_field.assert_not_called()

    def test_set_auth_key_config_saving_fails(self, console_mock):
        self.init()
        self.module._set_config_field = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)

        with self.assertRaises(CommandError) as cm:
            result = self.module.set_auth_key("a-key")

        self.assertEqual(cm.exception.message, "Unable to save config")
        self.module._set_config_field.assert_called_with("authkey", "a-key")

    @patch("backend.ngrok.EndlessConsole")
    def test_update_binary(self, endless_console_mock, console_mock):
        self.init()

        self.module.update_binary()

        endless_console_mock.assert_called_with(
            ["/var/opt/cleep/modules/bin/ngrok/ngrok", "update"], AnyArg(), AnyArg()
        )
        self.session.cleep_filesystem.enable_write.assert_called()

    def test___update_binary_callback(self, console_mock):
        self.init()

        self.module._Ngrok__update_binary_callback("stdout", "stderr")

        self.assertListEqual(
            self.module._Ngrok__binary_update_std, ["stdout", "ERR: stderr"]
        )

    def test___update_binary_end_callback(self, console_mock):
        self.init()

        self.module._Ngrok__update_binary_end_callback(0, False)

        self.session.cleep_filesystem.disable_write.assert_called()

    def test_get_tunnel_info(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        info = self.module.get_tunnel_info()
        logging.debug("Info: %s", info)

        self.assertDictEqual(
            info,
            {
                "id": "02a5fb59c6e79b784792608f7e118e9c",
                "metrics": {
                    "conns": {
                        "count": 0,
                        "gauge": 0,
                        "p50": 0,
                        "p90": 0,
                        "p95": 0,
                        "p99": 0,
                        "rate1": 0,
                        "rate5": 0,
                        "rate15": 0,
                    },
                    "http": {
                        "count": 0,
                        "p50": 0,
                        "p90": 0,
                        "p95": 0,
                        "p99": 0,
                        "rate1": 0,
                        "rate5": 0,
                        "rate15": 0,
                    },
                },
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "proto": "https",
            },
        )

    def test_get_tunnel_info_without_info(self, console_mock):
        self.init()

        with self.assertRaises(CommandError) as cm:
            self.module.get_tunnel_info()

        self.assertEqual(cm.exception.message, "Unable to get tunnel info")

    def test__get_tunnel_info(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        info = self.module._Ngrok__get_tunnel_info()
        logging.debug("info: %s", info)

        self.assertDictEqual(
            info,
            {
                "id": "02a5fb59c6e79b784792608f7e118e9c",
                "metrics": {
                    "conns": {
                        "count": 0,
                        "gauge": 0,
                        "p50": 0,
                        "p90": 0,
                        "p95": 0,
                        "p99": 0,
                        "rate1": 0,
                        "rate5": 0,
                        "rate15": 0,
                    },
                    "http": {
                        "count": 0,
                        "p50": 0,
                        "p90": 0,
                        "p95": 0,
                        "p99": 0,
                        "rate1": 0,
                        "rate5": 0,
                        "rate15": 0,
                    },
                },
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "proto": "https",
            },
        )

    def test__get_tunnel_info_handle_status_not_200(self, console_mock):
        self.init()
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO, status=400
        )

        info = self.module._Ngrok__get_tunnel_info()

        self.assertIsNone(info)

    def test__get_tunnel_info_handle_error(self, console_mock):
        self.init()
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, body=Exception("Network error")
        )

        info = self.module._Ngrok__get_tunnel_info()

        self.assertIsNone(info)

    def test__get_tunnel_info_on_tunnel_not_established(self, console_mock):
        self.init()
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=False)

        info = self.module._Ngrok__get_tunnel_info()

        self.assertIsNone(info)

    def test__is_tunnel_established(self, console_mock):
        self.init()
        logging.debug("HEAD url: %s", self.tunnel_head_url)
        self.resp_mock.replace(responses.HEAD, self.tunnel_head_url, status=200)

        result = self.module._Ngrok__is_tunnel_established()

        self.assertTrue(result)

    def test__is_tunnel_established_not_established(self, console_mock):
        self.init()
        logging.debug("HEAD url: %s", self.tunnel_head_url)
        self.resp_mock.replace(responses.HEAD, self.tunnel_head_url, status=400)

        result = self.module._Ngrok__is_tunnel_established()

        self.assertFalse(result)

    def test__is_tunnel_established_request_failure(self, console_mock):
        self.init()
        logging.debug("HEAD url: %s", self.tunnel_head_url)
        self.resp_mock.replace(
            responses.HEAD, self.tunnel_head_url, body=Exception("Network error")
        )

        result = self.module._Ngrok__is_tunnel_established()

        self.assertFalse(result)

    def test_start_tunnel(self, console_mock):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._Ngrok__is_agent_running = Mock(return_value=True)
        self.module._Ngrok__is_tunnel_established = Mock(return_value=False)
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=True)

        result = self.module.start_tunnel()

        self.assertIsNone(result)

    @patch("backend.ngrok.time.sleep")
    def test_start_tunnel_should_wait_agent_running(self, sleep_mock, console_mock):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._Ngrok__is_agent_running = Mock(side_effect=[False, True])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=False)
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=True)

        result = self.module.start_tunnel()

        self.assertIsNone(result)
        sleep_mock.assert_called()

    @patch("backend.ngrok.time.sleep")
    def test_start_tunnel_should_failed_if_agent_not_running_after_pause(
        self, sleep_mock, console_mock
    ):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._Ngrok__is_agent_running = Mock(side_effect=[False, False])

        with self.assertRaises(CommandError) as cm:
            self.module.start_tunnel()

        self.assertEqual(cm.exception.message, "Unable to start ngrok agent")
        sleep_mock.assert_called()

    def test_start_tunnel_already_started(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._Ngrok__start_agent = Mock(return_value=True)
        self.module._Ngrok__is_agent_running = Mock(return_value=True)
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        with self.assertRaises(CommandInfo) as cm:
            self.module.start_tunnel()

        self.assertEqual(cm.exception.message, "Tunnel already started")

    def test_start_tunnel_error(self, console_mock):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.start_tunnel()

        self.assertEqual(cm.exception.message, "Unable to start ngrok agent")

    def test_stop_tunnel(self, console_mock):
        self.init()
        self.module._Ngrok__remove_cleep_tunnel = Mock(return_value=True)

        result = self.module.stop_tunnel()

        self.assertIsNone(result)

    def test_stop_tunnel_error(self, console_mock):
        self.init()
        self.module._Ngrok__remove_cleep_tunnel = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.stop_tunnel()

        self.assertEqual(cm.exception.message, "Error stoping tunnel")

    def test__add_cleep_tunnel(self, console_mock):
        self.init()
        matches = [
            responses.matchers.json_params_matcher(
                {
                    "name": "cleep",
                    "proto": "http",
                    "addr": "https://localhost",
                }
            )
        ]
        self.resp_mock.replace(
            responses.POST, self.tunnel_post_url, json={}, status=201, match=matches
        )
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        result = self.module._Ngrok__add_cleep_tunnel()
        time.sleep(2.5)  # pause due to event delayed

        self.assertTrue(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "status": "STARTED",
            },
        )

    def test__add_cleep_tunnel_request_failed(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.POST, self.tunnel_post_url, json={}, status=400
        )
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        result = self.module._Ngrok__add_cleep_tunnel()

        self.assertFalse(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": None,
                "status": "ERROR",
            },
        )

    def test__remove_cleep_tunnel(self, console_mock):
        self.init()
        self.resp_mock.replace(responses.DELETE, self.tunnel_delete_url, status=204)
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        result = self.module._Ngrok__remove_cleep_tunnel()

        self.assertTrue(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": None,
                "status": "STOPPED",
            },
        )

    def test__remove_cleep_tunnel_request_failed(self, console_mock):
        self.init()
        self.resp_mock.replace(
            responses.POST, self.tunnel_post_url, json={}, status=400
        )
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_tunnel_established = Mock(return_value=True)

        result = self.module._Ngrok__remove_cleep_tunnel()

        self.assertFalse(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "status": "STOPPED",
            },
        )

    def test__authorize_agent(self, console_mock):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__authorize_agent("auth-key")

        self.assertTrue(result)
        command_mock.assert_called_with(
            [
                "/var/opt/cleep/modules/bin/ngrok/ngrok",
                "config",
                "add-authtoken",
                "auth-key",
                "--config",
                "/var/opt/cleep/modules/bin/ngrok/ngrok.yml",
            ],
            timeout=5,
            opts=AnyArg(),
        )

    def test__authorize_agent_failed(self, console_mock):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__authorize_agent("auth-key")

        self.assertFalse(result)

    @patch("backend.ngrok.os.path.exists")
    def test__install_agent(self, MockOsPathExists, console_mock):
        self.init()
        MockOsPathExists.side_effect = [False, True]
        command_mock = Mock(
            return_value={"returncode": 0, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__install_agent()

        self.assertTrue(result)
        command_mock.assert_called_with(
            [
                "/var/opt/cleep/modules/bin/ngrok/ngrok",
                "service",
                "install",
                "--config",
                "/var/opt/cleep/modules/bin/ngrok/ngrok.yml",
            ],
            timeout=10,
            opts=AnyArg(),
        )
        self.session.cleep_filesystem.write_data.assert_not_called()
        self.session.cleep_filesystem.enable_write.assert_called()
        self.session.cleep_filesystem.disable_write.assert_called()

    @patch("backend.ngrok.os.path.exists")
    def test__install_agent_service_already_installed(
        self, MockOsPathExists, console_mock
    ):
        self.init()
        MockOsPathExists.return_value = True
        command_mock = Mock()
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__install_agent()

        self.assertTrue(result)
        command_mock.assert_not_called()
        self.session.cleep_filesystem.enable_write.assert_not_called()
        self.session.cleep_filesystem.disable_write.assert_not_called()

    @patch("backend.ngrok.os.path.exists")
    def test__install_agent_service_command_failed(
        self, MockOsPathExists, console_mock
    ):
        self.init()
        MockOsPathExists.side_effect = [False, True]
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__install_agent()

        self.assertFalse(result)
        self.session.cleep_filesystem.enable_write.assert_called()
        self.session.cleep_filesystem.disable_write.assert_called()

    @patch("backend.ngrok.os.path.exists")
    def test__install_agent_create_default_config_file(
        self, MockOsPathExists, console_mock
    ):
        self.init()
        MockOsPathExists.side_effect = [False, False]
        command_mock = Mock(
            return_value={"returncode": 0, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__install_agent()

        self.assertTrue(result)
        self.session.cleep_filesystem.write_data.assert_called_with(
            "/var/opt/cleep/modules/bin/ngrok/ngrok.yml", AnyArg()
        )
        self.session.cleep_filesystem.enable_write.assert_called()
        self.session.cleep_filesystem.disable_write.assert_called()

    def test__is_agent_running_ngrock_running(self, console_mock):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 0, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__is_agent_running()

        self.assertTrue(result)

    def test__is_agent_running_ngrock_not_running(self, console_mock):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__is_agent_running()

        self.assertFalse(result)

    def test__start_agent(self, console_mock):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        console_mock.return_value.command = command_mock
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_agent_running = Mock(return_value=False)

        result = self.module._Ngrok__start_agent()

        self.assertTrue(result)
        command_mock.assert_called_with(
            [
                "/var/opt/cleep/modules/bin/ngrok/ngrok",
                "service",
                "start",
                "--config",
                "/var/opt/cleep/modules/bin/ngrok/ngrok.yml",
            ],
            timeout=10,
            opts=AnyArg(),
        )

    def test__start_agent_command_failed(self, console_mock):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__start_agent()

        self.assertEqual(result, (False, "No authkey"))

    def test__start_agent_should_not_start_agent_if_already_running(self, console_mock):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        console_mock.return_value.command = command_mock
        self.module._get_config_field = Mock(side_effect=["auth-key"])
        self.module._Ngrok__is_agent_running = Mock(return_value=True)

        result = self.module._Ngrok__start_agent()

        self.assertTrue(result)
        command_mock.assert_not_called()

    def test__stop_agent(self, console_mock):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        console_mock.return_value.command = command_mock

        result = self.module._Ngrok__stop_agent()

        self.assertTrue(result)
        command_mock.assert_called_with(
            [
                "/var/opt/cleep/modules/bin/ngrok/ngrok",
                "service",
                "stop",
                "--config",
                "/var/opt/cleep/modules/bin/ngrok/ngrok.yml",
            ],
            timeout=10,
            opts=AnyArg(),
        )

    def test__stop_agent_failed(self, console_mock):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": ["stdout"], "stderr": ["stderr"]}
        )
        console_mock.return_value.command = command_mock
        self.module._Ngrok__is_agent_running = Mock(return_value=True)

        result = self.module._Ngrok__stop_agent()

        self.assertFalse(result)

    def test__send_tunnel_event(self, console_mock):
        self.init()
        self.module.task_factory.create_timer = Mock()

        self.module._Ngrok__send_tunnel_event()

        self.session.assert_event_called_with(
            "ngrok.tunnel.update", {"publicurl": None, "status": "STOPPED"}
        )
        self.module.task_factory.create_timer.assert_not_called()

    def test__send_tunnel_event_delayed(self, console_mock):
        self.init()
        self.module.task_factory.create_timer = Mock()

        self.module._Ngrok__send_tunnel_event(delayed=True)

        self.session.assert_event_not_called("ngrok.tunnel.update")
        self.module.task_factory.create_timer.assert_called_with(2.0, AnyArg())

    def test__send_tunnel_event_disabled(self, console_mock):
        self.init()
        self.module.task_factory.create_timer = Mock()

        self.module._Ngrok__send_tunnel_event(send_event=False)

        self.session.assert_event_not_called("ngrok.tunnel.update")
        self.module.task_factory.create_timer.assert_not_called()


class TestNgrokTunnelUpdateEvent(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(
            level=LOG_LEVEL,
            format="%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s",
        )
        params = {
            "internal_bus": Mock(),
            "formatters_broker": Mock(),
            "get_external_bus_name": None,
        }
        self.event = NgrokTunnelUpdateEvent(params)

    def test_event_params(self):
        self.assertEqual(self.event.EVENT_PARAMS, ["publicurl", "status"])


# do not remove code below, otherwise tests won't run
if __name__ == "__main__":
    unittest.main()
