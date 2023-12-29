#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from cleep.libs.tests import session
from cleep.libs.tests.common import get_log_level
from mock import Mock, patch
import responses

LOG_LEVEL = get_log_level()


class DummyProc:
    def __init__(self, name):
        self.__name = name

    def name(self):
        return self.__name


# Unit testing is part of a development, it's why Cleep requires to have application code tested to
# guarantee a certain source code quality.
#
# If you new to unit testing, you can find a good introduction here https://realpython.com/python-testing/
# Cleep uses unittest framework for which you can find documentation here https://docs.python.org/3/library/unittest.html
#
# You can launch all your tests manually using this command:
#   python3 -m unittest test_ngrok.TestNgrok
# or a specific test with command:
#   python3 -m unittest test_ngrok.TestNgrok.test__on_configure
# You can get tests coverage with command:
#   coverage run --omit=*/lib/python*/*,test_* --concurrency=thread test_ngrok.py; coverage report -m -i
# or you can simply use developer application that allows you to perform all tests and coverage directly from web interface
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
        self.tunnel_post_url = f"{self.tunnels_url}"
        self.tunnel_delete_url = f"{self.tunnels_url}/{Ngrok.CLEEP_TUNNEL_NAME}"
        self.resp_mock.get(self.tunnel_get_url, None)
        self.resp_mock.delete(self.tunnel_delete_url, None)
        self.resp_mock.post(self.tunnel_post_url, json={}, status=201)

        if start:
            self.session.start_module(self.module)

    @patch("backend.ngrok.Timer")
    def test_on_start(self, MockTimer, MockConsole):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=True)

        self.module._on_start()

        MockTimer.assert_called_with(10.0, session.AnyArg())

    @patch("backend.ngrok.Timer")
    def test_on_start_should_start_tunnel_if_agent_starts_successfully(
        self, MockTimer, MockConsole
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=True)

        self.module._on_start()

        MockTimer.assert_called_with(10.0, session.AnyArg())

    @patch("backend.ngrok.Timer")
    def test_on_start_should_not_start_tunnel_if_agent_fails_to_authorize(
        self, MockTimer, MockConsole
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=False)
        self.module._Ngrok__start_agent = Mock(return_value=True)

        self.module._on_start()

        MockTimer.assert_not_called()
        self.module._Ngrok__start_agent.assert_not_called()

    @patch("backend.ngrok.Timer")
    def test_on_start_should_not_start_tunnel_if_agent_fails_to_start(
        self, MockTimer, MockConsole
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)
        self.module._Ngrok__start_agent = Mock(return_value=False)

        self.module._on_start()

        MockTimer.assert_not_called()

    @patch("backend.ngrok.Timer")
    def test_on_start_should_not_start_tunnel_if_tunnel_already_started(
        self, MockTimer, MockConsole
    ):
        self.init(start=False, mock_on_start=False)
        self.module._get_config_field = Mock(side_effect=["auth-key", True])
        self.module._Ngrok__is_agent_running = Mock(return_value=True)
        self.module._Ngrok__get_tunnel_info = Mock(return_value={"id": "123456789"})

        self.module._on_start()

        MockTimer.assert_not_called()

    def test_on_stop(self, MockConsole):
        self.init(start=False, mock_on_stop=False)
        self.module._Ngrok__remove_cleep_tunnel = Mock()

        self.module._on_stop()

        self.module._Ngrok__remove_cleep_tunnel.assert_called()

    def test_on_stop_shoud_not_fail_if_remove_cleep_tunnel_call_failed(
        self, MockConsole
    ):
        self.init(start=False, mock_on_stop=False)
        self.module._Ngrok__remove_cleep_tunnel = Mock(
            side_effect=Exception("Test error")
        )

        try:
            self.module._on_stop()
        except:
            self.fail("Should not trigger exception")

    def test_get_module_with_tunnel_info(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        config = self.module.get_module_config()

        self.assertDictEqual(
            config,
            {
                "authkey": None,
                "autostart": True,
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "tunnelstatus": "STOPPED",
            },
        )

    def test_get_module_without_tunnel_info(self, MockConsole):
        self.init()

        config = self.module.get_module_config()

        self.assertDictEqual(
            config,
            {
                "authkey": None,
                "autostart": True,
                "publicurl": None,
                "tunnelstatus": "STOPPED",
            },
        )

    def test_set_auto_start_ok(self, MockConsole):
        self.init()
        self.module._set_config_field = Mock(return_value=True)

        self.module.set_auto_start(True)

        self.module._set_config_field.assert_called_with("autostart", True)

    def test_set_auto_start_error_saving_config(self, MockConsole):
        self.init()
        self.module._set_config_field = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.set_auto_start(False)

        self.assertEqual(cm.exception.message, "Unable to save config")
        self.module._set_config_field.assert_called_with("autostart", False)

    def test_set_auto_start_check_params(self, MockConsole):
        self.init()

        with self.assertRaises(InvalidParameter) as cm:
            self.module.set_auto_start("test")

        self.assertEqual(
            cm.exception.message, 'Parameter "auto_start" must be of type "bool"'
        )

    def test_set_auth_key(self, MockConsole):
        self.init()
        self.module._set_config_field = Mock(return_value=True)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)

        result = self.module.set_auth_key("a-key")

        self.module._set_config_field.assert_called_with("authkey", "a-key")

    def test_set_auth_key_auth_failed(self, MockConsole):
        self.init()
        self.module._set_config_field = Mock(return_value=True)
        self.module._Ngrok__authorize_agent = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            result = self.module.set_auth_key("a-key")

        self.assertEqual(cm.exception.message, "Can't authorize with specified key")
        self.module._set_config_field.assert_not_called()

    def test_set_auth_key_config_saving_fails(self, MockConsole):
        self.init()
        self.module._set_config_field = Mock(return_value=False)
        self.module._Ngrok__authorize_agent = Mock(return_value=True)

        with self.assertRaises(CommandError) as cm:
            result = self.module.set_auth_key("a-key")

        self.assertEqual(cm.exception.message, "Unable to save config")
        self.module._set_config_field.assert_called_with("authkey", "a-key")

    def test_get_tunnel_info(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

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

    def test_get_tunnel_info_without_info(self, MockConsole):
        self.init()

        with self.assertRaises(CommandError) as cm:
            self.module.get_tunnel_info()

        self.assertEqual(cm.exception.message, "Unable to get tunnel info")

    def test__get_tunnel_info(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        info = self.module._Ngrok__get_tunnel_info()

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

    def test__get_tunnel_info_handle_status_not_200(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO, status=400
        )

        info = self.module._Ngrok__get_tunnel_info()

        self.assertIsNone(info)

    def test__get_tunnel_info_handle_error(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, body=Exception("Network error")
        )

        info = self.module._Ngrok__get_tunnel_info()

        self.assertIsNone(info)

    def test_start_tunnel(self, MockConsole):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=True)

        result = self.module.start_tunnel()

        self.assertIsNone(result)

    def test_start_tunnel_already_started(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=True)

        with self.assertRaises(CommandInfo) as cm:
            self.module.start_tunnel()

        self.assertEqual(cm.exception.message, "Tunnel already started")

    def test_start_tunnel_error(self, MockConsole):
        self.init()
        self.resp_mock.replace(responses.GET, self.tunnel_get_url, json=None)
        self.module._Ngrok__add_cleep_tunnel = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.start_tunnel()

        self.assertEqual(cm.exception.message, "Error starting tunnel")

    def test_stop_tunnel(self, MockConsole):
        self.init()
        self.module._Ngrok__remove_cleep_tunnel = Mock(return_value=True)

        result = self.module.stop_tunnel()

        self.assertIsNone(result)

    def test_stop_tunnel_error(self, MockConsole):
        self.init()
        self.module._Ngrok__remove_cleep_tunnel = Mock(return_value=False)

        with self.assertRaises(CommandError) as cm:
            self.module.stop_tunnel()

        self.assertEqual(cm.exception.message, "Error stoping tunnel")

    def test__add_cleep_tunnel(self, MockConsole):
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

    def test__add_cleep_tunnel_request_failed(self, MockConsole):
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
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "status": "ERROR",
            },
        )

    def test__remove_cleep_tunnel(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.DELETE, self.tunnel_delete_url, json={}, status=204
        )
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        result = self.module._Ngrok__remove_cleep_tunnel()

        self.assertTrue(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "status": "STOPPED",
            },
        )

    def test__remove_cleep_tunnel_request_failed(self, MockConsole):
        self.init()
        self.resp_mock.replace(
            responses.POST, self.tunnel_post_url, json={}, status=400
        )
        self.resp_mock.replace(
            responses.GET, self.tunnel_get_url, json=self.TUNNEL_INFO
        )

        result = self.module._Ngrok__remove_cleep_tunnel()

        self.assertFalse(result)
        self.session.assert_event_called_with(
            "ngrok.tunnel.update",
            {
                "publicurl": "https://dummy-82-64-200-227.ngrok-free.app",
                "status": "STOPPED",
            },
        )

    def test__authorize_agent(self, MockConsole):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__authorize_agent("auth-key")

        self.assertTrue(result)
        command_mock.assert_called_with(
            ["./ngrok", "config", "add-authtoken", "auth-key"],
            timeout=5,
            opts=session.AnyArg(),
        )

    def test__authorize_agent_failed(self, MockConsole):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": "stdout", "stderr": "stderr"}
        )
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__authorize_agent("auth-key")

        self.assertFalse(result)

    @patch(
        "backend.ngrok.psutil.process_iter",
        Mock(return_value=iter([DummyProc("ngrok")])),
    )
    def test__is_agent_running_ngrock_running(self, MockConsole):
        self.init()

        result = self.module._Ngrok__is_agent_running()

        self.assertTrue(result)

    @patch(
        "backend.ngrok.psutil.process_iter",
        Mock(return_value=iter([DummyProc("test")])),
    )
    def test__is_agent_running_ngrock_not_running(self, MockConsole):
        self.init()

        result = self.module._Ngrok__is_agent_running()

        self.assertFalse(result)

    def test__start_agent(self, MockConsole):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__start_agent()

        self.assertTrue(result)
        command_mock.assert_called_with(
            ["./ngrok", "service", "start"], timeout=10, opts=session.AnyArg()
        )

    def test__start_agent_failed(self, MockConsole):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": "stdout", "stderr": "stderr"}
        )
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__start_agent()

        self.assertFalse(result)

    def test__stop_agent(self, MockConsole):
        self.init()
        command_mock = Mock(return_value={"returncode": 0})
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__stop_agent()

        self.assertTrue(result)
        command_mock.assert_called_with(
            ["./ngrok", "service", "stop"], timeout=10, opts=session.AnyArg()
        )

    def test__stop_agent_failed(self, MockConsole):
        self.init()
        command_mock = Mock(
            return_value={"returncode": 1, "stdout": "stdout", "stderr": "stderr"}
        )
        MockConsole.return_value.command = command_mock

        result = self.module._Ngrok__stop_agent()

        self.assertFalse(result)

    @patch("backend.ngrok.Timer")
    def test__send_tunnel_event(self, MockTimer, MockConsole):
        self.init()

        self.module._Ngrok__send_tunnel_event()

        self.session.assert_event_called_with(
            "ngrok.tunnel.update", {"publicurl": None, "status": "STOPPED"}
        )
        MockTimer.assert_not_called()

    @patch("backend.ngrok.Timer")
    def test__send_tunnel_event_delayed(self, MockTimer, MockConsole):
        self.init()

        self.module._Ngrok__send_tunnel_event(delayed=True)

        self.session.assert_event_not_called("ngrok.tunnel.update")
        MockTimer.assert_called_with(2.0, session.AnyArg())

    @patch("backend.ngrok.Timer")
    def test__send_tunnel_event_disabled(self, MockTimer, MockConsole):
        self.init()

        self.module._Ngrok__send_tunnel_event(send_event=False)

        self.session.assert_event_not_called("ngrok.tunnel.update")
        MockTimer.assert_not_called()


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
