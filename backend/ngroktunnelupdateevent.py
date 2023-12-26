#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cleep.libs.internals.event import Event


class NgrokTunnelUpdateEvent(Event):
    """
    Ngrok.tunnel.update event
    """

    EVENT_NAME = "ngrok.tunnel.update"
    EVENT_PROPAGATE = False
    EVENT_PARAMS = ["publicurl", "status"]

    def __init__(self, params):
        """
        Constructor

        Args:
            params (dict): event parameters
        """
        Event.__init__(self, params)
