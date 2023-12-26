#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import logging
import sys
sys.path.append('../')
from backend.ngrok import Ngrok
from cleep.exception import InvalidParameter, MissingParameter, CommandError, Unauthorized
from cleep.libs.tests import session
from mock import Mock, patch

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
class TestNgrok(unittest.TestCase):

    def setUp(self):
        # Change here logging.DEBUG to logging.FATAL to disable logging during tests writings
        # Note that coverage command does not display logging
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s')
        self.session = session.TestSession(self)

    def tearDown(self):
        # clean session
        self.session.clean()

    def init(self, start=True):
        """
        Call this function at beginning of every test cases. By default it starts your app, but if you specify start=False,
        the application must be started manually which is useful in some cases like testing _on_configure app function.
        """
        # next line instanciates your module, overwriting all useful stuff to isolate your module for tests
        self.module = self.session.setup(Ngrok)
        if start:
            self.session.start_module(self.module)

    # Write your tests here defining functions starting with "test_"
    # See official documentation https://docs.python.org/3/library/unittest.html
    # def test__on_configure(self):
    #   self.init(start=False)
    #   # create your mocks...
    #
    #   self.module._on_configure()
    #
    #   # check your mocks

    # Write another test. A test case always starts with "test_"
    # def test_my_function(self):
    #   self.init()
    #   # create your mocks
    #
    #   result = self.module.my_function()
    #
    #   # checks your mocks or function result

# do not remove code below, otherwise tests won't run
if __name__ == '__main__':
    unittest.main()
    
