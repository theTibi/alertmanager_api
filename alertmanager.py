"""
AlertManager Library
"""

from abc import abstractmethod
from datetime import (
      datetime,
      timedelta
)
import logging
import os
import socket
import sys

import requests
import yaml

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(name)s: PID<%(process)d> %(module)s.%(funcName)s - %(message)s')

MULTIPLIER = 1000  # 1s
MAX_DELAY = 30000  # 30s
EXPONENTIAL_MAX = 8000  # 8s
MAX_ATTEMPTS = 3


class Alerts(object):
    """
    Interface to the AlertManager API.

    Alert Manager comes packaged with Prometheus and is used for alert
    management. This class aims to create an interface that simplifies
    interactions with the Alert Manager API. It also provides a simple means of
    introducing alerts into Alert Manager that do not originate from
    Prometheus.
    """

    enable_tls_verification = False
    valid_labels = ["node_name", "alertname", "severity", "service", "type", "service_type", "runbook",
                    "alertgroup", "message"]
    valid_annotations = ["description", "summary"]

    def __init__(self, **kwargs):
        """
        Init method.

        """
        self.kwargs = kwargs
        # _alert_obj is the basic dict for alerts
        self._alert_obj = {
            "labels": {
                "node_name": socket.gethostname(),
                "alertgroup": "Managed Service - Tooling Alerts",
                "service_type": "tooling",
                "service": "tooling"
            },
            "endsAt": self.endsat.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        }

        # list of dicts for labels and annotations
        self._alert_obj_list = []

    @property
    def api(self):
        """
        :return: Returns AlertManager API URL
        :rtype: str
        """
        if self.kwargs.get('api'):
            return self.kwargs.get('api')

        return self.get_api_url()

    @property
    def credentials(self):
        """
        :return: Returns AlertManager API credentials
        :rtype: tuple
        """
        if self.kwargs.get('username') and self.kwargs.get('password'):
            return self.kwargs.get('username'), self.kwargs.get('password')

        return self.get_credentials()

    @property
    def port(self):
        """
        :return: Returns AlertManager API URL
        :rtype: int
        """
        if self.kwargs.get('port'):
            return self.kwargs.get('port')

        return 443

    @property
    def endsat(self):
        """
        :return: Returns Alert's ends date
        :rtype: datetime
        """
        if self.kwargs.get('endsat'):
            return self.kwargs.get('endsat')

        return datetime.today() + timedelta(minutes=5)

    @staticmethod
    def get_api_url():
        """
        Lookup constants from disk

        :param
        :type
        :return:
        :rtype: tuple
        """
        return "https://127.0.0.1/alertmanager/"

    @staticmethod
    def get_credentials():
        """
        Lookup alertmanager address from disk

        :param
        :type
        :return:
        :rtype: tuple
        """
        customer_constants = {"username": "pmm",
                              "password": "password"}
        return customer_constants.get('username', 'pmm'), \
               customer_constants.get('password', 'password')

    @abstractmethod
    def configure_alert(self):
        """
        Every tool should Implement this methode and at least add the followings:
        - alertname
        - runbook

        Example:

        labels = {
        "alertname": "awesome tool",
        "runbook": "https://runbook_for_awesome_tool",
        }
        return labels
        """
        raise NotImplementedError("Subclasses should implement this!")

   # @retry(wait_exponential_multiplier=MULTIPLIER, stop_max_delay=MAX_DELAY,
   #        wait_exponential_max=EXPONENTIAL_MAX, stop_max_attempt_number=MAX_ATTEMPTS)
    def _make_request(self, method="GET", **kwargs):
        """
        Make our HTTP request and return a requests.Response object.

        :param method: This is our HTTP verb. (Default value = "GET")
        :type method: str
        :param kwargs: Arbitrary keyword arguments.
        :return: Return the response from our API call.
        :rtype: requests.Response
        """
        if not self.enable_tls_verification:
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

        api = "{}api/v1/alerts".format(self.api)
        if "127.0.0.1" in api or "localhost" in api:
            return requests.Session().request(method, api, verify=self.enable_tls_verification,
                                              json=kwargs.get('json'), params=kwargs.get('params'))

        return requests.Session().request(method, api, verify=self.enable_tls_verification, auth=self.credentials,
                                          json=kwargs.get('json'), params=kwargs.get('params'))

    def get_alerts(self, **kwargs):
        """
        Get a list of all alerts currently in Alert Manager.
        This method returns a list of all firing alerts from our Alert Manager
        instance.

        :param kwargs:  Arbitrary keyword arguments. These kwargs can be used to specify
            filters to limit the return of our list of alerts to alerts that
            match our filter.
        :type kwargs: dict
        :return response: Return a list of Alert objects from our Alert Manager instance.
        :rtype: requests.Response
        """
        self._validate_get_alert_kwargs(**kwargs)
        response = self._make_request("GET", params=kwargs)
        self._check_response(response)
        return response

    @staticmethod
    def _check_response(response):
        """
        Log an error if our responses are not what we expect.

        :param response: Response of our request to AlertManager API
        :type response: requests.Response
        :return: Return True if response check is successful.
        :rtype: boolean
        """
        if (response.status_code == requests.codes.ok  # pylint: disable=no-member
                and response.json()['status'] in "success"):
            logging.info("Sending Alert was successful.")
            return True

        if (response.status_code == requests.codes.ok  # pylint: disable=no-member
                and response.json()['status'] in "error"):
            logging.info("Sending Alert has failed!")
            logging.debug('Unexpected response error: %s - %s', response.json()['errorType'],
                          response.json()['error'])
            raise ValueError('Unexpected response error: %s - %s', response.json()['errorType'],
                             response.json()['error'])

        logging.info("Sending Alert has failed!")
        logging.debug('Unexpected HTTP error: %s - %s', response.status_code, response.text)
        raise requests.exceptions.RequestException(
            'Unexpected HTTP error: %s - %s', response.status_code, response.text)

    @staticmethod
    def _validate_get_alert_kwargs(**kwargs):
        """
        Check kwargs for validity.
        This is a protected method and should not be used outside of the
        get_alerts method. Here we verify that the kwargs we pass to filter our
        returned alerts is sane and contains keys Alert Manager knows about.

        :param kwargs: Arbitrary keyword arguments. These kwargs are used to specify
            filters to limit the return of our list of alerts to alerts that
            match our filter.
        :type kwargs: dict

        :raise: If a key in our kwargs doesn't match our list of valid_keys,
            we raise a key error. We prevent filter keys that Alert Manager
            doesn't understand from being passed in a request.
        :type: KeyError
        """
        valid_keys = ['filter', 'silenced', 'inhibited']
        for key in kwargs:
            if key not in valid_keys:
                raise ValueError('invalid get parameter {}'.format(key))

        return True

    @staticmethod
    def _check_alerts(alerts):
        """
        Check if our alert has the basic informations.

        :param alerts: Alerts list (list of dicts )
        :type alerts: list
        :return: True if it has all the informations.
        :rtype: boolean
        """
        if isinstance(alerts, list) and 'labels' in alerts[0]:
            return 'alertname' in alerts[0]['labels'] and 'message' in alerts[0]['labels']
        return False

    def post_alert(self):
        """
        Post Alert to AlertManager

        :return: Returns the response from AlertManager
        :rtype: requests.Response
        """
        self._alert_obj_list.append(self._alert_obj)
        if self._check_alerts(self._alert_obj_list):
            logging.info("Sending Alert - %s - %s", self._alert_obj_list[0]['labels']['alertname'],
                         self._alert_obj_list[0]['labels']['message'])
            response = self._make_request("POST", json=self._alert_obj_list)
        else:
            logging.info("Alert syntax is not valid!")
            raise SyntaxError("Alert syntax is not valid!")

        self._check_response(response)
        return response

    def add_labels(self, **kwargs):
        """
        Adding Labels to the alert dictionary

        :param kwargs: Key Value pairs for alert labels
        :type kwargs: dict
        :return: Alert dictionary
        :rtype: dict
        """
        if self.configure_alert():
            self._alert_obj['labels'].update(
                {k: v for k, v, in self.configure_alert().items() if self.validate_label(k)})

        self._alert_obj['labels'].update({k: v for k, v in kwargs.items() if self.validate_label(k)})

    def add_annotation(self, **kwargs):
        """
        Adding annotations to the alert dictionary

        :param kwargs: Key Value pairs for annotation labels
        :type kwargs: dict
        :return: Annotation dictionary
        :rtype: dict
        """
        self._alert_obj.setdefault('annotations', {})
        self._alert_obj['annotations'].update({k: v for k, v in kwargs.items() if self.validate_annotation(k)})

    def validate_label(self, label):
        """
        List of valid labels

        :param label: Label
        :type label: str
        :return: True if alert is in the list
        :rtype: boolean
        """
        if label in self.valid_labels:
            return True

        logging.info("%s will be skipped because it not in the valid labels list, ", label)
        return False

    def validate_annotation(self, annotation):
        """
        List of valid labels

        :param annotation: annotation
        :type annotation: str
        :return: True if annotation is in the list
        :rtype: boolean
        """
        if annotation in self.valid_annotations:
            return True

        logging.info("%s will be skipped because it not in the valid annotations list", annotation)
        return False

class MyTool(Alerts):
    """
    My awesome tool
    """

    def configure_alert(self):
        """
        Implementing configure_alert()
        """
        return {"alertname": "awesome tool", "runbook": "https://runbook_for_awesome_tool"}


def main():
    """
    Posting an alert.
    """
    alerts = MyTool()
    alerts.add_labels(severity="critical", message="awesome tool had an error in XY section")
    alerts.add_annotation(summary="alert summary", description="This is a test alert")
    alerts.post_alert()


if __name__ == "__main__":
    main()
