import logging
from pprint import pprint

import requests
from requests.auth import HTTPBasicAuth

"""
Configure Logging
"""
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class kibana:
    def __init__(self, username, password, base_url):
        """
        :param config: Configuration dict, needs URL, Authentication and Certificate
        {
        "url":"https://ivm.host",
        "auth":"base64 encoded username:password",
        "cert":"Path to certificate or False",
        }
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.headers = {
            "kbn-xsrf": "true",
        }

    def _post(self, url, payload):
        url = self.base_url + url
        response = requests.post(url,
                                 headers=self.headers,
                                 data=payload,
                                 auth=HTTPBasicAuth(self.username, self.password))
        if response.status_code == 200:
            pprint(response.text)
            return True
        else:
            print("error")
            pprint(payload)
            pprint(response.json())
            return False

    def _patch(self, url, payload):
        url = self.base_url + url
        response = requests.patch(url,
                                  headers=self.headers,
                                  data=payload,
                                  auth=HTTPBasicAuth(self.username, self.password))
        if response.status_code == 200:
            pprint(response.text)
            return True
        else:
            print("error")
            pprint(payload)
            pprint(response.json())
            return False

    def disable_rule(self, rule):
        payload = {"rule_id": rule,
                   "enabled": False}
        self._patch("/detection_engine/rules", payload)

    def add_rule(self, rule):
        # self._post("/detection_engine/rules", rule)
        self._post("/detection_engine/rules/_bulk_create", rule)

    def add_rule_import(self, rule):
        self._post("/detection_engine/rules/_import", rule)

    def post_close_alert(self, signal_ids):
        payload = {"signal_ids": signal_ids,
                   "status": "closed"}
        self._post("/detection_engine/signals/status", payload)

    def post_ack_alert(self, signal_ids):
        payload = {"signal_ids": signal_ids,
                   "status": "in-progress"}
        self._post("/detection_engine/signals/status", payload)

    def _get(self, url, params={}):
        url = self.base_url + url
        return requests.get(url,
                            headers=self.headers,
                            params=params,
                            auth=HTTPBasicAuth(self.username, self.password)).json()

    def _get_paginated(self, url, params={}):
        url = self.base_url + url
        page = 1
        go = 1
        while go == 1:
            params["page"] = page
            response = requests.get(url,
                                    headers=self.headers,
                                    params=params,
                                    auth=HTTPBasicAuth(self.username, self.password), )
            if response.status_code == 200 and "data" in response.json():
                response = response.json()
                if len(response["data"]) > 0:
                    page += 1
                    if "output" in locals():
                        output = output + response["data"]
                    else:
                        output = response["data"]
                else:
                    go = 0
        return output

    def get_rules(self, filter=None):
        params = {}
        if filter:
            params = {"filter": filter}
        return self._get_paginated("/detection_engine/rules/_find", params=params)

    def get_rule(self, rule_id=None):
        if rule_id:
            url = "/detection_engine/rules?rule_id=" + rule_id
            return self._get(url)
        else:
            print("Rule ID Missing")

    def get_dataview(self, view_id=None):
        if view_id:
            url = "/data_views/data_view/" + view_id
            return self._get(url)
        else:
            print("View ID Missing")

    def get_exception_lists(self):
        return self._get_paginated("/exception_lists/_find")

    def _patch(self, url, payload):
        url = self.base_url + url
        response = requests.patch(
            url,
            auth=HTTPBasicAuth(self.username, self.password),
            headers=self.headers,
            json=payload,
        )
        if response.status_code == 200:
            return True
        else:
            logger.error(payload)
            logger.error(response.json())
            return False

    def update_rule_exceptions_list(self, rule_id, exceptions_list=None):
        if exceptions_list:
            payload = {"rule_id": rule_id, "exceptions_list": exceptions_list}
            url = "/detection_engine/rules"
            self._patch(url, payload)
        else:
            print("Exception List missing")
