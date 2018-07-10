# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from code42_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class Code42Connector(BaseConnector):

    def __init__(self):
        super(Code42Connector, self).__init__()
        self._state = None
        self.username = None
        self.password = None
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if not r.text:
            return self._process_empty_reponse(r, action_result)
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            auth=(self.username, self.password),  # basic authentication
                            data=data,
                            headers=headers,
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call('/api/Org', action_result, method="get")
        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed")
        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['Result'] = "Connection Successful"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        required_parameter = param['required_parameter']
        ret_val, response = self._make_rest_call('/api/ComputerBlock/{}'.format(required_parameter), action_result, params=None, headers=None, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        summary = action_result.update_summary({})
        summary['Blocked'] = "Successful"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activate_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        required_parameter = param['required_parameter']
        ret_val, response = self._make_rest_call('/api/UserDeactivation/{}'.format(required_parameter), action_result, params=None, headers=None, method="delete")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        summary = action_result.update_summary({})
        summary['result: '] = "User has been activated"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_deactivate_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        required_parameter = param['required_parameter']
        ret_val, response = self._make_rest_call('api/UserDeactivation/{}'.format(required_parameter), action_result, params=None, headers=None, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(response)
        action_result.add_data({})
        summary = action_result.update_summary({})
        summary['User deactivation Result'] = "Given user has been deactivated"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        required_parameter = param['required_parameter']
        ret_val, response = self._make_rest_call('api/ComputerBlock/{}'.format(required_parameter), action_result, params=None, headers=None, method="delete")
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        summary = action_result.update_summary({})
        summary['Result: '] = "Device has been unblocked"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_devices(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call('/api/Computer', action_result, params=None, headers=None, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['Number of devices'] = len(response["data"]["computers"])
        summary['ComputerIds:'] = [x["computerId"] for x in response["data"]["computers"]]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call('/api/User', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['Number of users'] = response["data"]["totalCount"]
        summary['UserIds:'] = [x["userId"] for x in response["data"]["users"]]

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'block_device':
            ret_val = self._handle_block_device(param)

        elif action_id == 'activate_user':
            ret_val = self._handle_activate_user(param)

        elif action_id == 'unblock_device':
            ret_val = self._handle_unblock_device(param)

        elif action_id == 'deactivate_user':
            ret_val = self._handle_deactivate_user(param)

        elif action_id == 'list_devices':
            ret_val = self._handle_list_devices(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self.username = config.get("username")
        self.password = config.get("password")
        self._base_url = config.get('server_url')

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Code42Connector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
