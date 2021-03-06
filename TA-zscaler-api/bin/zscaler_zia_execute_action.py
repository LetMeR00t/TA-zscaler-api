
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_zscaler_api_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_zscaler_zia_execute_action_helper

class AlertActionWorkerzscaler_zia_execute_action(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerzscaler_zia_execute_action, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("instances"):
            self.log_error('instances is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("account_username_instance_1"):
            self.log_error('account_username_instance_1 is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("account_username_instance_2"):
            self.log_error('account_username_instance_2 is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("account_username_instance_3"):
            self.log_error('account_username_instance_3 is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("action"):
            self.log_error('action is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_zscaler_zia_execute_action_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkerzscaler_zia_execute_action("TA-zscaler-api", "zscaler_zia_execute_action").run(sys.argv)
    sys.exit(exitcode)
