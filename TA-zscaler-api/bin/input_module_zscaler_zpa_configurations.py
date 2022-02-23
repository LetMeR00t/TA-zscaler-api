
# encoding = utf-8

import os
import sys
import time
import datetime
import json

# Import custom librairies
from pyzscaler import ZPA

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # client_account = definition.parameters.get('client_account', None)
    if(definition.parameters.get('client_account', None) is None):
        helper.log_error("[ZPA] #1 - No client account was provided")
        sys.exit(1)
    pass

def collect_events(helper, ew):
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_client_account = helper.get_arg('client_account')
    # In single instance mode, to get arguments of a particular input, use
    opt_client_account = helper.get_arg('client_account', stanza_name)

    # get input type
    helper.get_input_type()

    # The following examples get input stanzas.
    # get all detailed input stanzas
    helper.get_input_stanza()
    # get specific input stanza with stanza name
    helper.get_input_stanza(stanza_name)
    # get all stanza names
    helper.get_input_stanza_names()

    # The following examples get options from setup page configuration.
    # get the loglevel from the setup page
    loglevel = helper.get_log_level()
    # get proxy setting configuration
    proxy_settings = helper.get_proxy()
    # get account credentials as dictionary
    account = helper.get_user_credential_by_username("username")
    account = helper.get_user_credential_by_id("account id")
    # get global variable configuration
    global_customer_id = helper.get_global_setting("customer_id")

    # The following examples show usage of logging related helper functions.
    # write to the log for this modular input using configured global log level or INFO as default
    helper.log("log message")
    # write to the log using specified log level
    helper.log_debug("log message")
    helper.log_info("log message")
    helper.log_warning("log message")
    helper.log_error("log message")
    helper.log_critical("log message")
    # set the log level for this modular input
    # (log_level can be "debug", "info", "warning", "error" or "critical", case insensitive)
    helper.set_log_level(log_level)

    # The following examples send rest requests to some endpoint.
    response = helper.send_http_request(url, method, parameters=None, payload=None,
                                        headers=None, cookies=None, verify=True, cert=None,
                                        timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()

    # The following examples show usage of check pointing related helper functions.
    # save checkpoint
    helper.save_check_point(key, state)
    # delete checkpoint
    helper.delete_check_point(key)
    # get checkpoint
    state = helper.get_check_point(key)

    # To create a splunk event
    helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    """

    '''
    # The following example writes a random number as an event. (Multi Instance Mode)
    # Use this code template by default.
    import random
    data = str(random.randint(0,100))
    event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data)
    ew.write_event(event)
    '''

    '''
    # The following example writes a random number as an event for each input config. (Single Instance Mode)
    # For advanced users, if you want to create single instance mod input, please use this code template.
    # Also, you need to uncomment use_single_instance_mode() above.
    import random
    input_type = helper.get_input_type()
    for stanza_name in helper.get_input_stanza_names():
        data = str(random.randint(0,100))
        event = helper.new_event(source=input_type, index=helper.get_output_index(stanza_name), sourcetype=helper.get_sourcetype(stanza_name), data=data)
        ew.write_event(event)
    '''
    # Get information about the Splunk input
    input_type = helper.get_input_type()
    opt_items = helper.get_arg('items')
    
    # Get credentials for Zscaler
    client = helper.get_user_credential_by_id("account0")
    customer_id = helper.get_global_setting("customer_id")
    
    ITEMS_MAP = {
        "app_segments": "list_segments",
        "certificates": "list_browser_access",
        "cloud_connector_groups": "list_groups",
        "connector_groups": "list_groups",
        "connectors": "list_connectors",
        "idp": "list_idps",
        "machine_groups": "list_groups",
        "posture_profiles": "list_profiles",
        "saml_attributes": "list_attributes",
        "scim_groups": "list_groups",
        "segment_groups": "list_groups",
        "server_groups": "list_groups",
        "servers": "list_servers",
        "trusted_networks": "list_networks"
    }
    
    zpa = ZPA(client_id=client["username"], client_secret=client["password"], customer_id=customer_id)
    
    # Get items (simple methods)
    for item in opt_items:
        if item in ITEMS_MAP:
            function = ITEMS_MAP[item]
            for data in getattr(getattr(zpa,item),function)():
                event = helper.new_event(source=input_type+":"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(data))
                ew.write_event(event)
    
    
    # Get policies if specified (more complex)
    if "policies" in opt_items:
        for policy_name in ["access","timeout","client_forwarding","siem"]:
            policy = zpa.policies.get_policy(policy_name)
            event = helper.new_event(source=input_type+":policies", index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(policy))
            ew.write_event(event) 
            if policy_name != "siem":
                for rule in zpa.policies.list_rules(policy_name):
                    event = helper.new_event(source=input_type+":policies:rules"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(rule))
                    ew.write_event(event) 
                
    
    # Get provisioning if specified (more complex)
    if "provisioning" in opt_items:
        for key in ["connector","service_edge"]:
            provisioning = zpa.provisioning.list_provisioning_keys(key)
            if provisioning != []:
                event = helper.new_event(source=input_type+":provisioning", index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(provisioning))
                ew.write_event(event) 
                
                
    # Get SCIM attributes if specified (more complex)
    if "scim_attributes" in opt_items:
        for idp in zpa.idp.list_idps():
            list_attributes = zpa.scim_attributes.list_attributes_by_idp(idp["id"])
            if list_attributes != []:
                event = helper.new_event(source=input_type+":scim_attributes", index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(list_attributes))
                ew.write_event(event) 


    # Get service edges if specified (more complex)
    if "service_edges" in opt_items:
        for service_edges in zpa.service_edges.list_service_edges():
            event = helper.new_event(source=input_type+":"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(service_edges))
            ew.write_event(event)
        for service_edge_groups in zpa.service_edges.list_service_edge_groups():
            event = helper.new_event(source=input_type+":"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(service_edge_groups))
            ew.write_event(event)
    