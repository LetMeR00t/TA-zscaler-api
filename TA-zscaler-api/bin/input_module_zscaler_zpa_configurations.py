
# encoding = utf-8

import os
import sys
import time
import datetime
import json
import hashlib

# Import custom librairies
from pyzscaler import ZPA
import restfly

CUSTOMER_ID_HASHED = None

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
        helper.log_error("[ZPA-E-NO_CLIENT_ACCOUNT] No client account was provided")
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
    helper.log_info("[ZPA-I-START-COLLECT] Start to recover events from Zscaler ZPA")
    
    global CUSTOMER_ID_HASHED
    
    # Get information about the Splunk input
    opt_items = helper.get_arg('items')
    
    # Get credentials for Zscaler
    client = helper.get_arg('client_account')
    customer_id = helper.get_global_setting("zpa_customer_id")
    if customer_id is None or customer_id == "":
        helper.log_error("[ZPA-E-CUSTOMER_ID_NULL] No Customer ID was provided, check your configuration")
        sys.exit(1)
        
    # Hash the Customer ID
    CUSTOMER_ID_HASHED = hashlib.sha256(customer_id.encode()).hexdigest()[:8]
    
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
        "server_groups": "list_groups",
        "servers": "list_servers",
        "trusted_networks": "list_networks"
    }
    
    # Instanciate the ZPA object with given inputs
    try:
        zpa = ZPA(client_id=client["username"], client_secret=client["password"], customer_id=customer_id)
    except restfly.errors.UnauthorizedError as e:
        helper.log_error("[ZPA-E-BAD_CREDENTIALS] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(10)
    helper.log_debug("[ZPA-D-ZPA_OBJECT] Zscaler ZPA connection object is created successfully")
    
    try:
        # Get items (simple methods)
        for item in opt_items:
            if item in ITEMS_MAP:
                function = ITEMS_MAP[item]
                all_data = getattr(getattr(zpa,item),function)()
                for data in all_data:
                    write_to_splunk(helper, ew, item, data)
                log(helper, item, all_data)
        
        # Get segment groups if specified (more complex, as we can have big segment groups)
        if "segment_groups" in opt_items:
            for data in zpa.segment_groups.list_groups():
                applications = data["applications"]
                del data["applications"]
                for app in applications:
                    data["application"] = app
                    write_to_splunk(helper, ew, "segment_groups:"+str(data["id"]), data)
                    log(helper, "segment_groups", data)
                    
        
        # Get policies if specified (more complex)
        if "policies" in opt_items:
            for policy_name in ["access","timeout","client_forwarding","siem"]:
                policy = zpa.policies.get_policy(policy_name)
                write_to_splunk(helper, ew, "policies", policy)
                log(helper, "policies", policy)
                if policy_name != "siem":
                    all_data = zpa.policies.list_rules(policy_name)
                    for rule in all_data:
                        write_to_splunk(helper, ew, "policies:rules", rule)
                    log(helper, "policies:rules", all_data)
                    
        
        # Get provisioning if specified (more complex)
        if "provisioning" in opt_items:
            for key in ["connector","service_edge"]:
                provisioning = zpa.provisioning.list_provisioning_keys(key)
                if provisioning != []:
                    write_to_splunk(helper, ew, "provisioning", provisioning)
                    log(helper, "provisioning", provisioning)
                    
                    
        # Get SCIM attributes if specified (more complex)
        if "scim_attributes" in opt_items:
            for idp in zpa.idp.list_idps():
                list_attributes = zpa.scim_attributes.list_attributes_by_idp(idp["id"])
                if list_attributes != []:
                    write_to_splunk(helper, ew, "scim_attributes", list_attributes)
                    log(helper, "scim_attributes", list_attributes)
    
    
        # Get SCIM groups if specified (more complex)
        if "scim_groups" in opt_items:
            for idp in zpa.idp.list_idps():
                list_groups = zpa.scim_groups.list_groups(idp["id"])
                if list_groups != []:
                    write_to_splunk(helper, ew, "scim_groups", list_groups)
                    log(helper, "scim_groups", list_groups)
    
    
        # Get service edges if specified (more complex)
        if "service_edges" in opt_items:
            all_data = zpa.service_edges.list_service_edges()
            for service_edges in all_data:
                write_to_splunk(helper, ew, "service_edges", service_edges)
            log(helper, "service_edges", list_groups)
            all_data = zpa.service_edges.list_service_edge_groups()
            for service_edge_groups in all_data:
                write_to_splunk(helper, ew, "service_edge_groups", service_edge_groups)
            log(helper, "service_edge_groups", list_groups)
    except restfly.errors.BadRequestError as e:
        helper.log_error("[ZPA-E-BAD_REQUEST] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(15)
        
    helper.log_info("[ZPA-I-END-COLLECT] 🟢 Events from Zscaler ZPA are recovered")



# This function is writing events in Splunk
def write_to_splunk(helper, ew, item, data):
    # Add which Zscaler instance
    event = helper.new_event(source="zpa:"+CUSTOMER_ID_HASHED+":"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(data))
    ew.write_event(event)
    
    
# This function is logging information in the search.log
def log(helper, item, all_data):
    if len(all_data)>0 and all_data!=[]:
        helper.log_debug("[ZPA-D-EVENTS_WRITTEN] Events are written for "+item+" to the index "+helper.get_output_index()+": "+str(all_data))
    else:
        helper.log_debug("[ZPA-D-NO_EVENT_FOUND] No event found for "+item)
        