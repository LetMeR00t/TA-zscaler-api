
# encoding = utf-8

import os
import sys
import time
import datetime
import json
import hashlib

# Import custom librairies
from pyzscaler import ZIA
import restfly

INPUT_UID = None
ZSCALER_INSTANCE = None
MAXIMUM_URL_PER_CATEGORY = 200
MAXIMUM_DEST_IP_PER_RULE = 300

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
    # items = definition.parameters.get('items', None)
    if(definition.parameters.get('client_account', None) is None):
        helper.log_error("[ZIA-E-NO_CLIENT_ACCOUNT] No client account was provided")
        sys.exit(1)
    pass

def collect_events(helper, ew):
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_client_account = helper.get_arg('client_account')
    opt_items = helper.get_arg('items')
    # In single instance mode, to get arguments of a particular input, use
    opt_client_account = helper.get_arg('client_account', stanza_name)
    opt_items = helper.get_arg('items', stanza_name)

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
    helper.log_info("[ZIA-I-START-COLLECT] Start to recover configuration events from Zscaler ZIA")
    
    global ZSCALER_INSTANCE
    global INPUT_UID
    
    # Set the Zscaler instance name
    ZSCALER_INSTANCE = list(helper.get_input_stanza().keys())[0]
    
    # Calculate a unique ID for the given input event recovery
    INPUT_UID = hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:8]
    
    # Get information about the Splunk input
    opt_instance = helper.get_arg('instance')
    opt_items = helper.get_arg('items')
    
    # Get credentials for Zscaler
    client = helper.get_arg('client_account')
    api_key = helper.get_global_setting("instance_"+str(opt_instance)+"_zia_api_key")
    if api_key is None or api_key == "":
        helper.log_error("[ZIA-E-API_KEY_NULL] No API key was provided for instance n°"+str(opt_instance)+", check your configuration")
        sys.exit(1)
        
    cloud = helper.get_global_setting("instance_"+str(opt_instance)+"_zia_cloud")
    if cloud is None or cloud == "":
        helper.log_error("[ZIA-E-CLOUD_NULL] No Cloud information was provided for instance n°"+str(opt_instance)+", check your configuration")
        sys.exit(1)

    ITEMS_MAP = {
        "admin_users": {"key": "admin_and_role_management", "func": "list_users"},
        "admin_roles": {"key": "admin_and_role_management", "func": "list_roles"},
        "dlp": {"key": "dlp", "func": "list_dicts"},
        "network_app_groups": {"key": "firewall", "func": "list_network_app_groups"},
        "network_apps": {"key": "firewall", "func": "list_network_apps"},
        "network_svc_groups": {"key": "firewall", "func": "list_network_svc_groups"},
        "network_services": {"key": "firewall", "func": "list_network_services"},
        "gre_tunnels": {"key": "traffic", "func": "list_gre_tunnels"},
        "gre_ranges": {"key": "traffic", "func": "list_gre_ranges"},
        "static_ips": {"key": "traffic", "func": "list_static_ips"},
        "vips": {"key": "traffic", "func": "list_vips"},
        "vpn_credentials": {"key": "traffic", "func": "list_vpn_credentials"},
        "url_filtering_rules": {"key": "url_filters", "func": "list_rules"},
        "users": {"key": "users", "func": "list_users"},
        "users_departments": {"key": "users", "func": "list_departments"},
        "users_groups": {"key": "users", "func": "list_groups"}
    }
    
    # Instanciate the ZPA object with given inputs
    try:
        zia = ZIA(api_key=api_key, cloud=cloud, username=client["username"], password=client["password"])
    except restfly.errors.BadRequestError as e:
        helper.log_error("[ZIA-E-BAD_CREDENTIALS] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(10)
    
    helper.log_debug("[ZIA-D-ZIA_OBJECT] Zscaler ZIA connection object is created successfully")
    try:
        # Get items (simple methods)
        for item in opt_items:
            if item in ITEMS_MAP:
                key = ITEMS_MAP[item]["key"]
                function = ITEMS_MAP[item]["func"]
                all_data = getattr(getattr(zia,key),function)()
                for data in all_data:
                    write_to_splunk(helper, ew, item, data)
                log(helper, item, all_data)
            
        # Get URL categories if specified (more complex, as we can have categories with a lot of URLs defined)
        if "url_categories" in opt_items:
            for data in zia.url_categories.list_categories():
                urls_lists = [data["urls"][i:i+MAXIMUM_URL_PER_CATEGORY] for i in range(0, len(data["urls"]), MAXIMUM_URL_PER_CATEGORY)]
                total_urls = data["custom_urls_count"]
                page = 0
                if len(urls_lists) > 0:
                    while page < len(urls_lists):
                        data["urls"] = urls_lists[page]
                        data["custom_urls_count"] = len(data["urls"])
                        data["custom_urls_total"] = total_urls
                        write_to_splunk(helper, ew, "url_category:"+str(data["id"]), data)
                        log(helper, "url_category:"+str(data["id"]), data)
                        page += 1
                else:
                    write_to_splunk(helper, ew, "url_category:"+str(data["id"]), data)
                    log(helper, "url_category:"+str(data["id"]), data)
                    
        # Get Firewall rules if specified (more complex, as we can have a lot of IPs defined in one rule)
        if "firewall_rules" in opt_items:
            for data in zia.firewall.list_rules():
                if "dest_addresses" in data:
                    dest_addresses_lists = [data["dest_addresses"][i:i+MAXIMUM_DEST_IP_PER_RULE] for i in range(0, len(data["dest_addresses"]), MAXIMUM_DEST_IP_PER_RULE)]
                    total_dest_addr = len(data["dest_addresses"])
                    page = 0
                    while page < len(dest_addresses_lists):
                        data["dest_addresses"] = dest_addresses_lists[page]
                        data["dest_addresses_count"] = len(data["dest_addresses"])
                        data["dest_addresses_total"] = total_dest_addr
                        write_to_splunk(helper, ew, "firewall_rule:"+str(data["id"]), data)
                        log(helper, "firewall_rule:"+str(data["id"]), data)
                        page += 1
                else:
                    write_to_splunk(helper, ew, "firewall_rule:"+str(data["id"]), data)
                    log(helper, "firewall_rule:"+str(data["id"]), data)
                    
        # Get Firewall IP Source Groups if specified (more complex, as we can have a lot of IPs defined in one group)
        if "firewall_ip_source_groups" in opt_items:
            for data in zia.firewall.list_ip_source_groups():
                addresses_lists = [data["ip_addresses"][i:i+MAXIMUM_DEST_IP_PER_RULE] for i in range(0, len(data["ip_addresses"]), MAXIMUM_DEST_IP_PER_RULE)]
                total_dest_addr = len(data["ip_addresses"])
                page = 0
                while page < len(addresses_lists):
                    data["ip_addresses"] = addresses_lists[page]
                    data["ip_addresses_count"] = len(data["ip_addresses"])
                    data["ip_addresses_total"] = total_dest_addr
                    write_to_splunk(helper, ew, "firewall_ip_source_group:"+str(data["id"]), data)
                    log(helper, "firewall_ip_source_group:"+str(data["id"]), data)
                    page += 1

        # Get Firewall IP Destination Groups if specified (more complex, as we can have a lot of IPs defined in one group)
        if "firewall_ip_destination_groups" in opt_items:
            for data in zia.firewall.list_ip_destination_groups():
                addresses_lists = [data["addresses"][i:i+MAXIMUM_DEST_IP_PER_RULE] for i in range(0, len(data["addresses"]), MAXIMUM_DEST_IP_PER_RULE)]
                total_dest_addr = len(data["addresses"])
                page = 0
                while page < len(addresses_lists):
                    data["addresses"] = addresses_lists[page]
                    data["addresses_count"] = len(data["addresses"])
                    data["addresses_total"] = total_dest_addr
                    write_to_splunk(helper, ew, "firewall_ip_destination_group:"+str(data["id"]), data)
                    log(helper, "firewall_ip_destination_group:"+str(data["id"]), data)
                    page += 1
                    
        # Get Locations if specified (more complex, as we can have sub locations)
        if "locations" in opt_items:
            for data in zia.locations.list_locations_lite(include_sub_locations=True):
                write_to_splunk(helper, ew, "locations", data)
                log(helper, "locations", data)

        # Get Security policy blacklist if specified (more complex)
        if "sandbox" in opt_items:
            sandbox_quota = zia.sandbox.get_quota()
            write_to_splunk(helper, ew, "sandbox:quota", sandbox_quota)
            log(helper, "sandbox:quota", sandbox_quota)
        
        # Get Security policy blacklist if specified (more complex)
        if "security_blacklist" in opt_items:
            blacklist = zia.security.get_blacklist()
            write_to_splunk(helper, ew, "security:blacklist", blacklist)
            log(helper, "sandbox:security:blacklist", blacklist)
        
        # Get Security policy whitelist if specified (more complex)
        if "security_whitelist" in opt_items:
            whitelist = zia.security.get_whitelist()
            write_to_splunk(helper, ew, "security:whitelist", whitelist)
            log(helper, "sandbox:security:whitelist", whitelist)
        
        # Get SSL Inspection if specified (more complex)
        if "ssl_inspection" in opt_items:
            data = zia.ssl.get_intermediate_ca()
            write_to_splunk(helper, ew, "ssl_inspection", data)
            log(helper, "ssl_inspection", data)

        # Get Zscaler Public information if specified (more complex)
        if "public_se" in opt_items:
            data = zia.vips.list_public_se(cloud=cloud)
            final_data = None
            for continent in data.keys():
                final_continent = continent.split(" :")[1].replace(" ","")
                for city in data[continent].keys():
                    final_city = city.split(" :")[1]
                    final_data = {"continent": final_continent, "city": final_city, "data": data[continent][city]}
                    write_to_splunk(helper, ew, "public_service_edge", final_data)
                    log(helper, "public_service_edge", final_data)
            data = zia.vips.list_ca(cloud=cloud)
            write_to_splunk(helper, ew, "public_central_authority", {"ca": data})
            log(helper, "public_central_authority", data)
            data = zia.vips.list_pac(cloud=cloud)
            write_to_splunk(helper, ew, "public_proxy_auto_configuration", {"pac": data})
            log(helper, "public_proxy_auto_configuration", data)
            
                    
    except restfly.errors.BadRequestError as e:
        helper.log_error("[ZIA-E-BAD_REQUEST] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(15)
    except restfly.errors.ForbiddenError as e:
        helper.log_error("[ZIA-E-FORBIDDEN_REQUEST] 🔴 Your request is forbidden and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(16)
    
    helper.log_info("[ZIA-I-END-COLLECT] 🟢 Events from Zscaler ZIA ("+str(opt_items)+") are recovered")


# This function is writing events in Splunk
def write_to_splunk(helper, ew, item, data):
    event = helper.new_event(source="zia:"+ZSCALER_INSTANCE+":"+INPUT_UID+":"+item, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(data))
    ew.write_event(event)
    
    
# This function is logging information in the search.log
def log(helper, item, all_data):
    if len(all_data)>0 and all_data!=[]:
        helper.log_debug("[ZIA-D-EVENTS_WRITTEN] Events are written for "+item+" to the index "+helper.get_output_index()+": "+str(all_data))
    else:
        helper.log_debug("[ZIA-D-NO_EVENT_FOUND] No event found for "+item)
