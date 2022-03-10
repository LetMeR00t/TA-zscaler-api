import json
import inspect
import sys

# Import custom librairies
from pyzscaler import ZPA

# encoding = utf-8
OPT_ARGS = {
    "add_segment": [
        {"name": "bypass_type", "annotation": str, "accepted_values": ["ALWAYS","NEVER","ON_NET"]},
        {"name": "clientless_app_ids", "annotation": list},
        {"name": "config_space", "annotation": str, "accepted_values": ["DEFAULT","SIEM"]},
        {"name": "default_idle_timeout", "annotation": int},
        {"name": "default_max_age", "annotation": int},
        {"name": "description", "annotation": str},
        {"name": "double_encrypt", "annotation": bool},
        {"name": "enabled", "annotation": bool},
        {"name": "health_check_type", "annotation": str, "accepted_values": ["DEFAULT","NONE"]},
        {"name": "health_reporting", "annotation": str, "accepted_values": ["NONE","ON_ACCESS","CONTINUOUS"]},
        {"name": "ip_anchored", "annotation": bool},
        {"name": "is_cname_enabled", "annotation": bool},
        {"name": "passive_health_enabled", "annotation": bool}
        ],
    "update_segment": [
        {"name": "bypass_type", "annotation": str, "accepted_values": ["ALWAYS","NEVER","ON_NET"]},
        {"name": "clientless_app_ids", "annotation": list},
        {"name": "config_space", "annotation": str, "accepted_values": ["DEFAULT","SIEM"]},
        {"name": "default_idle_timeout", "annotation": int},
        {"name": "default_max_age", "annotation": int},
        {"name": "description", "annotation": str},
        {"name": "domain_names", "annotation": list},
        {"name": "double_encrypt", "annotation": bool},
        {"name": "enabled", "annotation": bool},
        {"name": "health_check_type", "annotation": str, "accepted_values": ["DEFAULT","NONE"]},
        {"name": "health_reporting", "annotation": str, "accepted_values": ["NONE","ON_ACCESS","CONTINUOUS"]},
        {"name": "ip_anchored", "annotation": bool},
        {"name": "is_cname_enabled", "annotation": bool},
        {"name": "name", "annotation": str},
        {"name": "segment_group_id", "annotation": str},
        {"name": "server_group_ids", "annotation": list},
        {"name": "tcp_ports", "annotation": list},
        {"name": "server_group_ids", "annotation": list},
        {"name": "udp_ports", "annotation": bool}
        ]
    }
    

# Used to debug errors, get the good reference in the original python library
REF_URL = "https://github.com/mitchos/pyZscaler/blob/1.1.0/pyzscaler"
REF_TOOL = "zpa"
REF_FILE = None

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets account information
    user_account = helper.get_user_credential("<account_name>")

    # The following example gets the setup parameters and prints them to the log
    customer_id = helper.get_global_setting("customer_id")
    helper.log_info("customer_id={}".format(customer_id))

    # The following example gets the alert action parameters and prints them to the log
    account_name = helper.get_param("account_name")
    helper.log_info("account_name={}".format(account_name))

    action = helper.get_param("action")
    helper.log_info("action={}".format(action))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    
    Use the following code to access to function params
    func = < your function >
    signature = inspect.signature(func)
    for name, v in signature.parameters.items():
        # Get the name of the parameter
        helper.log_info(name)
        # Get the type of the parameter
        helper.log_info(v.annotation)
        helper.log_info("Is string" if v.annotation is str else "Not a string")
        # Get the default value of the parameter
        helper.log_info(v.default)
        helper.log_info("Default is: "+v.default if v.default is not inspect._empty else "No default value")
    """

    helper.log_info("Alert action zscaler_zpa_action started.")
    
    # Define global variables
    global REF_FILE
    
    # Get Zscaler information
    client = helper.get_user_credential(helper.get_param("account_name"))
    helper.log_debug("[ZPA-D-AUTH] Authentication will be done using the account \""+helper.get_param("account_name")+"\"")
    customer_id = helper.get_global_setting("customer_id")
    
    # Get parameters
    action = helper.get_param("action")
    
    # Get events
    events = helper.get_events()
    
    # Instanciate the ZPA object with given inputs
    zpa = ZPA(client_id=client["username"], client_secret=client["password"], customer_id=customer_id)
    
    helper.log_debug("[ZPA-D-ZPA_OBJECT] Zscaler ZPA connection object is created successfully")
    for event in events:
        if action == "create_app_segment":
            REF_FILE = "app_segments.py#L61"
            helper.log_info("[ZPA-I-VALIDATE_NEW_APP_SEGMENT] Validating events for a new app segment")
            # Validate the function with current events
            params = validate_function(helper, zpa.app_segments.add_segment, event)
            # Execute the action to Zscaler
            zpa.app_segments.add_segment(**params)
            helper.log_info("[ZPA-I-ACTION_NEW_APP_SEGMENT] Action was performed in Zscaler")
        elif action == "update_app_segment":
            REF_FILE = "app_segments.py#L150"
            helper.log_info("[ZPA-I-VALIDATE_UPDATE_APP_SEGMENT] Validating events for updating an existing app segment")
            # Validate the function with current events
            params = validate_function(helper, zpa.app_segments.update_segment, event)
            # Execute the action to Zscaler
            zpa.app_segments.update_segment(**params)
            helper.log_info("[ZPA-I-ACTION_UPDATE_APP_SEGMENT] Action was performed in Zscaler") 
        elif action == "delete_app_segment":
            REF_FILE = "app_segments.py#L44"
            helper.log_info("[ZPA-I-VALIDATE_DELETE_APP_SEGMENT] Validating events for a delete an existing app segment")
            # Validate the function with current events
            params = validate_function(helper, zpa.app_segments.delete_segment, event)
            # Execute the action to Zscaler
            helper.log_info("[ZPA-I-PROCESS_DELETE_APP_SEGMENT] #1: Remove the application segment from the segment group to which it belongs")
            app = zpa.app_segments.get_segment(**params)
            helper.log_debug("[ZPA-D-APP_SEGMENT_FOUND] Application segment was found for the given ID: "+str(params))
            # If there is no error on the previous command, it means that the app_segment really exist for the given id
            segment = zpa.segment_groups.get_group(app["segment_group_id"])
            helper.log_debug("[ZPA-D-SEGMENT_GROUP_FOUND] Segment group was found for the given ID: "+str(app["segment_group_id"]))
            # We remove the ID by getting all other IDs without it
            app_id_remaining = [app_of_segment["id"] for app_of_segment in segment["applications"] if app_of_segment["id"]!=app["id"]]
            # We update the segment group to remove the application segment
            zpa.segment_groups.update_group(group_id=segment["id"], application_ids=app_id_remaining)
            helper.log_debug("[ZPA-D-SEGMENT_GROUP_UPDATED] Segment group was updated for the given ID: "+str(app["segment_group_id"]))
            # Now we can delete the application segment itself
            helper.log_info("[ZPA-I-PROCESS_DELETE_APP_SEGMENT] #2: Delete the application segment (id="+app["id"]+") itself")
            zpa.app_segments.delete_segment(segment_id=app["id"])
            helper.log_info("[ZPA-I-ACTION_DELETE_APP_SEGMENT] Action was performed in Zscaler") 
        else:
            helper.log_error("[ZPA-E-ACTION] Selected action is not supported by this custom alert action")
            sys.exit(10)

    return 0

# This function is used to validate inputs for the given function
# It's returning the dictionary with all parameters
def validate_function(helper, func, event):
    
    # Log on which event we are working on
    helper.log_debug("[ZPA-D-FUNC] Validating following event for the function ("+func.__name__+"): "+str(event))
    
    # Prepare final dictionnary
    params = {}
    
    helper.log_debug("[ZPA-D-VALID1] (#1) Validating parameters from function signature")
    # /1 Check all parameters from the function signature
    signature = inspect.signature(func)
    for sig_name, sig_values in signature.parameters.items():
        # Remove false positives:
        if sig_name not in ["kwargs"]:
            param = process_param(helper, event, sig_name, sig_values.annotation, sig_values.default)
            params[sig_name] = param
    
    helper.log_debug("[ZPA-D-VALID2] (#2) Validating parameters for optional arguments")
    # /2 Check all optional parameters for the given function
    if func.__name__ in OPT_ARGS:
        opt_args = OPT_ARGS[func.__name__]
        for arg in opt_args:
            param = process_param(helper, event, arg["name"], arg["annotation"], None)
            if "accepted_values" in arg:
                if param not in arg["accepted_values"] and param is not None:
                    helper.log_error("[ZPA-E-ACCEPTED_VALUES] Provided value ("+str(param)+") for the parameter ("+arg["name"]+" is not accepted as it's expected only one of these values: "+str(arg["accepted_values"])+". Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
                    sys.exit(1)
                elif param is not None:
                    params[arg["name"]] = param
                else:
                    helper.log_info("[ZPA-I-OPTIONAL_ARG_NONE] Optional argument "+arg["name"]+" will not be added in the payload as it's value is None")
            else:
                if param is not None:
                    params[arg["name"]] = param
        
    helper.log_info("[ZPA-I-FINAL_PARAMS] Params built from event: "+str(params))
    return params


# This function is used to get the final value and validate the type
def process_param(helper, event, sig_name, sig_annotation, sig_default):
    
    helper.log_debug("[ZPA-D-PROCESS_PARAMS_INPUT] Processing parameter with following inputs: event="+str(event)+", sig_name="+str(sig_name)+", sig_annotation="+str(sig_annotation)+", sig_default="+str(sig_default))
    
    # Default is None
    value = None
    try:
        value = event[sig_name]
    except KeyError as e:
        if sig_default is inspect._empty:
            helper.log_error("[ZPA-E-FIELD_NOT_PRESENT] An expected field ("+sig_name+") is not present in the event (and no default value was found). Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
            sys.exit(1)
        else:
            helper.log_info("[ZPA-I-FIELD_NOT_PRESENT_DEFAULT] An expected field ("+sig_name+") is not present but a default value will be used: "+str(value)+". Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
            value = sig_default
    helper.log_debug("[ZPA-D-TYPE_PROCESSING] Type for "+sig_name+" need to be "+str(sig_annotation)+", processing it...")
    # Avoid adding none values
    if value is not None:
        # Process data with the expected type
        if sig_annotation is int:
            value = int(value)
        elif sig_annotation is str:
            value = str(value)
        elif sig_annotation is list:
            value = value.split(",")
        elif sig_annotation is bool:
            if value in ["0","false"]:
                value = False
            else:
                value = True
        else:
            helper.log_error("[ZPA-E-UNSUPPORTED_TYPE] Unsupported type for parameter: "+str(sig_annotation))
            sys.exit(1)
    return value