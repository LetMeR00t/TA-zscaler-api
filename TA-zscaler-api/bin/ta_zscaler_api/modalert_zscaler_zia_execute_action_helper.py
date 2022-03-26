import json
import inspect
import sys

# Import custom librairies
from pyzscaler import ZIA
import restfly

# encoding = utf-8
OPT_ARGS = {
    }

# Used to debug errors, get the good reference in the original python library
REF_URL = "https://github.com/mitchos/pyZscaler/blob/1.1.0/pyzscaler"
REF_TOOL = "zia"
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
    zia_api_key = helper.get_global_setting("zia_api_key")
    helper.log_info("zia_api_key={}".format(zia_api_key))
    zia_cloud = helper.get_global_setting("zia_cloud")
    helper.log_info("zia_cloud={}".format(zia_cloud))
    zpa_customer_id = helper.get_global_setting("zpa_customer_id")
    helper.log_info("zpa_customer_id={}".format(zpa_customer_id))

    # The following example gets the alert action parameters and prints them to the log
    account_username = helper.get_param("account_username")
    helper.log_info("account_username={}".format(account_username))

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
    """
    # Define global variables
    global REF_FILE
    
    # Get Zscaler information
    client = helper.get_user_credential(helper.get_param("account_username"))
    if client is None:
        helper.log_error("[ZIA-E-AUTH-ACCOUNT] Account can't be found. Did you configured the account under Configuration ? Did you mentionned the account username to use when raising this action ?")
        sys.exit(1)
    helper.log_debug("[ZIA-D-AUTH] Authentication will be done using the account \""+str(client["username"])+"\"")
    # Get credentials for Zscaler
    api_key = helper.get_global_setting("zia_api_key")
    if api_key is None or api_key == "":
        helper.log_error("[ZIA-E-API_KEY_NULL] No API key was provided, check your configuration")
        sys.exit(1)
        
    cloud = helper.get_global_setting("zia_cloud")
    if cloud is None or cloud == "":
        helper.log_error("[ZIA-E-CLOUD_NULL] No Cloud information was provided, check your configuration")
        sys.exit(1)
    
    # Get parameters
    action = helper.get_param("action")
    
    # Get events
    events = helper.get_events()
    
    # Instanciate the ZPA object with given inputs
    try:
        zia = ZIA(api_key=api_key, cloud=cloud, username=client["username"], password=client["password"])
    except restfly.errors.BadRequestError as e:
        helper.log_error("[ZIA-E-BAD_CREDENTIALS] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(10)
    
    helper.log_debug("[ZIA-D-ZIA_OBJECT] Zscaler ZPA connection object is created successfully")
    
    # Check the activate status before submitting changes
    status = zia.config.status()
    if status != "ACTIVE":
        helper.log_error("[ZIA-E-CHANGE_PENDING_OR_INPROGRESS] 🔴 Your request will not be processed as changes are pending or in progress in Zscaler ZIA. By precaution, no action will be done to avoid pushing any wrong change that is not yet validated")
        sys.exit(11)
    else:
        helper.log_info("[ZIA-I-CHECK_CHANGES] No change is pending or in progress in ZIA, process the action")
    
    try:
        for event in events:
            if action == "add_urls_to_category":
                REF_FILE = "url_categories.py#L215"
                helper.log_info("[ZIA-I-VALIDATE_ADD_URLS_TO_CATEGORY] Validating events for adding URLs to category")
                # Validate the function with current events
                params = validate_function(helper, zia.url_categories.add_urls_to_category, event)
                # Execute the action to Zscaler
                zia.url_categories.add_urls_to_category(**params)
                helper.log_info("[ZIA-I-ACTION_ADD_URLS_TO_CATEGORY] 🟢 Action was performed in Zscaler")
            else:
                helper.log_error("[ZIA-E-ACTION] Selected action is not supported by this custom alert action")
                sys.exit(10)
    except restfly.errors.BadRequestError as e:
        helper.log_error("[ZIA-E-BAD_REQUEST] 🔴 Your request is not correct and was rejected by Zscaler: "+str(e.msg.replace("\"","'")))
        sys.exit(15)
    
    # Activate the configuration
    status = zia.config.activate()
    helper.log_info("[ZIA-I-AUTOMATIC_ACTIVATE] Configuration has been automatically activated")
    
    return 0

# This function is used to validate inputs for the given function
# It's returning the dictionary with all parameters
def validate_function(helper, func, event):
    
    # Log on which event we are working on
    helper.log_debug("[ZIA-D-FUNC] Validating following event for the function ("+func.__name__+"): "+str(event))

    # Prepare final dictionnary
    params = {}
    
    helper.log_debug("[ZIA-D-VALID1] (#1) Validating parameters from function signature")
    # /1 Check all parameters from the function signature
    signature = inspect.signature(func)
    for sig_name, sig_values in signature.parameters.items():
        # Remove false positives:
        if sig_name not in ["kwargs"]:
            param = process_param(helper, event, sig_name, sig_values.annotation, sig_values.default)
            params[sig_name] = param
    
    helper.log_debug("[ZIA-D-VALID2] (#2) Validating parameters for optional arguments")
    # /2 Check all optional parameters for the given function
    if func.__name__ in OPT_ARGS:
        opt_args = OPT_ARGS[func.__name__]
        for arg in opt_args:
            param = process_param(helper, event, arg["name"], arg["annotation"], None)
            if "accepted_values" in arg:
                if param not in arg["accepted_values"] and param is not None:
                    helper.log_error("[ZIA-E-ACCEPTED_VALUES] Provided value ("+str(param)+") for the parameter ("+arg["name"]+" is not accepted as it's expected only one of these values: "+str(arg["accepted_values"])+". Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
                    sys.exit(1)
                elif param is not None:
                    params[arg["name"]] = param
                else:
                    helper.log_debug("[ZIA-D-OPTIONAL_ARG_NONE] Optional argument "+arg["name"]+" will not be added in the payload as it's value is None")
            else:
                if param is not None:
                    params[arg["name"]] = param
        
    helper.log_info("[ZIA-I-FINAL_PARAMS] Params built from event: "+str(params))
    return params


# This function is used to get the final value and validate the type
def process_param(helper, event, sig_name, sig_annotation, sig_default):
    
    helper.log_debug("[ZIA-D-PROCESS_PARAMS_INPUT] Processing parameter with following inputs: event="+str(event)+", sig_name="+str(sig_name)+", sig_annotation="+str(sig_annotation)+", sig_default="+str(sig_default))
    
    # Default is None
    value = None
    try:
        value = event[sig_name]
    except KeyError as e:
        if sig_default is inspect._empty:
            helper.log_error("[ZIA-E-FIELD_NOT_PRESENT] An expected field ("+sig_name+") is not present in the event (and no default value was found). Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
            sys.exit(1)
        else:
            helper.log_debug("[ZIA-D-FIELD_NOT_PRESENT_DEFAULT] An expected field ("+sig_name+") is not present but a default value will be used: "+str(value)+". Please refer to the original python library code to verify which fields are expected: "+REF_URL+"/"+REF_TOOL+"/"+REF_FILE)
            value = sig_default
    helper.log_debug("[ZIA-D-TYPE_PROCESSING] Type for "+sig_name+" need to be "+str(sig_annotation)+", processing it...")
    # Avoid adding none values
    if value is not None:
        # Process data with the expected type
        if sig_annotation is int:
            value = int(value)
        elif sig_annotation is str:
            value = str(value)
        elif sig_annotation is list:
            value = value.replace(", ",",").split(",")
        elif sig_annotation is bool:
            if value in ["0","false"]:
                value = False
            else:
                value = True
        elif sig_annotation is inspect._empty:
            helper.log_error("[ZIA-E-EMPTY-TYPE] This error should come from the pyzscaler library on which a field has no type defined. Please check this information for the field '"+str(sig_name)+"'")
            sys.exit(1)
        else:
            helper.log_error("[ZIA-E-UNSUPPORTED_TYPE] Unsupported type for parameter: "+str(sig_annotation))
            sys.exit(1)
    return value
