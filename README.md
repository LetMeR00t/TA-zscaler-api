[![TA-zscaler-api](https://github.com/LetMeR00t/TA-zscaler-api/blob/3e786c9dd5701a0a3e82fddd638e61d432479899/images/logo.png?raw=true)](https://github.com/LetMeR00t/TA-zscaler-api/)

[![GitHub Release](https://img.shields.io/github/release/LetMeR00t/TA-zscaler-api.svg)](https://github.com/LetMeR00t/TA-zscaler-api/releases/)
[![dependency pyzscaler version](https://img.shields.io/badge/dependency-pyzscaler:v1.1.1-green)](https://github.com/mitchos/pyZscaler/tree/1.1.1/)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
[![License](https://img.shields.io/github/license/LetMeR00t/TA-zscaler-api.svg)](https://github.com/LetMeR00t/TA-zscaler-api)

# TA-zscaler-api - An unofficial Splunk technical add-on for the Zscaler API

This TA allows to **add an integration** between [Zscaler](https://www.zscaler.com/) and Splunk. It lets you:
* ZIA
  * Get all configurations for Zscaler ZIA periodically using a HTTP input within Splunk
  * Interact with Zscaler ZIA using custom alert actions
    * Add URLs to an existing category
    * Delete URLs from an existing category
* ZPA
  * Get all configurations for Zscaler ZPA periodically using a HTTP input within Splunk
  * Interact with Zscaler ZPA using custom alert actions
    * Create/update/delete an application segment
    * Create a segment group

As this TA is based on the [unofficial SDK for the Zscaler API (mitchos/pyZscaler)](https://github.com/mitchos/pyZscaler), it is not affiliated with, nor supported by Zscaler in any way.

Click on the link above to access to the information you want to know:
- [TA-zscaler-api - An unofficial Splunk technical add-on for the Zscaler API](#ta-zscaler-api---an-unofficial-splunk-technical-add-on-for-the-zscaler-api)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [Security of credentials](#security-of-credentials)
- [Support](#support)
- [Credits](#credits)
- [License](#license)


# Use Cases
The objective is to interface a security tool such as Zscaler with Splunk to enable integrations and automations. This TA has been designed in such a way that :
- All ZIA or ZPA configurations can be recovered periodically partially or totally within Splunk to check changes over time
- Ability to create "application segments" automatically through a custom alert action or using a dedicated dashboard that could check input data before sending 

# Configuration
TBD soon

Good practice is to use one account for one instance. Don't use the same account for different instances. Moreover, don't use different accounts with the same username on different instances (you will have some issues with the scripts)

# Security of credentials
To let Splunk interact with Zscaler, you will have to provide critical information such as the Zscaler customer ID, a client ID and a client password for ZPA. 

Those information are stored in the application in plaintext for the Zscaler customer ID and the client ID, the client secret as for it is stored in the storage/password feature of Splunk and is encrypted.

**Application read access is allowed for anyone by default** (crendentials are not shown to simple users but they can access to dashboards) when write access are restricted to people having the "admin" role.

Custom alert actions are available only for people having the "power" or "admin" role.

**⚠️ Be aware that anyone who has read access to the application could use the dedicated dashboards used to interact with Zscaler. If you want to avoid this, please change the metadata access (under metadata/local.meta) with your own policy.**

# Support
Please [open an issue on GitHub](https://github.com/LetMeR00t/TA-zscaler-api/issues) if you'd like to report a bug or request a feature.

# Credits
This app was developed to help brilliant colleagues and improve the response in the field of security

# License
MIT License

Copyright (c) 2021 Mitch Kelly

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.