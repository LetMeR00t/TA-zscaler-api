<p align="center">
  <img src="https://github.com/LetMeR00t/TA-zscaler-api/blob/2792791749b11d38c32659592f11e9d6c788bf82/images/logo.png?raw=true" alt="Logo TA-zscaler-api"/>
</p>

[![GitHub Release](https://img.shields.io/github/release/LetMeR00t/TA-zscaler-api.svg)](https://github.com/LetMeR00t/TA-zscaler-api/releases/)
[![dependency pyzscaler version](https://img.shields.io/badge/dependency--version:pyzscaler-1.0.0-brightgreen)](https://github.com/mitchos/pyZscaler/tree/1.0.0)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
[![License](https://img.shields.io/github/license/LetMeR00t/TA-zscaler-api.svg)](https://github.com/LetMeR00t/TA-zscaler-api)

# TA-zscaler-api - An unofficial Splunk technical add-on for the Zscaler API

This TA allows to **add an integration** between [Zscaler](https://www.zscaler.com/) and Splunk. It lets you:
- Get all configurations for Zscaler ZPA periodically using a HTTP input within Splunk
- Interact with Zscaler ZPA using custom alert actions and interactive dashboards

As this TA is based on the [unofficial SDK for the Zscaler API (mitchos/pyZscaler)](https://github.com/mitchos/pyZscaler), it is not affiliated with, nor supported by Zscaler in any way.

Click on the link above to access to the information you want to know:
- [TA-zscaler-api - An unofficial Splunk technical add-on for the Zscaler API](#ta-zscaler-api---an-unofficial-splunk-technical-add-on-for-the-zscaler-api)
- [Use Cases](#use-cases)
- [Security of credentials](#security-of-credentials)
- [Support](#support)
- [Credits](#credits)
- [License](#license)


# Use Cases
The objective is to interface a security tool such as Zscaler with Splunk to enable integrations and automations. This TA has been designed in such a way that :
- All ZPA configurations can be recovered periodically partially or totally within Splunk to check changes over time
- Ability to create "application segments" automatically through a custom alert action or using a dedicated dashboard that could check input data before sending 

# Security of credentials
To let Splunk interact with Zscaler, you will have to provide critical information such as the Zscaler customer ID, a client ID and a client password. 

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