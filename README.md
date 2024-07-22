# google-chat-app

Publisher: Splunk  
Connector Version: 1\.0\.0  
Product Vendor: Google Cloud  
Product Name: Google Chat App  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 6\.1\.1  

App repository to integrate services with Google Chat and manage Chat resources such as i.e messages on Splunk SOAR.

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

## Asset Configuration

Before you start any app exploration user have to create App authuentication on GCP to authenticate for API calls. More info under [Google Authenticate](https://developers.google.com/workspace/chat/authenticate-authorize). after user have created the application and have the Client ID, Client Secret and Redirect URI, user can generate authenticate code. To do this open 
```bash
https://accounts.google.com/o/oauth2/auth?client_id=<Client_ID>&redirect_uri=<redirect_uri>&response_type=code&scope=https://www.googleapis.com/auth/chat.messages&access_type=offline
```
and pass all veryfication, at the end in new url user will see code variable, examplary 
```bash
4/0AeaYSHBzshfJQe5ccwX25jAGkzR5TFNkEyDTL8NrSnqQj4VboVd2TlLx50h6_a7OiG8ZHA
```
Thanks to this we can start asset configuration with all required fields. 

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a EC2 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client\_id** |  required  | string | Auth application Client ID
**client\_secret** |  required  | password | Auth application Client Secret
**code** |  required  | password | Code to receive authorization token
**redirect\_uri** |  required  | bollean | Redirect URL for authorization

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity to obatin access token  
[create message](#action-get-connection-information) - Creates a message in a Google Chat space  

## action: 'test connectivity'
Validate the asset configuration for connectivity to obtain access token

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
Encrypet Access token and Refresh token in state file

## action: 'create message'
Creates a message in a Google Chat space

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**parent\_space** |  required  | The resource name of the space in which to create a message. | string | 
**text\_message** |  required  | Message content. | string | 
**requestid** |  optional  | A unique request ID for this message. Specifying an existing request ID returns the message created with that ID instead of creating a new message. | string | 
**messagereplyoption** |  optional  | Specifies whether a message starts a thread or replies to one. Only supported in named spaces. | string | 
**messageid** |  optional  | A custom ID for a message. | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.parent\_space | string | 
action\_result\.parameter\.text\_message | string | 
action\_result\.parameter\.requestid | string | 
action\_result\.parameter\.messagereplyoption | string | 
action\_result\.parameter\.messageid | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   
