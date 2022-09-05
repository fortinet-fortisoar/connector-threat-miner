## About the connector
ThreatMiner is a threat intelligence portale that aggregates data from multiple open-source platforms like: VirusTotal, CIRCL etc... and enable analysts to research under a single interface. This connector enables users to create automated solutions to query against ThreatMiner's database.
<p>This document provides information about the ThreatMiner Connector, which facilitates automated interactions, with a ThreatMiner server using FortiSOAR&trade; playbooks. Add the ThreatMiner Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with ThreatMiner.</p>

### Version information

Connector Version: 1.0.0


Authored By: spryIQ.co

Certified: No
## Installing the connector
<p>From FortiSOAR&trade; 5.0.0 onwards, use the <strong>Connector Store</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.<br>You can also use the following <code>yum</code> command as a root user to install connectors from an SSH session:</p>
`yum install cyops-connector-threat-miner`

## Prerequisites to configuring the connector
- You must have the URL of ThreatMiner server to which you will connect and perform automated operations and credentials to access that server.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the ThreatMiner server.

## Minimum Permissions Required
- N/A

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>ThreatMiner</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations&nbsp;</strong> tab enter the required configuration details:&nbsp;</p>
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Server URL<br></td><td>URL of the threat-miner connector to access the connector website.<br>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function<br></th><th>Description<br></th><th>Annotation and Category<br></th></tr></thead><tbody><tr><td>Get Domain Details<br></td><td>Returns threat analysis details for the given domain based on the query performed.<br></td><td>get_domain_details <br/>Investigation<br></td></tr>
<tr><td>Get IP Details<br></td><td>Returns threat analysis details for given IP address based on the query performed.<br></td><td>get_ip_details <br/>Investigation<br></td></tr>
<tr><td>Get File Hash Details<br></td><td>Returns threat analysis details for given file hash based on the query performed.<br></td><td>get_file_hash_details <br/>Investigation<br></td></tr>
<tr><td>Get Import Hash Details<br></td><td>Reports samples,report tagging used in malware analysis to identify malware binaries that belong to the same family.<br></td><td>get_import_hash_details <br/>Investigation<br></td></tr>
<tr><td>Get SSDeep Details<br></td><td>Retrieves the data that detect the level of similarity between two files at the binary level.<br></td><td>get_ssdeep_details <br/>Investigation<br></td></tr>
<tr><td>Get Email Details<br></td><td>Email (Reverse WHOIS) allows you to search for domains by the name, address, telephone number, email address, or physical address of the Registrant listed in current or historical Whois records.<br></td><td>email_reverse_whois_details <br/>Investigation<br></td></tr>
</tbody></table>

### operation: Get Domain Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Domain Name<br></td><td>Domain name required for retrieving malware samples associated with the domain.<br>
</td></tr><tr><td>Query Type<br></td><td>Select the type of query that is how you want to perform get domain operation.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
### operation: Get IP Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>IP Address<br></td><td>Required IP address whose malware related details needs to be retrieved.<br>
</td></tr><tr><td>Query Type<br></td><td>Select the type of query that is how you want to perform IP operation.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
### operation: Get File Hash Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>File Hash<br></td><td>Requires a file hash(md5, sha1, sha256) to find malware analysis details.<br>
</td></tr><tr><td>Query Type<br></td><td>Select the type of query that is how you want to perform samples operation.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
### operation: Get Import Hash Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Import Hash<br></td><td>It requires a import hash value to retrieve samples query type malware analysis report.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
### operation: Get SSDeep Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>SSDeep<br></td><td>Provide the SSDeep hash value that attempts to detect the level of similarity between two files at the binary level. By default Samples query type is used.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
### operation: Get Email Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Email (Reverse WHOIS)<br></td><td>Required email address (SHA1 only) value to retrieved Whois records.<br>
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:
<code><br>{
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_code": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "status_message": "",
</code><code><br>&nbsp;&nbsp;&nbsp;&nbsp;    "results": []
</code><code><br>}</code>
## Included playbooks
The `Sample - threat-miner - 1.0.0` playbook collection comes bundled with the ThreatMiner connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR<sup>TM</sup> after importing the ThreatMiner connector.

- Get Domain Details
- Get Email Details
- Get File Details
- Get IP Details
- Get Import Hash Details
- Get SSDeep

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection, since the sample playbook collection gets deleted during connector upgrade and delete.
