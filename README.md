# nexusiq-reports

  * Primarily, these scripts attempt to provide information on the use of the status property on security vulnerabilities
  * Typically, these scripts should be run on a Nexus IQ before it is enabled for MJA
  * Data is extracted from a number of Nexus IQ API's and saves to files for later analysis
  * All output files are written to a sub-directory named 'datafiles'
  * These scripts do not actually makes any changes to the Nexus IQ data
  * It is highly recommended to run these scripts on test instances of Nexus IQ and not on any production instance
  * NB. THESE SCRIPTS ARE EXPERIMENTAL ONLY
  
 &nbsp;

  * Pre-requisites:
    * python3 
    * Nexus IQ url, username and password
  
  * Example:
```
The Unix shell script run.sh provides an example of the setup and run sequence of all the files.
```
   
&nbsp;
&nbsp;
&nbsp;

  * Description
  * 
    get-security-overrides.py
    - gets a list of all security vulnerabilities - ie. any vulnerabilities where Status has been changed - (is not Open). 
    - writes output to datafiles/security_overrides.json/.csv
    
    get-application-reports.py
    - gets links to all current scan results 
    - writes output to datafiles/app_reports.json and datafiles/app_reportsurls.json
    
    get-license-overrides.py
    - reads all scan results (from list above) and gets license all license overrides ie. where Status is not 'Overriden')
    - writes output datafiles/license_ovveriddes.csv (also outputs json file for each application in datafiles/licensedata/<appname>.json
    - this script is potentially resource-intensive so it is definitely not recommended running this on a production instance
    
    get-security-overrides-policyinfo.py
    - gets the policy violations for each overriden CVE 
    - writes output to datafiles/overrides_violations.csv only for security/license overrides associated with MJA-related files only (ie. a-name)
    
    waiver-cmds.py
    - read the security overrides file ad write out example curl command to apply a waiver to replace the status override after MJA is enabled
    - Writes waiver parameters to datafiles/applywaivers.csv. Also writes example curl commands to datafiles/cmdfile.txt.
    
&nbsp;
&nbsp;
&nbsp;

**The Fine Print**
* It is worth noting that this is NOT SUPPORTED by Sonatype, and is a contribution to the open source community 

* Don't worry, using this community item does not "void your warranty". In a worst case scenario, you may be asked by the Sonatype Support team to remove the community item in order to determine the root cause of any issues.

* Remember:

* Use this contribution at the risk tolerance that you have
* Do NOT file Sonatype support tickets related to these scripts
    
    
    
    
