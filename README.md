# nexusiq-reports

**component-status-report.py**
  * Primarily, this script attempts to provide information on the use of the status property on security vulnerabilities
  * It extracts data from a number of Nexus IQ API's and saves to files for later analysis
  * All output files written to a sub-directory named 'datafiles'
  
  * Pre-requisites:
    * python3 
    * Nexus IQ url, username and password
  
  * Example:
```
python3 component-status-report.py <iq-url> <iq-username> <iq-password>
```

  * Output files
    * output from security vulnerability overrides API
    ```
    ./datafiles/overrides.json
    ./datafiles/overrides.csv
    ```
    
    
    
