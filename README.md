# py_cp-monitoring
Script for monitoring aspects of Check Point installation

## detailed description


## goals for using this

This is for when having a monitoring system like Paessler PRTG or Nagios compatible having some aspects monitored by those systems and being notified if something is out of normal ranges. For example, when managing several Installations.

## Usage

Before being able to use this, please state "mode" inside of the script file. (arount row 10) This value does switch the script to "Nagios mode" or "PRTG Mode" (others might be added later, like Zabbix). This switches how output is generated and returned.


### Example configuration (PRTG)

Place script file under PRTGs custom python sensor directory (default: C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\python )
Create a new "Custom Advanced Python Sensor"


Configure the sensor according your needs:


### Example configuration (Centreon)

Place the script under Monitoring Systems plugin folder (centreon default /usr/lib/centreon/plugins/) and configure a new check, using the script.
# Notice
This is also posted at Check Points Checkmates Community Toolbox
Please tell questions about it there
