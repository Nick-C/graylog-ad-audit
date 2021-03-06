# Graylog AD Audit

## Description

This is a modified verssion of https://github.com/leftorbit23/graylog-ad-audit that supports WinLogBeat event names and works with the latest 2.2.3 version of Graylog.

There may still be fields mapped incorrectly or other bugs, please let me know if you find any!

This Powershell script can be scheduled to run either daily or as frequently as you like to report on changes in the Active Directory.

Disclaimer: It's only configured to search for specific event ids, so there may be other critical events that are not captured.


## Prerequisites

- Graylog server
 - Must be configured to collect logs from all Domain Controllers
 - Must be using WinLogBeat (included in Graylog Collector Sidecar: https://github.com/Graylog2/collector-sidecar)
- Graylog user 
 - User must have access to a stream that contains Domain Controller security events
 - User's timezone should be set to your local time
- PowerShell (Tested with version 5)
- Active Directory Module for Powershell
- Domain user to run the script with

## Installation

Download the Scripts folder and place it under C:\

Open ad-audit.ps1 in an editor and change the config settings.

Run manually or schedule it to run from task scheduler.

