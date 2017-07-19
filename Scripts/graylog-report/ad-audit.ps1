#graylogserver
$graylogserver='https://graylog.yourdomain.com'
#stream name (default stream introduced in Graylog v2.2.0)
$stream="000000000000000000000001"
#search range (in seconds)
$range=86400
#maximum number of results
$size=2000
#report sender
$sender="graylog@graylog.yourdomain.com"
#report recipient
$recipient="you@yourdomain.com"
#smtp server
$smtpserver="mailserver.yourdomain.com"
#define critical AD Groups (will be marked severity critical)
$ADCriticalGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins'



#search "from" datetime (only used for first run, otherwise start from previous "to" datetime)
$FromDateTime=(Get-Date (Get-Date).AddHours(-24).ToUniversalTime() -Format s) + '.00Z'
#search "to" datetime (current datetime)
$ToDateTime=(Get-Date (Get-Date).ToUniversalTime() -Format s) + '.00Z'


#load functions
. C:\Scripts\powershell-libraries\get-cname.ps1
. C:\Scripts\powershell-libraries\get-accountfromsid.ps1
. C:\Scripts\powershell-libraries\get-cnamefromsid.ps1
. C:\Scripts\powershell-libraries\get-useraccountcontrolvalue.ps1

CD C:\Scripts\graylog-report

$DbEventIds = Import-CSV 'data\ad-events.csv'

#retrieve last run time (if file exists)
if (Test-Path 'data\ad-audit-lastrun.txt') { $FromDateTime = Get-Content 'data\ad-audit-lastrun.txt' }

#function to update last run time
function Update-LastRunTime {
  $ToDateTime > 'data\ad-audit-lastrun.txt'
}
#Used by URLEncode
Add-Type -AssemblyName System.Web

#Set Graylog login credentials
$GLUser='reportuser' 
$GLPass='########'
$GLSecurePass=Convertto-SecureString -String $GLPass -AsPlainText -force

## Password may also be stored encrypted
#$securestring = ConvertFrom-SecureString (ConvertTo-SecureString -AsPlainText -Force "abc123")
#$securestring="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#$GLSecurePass=ConvertTo-SecureString $securestring

$cred=New-object System.Management.Automation.PSCredential $GLUser,$GLSecurePass




#######################
## 4728: A member was added to a security-enabled global group
## 4729: A member was removed from a security-enabled global group
## 4756: A member was added to a security-enabled universal group
## 4757: A member was removed from a security-enabled universal group
## 4761: A member was added to a security-disabled universal group
## 4762: A member was removed from a security-disabled universal group
## 4740: A user account was locked out
## 4767: A user account was unlocked
## 4724: An attempt was made to reset an accounts password
## 4722: A user account was enabled
## 4725: A user account was disabled
## 4738: A user account was changed
## 5139: A directory service object was moved
## 5136: A directory service object was modified (Used instead of 4781)
## 5141: A directory service object was deleted (Used instead of 4726)
## 5137: A directory service object was created (Used instead of 4720)
#######################
$query='winlogbeat_log_name:Security AND (winlogbeat_event_id:(4728 4729 4756 4757 4761 4762 4740 4767 4724 4722 4725 5139) OR (winlogbeat_event_id:4738 AND NOT winlogbeat_event_data_OldUacValue:"-") OR (winlogbeat_event_id:5136 AND winlogbeat_event_data_AttributeLDAPDisplayName:(sAMAccountName physicalDeliveryOfficeName description accountExpires telephoneNumber userAccountControl member pwdLastSet displayName givenName sn initials mDBStorageQuota mDBOverQuotaLimit mDBOverHardQuotaLimit dNSHostName)) OR (winlogbeat_event_id:(5141 5137) AND winlogbeat_event_data_ObjectClass:(user group computer))) AND NOT _exists_:Message'


$query=[System.Web.HttpUtility]::UrlEncode($query)

$queryuri = $graylogserver + "/api/search/universal/absolute?query=" + $query + "&from=" + $FromDateTime + "&to=" + $ToDateTime + "&limit=" + $limit + "&filter=streams:" + $stream

# This forces Powershell to use TLS 1.2, if you don't use https for the connection or allow TLS 1.0 connections then this can be removed.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraylogResults = Invoke-RestMethod -Uri $queryuri -Headers @{"Accept"="application/json"} -Credential $cred 

$GraylogResults = $GraylogResults.messages.message

#Exit script if the search returns no results
if ($GraylogResults.Length -eq 0 ) { 
  Update-LastRunTime
 
  exit 
}

#Create correlation arrays. Allows us to combine multiple (delete&add) ldap events into a single event.
$OpCorrelationCount = @{}
$OpCorrelationPreviousValue = @{}
$GraylogResults | % {
  if ($_.winlogbeat_event_data_OpCorrelationID.Length -gt 0 -and $_.winlogbeat_event_data_AttributeLDAPDisplayName -gt 0) {
    $OpCorrelationCount[($_.winlogbeat_event_data_OpCorrelationID.ToString())+($_.winlogbeat_event_data_AttributeLDAPDisplayName.ToString())] += 1
    if ($_.winlogbeat_event_data_OperationType -eq '%%14675') {
      $OpCorrelationPreviousValue[($_.winlogbeat_event_data_OpCorrelationID.ToString())+($_.winlogbeat_event_data_AttributeLDAPDisplayName.ToString())] = $_.winlogbeat_event_data_AttributeValue.ToString()
    }
  }
}

#AttributeLDAPDisplayName lookup table for EventID 5136
$AttributeLDAPDisplayNameList = @{
 'sAMAccountName' = 'Name';
 'displayName' = 'Display Name';
 'givenName' = 'First Name';
 'sn' = 'Last Name';
 'initials' = 'Initials';
 'physicalDeliveryOfficeName' = 'Office';
 'description' = 'Description';
 'telephoneNumber' = 'Telephone Number';
 'mDBStorageQuota' = 'Exchange Soft Quota'
 'mDBOverQuotaLimit' = 'Exchange Send Quota';
 'mDBOverHardQuotaLimit' = 'Exchange Hard Quota';
 'dNSHostName' = 'Computer Name';
}

$email_body = ''
$AuditEventCount = 0

Write-Output $GraylogResults

$GraylogResults| % {
  #If $skip is set to 1, the event will be ignored
  $skip=0
  $EventId = $_.winlogbeat_event_id 

  # Get Event description from $DbEventIds
  $DbEventId = $DbEventIds | ? { $_.winlogbeat_event_id -eq $EventID }
  # Use ObjectClass to set ObjectType if available. Otherwise use lookup from $DbEventId.
  if ($_.winlogbeat_event_data_ObjectClass.length -ne 0) { $ObjectType =  (Get-Culture).textinfo.totitlecase($_.winlogbeat_event_data_ObjectClass)  } else {  $ObjectType = $DbEventId.ObjectType }
  # Use lookup from $DbEventId to set ChangeType
  $ChangeType = $DbEventId.ChangeType
  # Use TargetSid to set ObjectName if available. Otherwise use ObjectDN.
  if ($_.winlogbeat_event_data_TargetSid.length -ne 0) {
    $ObjectName = (Get-CNameFromSID ($_.winlogbeat_event_data_TargetSid))
  } elseif ($_.winlogbeat_event_data_ObjectDN.length -ne 0) {
    $ObjectName = (Get-CName($_.winlogbeat_event_data_ObjectDN )) 
  } else {
    #5139 (rename) uses NewObjectDN
    $ObjectName = ''
  }
  # Set severity level
  if ($ADCriticalGroups -contains $_.winlogbeat_event_data_TargetUserName ) {
    $Severity = '<b><font color=red>Critical</font></b>'
  } elseif  ($ADCriticalGroups -contains ($_.winlogbeat_event_data_ObjectDN -match 'CN=([^,]+)' | % { $Matches[1].ToString() }) ) {
    $Severity = '<b><font color=red>Critical</font></b>'
  } else {
    $Severity = 'Normal'
  }
  

  # EventId:(4728 4729 4756 4757 4761 4762)
  if ($EventId -eq '4728' -or $EventId -eq '4729' -or $EventId -eq '4756' -or $EventId -eq '4757'  -or $EventId -eq '4761' -or $EventId -eq '4762') {
    $Details = $DbEventId.Details + '""' + (Get-CNameFromSID ($_.winlogbeat_event_data_MemberSid)) + '""' 
  # EventId:4740
  } elseif ($EventId -eq '4740') {
    if ($_.winlogbeat_event_data_TargetDomainName.Length -eq 0 ) { $Workstation = '' } else { $Workstation = '(Workstation name: ' + $_.winlogbeat_event_data_TargetDomainName + ')'}
    $Details = $DbEventId.Details + ' ' + $Workstation 
  # EventId:4738
  } elseif ($EventId -eq '4738') {
    $Details = $_.message -replace '`n","' -replace '`r","' -match 'User Account Control:(.*)User Parameters:' | % {$Matches[1].Trim()}
  # EventId:5139
  } elseif ($EventId -eq '5139') {
    $Details = $DbEventId.Details + '""' + (Get-CName($_.winlogbeat_event_data_ObjectDN )) + '"" to ""' + (Get-CName($_.winlogbeat_event_data_NewObjectDN )) + '""'
    $ObjectName = (Get-CName($_.winlogbeat_event_data_ObjectDN ))
  # EventId:5136 (LDAP Events)
  } elseif ($EventId -eq '5136') {
    # LDAP Add Operation
    if ($_.winlogbeat_event_data_OperationType -eq '%%14674') {$LDAPOperationType = ' value added'}
    # LDAP Delete Operation
    if ($_.winlogbeat_event_data_OperationType -eq '%%14675') {$LDAPOperationType = ' value deleted'}
    # Set Correlation Type to add/delete/none. Allows us to combine multiple (delete&add) ldap events into a single event.
    if ($OpCorrelationCount[($_.winlogbeat_event_data_OpCorrelationID.ToString())+($_.winlogbeat_event_data_AttributeLDAPDisplayName.ToString())] -ge 2 -and $_.winlogbeat_event_data_OperationType -eq '%%14674') {
      $CorrelationType = 'add';
      $PreviousAttributeValue  = $OpCorrelationPreviousValue[($_.winlogbeat_event_data_OpCorrelationID.ToString())+($_.winlogbeat_event_data_AttributeLDAPDisplayName.ToString())]
    } elseif ($OpCorrelationCount[($_.winlogbeat_event_data_OpCorrelationID.ToString())+($_.winlogbeat_event_data_AttributeLDAPDisplayName.ToString())] -ge 2 -and $_.winlogbeat_event_data_OperationType -eq '%%14675') {
      $CorrelationType = 'delete';
    } else {
      $CorrelationType = 'none';
    }          
    # Set ChangeType to "Added" when sAMAccountName is set for the first time
    if ($CorrelationType -eq 'none' -and $_.winlogbeat_event_data_AttributeLDAPDisplayName -eq 'sAMAccountName'  ) {$ChangeType = 'Added'}

    # EventId:5136 AND (sAMAccountName displayName givenName sn initials physicalDeliveryOfficeName description telephoneNumber mDBStorageQuota mDBOverQuotaLimit mDBOverHardQuotaLimit dNSHostName)
    $AttributeLDAPDisplayName = $_.winlogbeat_event_data_AttributeLDAPDisplayName
    $AttributeValue = $_.winlogbeat_event_data_AttributeValue
    # Loop through AttributeLDAPDisplayName lookup hash table
    $AttributeLDAPDisplayNameList.GetEnumerator() | % {
      if ($AttributeLDAPDisplayName -eq $_.Name ) {
        if ($CorrelationType -eq 'add') {$Details = $_.Value + ' changed from ""' +  ( $PreviousAttributeValue )+ '"" to ""' + ($AttributeValue)  + '"" '
        } elseif  ($CorrelationType -eq 'delete') {$skip=1
        #} else {$Details = "Name changed to """ + $AttributeValue  + """"}
        } else {$Details = $_.Value + ' ""' + $AttributeValue  + '"" $LDAPOperationType'}
      }
    }
    # EventId:5136 AND accountExpires
    if ($_.winlogbeat_event_data_AttributeLDAPDisplayName -eq 'accountExpires' ) { 
      if ($_.winlogbeat_event_data_AttributeValue -eq 0  -or $_.winlogbeat_event_data_AttributeValue -eq 9223372036854775807) { $AccountExpires = 'Never' } else { $AccountExpires = Get-Date (Get-Date ([DateTime]::FromFileTime($_.winlogbeat_event_data_AttributeValue)).ToString()).ToUniversalTime() -Format G}
      if ($CorrelationType -eq 'add') {
        if ($PreviousAttributeValue -eq 0 -or $PreviousAttributeValue -eq 9223372036854775807) { $PreviousAccountExpires = 'Never' } else { $PreviousAccountExpires = Get-Date (Get-Date ([DateTime]::FromFileTime($_.winlogbeat_event_data_AttributeValue)).ToString()).ToUniversalTime() -Format G}
        $Details = 'Account Expires changed from ""' +  ( $PreviousAccountExpires )+ '"" to ""' + ($AccountExpires)  + '" '
      } elseif  ($CorrelationType -eq 'delete') {$skip=1
      } else {$Details = 'Account Expires ""' + $AccountExpires  + '"" $LDAPOperationType'}      
    }
    # EventId:5136 AND userAccountControl
    if ($_.winlogbeat_event_data_AttributeLDAPDisplayName -eq 'userAccountControl' ) { 
      if ($CorrelationType -eq 'add') {$Details = 'User Access changed from ""' +  (Get-UserAccountControlValue( $PreviousAttributeValue  )  )+ '" to ""' + (Get-UserAccountControlValue($_.winlogbeat_event_data_AttributeValue))  + '" '
      } elseif  ($CorrelationType -eq 'delete') {$skip=1
      } else {$Details = 'User Access ""' + (Get-UserAccountControlValue($_.winlogbeat_event_data_AttributeValue))  + '"" $LDAPOperationType'}
    }    
    # EventId:5136 AND member
    if ($_.winlogbeat_event_data_AttributeLDAPDisplayName -eq 'member' ) {
      $Details = 'Directory Service group modified:  ""' + (Get-CName ($_.winlogbeat_event_data_AttributeValue))  + '"" $LDAPOperationType'
    }
    # EventId:5136 AND pwdLastSetl
    if ($_.winlogbeat_event_data_AttributeLDAPDisplayName -eq 'pwdLastSet' ) { 
      if ($CorrelationType -eq 'add' -and $_.winlogbeat_event_data_AttributeValue -eq -1) { $Details = 'User is not required to change password at next logon' 
      } elseif ($CorrelationType -eq 'add' -and $_.winlogbeat_event_data_AttributeValue -eq 0) { $Details = 'User must change password at next logon'
      } else { $skip=1 }
    }    

  # Use $DbEventId lookup for default Details
  } else {
    $Details = $DbEventId.Details
  }
  # If skip is not equal to 0, the event will be skipped
  if ($skip -eq 0) {
    $email_body += '<font size=+2>Changes to Active Directory Objects</font>'
    $email_body += '<table>' ; 
    $email_body += '<tr><td colspan=2>--------------------------------------------------</td></tr>' ; 
    $email_body += '<tr><td width=140>Severity</td><td>' + $Severity + '</td></tr>' ; 
    $email_body += '<tr><td colspan=2>--------------------------------------------------</td></tr>' ; 
    $email_body += '<tr><td>Change Type:</td><td>' + $ChangeType + '</td></tr>' ; 
    $email_body += '<tr><td>Object Type:</td><td>' + $ObjectType + '</td></tr>' ; 
    $email_body += '<tr><td>When Changed:</td><td>' + (Get-Date    $_.timestamp -format G ) + '</td></tr>' ; 
    $email_body += '<tr><td>Who Changed:</td><td>' + (Get-AccountFromSID ($_.winlogbeat_event_data_SubjectUserSid)) + '</td></tr>' ; 
    $email_body += '<tr><td>Where Changed:</td><td>' + $_.source + '</td></tr>' ; 
    $email_body += '<tr><td colspan=2>--------------------------------------------------</td></tr>' ; 
    $email_body += '<tr><td>Object Name:</td><td>' + $ObjectName + '</td></tr>' ; 
    $email_body += '<tr><td>Details:</td><td>' + $Details + '</td></tr>' ; 
    $email_body += '<tr><td colspan=2>--------------------------------------------------</td></tr>' ;
    $email_body += '</table><br/><br/>' ;
    $AuditEventCount +=1
  }
}
#$email_body

if ($email_body.Length -gt 0) { 
  $msg=new-object System.Net.Mail.MailMessage
  $msg.From=$sender
  $msg.to.Add($recipient)
  $msg.Subject="AD Audit - $AuditEventCount Event(s)"
  $msg.IsBodyHtml=$true
  $msg.Body="<html><body>$email_body</body></html>"
  $smtp=new-object System.Net.Mail.SmtpClient
  $smtp.host=$smtpserver
  $smtp.Send($msg)
}

#update last run time
Update-LastRunTime
