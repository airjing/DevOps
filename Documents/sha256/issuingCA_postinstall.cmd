::Declare Configuration NC
certutil -setreg CA\DSConfigDN CN=configuration,DC=??,DC=??
::Define CRL Publication Intervals
certutil -setreg CA\CRLPeriodUnits 26
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLDeltaPeriod "Days"
::Enable all auditing events for the Issuing CA
certutil -setreg CA\AuditFilter 127
::Set Validity Period for Issued Certificates
certutil -setreg CA\ValidityPeriodUnits 5
certutil -setreg CA\ValidityPeriod "Years"
::Restart Certificate Services
net stop certsvc & net start certsvc
certutil -crl