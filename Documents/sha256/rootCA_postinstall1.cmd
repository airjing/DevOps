::Define CRL Publication Intervals
certutil -setreg CA\CRLPeriodUnits 26
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLDeltaPeriod "Days"
::Enable all auditing events for the Intermediate CA
certutil -setreg CA\AuditFilter 127
::Set Validity Period for Intermediate Certificates
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod "Years"
::Restart Certificate Services
net stop certsvc & net start certsvc
sleep.exe 20
certutil -crl