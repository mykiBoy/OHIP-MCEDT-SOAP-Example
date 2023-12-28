# OHIP-MCEDT-SOAP-Example
Ontario Ministry of Health's MCEDT web service. A working example to access the conformance testing API with a valid SOAP request message. Valid certificate included to enable WSS security. You should be able to just plug in your conformance testing key, username, password and MOH ID.
Hope this helps those who find the MOH's technical documents lacking, and if this helps you, please give the youtube video tutorial a like. If you have better implementation of code, please share in the comments.

Create your own keystore
-
Use this command on any linux shell. I used replit.com, all of their language templates has a shell tab which runs linux shell. Keytool is part of the JRE (java runtime) built-in tools.
replit.com allows me to run linux shell commands without having a linux machine at home. This command will create a 1024 bit RSA key and store it in a p12 type store named testStore.p12, the password is "changeit",
and the key will expire in 7300 days or 20 years.
```
keytool -genkeypair -keystore teststore.p12 -storetype PKCS12 -storepass changeit -alias client -keyalg RSA -keysize 1024 -validity 7300
```

You will also need to replace the public certificate included in the SOAP request with your own public certificate.
```xml
<wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-28C9CE93E0A1F26FD917013530402403">MIICdTCCAd6gAwIBAgIJAIgq6l1JzkMMMA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjAeFw0yMzExMzAwMzUzNTJaFw00MzExMjUwMzUzNTJaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuTOk0wQTfR5gkaprZ2bk/sIR5UEHV+TQhuUXCnoBgykoM+FOiumHxeZobIYLanFZ7VPxZyXIYB/uPD6NJ5YOd3UhbD7RFgpS7TQiF2Y+Ndu9wwYkXpJSVfd7q+R+xG/zpEVedm8/vJLFLmeHMKELqxKrjmObRyn5BJd0UrhGtzcCAwEAAaMhMB8wHQYDVR0OBBYEFFB8aN77G0N7cC/zkKR9vWrHEycdMA0GCSqGSIb3DQEBCwUAA4GBAKlcecHQkrLz2F033QK3bYn9cJ+Qf3we+VDCr8Wbrp+Bh4wFYs6k57EITm5h/MpAIWO9lc0xaw6wKDlHhrl6fGs7Sxjk/AN7Sm5Bi9hzAyzCSPMhxr3njIDVZr5h0ekzoRnaoPAByM2e4ZKc288DAtE3sirNxmHswrnyZEO7BGa2</wsse:BinarySecurityToken>
```
Command to export your own public certificate
-
Export the public certificate from the .p12 store.
```
openssl pkcs12 -in teststore.p12 -out publicCertificate.pem -nokeys
```
Copy the plain text from publicCertificate.pem and paste it to replace the certificate wrapped by the "<wsse:BinarySecurityToken>" tag.