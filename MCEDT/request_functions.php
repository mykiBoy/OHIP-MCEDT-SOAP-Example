<?php
function command_menu(){
  $apiCommands = [
      '1' => 'getTypeList',
      '2' => 'list',
      '3' => 'upload',
      '4' => 'update',
      '5' => 'info',
      '6' => 'delete',
      '7' => 'submit',
      '8' => 'download',
  ];

  // Display menu options
  echo "Select an API command:\n";
  foreach ($apiCommands as $key => $command) {
      echo "{$key}. {$command}\n";
  }

  // Get user input
  $userInput = readline("Enter the number of the command: ");

  // Validate user input
  if (!array_key_exists($userInput, $apiCommands)) {
      echo "Invalid command. Please enter a valid number.\n";
      exit;
  }
  echo "You selected: {$apiCommands[$userInput]}\n";
  $method = $apiCommands[$userInput];
  echo "Method: {$method}\n";
  return $method;
}
// ============ initialization complete ================

// in replit functions can be collapsed. collapsing all functions will help you get a sense of the structure.
// first a number of functions defined to build different parts of the xml request. then all the parts are put together in loadxmltemplate()
function loadbody() {
  // must declare var global to be able to use global var from outside the function
  global $method, $claimfile, $resourceID;
  switch ($method) {
    case 'getTypeList':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
            <edt:getTypeList/>
         </soapenv:Body>
      EOT;
        break;
    case 'list':
      global $resourceType, $resourceStatus, $resourcePage;
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
            <edt:list>
               <!--Optional:-->
               <resourceType>$resourceType</resourceType>
               <!--Optional:-->
               <status>$resourceStatus</status>
               <!--Optional:-->
               <pageNo>$resourcePage</pageNo>
            </edt:list>
         </soapenv:Body>
      EOT;
        break;
  case 'upload':
    $claimfilename = basename($claimfile); // just filename
    // hardcode cid or contentID, assuming just one attachment
    // cid need not be the filename, although it could.
    $rawbody = <<<EOT
    <soapenv:Body wsu:Id="id-5">
      <edt:upload>
         <!--1 to 5 repetitions:-->
         <upload>
            <content>
              <inc:Include href="cid:mykiboy" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
            </content>
            <!--Optional:-->
            <description>$claimfilename</description>
            <resourceType>CL</resourceType>
         </upload>
      </edt:upload>
    </soapenv:Body>
    EOT;
      break;
    case 'update':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
          <edt:update>
             <!--1 to 5 repetitions:-->
             <updates>
                <content>
        <inc:Include href="cid:mykiboy" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
                </content>
                <resourceID>$resourceID</resourceID>
             </updates>
          </edt:update>
         </soapenv:Body>
      EOT;
        break;

    case 'info':
    case 'delete':
    case 'submit':
    case 'download':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
            <edt:$method>
               <!--1 to 100 repetitions:-->
               <resourceIDs>$resourceID</resourceIDs>
            </edt:$method>
         </soapenv:Body>
      EOT;
        break;
  default:
      echo "invalid method parameter";
      break;
  }

    return $rawbody;
  }
function loadtimestamp() {
  // Create the first timestamp
  $firstTimestamp = new DateTime('now', new DateTimeZone('UTC'));
  $firstTimestampStr = $firstTimestamp->format('Y-m-d\TH:i:s.v\Z');

  // Create the second timestamp (10 minutes after the first one)
  $secondTimestamp = clone $firstTimestamp;
  $secondTimestamp->add(new DateInterval('PT10M')); // Add 10 minutes
  $secondTimestampStr = $secondTimestamp->format('Y-m-d\TH:i:s.v\Z');

$timestamp = <<<EOT
  <wsu:Timestamp wsu:Id="TS-1">
    <wsu:Created>$firstTimestampStr</wsu:Created>
    <wsu:Expires>$secondTimestampStr</wsu:Expires>
  </wsu:Timestamp>
EOT;
  return $timestamp;
}
function loadUsernameToken($username,$password) {
$usernameToken = <<<EOT
  <wsse:UsernameToken wsu:Id="UsernameToken-2">
      <wsse:Username>$username</wsse:Username>
      <wsse:Password 
      Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$password</wsse:Password>
  </wsse:UsernameToken>
EOT;
return $usernameToken;
}
function loadIDP($MOH_ID) {
//IDP model is used, not MSA model. reference moh-tech-spec-electronic-business-services-en-2023-06-12.pdf page 10
//The trusted external identity provider is referring to GoSecure at https://www.edt.health.gov.on.ca All doctors in Ontario get a username and password to GoSecure when they get licensed. Thus credentials to logging into GoSecure is considered high trust and a user there has rights to access patient health information.
$IDP = <<<EOT
  <idp:IDP wsu:Id="id-3">
    <ServiceUserMUID>$MOH_ID</ServiceUserMUID>
  </idp:IDP>
EOT;
//per FAQ word document provided by MOH, serviceUserMUID is the same as MOH ID
  return $IDP;
}
function loadEBS() {
// generate uuid without external library because my server doesn't have composer
$uuid = vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex(random_bytes(16)), 4) );

global $responseObj;
$responseObj->uuid = $uuid;
// hardcode conformance key here, as it will be permanent
// auditId is an arbitrary random unique ID sent with each request to identify each request. To pass ministry of health's conformance testing you must prove you can receive correct responses from the web service and the government team can verify against server log that you indeed sent the correct request identified by the AuditId.
$EBS = <<<EOT
  <ebs:EBS wsu:Id="id-4">
      <SoftwareConformanceKey>da3c7d46-42b9-4cd5-8485-8580e3a39593</SoftwareConformanceKey>
      <AuditId>$uuid</AuditId>
  </ebs:EBS>
EOT;
  return $EBS;
}

// given xml input, digestxml will canonicalize xml then hash it with SHA256, returning a hash value as digest string
function digestxml($xml) {
  // Create a DOMDocument
  $dom = new DOMDocument(); 
  // echo $xml."\n\n"; //for degug
  // Load the XML content into the DOMDocument
  $dom->loadXML($xml);


  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();

  // Output the canonicalized XML
  // echo $canonicalizedXML."\n\n";

  // Calculate SHA-256 hash, set hash func binary option to true
  $digestvalue = base64_encode(hash('sha256', $canonicalizedXML, true));
  return $digestvalue;
}


function loadxmltemplate() {

$root_namespaces = <<<EOT
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:edt="http://edt.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:inc="http://www.w3.org/2004/08/xop/include"
EOT;

// insert namespace definition from all parent nodes ($root_namespaces) into the xml part to be canonicalized. this is required, otherwise wsu or soapenv namespace would be undefined.

$timestamp = loadtimestamp();
$modtimestamp = substr_replace($timestamp, $root_namespaces, strpos($timestamp, '<wsu:Timestamp') + strlen('<wsu:Timestamp'), 0);
// echo $modtimestamp."\n\n"; //for debugging
$digestvalue1 = digestxml($modtimestamp);
// echo $digestvalue1."\n\n"; //for debugging

global $username,$password;
$usernameToken = loadUsernameToken($username,$password);
$modusernameToken = substr_replace($usernameToken, $root_namespaces, strpos($usernameToken, '<wsse:UsernameToken') + strlen('<wsse:UsernameToken'), 0);
$digestvalue2 = digestxml($modusernameToken);

global $MOH_ID;
$IDP = loadIDP($MOH_ID);
$modifiedIDP = substr_replace($IDP, $root_namespaces, strpos($IDP, '<idp:IDP') + strlen('<idp:IDP'), 0);
$digestvalue3 = digestxml($modifiedIDP);

$EBS = loadEBS();
$modifiedEBS = substr_replace($EBS, $root_namespaces, strpos($EBS, '<ebs:EBS') + strlen('<ebs:EBS'), 0);
$digestvalue4 = digestxml($modifiedEBS);

$body = loadbody();
$modifiedbody = substr_replace($body, $root_namespaces, strpos($body, '<soapenv:Body') + strlen('<soapenv:Body'), 0);
// echo $body."\n\n"; //for debugging
$digestvalue5 = digestxml($modifiedbody);
// echo $digestvalue5."\n\n"; //for debugging

$signedInfo = <<<EOT
<ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
    <ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv wsu"
    xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  </ds:CanonicalizationMethod>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#TS-1">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt idp msa"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestvalue1</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#UsernameToken-2">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="wsse ebs edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestvalue2</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-3">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestvalue3</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-4">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestvalue4</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-5">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestvalue5</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>
EOT;

// turns out after all that work for me to get the digest values right, or so I thought.
// it doesn't matter at all. if changing the digestvalue above to a wrong value, server will still respond with correct response.
// so server is only checking the format and structure of your request, but not the actual digest values. as long as you have the right tags and the right SOAP and WSS structure, this web service doesn't actually check content is tampered with.

//insert namespace from all parent nodes before canonicalization
$modsignedInfo = substr_replace($signedInfo, $root_namespaces, strpos($signedInfo, '<ds:SignedInfo') + strlen('<ds:SignedInfo'), 0);

  // Create a DOMDocument to prep for C14N canonicalization
  $dom = new DOMDocument();
  // Load the XML content into the DOMDocument
  $dom->loadXML($modsignedInfo);
  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();
  // Calculate SHA-1 hash of $signedInfo
  // The second parameter 'true' outputs raw binary data
  $digest = sha1($canonicalizedXML, true);

  // Calculate SHA-256 hash of $signedInfo
  // $digest = hash('sha256', $signedInfo, true);

global $privatekey;
// Sign the SHA-1 hash using private key and PKCS1 padding
openssl_sign($digest, $signature, $privatekey, OPENSSL_ALGO_SHA1);
// Signature is now in $signature
$signature=base64_encode($signature);
// echo 'Signature: ', base64_encode($signature), "\n\n"; //for debug
global $sender_public_cert;
$rawxml = <<<EOT
<soapenv:Envelope
xmlns:ebs="http://ebs.health.ontario.ca/"
xmlns:edt="http://edt.health.ontario.ca/"
xmlns:idp="http://idp.ebs.health.ontario.ca/"
xmlns:msa="http://msa.ebs.health.ontario.ca/"
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<soapenv:Header>
<wsse:Security
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-4A6564966742022D8B170319672914254">$sender_public_cert</wsse:BinarySecurityToken>
$usernameToken
$timestamp
<ds:Signature Id="SIG-6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
$signedInfo
<ds:SignatureValue>
$signature
</ds:SignatureValue>
<ds:KeyInfo Id="KI-4A6564966742022D8B170319672914255">
  <wsse:SecurityTokenReference wsu:Id="STR-4A6564966742022D8B170319672914256">
    <wsse:Reference URI="#X509-4A6564966742022D8B170319672914254" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
  </wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
</wsse:Security>
$IDP
$EBS
</soapenv:Header>
$body
</soapenv:Envelope>
EOT;
  return $rawxml;
}
function sendrequest($xmlPayload) {
  $url = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService';
  // this is the same as https://204.41.14.200:1443/EDTService/EDTService in WSDL
  // better to use the domain name instead of IP, matches with the SSL certificate.

  global $method, $claimfile;
  switch ($method) {
    // upload and update use the same MIME message structure
    case 'upload':
    case 'update':
      $fileContent = file_get_contents($claimfile);

      // Boundary for the multipart message
      // Generate a random boundary string, to avoid collision with msg content
      // $boundary = '----=' . bin2hex(random_bytes(16));
      $boundary = '----=Boundary_' . md5(uniqid(time()));

      // Construct the MIME message
      $mimeMessage = "--$boundary\r\n";
      $mimeMessage .= "Content-Type: application/xop+xml; charset=UTF-8; type=\"text/xml\"\r\n";
      $mimeMessage .= "Content-Transfer-Encoding: 8bit\r\n";
      $mimeMessage .= "Content-ID: <rootpart@soapui.org>\r\n\r\n";
      // there must be an extra line break between header and soap envelope
      $mimeMessage .= "$xmlPayload\r\n";
      $mimeMessage .= "--$boundary\r\n";
      // $mimeMessage .= "Content-Type: application/octet-stream;       name=$contentId\r\n";
      // $mimeMessage .= "Content-Transfer-Encoding: binary\r\n";
      $mimeMessage .= "Content-Type: text/plain; charset=us-ascii\r\n";
      $mimeMessage .= "Content-Transfer-Encoding: 7bit\r\n";
      // contentId is just the file name e.g. HL8012345.001
      $mimeMessage .= "Content-ID: <mykiboy>\r\n";
      $mimeMessage .= "Content-Disposition: attachment;   name=\"$claimfile\"\r\n\r\n";
      $mimeMessage .= "$fileContent\r\n";
      $mimeMessage .= "--$boundary--";

      $headers = [
        "Content-Type:multipart/related; type=\"application/xop+xml\"; start=\"<rootpart@soapui.org>\"; start-info=\"text/xml\"; boundary=\"$boundary\"",
        'MIME-Version: 1.0',
        // 'User-Agent: Apache-HttpClient/4.5.5 (Java/16.0.2)',
        // 'Connection: Keep-Alive',
        // 'Accept-Encoding: gzip, deflate',
        // 'Authorization: Basic Y29uZnN1KzQyN0BnbWFpbC5jb206UGFzc3dvcmQyIQ==',
        // 'SOAPAction: ""',
        // "Content-Length:".strlen($mimeMessage), //xmlPayload
      ];

      $xmlPayload = $mimeMessage;
      break;

    // case 'value3':
    //   // Code to execute if $method equals 'value3'
    //   break;

    // default works for info, getTypeInfo, delete, submit, download
    default:
      $headers = [
          'Content-Type: text/xml;charset=UTF-8',
          // 'Connection: Keep-Alive',
      ];
      break;
  }

  // file_put_contents('rawrequest.txt', $xmlPayload);
  // exit("rawrequest exported");

  // Initialize cURL session
  $ch = curl_init($url);

  // Set cURL options
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $xmlPayload);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  // visit endpoint url in chrome, download certificates from chrome
  // including Certificate Authority G2, intermediate L1K and server certificate
  // open all three in notepad and paste together, save as cacert.pem
  curl_setopt($ch, CURLOPT_CAINFO, 'cacert.pem');
  // set option to track request header in curl_getinfo
  curl_setopt($ch, CURLINFO_HEADER_OUT, true);
  // set option to include response header in $response
  curl_setopt($ch, CURLOPT_HEADER, true);

  // Execute cURL session
  $response = curl_exec($ch);
// var_dump($response);

    if (curl_errno($ch)) {
        echo 'Curl error: ' . curl_error($ch);
    }

    $info_array = curl_getinfo($ch);
    // print_r($info_array); //for debug
    // echo $info_array['http_code']."\n\n"; //== $serverStatus
    // echo $info_array['request_header'];
    $serverStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    // request headers

    // Create and open a file for writing verbose output
    $httpLogFile = fopen('httplog.txt', 'w');
    // Write request headers to the log file
    fwrite($httpLogFile, curl_getinfo($ch, CURLINFO_HEADER_OUT));
    fwrite($httpLogFile, $xmlPayload."\n\n\n");

    // Extract body from the response
    $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
    fwrite($httpLogFile, $response);
    // Close the file handle for http log
    fclose($httpLogFile);

    // Close cURL session
    curl_close($ch);

    // Output the response
    return [$serverStatus,$response];
  }


/* Mike's original decrypt function that would not work for decrypting the downloaded attachment. John rewrote function to handle decrypting attachment, and wrote a separate function to decrypt XML reponse from server for other methods other than download.

function decryptResponse($response) {
  // input encrypted server response, output decrypted result XML
  // first need to extract xml from MIME message for the download method
  // Define the pattern to extract content between <soapenv> tags
  $pattern = '/<soapenv:Envelope[^>]*>.*?<\/soapenv:Envelope>/s';
  // Perform the regular expression match
  preg_match($pattern, $response, $matches);
  // Extracted content between and including <soapenv> tags
  $soapenvContent = $matches[0];
  // Now, you can create SimpleXML object from $soapenvContent
  $xml = simplexml_load_string($soapenvContent);

  // Register the 'xenc' namespace
  $xml->registerXPathNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

  // Use XPath to select the CipherValue
  $cipherValues = $xml->xpath('//xenc:CipherValue');

  // Check if CipherValues were found
  if (!empty($cipherValues)) {
    // Decrypt using private key
    global $privatekey;
    openssl_private_decrypt(base64_decode($cipherValues[0]), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
    echo "AES key: ",base64_encode($decryptedAesKey),"\n\n";
    // Extract the initialization vector required for AES decryption
    $iv = substr(base64_decode(end($cipherValues)), 0, 16);
    // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
    $decryptedData = openssl_decrypt(end($cipherValues), 'aes-128-cbc', $decryptedAesKey, 0, $iv);
    $responseXML = substr($decryptedData, 16);

    if (count($cipherValues) > 2) { // for download method
    openssl_private_decrypt(base64_decode($cipherValues[1]), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
    echo "AES key: ",base64_encode($decryptedAesKey),"\n\n";

    // Define the regular expression pattern
    $pattern = "/Content-Type: application\/octet-stream(.*?)--MIMEBoundary/s";
    // Perform the regular expression match
    preg_match($pattern, $response, $matches);
    $attachmentpart = $matches[1];
    $binaryAttachment = substr($attachmentpart, strpos($attachmentpart, "apache.org>\r\n\r\n") + 15);
    // Extract the initialization vector required for AES decryption
    // $binaryAttachment = base64_decode($binaryAttachment);
    $iv = substr(base64_decode($binaryAttachment), 0, 16);
      echo $binaryAttachment . "\n============\n";
    $decryptedData = openssl_decrypt($binaryAttachment, 'aes-128-cbc', $decryptedAesKey, 0, $iv);
    echo $decryptedData;
    }

    buildResponseObj($responseXML);
      return $responseXML;
  } else {
      //error handling
      // echo "Ciphervalue not found. Nothing to decrypt here.\n";
      // echo "Raw response received from server:\n\n";
      global $response;
      return $response[1];
  }
}
*/

function buildResponseObj($decryptedResult) {
  // Parse the XML
  $xml = simplexml_load_string($decryptedResult);

  global $responseObj;
  // Store properties in $responseObj
  $responseObj->auditID = (string)$xml->auditID;
  if ($xml->xpath('//code')[0] == "IEDTS0001") {
    if (isset($xml->xpath('//status')[0])) {  // download method
      $responseObj->status = (string)$xml->xpath('//status')[0];
    }
    $responseObj->description = (string)$xml->xpath('//description')[0];
    $responseObj->resourceID = (string)$xml->xpath('//resourceID')[0];
  }
  $responseObj->msg = (string)$xml->xpath('//msg')[0];
  $responseObj->code = (string)$xml->xpath('//code')[0];
  if (isset($xml->resultSize)) {
    $responseObj->resultSize = (int)$xml->resultSize;
  }

  // Create and open a file for writing verbose output
  $auditLogFile = fopen('auditlog.txt', 'a');

  $auditContent = "Request AuditID: " . $responseObj->uuid."\n";
  $auditContent .= "Response AuditID: ".$responseObj->auditID."\n";
  $auditContent .= "Message: " . $responseObj->msg . "\n";
  $auditContent .= "Code: " . $responseObj->code . "\n";
  if ($responseObj->code == "IEDTS0001") {
    if (isset($responseObj->status)) {
      $auditContent .= "Status: " . $responseObj->status . "\n";      
    }
    $auditContent .= "Description: ".$responseObj->description."\n";
    $auditContent .= "ResourceID: " . $responseObj->resourceID ."\n";
    if (isset($responseObj->resultSize)) {
      $auditContent .= "Result Size: ".$responseObj->resultSize."\n";
    }
  }
  $auditContent .= "===========================\n";
  // Write request headers to the log file
  fwrite($auditLogFile, $auditContent);

  // Close the file handle for http log
  fclose($auditLogFile);
}
function decryptResponse_1($responseXML,$private_key){
  // decrypt server response for all methods except download
  // Extract AES key for SOAP body
  preg_match('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  $aesKey = base64_decode($matches[1]);

  // Load private key
  $privateKey = openssl_pkey_get_private($private_key);

  // Decrypt AES key for SOAP body
  openssl_private_decrypt($aesKey, $decryptedAesKey, $privateKey);

  // Output decrypted AES key for SOAP body for debug
  // echo "Decrypted AES key for SOAP body: " .     base64_encode($decryptedAesKey) . "\n\n";

  preg_match_all('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  // var_dump($matches);
  $ciphertext = $matches[1][1];
  // var_dump($ciphertext);
  if (!empty($ciphertext)) {
      // Decrypt using private key
      global $privatekey;
    // Initialize the AES cipher with the decrypted AES key and CBC mode
    $iv = str_repeat("\0", 16); // Initialization vector (first 16 bytes)
    $decryptedData = openssl_decrypt($ciphertext, 'aes-128-cbc', $decryptedAesKey, 0, $iv);

    // Remove PKCS5 padding from the decrypted text
    $responseXML = rtrim($decryptedData, "\0");

      $responseXML = substr($responseXML , 16);
    // echo "Decrypted XML: " . $responseXML . "\n";
      return $responseXML;
  } else {
      global $responseObj;
      //set error flag to true
      $responseObj->error = true;
      $responseObj->errorMsg = "Ciphervalue not found";
  }
}
function decryptResponse($responseXML,$privatekey) {
  // for the download method case
  list($decrypted_aes_key, $attachmentAesKey) = get_keys($privatekey,$responseXML);
  $decryptedResult=decrypt_body_content($decrypted_aes_key,$responseXML);
  $decrypted_attachment=decryptAttachmentModeCBCNoDecode($attachmentAesKey, $responseXML);
  return [$decryptedResult,$decrypted_attachment];
}

function decryptAttachmentModeCBCNoDecode_1($attachmentAesKey, $responseXML)
{
    $contentId = getCID($responseXML);
    echo $contentId . "\n";
    // Escape the dot in .org with double backslashes
    $escapedContentId = preg_quote($contentId, '/');

    // Create a pattern to match the content
    // $pattern = '/Content-ID: <' . $escapedContentId. '>\r\n\r\n(.*?)\r\n--MIMEBoundary_/s';
    $pattern = '/Content-ID: <' . $escapedContentId. '>\\r\\n\\r\\n(.*?)\\r\\n--MIMEBoundary_/s';

    echo $pattern . "\n";
    // $pattern = '/Content-ID: <' . $contentId. '>(.*?)--MIMEBoundary_/';
    // Search for the pattern in the raw response
    preg_match($pattern, $responseXML, $matches);
    $attachmentByte = $matches[1];

    // preg_match_all($pattern, $responseXML, $matches);
    // $attachmentByte  = $matches[1][2];
    // echo $matches[1][1] . "\n";
    echo $attachmentByte . "\n\naaaaaaaaaaa\n";

    // Initialize the AES cipher with the decrypted_aes_key and CBC mode
    $cipher = openssl_decrypt($attachmentByte, 'AES-128-CBC', $attachmentAesKey, 0, hex2bin($contentId));

    echo $cipher . "\n";

    // Remove PKCS5 padding from the decrypted text
    $plaintext = rtrim($cipher, "\0");
    // First 16 bytes removed as it is just initialization vector per MOH documentation
    $plaintext = substr($plaintext, 16);

    echo "\n===============\n", utf8_decode($plaintext);
    return $plaintext;
}

function getCID($responseXML)
{
    // Create a pattern to match the cipher reference URI
    $pattern = '/<xenc:CipherReference URI="(.*?)">/s';

    // Search for the pattern in the raw response
    preg_match($pattern, $responseXML, $matches);
    $cipherReferenceUri = $matches[1];

    // Remove double quotes using trim
    $cleanedCID = trim($cipherReferenceUri, '"');

    // Split the cleaned CID using the colon and get the second part
    $contentID = explode(":", $cleanedCID)[1];

    return $contentID;
}
function decrypt_body_content($decrypted_aes_key,$responseXML) {
  // Extract the ciphertext from the raw SOAP response
  // preg_match('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  preg_match_all('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  // var_dump($matches);
  $ciphertext = $matches[1][2];
  // echo "***body_content\n\n";
  // var_dump($ciphertext);

  // Initialize the AES cipher with the decrypted AES key and CBC mode
  $iv = str_repeat("\0", 16); // Initialization vector (first 16 bytes)
  $cipher = openssl_decrypt($ciphertext, 'aes-128-cbc', $decrypted_aes_key, 0, $iv);

  // Remove PKCS5 padding from the decrypted text
  $plaintext = rtrim($cipher, "\0");

  // Remove the first 16 bytes (initialization vector)
  $plaintext = substr($plaintext, 16);
  // echo $plaintext;
  return $plaintext;
}

function get_keys($private_key,$responseXML) {
  // Extract AES key for SOAP body
  preg_match('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  $aesKey = base64_decode($matches[1]);

  // Load private key
  $privateKey = openssl_pkey_get_private($private_key);

  // Decrypt AES key for SOAP body
  openssl_private_decrypt($aesKey, $decryptedAesKey, $privateKey);

  // Output decrypted AES key for SOAP body for debugging
  // echo "Decrypted AES key for SOAP body: " . base64_encode($decryptedAesKey) . "\n\n";

  // Extract AES key for attachment
  preg_match_all('/<xenc:CipherValue>(.*?)<\/xenc:CipherValue>/', $responseXML, $matches);
  $aesKeyAttachment = base64_decode($matches[1][1]);

  // Decrypt AES key for attachment
  openssl_private_decrypt($aesKeyAttachment, $decryptedAesKeyAttachment, $privateKey);

  // Output decrypted AES key for attachment for debugging
  // echo "Decrypted AES key for attachment: " . base64_encode($decryptedAesKeyAttachment) . "\n\n";

  // Return the decrypted AES keys
  return [$decryptedAesKey, $decryptedAesKeyAttachment];
}

function decryptAttachmentModeCBCNoDecode($attachmentAesKey, $rawResponse)
{
  // var_dump($attachmentAesKey);
  // var_dump(base64_encode($attachmentAesKey));
  // var_dump($rawResponse);
    $contentId = getCID($rawResponse);
    // echo "\n".$contentId . "\n\n";
    // Create a pattern to match the content
    $pattern = '/Content-ID: <' . preg_quote($contentId) . '>\r\n\r\n(.*?)\r\n--MIMEBoundary_/s';

    // Search for the pattern in the raw response
    preg_match($pattern, $rawResponse, $matches);
    $attachmentByte = $matches[1];
// var_dump($attachmentByte);
   $a= base64_encode($attachmentByte);
  // var_dump($a);
//   $d=bin2hex($a);
//   var_dump($d);
//   echo "base64 encoded > bin2hex\n";
//   // $c=base64_decode($attachmentByte);
//   // var_dump($c);
//   // var_dump(bin2hex($c));
//   // echo "base64 decoded > bin2hex\n";

  
//   $b=hex2bin($d);
//   var_dump($b);
//   // $byteString = pack("H*", $b);
//   // var_dump($byteString);
//   // $byteString = unpack("H*", $b);
//   // var_dump($byteString);
// echo "bin2hex pack> unpack\n";
  // how to convert to hex string?
    // echo  "__aaaaaaaaaaa\n";
  $iv = str_repeat("\0", 16); // Initialization vector (first 16 bytes)
    // Initialize the AES cipher with the decrypted_aes_key and CBC mode
    $cipher = openssl_decrypt($a, 'AES-128-CBC', $attachmentAesKey, 0, $iv);

    // echo $cipher . "\n";
  // var_dump($cipher);

    // Remove PKCS5 padding from the decrypted text
    $plaintext = rtrim($cipher, "\0");
    // First 16 bytes removed as it is just initialization vector per MOH documentation
    $plaintext = substr($plaintext, 16);

    // echo "\n===============\n", utf8_decode($plaintext);
  // file_put_contents('attachment.txt', utf8_decode($plaintext));
  return $plaintext;
}




