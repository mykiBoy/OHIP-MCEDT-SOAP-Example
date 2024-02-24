<?php
include_once 'MCEDT/request_functions.php';
include_once 'MCEDT/response_to_file.php';

ini_set('display_errors', 1); ini_set('display_startup_errors', 1); error_reporting(E_ALL);
// this API takes POST input with a specified method and output server response as decrypted XML
// initialize with input parameters to this API
// Define API commands and their corresponding functions

global $method, $claimfile, $resourceID;
// $method = command_menu();
$method = 'info'; //$_POST['method']
//getTypeList,list,info,upload,delete,update,submit,download 
$claimfile = 'MCEDT/Claim_File.txt'; 
//can contain forward slash for claimfile foldername

// vars needed for list method
global $resourceType, $resourceStatus, $resourcePage;
// ref getTypeList method's server response
$resourceStatus = 'DOWNLOADABLE'; 
// UPLOADED, SUBMITTED, WIP, DOWNLOADABLE, APPROVED, DENIED
// ref pg25 moh-ohip-techspec-mcedt-ebs-v4-5-en-2023-10-18.pdf
$resourcePage = 1;
$resourceID = "83450";
$resourceType = 'GCM'; // OPTIONAL can leave empty
// CL, BE, ER, ES, RA, RS, PSP, GCM
// replace with your own conformance testing credentials
// scroll down to replace conformance testing key further down the code base
global $MOH_ID, $username, $password;
$MOH_ID = '621300';
$username = 'confsu+427@gmail.com';
$password = 'Password2!';

// load $privatekey
global $privatekey;
// Load the PKCS#12 file
$pkcs12 = file_get_contents('teststore.p12');
// Parse the PKCS#12 file to extract private key and certificate
openssl_pkcs12_read($pkcs12, $pkcs12Info, 'changeit');
// load the private key
$privatekey = $pkcs12Info['pkey'];

// create responseObj for auditlog tracking
$responseObj = new stdClass();
global $responseObj;


$rawxml = loadxmltemplate();
// echo $rawxml."\n\n"; //for debugging

global $response;
// list($serverStatus,$body)=sendrequest($rawxml);
// echo $serverStatus."\n\n";
// echo 'Body\n'.$body."\n\n"; //for debugging
list($serverStatus,$response) = sendrequest($rawxml);

// file_put_contents('soap_response.pickle', serialize($response));
// Save the SOAP response to a file
// file_put_contents('soap_response.xml', $response);
// echo out the response to console
// echo "\nServerStatus= ".$response[0]."\n\n\n"; //for debugging
// echo $response[1]."\n\n\n"; // for debugging
// echo $serverStatus."\n\n\n";
// echo $response."\n\n\n";

// $decryptedResult = decryptResponse($response[1]);
// echo $decryptedResult; // output plain text response to console
// echo "\n\n" . json_encode($responseObj);
// you will need to build your own code to handle errors e.g. $response[0] > 300
// you will need to also parse $decryptedResult to extract the relevant data
// echo "Response Status: ".$serverStatus."\n\n";
if ($serverStatus == 200){
  switch ($method) {
    case 'download':  list($decryptedResult,$decrypted_attachment)=decryptResponse($response,$privatekey);
    echo $decryptedResult;
    buildResponseObj($decryptedResult);
    // echo "\nDecrypted Attachment:\n$decrypted_attachment\n";
    $xml = simplexml_load_string($decryptedResult);
    // get_content_from_xml_1($xml);
    $file_name=get_content_from_xml($xml,'description');
    file_put_contents("MCEDT/".$file_name, $decrypted_attachment);
      break;
    default:
      $decryptedResult = decryptResponse_1($response,$privatekey);
    echo $decryptedResult;
    buildResponseObj($decryptedResult);
    // $xml = simplexml_load_string($decryptedResult);
    // get_content_from_xml_1($xml);
      break;
  }
}



