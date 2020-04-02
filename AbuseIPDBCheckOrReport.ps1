<#

.SYNOPSIS
	AbuseIPDBCheckOrReport.ps1: AbuseIPDB.com Check or Report IP

.DESCRIPTION
	AbuseIPDBCheckOrReport.ps1: Powershell script to check or report IP at AbuseIPDB.com

.FUNCTIONALITY
	1) Checks IP -> Returns status, abuseConfidenceScore
	2) Reports IP -> Returns status, abuseConfidenceScore

.PARAMETER IP
	Specifies the IP address to be checked or reported.
	
.PARAMETER Categories
	Specifies the categories of reported IPs. !REQUIRED FOR REPORT IP! See https://www.abuseipdb.com/categories for full list.

.PARAMETER Comment
	Specifies the comments to be included with reported IP. Parameter optional.
	
.NOTES
	Create account and get API key from https://www.abuseipdb.com/account, then fill in $APIKey variable under USER VARIABLES.
	
.EXAMPLE
	Check IP:
		$CheckIP = & C:\path\to\AbuseIPDBCheckOrReport.ps1 "77.40.61.210"
		$CheckIP.Status
		$CheckIP.Confidence

	Report IP:
		$CheckIP = & C:\path\to\AbuseIPDBCheckOrReport.ps1 "77.40.61.210" "11"
		$CheckIP.Status
		$CheckIP.Confidence

		$CheckIP = & C:\path\to\AbuseIPDBCheckOrReport.ps1 "77.40.61.210" "11" "spammer"
		$CheckIP.Status
		$CheckIP.Confidence

	Report IP with error:
		$CheckIP = & C:\path\to\AbuseIPDBCheckOrReport.ps1 "127.0.0.2" "11"
		$CheckIP.Status
		$CheckIP.Confidence

		$CheckIP = & C:\path\to\AbuseIPDBCheckOrReport.ps1 "127.0.0.2" "11" "spammer"
		$CheckIP.Status
		$CheckIP.Confidence

#>

Param(
	[Parameter(Mandatory=$True)]
	[ValidatePattern("((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))")]
	[String]$IP,

	[Parameter(Mandatory=$False)]
	[AllowEmptyString()]
	[String]$Categories,

	[Parameter(Mandatory=$False)]
	[AllowEmptyString()]
	[String]$Comment
)

<###   USER VARIABLES   ###>
$APIKey = "supersecretkey"

<#  Begin Script  #>

<#  Clear out error variable  #>
$Error.Clear()

<#  Set header  #>
$Header = @{
	'Key' = $APIKey;
}

<#  If Categories and Comment empty, then the call must be to check  #>
If (([string]::IsNullOrEmpty($Categories)) -and ([string]::IsNullOrEmpty($Categories))){

	$URICheck = "https://api.abuseipdb.com/api/v2/check"
	$BodyCheck = @{
		'ipAddress' = $IP;
		'maxAgeInDays' = '90';
		'verbose' = '';
	}
	Try {
		<#  GET abuse confidence score and set status if successful  #>
		$AbuseIPDB = Invoke-RestMethod -Method GET $URICheck -Header $Header -Body $BodyCheck -ContentType 'application/json; charset=utf-8' 
		$StatusNum = "200"
		$ConfidenceScore = $AbuseIPDB.data.abuseConfidenceScore
	}
	Catch {
		<#  If error, capture status number from message  #>
		$ErrorMessage = $_.Exception.Message
		[regex]$RegexErrorNum = "\d{3}"
		$StatusNum = ($RegexErrorNum.Matches($ErrorMessage)).Value	
	}

<#  If Categories or Comment exist, then the call must be to report  #>
} Else {

	$URIReport = "https://api.abuseipdb.com/api/v2/report"
	$BodyReport = @{
		'ip' = $IP;
		'categories' = $Categories;
		'comment' = $Comment;
	} | ConvertTo-JSON 

	Try {
		<#  GET abuse confidence score and set status if successful  #>
		$AbuseIPDB = Invoke-RestMethod -Method POST $URIReport -Header $Header -Body $BodyReport -ContentType 'application/json; charset=utf-8' 
		$StatusNum = "200"
		$ConfidenceScore = $AbuseIPDB.data.abuseConfidenceScore
	}
	Catch {
		<#  If error, capture status number from message  #>
		$ErrorMessage = $_.Exception.Message
		[regex]$RegexErrorNum = "\d{3}"
		$StatusNum = ($RegexErrorNum.Matches($ErrorMessage)).Value	
	}
}

<#  Return result in a parseable hash  #>
$Response = @{
	'Status' = $StatusNum;
	'Confidence' = $ConfidenceScore;
}
Return $Response