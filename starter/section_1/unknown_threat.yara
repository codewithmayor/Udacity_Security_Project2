rule illegal_server {
	meta:
		Author = "mayor.michael19@gmail.com"
		Description = "this rule detects the presence of malicious server domains" 		   
	strings:
		$script = "SSH-One|SSH-T" nocase
		$url = "http://darkl0rd.com:7758"

	condition:
		all of them

}
