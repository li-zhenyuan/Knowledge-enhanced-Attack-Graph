graph [
  directed 1
  node [
    id 0
    label "seeley#executable#8"
    type "executable"
    nlp "Steven Seeley"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "exploit#vulnerability#40"
    type "vulnerability"
    nlp "exploit"
    regex "CVE-2020-10189"
    contraction ""
  ]
  node [
    id 2
    label "fireeye#file#48"
    type "file"
    nlp "FireEye"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "apt41#executable#50"
    type "executable"
    nlp "APT41"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "march#network#45"
    type "network"
    nlp "March zero-day remote"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "payloads#executable#89"
    type "executable"
    nlp "payloads PowerShell"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "program#file#118"
    type "file"
    nlp "program document"
    regex "logger.zip"
    contraction ""
  ]
  node [
    id 7
    label "fireeye#executable#137"
    type "executable"
    nlp "FireEye"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "batch#executable#170"
    type "executable"
    nlp "batch"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "file#file#155"
    type "file"
    nlp "file"
    regex "7966c2c546b71e800397a67f942858d0"
    contraction ""
  ]
  node [
    id 10
    label "file#file#192"
    type "file"
    nlp "file"
    regex "5909983db4d9023e4098e56361c96a6f"
    contraction ""
  ]
  node [
    id 11
    label "c2#network#227"
    type "network"
    nlp "C2 network DNS"
    regex "exchange.dumb1[.]com"
    contraction ""
  ]
  node [
    id 12
    label "backdoor#executable#249"
    type "executable"
    nlp "secondary backdoor"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "exploitation#vulnerability#237"
    type "vulnerability"
    nlp "exploitation"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "certutil#file#258"
    type "file"
    nlp "Microsoft CertUtil 66.42.98[.]220"
    regex ""
    contraction ""
  ]
  node [
    id 15
    label "file#file#283"
    type "file"
    nlp "file"
    regex "3e856162c36b532925c8226b4ed3481c"
    contraction ""
  ]
  node [
    id 16
    label "executable#executable#288"
    type "executable"
    nlp "executable"
    regex "2.exe"
    contraction ""
  ]
  node [
    id 17
    label "shellcode#file#300"
    type "file"
    nlp "BEACON shellcode 91.208.184[.]78"
    regex ""
    contraction ""
  ]
  node [
    id 18
    label "actor#executable#323"
    type "executable"
    nlp "actor"
    regex ""
    contraction ""
  ]
  node [
    id 19
    label "systems#system#334"
    type "system"
    nlp "systems"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 4
    action ""
    sequence 0
    nlp "On March 5, 2020, researcher Steven Seeley, published an advisory and released proof-of-concept code for a zero-day remote code execution vulnerability in Zoho ManageEngine Desktop Central versions prior to 10.0.474 (exploit)."
  ]
  edge [
    source 1
    target 6
    action ""
    sequence 10
    nlp "In the first variation the exploit exploit was used to directly upload &#8220;document&#8221;, a simple Java based program, which contained a set of commands to use PowerShell to download and execute executable and executable."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 3
    nlp "Beginning on March 8, FireEye observed APT41 use 91.208.184[.]78 to attempt to exploit the Zoho ManageEngine vulnerability at more than a dozen FireEye customers, which resulted in the compromise of at least five separate customers."
  ]
  edge [
    source 2
    target 5
    action ""
    sequence 8
    nlp "FireEye observed two separate variations of how the payloads (executable and executable) were deployed."
  ]
  edge [
    source 2
    target 8
    action ""
    sequence 16
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 4
    nlp "Beginning on March 8, FireEye observed APT41 use 91.208.184[.]78 to attempt to exploit the Zoho ManageEngine vulnerability at more than a dozen FireEye customers, which resulted in the compromise of at least five separate customers."
  ]
  edge [
    source 3
    target 9
    action ""
    sequence 18
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 3
    target 15
    action ""
    sequence 35
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 3
    target 17
    action ""
    sequence 28
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 4
    target 7
    action ""
    sequence 6
    nlp "Beginning on March 8, FireEye observed APT41 use 91.208.184[.]78 to attempt to exploit the Zoho ManageEngine vulnerability at more than a dozen FireEye customers, which resulted in the compromise of at least five separate customers."
  ]
  edge [
    source 4
    target 1
    action ""
    sequence 2
    nlp "On March 5, 2020, researcher Steven Seeley, published an advisory and released proof-of-concept code for a zero-day remote code execution vulnerability in Zoho ManageEngine Desktop Central versions prior to 10.0.474 (exploit)."
  ]
  edge [
    source 5
    target 10
    action ""
    sequence 22
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 5
    target 14
    action ""
    sequence 24
    nlp "executable was a Cobalt Strike BEACON implant (trial-version) which connected to network (with a DNS resolution of 74.82.201[.]8) using a jquery malleable command and control (C2) profile."
  ]
  edge [
    source 6
    target 5
    action ""
    sequence 12
    nlp "In the first variation the exploit exploit was used to directly upload &#8220;document&#8221;, a simple Java based program, which contained a set of commands to use PowerShell to download and execute executable and executable."
  ]
  edge [
    source 7
    target 2
    action ""
    sequence 7
    nlp "FireEye observed two separate variations of how the payloads (executable and executable) were deployed."
  ]
  edge [
    source 8
    target 3
    action ""
    sequence 17
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 9
    target 14
    action ""
    sequence 19
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 10
    target 3
    action ""
    sequence 23
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 11
    target 14
    action ""
    sequence 32
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 12
    target 13
    action ""
    sequence 30
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 13
    target 1
    action ""
    sequence 9
    nlp "In the first variation the exploit exploit was used to directly upload &#8220;document&#8221;, a simple Java based program, which contained a set of commands to use PowerShell to download and execute executable and executable."
  ]
  edge [
    source 13
    target 11
    action ""
    sequence 31
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 14
    target 11
    action ""
    sequence 25
    nlp "executable was a Cobalt Strike BEACON implant (trial-version) which connected to network (with a DNS resolution of 74.82.201[.]8) using a jquery malleable command and control (C2) profile."
  ]
  edge [
    source 14
    target 7
    action ""
    sequence 14
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 14
    target 17
    action ""
    sequence 36
    nlp "The file executable was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode."
  ]
  edge [
    source 14
    target 3
    action ""
    sequence 34
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 14
    target 5
    action ""
    sequence 21
    nlp "FireEye observed APT41 leverage the Microsoft BITS Admin command-line tool to download executable (MD5: file) from known APT41 infrastructure 66.42.98[.]220 on port 12345.In both variations, the executable batch file was used to install persistence for a trial-version of Cobalt Strike BEACON loader named executable (MD5: file)."
  ]
  edge [
    source 16
    target 17
    action ""
    sequence 38
    nlp "The file executable was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode."
  ]
  edge [
    source 17
    target 12
    action ""
    sequence 29
    nlp "Within a few hours of initial exploitation, APT41 used the executable BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we&#8217;ve observed APT41 use in past intrusions, which they then used to download executable (MD5: file)."
  ]
  edge [
    source 17
    target 16
    action ""
    sequence 37
    nlp "The file executable was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode."
  ]
  edge [
    source 17
    target 11
    action ""
    sequence 41
    nlp "The downloaded BEACON shellcode connected to the same C2 server: 91.208.184[.]78."
  ]
  edge [
    source 18
    target 19
    action ""
    sequence 42
    nlp "We believe this is an example of the actor attempting to diversify post-exploitation access to the compromised systems."
  ]
]
