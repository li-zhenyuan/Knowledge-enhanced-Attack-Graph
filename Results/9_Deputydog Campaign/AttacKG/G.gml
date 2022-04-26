graph [
  directed 1
  node [
    id 0
    label "fireeye#executable#5"
    type "executable"
    nlp "FireEye"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "day#network#10"
    type "network"
    nlp "zero-day network Foreign"
    regex "vfw[.]org"
    contraction ""
  ]
  node [
    id 2
    label "vfw#file#35"
    type "file"
    nlp "VFW"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "exploit#vulnerability#80"
    type "vulnerability"
    nlp "exploit"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "document#file#125"
    type "file"
    nlp "document"
    regex "img.html"
    contraction ""
  ]
  node [
    id 5
    label "www.[redacted].com#network#119"
    type "network"
    nlp "www.[REDACTED].com/Data/img/"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "microsoft#file#131"
    type "file"
    nlp "Microsoft."
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "control#network#135"
    type "network"
    nlp "control XML"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "path#file#147"
    type "file"
    nlp "path"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "order#file#165"
    type "file"
    nlp "order"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "dll#file#192"
    type "file"
    nlp "EMET DLL"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "attacker#executable#225"
    type "executable"
    nlp "attacker"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "sound#file#237"
    type "file"
    nlp "Sound"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "vector#file#262"
    type "file"
    nlp "Flash Vector"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "files#file#344"
    type "file"
    nlp "files"
    regex ""
    contraction ""
  ]
  node [
    id 15
    label "call#file#379"
    type "file"
    nlp "Windows API call"
    regex ""
    contraction ""
  ]
  node [
    id 16
    label "xor#file#389"
    type "file"
    nlp "XOR"
    regex ""
    contraction ""
  ]
  node [
    id 17
    label "file#file#402"
    type "file"
    nlp "file"
    regex "8455bbb9a210ce603a1b646b0d951bce"
    contraction ""
  ]
  node [
    id 18
    label "network#network#440"
    type "network"
    nlp "network"
    regex "newss[.]effers[.]com"
    contraction ""
  ]
  node [
    id 19
    label "network#network#447"
    type "network"
    nlp "network"
    regex "118.99.60.142"
    contraction ""
  ]
  node [
    id 20
    label "network#network#451"
    type "network"
    nlp "network"
    regex "info[.]flnet[.]org"
    contraction ""
  ]
  edge [
    source 0
    target 3
    action ""
    sequence 0
    nlp "&#10;    On February 11, FireEye identified a zero-day exploit (exploit)  being served up from the U.S. Veterans of Foreign Wars&#8217; website (network)."
  ]
  edge [
    source 1
    target 3
    action ""
    sequence 2
    nlp "&#10;    On February 11, FireEye identified a zero-day exploit (exploit)  being served up from the U.S. Veterans of Foreign Wars&#8217; website (network)."
  ]
  edge [
    source 2
    target 11
    action ""
    sequence 7
    nlp "After compromising the VFW website, the attackers added an iframe into the beginning of the website&#8217;s HTML code that loads the attacker&#8217;s page in the background."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 14
    nlp "Specifically, visitors to the VFW website were silently redirected through an iframe to the exploit at www.[REDACTED].com/Data/img/document."
  ]
  edge [
    source 3
    target 10
    action ""
    sequence 26
    nlp "The exploit proceeds only if this check determines that the EMET DLL is not present."
  ]
  edge [
    source 3
    target 1
    action ""
    sequence 3
    nlp "&#10;    On February 11, FireEye identified a zero-day exploit (exploit)  being served up from the U.S. Veterans of Foreign Wars&#8217; website (network)."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 16
    nlp "Specifically, visitors to the VFW website were silently redirected through an iframe to the exploit at www.[REDACTED].com/Data/img/document."
  ]
  edge [
    source 3
    target 9
    action ""
    sequence 23
    nlp "Then the exploit code parses the error resulting from the XML load order to determine whether the load failed because the EMET DLL is not present."
  ]
  edge [
    source 3
    target 11
    action ""
    sequence 49
    nlp "As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: file)."
  ]
  edge [
    source 4
    target 5
    action ""
    sequence 17
    nlp "Specifically, visitors to the VFW website were silently redirected through an iframe to the exploit at www.[REDACTED].com/Data/img/document."
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 20
    nlp "XMLDOM ActiveX control to load a one-line XML string containing a file path to the EMET DLL."
  ]
  edge [
    source 8
    target 14
    action ""
    sequence 21
    nlp "XMLDOM ActiveX control to load a one-line XML string containing a file path to the EMET DLL."
  ]
  edge [
    source 9
    target 10
    action ""
    sequence 24
    nlp "Then the exploit code parses the error resulting from the XML load order to determine whether the load failed because the EMET DLL is not present."
  ]
  edge [
    source 11
    target 18
    action ""
    sequence 54
    nlp "This particular variant called back to a command and control server located at network."
  ]
  edge [
    source 11
    target 2
    action ""
    sequence 6
    nlp "After compromising the VFW website, the attackers added an iframe into the beginning of the website&#8217;s HTML code that loads the attacker&#8217;s page in the background."
  ]
  edge [
    source 11
    target 16
    action ""
    sequence 50
    nlp "As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: file)."
  ]
  edge [
    source 11
    target 3
    action ""
    sequence 10
    nlp "The attacker&#8217;s HTML/JavaScript page runs a Flash object, which orchestrates the remainder of the exploit."
  ]
  edge [
    source 11
    target 14
    action ""
    sequence 36
    nlp "The beginning of the file is a JPG image; the end of the file (offset 36321) is the payload, encoded with an XOR key of 0x95."
  ]
  edge [
    source 11
    target 17
    action ""
    sequence 52
    nlp "As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: file)."
  ]
  edge [
    source 11
    target 6
    action ""
    sequence 18
    nlp "The attacker uses the Microsoft."
  ]
  edge [
    source 11
    target 13
    action ""
    sequence 28
    nlp "Once the attacker&#8217;s code has full memory access through the corrupted Flash Vector object, the code searches through loaded libraries gadgets by machine code."
  ]
  edge [
    source 13
    target 3
    action ""
    sequence 30
    nlp "After successful exploitation, the code repairs the corrupted Flash Vector and flash."
  ]
  edge [
    source 14
    target 11
    action ""
    sequence 31
    nlp "Subsequently, the malicious Flash code downloads a file containing the dropped malware payload."
  ]
  edge [
    source 14
    target 10
    action ""
    sequence 22
    nlp "XMLDOM ActiveX control to load a one-line XML string containing a file path to the EMET DLL."
  ]
  edge [
    source 14
    target 16
    action ""
    sequence 38
    nlp "The beginning of the file is a JPG image; the end of the file (offset 36321) is the payload, encoded with an XOR key of 0x95."
  ]
  edge [
    source 16
    target 11
    action ""
    sequence 51
    nlp "As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: file)."
  ]
  edge [
    source 16
    target 14
    action ""
    sequence 39
    nlp "The beginning of the file is a JPG image; the end of the file (offset 36321) is the payload, encoded with an XOR key of 0x95."
  ]
]
