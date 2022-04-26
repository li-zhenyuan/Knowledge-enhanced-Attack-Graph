graph [
  directed 1
  node [
    id 0
    label "attachment#file#14"
    type "file"
    nlp "attachment INF"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "email#network#38"
    type "network"
    nlp "email first stage of"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "pdf#executable#89"
    type "executable"
    nlp "PDF"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "rtf#network#106"
    type "network"
    nlp "RTF"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "exploits#vulnerability#109"
    type "vulnerability"
    nlp "exploits exploit"
    regex "CVE-2017-11882"
    contraction ""
  ]
  node [
    id 5
    label "system#system#136"
    type "system"
    nlp "system"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "inf#executable#199"
    type "executable"
    nlp "INF"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "com#executable#223"
    type "executable"
    nlp "COM"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "windows#executable#272"
    type "executable"
    nlp "Windows"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "perl#network#288"
    type "network"
    nlp "Perl"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "python#executable#290"
    type "executable"
    nlp "Python"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "code#network#321"
    type "network"
    nlp "malicious code"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "parameters#network#341"
    type "network"
    nlp "appropriate parameters"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "xml#network#324"
    type "network"
    nlp "XML"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "dll#executable#366"
    type "executable"
    nlp "DLL"
    regex ""
    contraction ""
  ]
  node [
    id 15
    label "scriptlet#executable#441"
    type "executable"
    nlp "scriptlet More_eggs"
    regex ""
    contraction ""
  ]
  node [
    id 16
    label "c2#network#450"
    type "network"
    nlp "C2"
    regex ""
    contraction ""
  ]
  node [
    id 17
    label "layers#network#499"
    type "network"
    nlp "several layers before"
    regex ""
    contraction ""
  ]
  node [
    id 18
    label "memory#network#513"
    type "network"
    nlp "memory"
    regex ""
    contraction ""
  ]
  node [
    id 19
    label "strike#file#542"
    type "file"
    nlp "Cobalt Strike"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 2
    action ""
    sequence 5
    nlp "The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for exploit, exploit and exploit."
  ]
  edge [
    source 0
    target 3
    action ""
    sequence 7
    nlp "The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for exploit, exploit and exploit."
  ]
  edge [
    source 0
    target 8
    action ""
    sequence 29
    nlp "Although it is common to use JScript or VBScript, as they are available in Windows by default, a scriptlet can contain COM+ objects implemented in other languages, including Perl and Python, which would be fully functional if the respective interpreters are installed."
  ]
  edge [
    source 0
    target 6
    action ""
    sequence 19
    nlp "A malicious INF file can be supplied as a parameter to download and execute remote code."
  ]
  edge [
    source 0
    target 1
    action ""
    sequence 0
    nlp "&#10;        All observed attacks start with an email message, containing either a malicious attachment or a URL which leads to the first stage of the attack."
  ]
  edge [
    source 0
    target 15
    action ""
    sequence 15
    nlp "The Microsoft Connection Manager Profile Installer (executable) is a command-line program used to install Connection Manager service profiles."
  ]
  edge [
    source 0
    target 12
    action ""
    sequence 22
    nlp "Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers."
  ]
  edge [
    source 2
    target 0
    action ""
    sequence 6
    nlp "The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for exploit, exploit and exploit."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 8
    nlp "The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for exploit, exploit and exploit."
  ]
  edge [
    source 7
    target 0
    action ""
    sequence 21
    nlp "Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 30
    nlp "Although it is common to use JScript or VBScript, as they are available in Windows by default, a scriptlet can contain COM+ objects implemented in other languages, including Perl and Python, which would be fully functional if the respective interpreters are installed."
  ]
  edge [
    source 9
    target 10
    action ""
    sequence 31
    nlp "Although it is common to use JScript or VBScript, as they are available in Windows by default, a scriptlet can contain COM+ objects implemented in other languages, including Perl and Python, which would be fully functional if the respective interpreters are installed."
  ]
  edge [
    source 11
    target 15
    action ""
    sequence 33
    nlp "&#10;        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters."
  ]
  edge [
    source 11
    target 12
    action ""
    sequence 43
    nlp "&#10;        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the executable utility."
  ]
  edge [
    source 12
    target 15
    action ""
    sequence 49
    nlp "&#10;        The PowerShell chain is launched from an obfuscated JScript scriptlet previously downloaded from the command and control (C2) server and launched using executable."
  ]
  edge [
    source 12
    target 7
    action ""
    sequence 23
    nlp "Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers."
  ]
  edge [
    source 12
    target 14
    action ""
    sequence 44
    nlp "&#10;        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the executable utility."
  ]
  edge [
    source 12
    target 11
    action ""
    sequence 42
    nlp "&#10;        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the executable utility."
  ]
  edge [
    source 13
    target 0
    action ""
    sequence 39
    nlp "&#10;        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters."
  ]
  edge [
    source 14
    target 0
    action ""
    sequence 45
    nlp "&#10;        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the executable utility."
  ]
  edge [
    source 15
    target 19
    action ""
    sequence 56
    nlp "&#10;        On the PowerShell side of the infection chain, the downloaded final payload is a Cobalt Strike beacon, which provides the attacker with rich backdoor functionality."
  ]
  edge [
    source 15
    target 11
    action ""
    sequence 32
    nlp "&#10;        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters."
  ]
  edge [
    source 15
    target 17
    action ""
    sequence 54
    nlp "The downloaded PowerShell script code is obfuscated in several layers before the last layer is reached."
  ]
  edge [
    source 15
    target 0
    action ""
    sequence 16
    nlp "The Microsoft Connection Manager Profile Installer (executable) is a command-line program used to install Connection Manager service profiles."
  ]
  edge [
    source 15
    target 12
    action ""
    sequence 48
    nlp "&#10;        The PowerShell chain is launched from an obfuscated JScript scriptlet previously downloaded from the command and control (C2) server and launched using executable."
  ]
  edge [
    source 15
    target 13
    action ""
    sequence 38
    nlp "&#10;        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters."
  ]
  edge [
    source 15
    target 5
    action ""
    sequence 13
    nlp "The final payload is a JScript backdoor also known as More_eggs that allows the attacker to control the affected system remotely."
  ]
  edge [
    source 15
    target 7
    action ""
    sequence 20
    nlp "Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers."
  ]
  edge [
    source 15
    target 16
    action ""
    sequence 50
    nlp "&#10;        The PowerShell chain is launched from an obfuscated JScript scriptlet previously downloaded from the command and control (C2) server and launched using executable."
  ]
  edge [
    source 18
    target 15
    action ""
    sequence 55
    nlp "The last layer loads shellcode into memory and creates a thread within the PowerShell interpreter process space."
  ]
  edge [
    source 19
    target 15
    action ""
    sequence 57
    nlp "&#10;        On the PowerShell side of the infection chain, the downloaded final payload is a Cobalt Strike beacon, which provides the attacker with rich backdoor functionality."
  ]
]
