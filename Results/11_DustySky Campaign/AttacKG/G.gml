graph [
  directed 1
  node [
    id 0
    label "attackers#executable#1"
    type "executable"
    nlp "attackers"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "files#file#83"
    type "file"
    nlp "files ZIP"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "macro#executable#88"
    type "executable"
    nlp "macro"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "engineering#network#107"
    type "network"
    nlp "social engineering -"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "email#network#138"
    type "network"
    nlp "email"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "diplomacy#network#160"
    type "network"
    nlp "diplomacy"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "politics#executable#165"
    type "executable"
    nlp "politics"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "message#file#235"
    type "file"
    nlp "message"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "server#network#263"
    type "network"
    nlp "server network"
    regex "copy.com"
    contraction ""
  ]
  node [
    id 9
    label "software#file#319"
    type "file"
    nlp "iMazing software"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "version#file#340"
    type "file"
    nlp "version ( file"
    regex "2f452e90c2f9b914543847ba2b431b9a"
    contraction ""
  ]
  node [
    id 11
    label "imazing#executable#346"
    type "executable"
    nlp "iMazing"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "dustysky#executable#354"
    type "executable"
    nlp "DustySky"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "network#network#383"
    type "network"
    nlp "network"
    regex "ns.suppoit[.]xyz"
    contraction ""
  ]
  node [
    id 14
    label "network#network#393"
    type "network"
    nlp "network"
    regex "45.32.13.169"
    contraction ""
  ]
  node [
    id 15
    label "command#executable#375"
    type "executable"
    nlp "command"
    regex ""
    contraction ""
  ]
  node [
    id 16
    label "network#network#385"
    type "network"
    nlp "network"
    regex "supo.mefound[.]com"
    contraction ""
  ]
  edge [
    source 0
    target 7
    action ""
    sequence 17
    nlp "When linked from the malicious message, the malware would be hosted either on a cloud service (many times in network, a legitimate file hosting service), or on a server controlled by the attackers."
  ]
  edge [
    source 0
    target 4
    action ""
    sequence 0
    nlp "The attackers would usually send a malicious email message that either links to an archive file (RAR or ZIP compressed) or has one attached to it."
  ]
  edge [
    source 0
    target 12
    action ""
    sequence 26
    nlp "However, the version on the fake website is bundled with DustySky malware."
  ]
  edge [
    source 1
    target 3
    action ""
    sequence 12
    nlp "Note, that these infection methods rely on social engineering - convincing the victim to open the file (and enabling content if it is disabled) - and not on software vulnerabilities."
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 16
    nlp "The content of the lure document is always copied from a public news item or other web content, and is never an original composition of the attackers."
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 10
    nlp "In recent samples the group used Microsoft Word files embed with a malicious macro, which would infect the victim if enabled."
  ]
  edge [
    source 1
    target 5
    action ""
    sequence 14
    nlp "The subject line of the malicious email message, as well as the name and content of the lure document, are usually related to recent events in diplomacy, defense, and politics."
  ]
  edge [
    source 1
    target 12
    action ""
    sequence 7
    nlp "If the victim extracts the archive and clicks the .exe file, the lure document or video are presented while the computer is being infected with DustySky."
  ]
  edge [
    source 4
    target 1
    action ""
    sequence 13
    nlp "The subject line of the malicious email message, as well as the name and content of the lure document, are usually related to recent events in diplomacy, defense, and politics."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 15
    nlp "The subject line of the malicious email message, as well as the name and content of the lure document, are usually related to recent events in diplomacy, defense, and politics."
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 18
    nlp "When linked from the malicious message, the malware would be hosted either on a cloud service (many times in network, a legitimate file hosting service), or on a server controlled by the attackers."
  ]
  edge [
    source 8
    target 1
    action ""
    sequence 20
    nlp "When linked from the malicious message, the malware would be hosted either on a cloud service (many times in network, a legitimate file hosting service), or on a server controlled by the attackers."
  ]
  edge [
    source 10
    target 11
    action ""
    sequence 28
    nlp "Upon execution of the malicious version (file) the legitimate iMazing is installed, while in the background DustySky is dropped as a file named executable (file), and executed."
  ]
  edge [
    source 11
    target 12
    action ""
    sequence 29
    nlp "Upon execution of the malicious version (file) the legitimate iMazing is installed, while in the background DustySky is dropped as a file named executable (file), and executed."
  ]
  edge [
    source 12
    target 1
    action ""
    sequence 8
    nlp "If the victim extracts the archive and clicks the .exe file, the lure document or video are presented while the computer is being infected with DustySky."
  ]
  edge [
    source 13
    target 14
    action ""
    sequence 32
    nlp "executable immediately starts communicating with its command and control sever using the hardcoded address network and network, both also pointing to above mentioned network."
  ]
  edge [
    source 14
    target 15
    action ""
    sequence 33
    nlp "executable immediately starts communicating with its command and control sever using the hardcoded address network and network, both also pointing to above mentioned network."
  ]
  edge [
    source 14
    target 1
    action ""
    sequence 23
    nlp "IP address network and all the domains that are pointing to it8 host a webpage which is a copy of a legitimate and unrelated software website - iMazing, an iOS management software."
  ]
  edge [
    source 15
    target 16
    action ""
    sequence 34
    nlp "executable immediately starts communicating with its command and control sever using the hardcoded address network and network, both also pointing to above mentioned network."
  ]
  edge [
    source 16
    target 12
    action ""
    sequence 35
    nlp "executable immediately starts communicating with its command and control sever using the hardcoded address network and network, both also pointing to above mentioned network."
  ]
]
