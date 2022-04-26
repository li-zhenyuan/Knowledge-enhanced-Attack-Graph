graph [
  directed 1
  node [
    id 0
    label "network#network#6"
    type "network"
    nlp "network"
    regex "http://128.55.12.167:8641/config.html"
    contraction ""
  ]
  node [
    id 1
    label "firefox#executable#28"
    type "executable"
    nlp "Firefox"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "dns#network#34"
    type "network"
    nlp "DNS"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "network:8640#network#48"
    type "network"
    nlp "network:8640 C2"
    regex "128.55.12.167"
    contraction ""
  ]
  node [
    id 4
    label "attacker#executable#54"
    type "executable"
    nlp "attacker"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "driver#system#63"
    type "system"
    nlp "Driver"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "file#file#97"
    type "file"
    nlp "file"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "passwd#system#96"
    type "system"
    nlp "passwd"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "network#network#90"
    type "network"
    nlp "network"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 2
    action ""
    sequence 0
    nlp "The attack started by browsing to network, selecting DNS, entering hostname Xxnetwork, file 938527054, and clicking the Visit button."
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 2
    nlp "This triggered the Firefox backdoor to connect out via DNS to XXnetwork.  "
  ]
  edge [
    source 2
    target 8
    action ""
    sequence 3
    nlp "This triggered the Firefox backdoor to connect out via DNS to XXnetwork.  "
  ]
  edge [
    source 4
    target 5
    action ""
    sequence 6
    nlp "The attacker escalated privileges using the new File System Filter Driver, which looks for processes opening specific files which don&#8217;t exist and elevates them."
  ]
  edge [
    source 4
    target 6
    action ""
    sequence 12
    nlp "Once SYSTEM, the attacker exfil&#8217;ed the host and network files as well as a passwd file in the home directory."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 8
    nlp "The attacker escalated privileges using the new File System Filter Driver, which looks for processes opening specific files which don&#8217;t exist and elevates them."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 14
    nlp "Once SYSTEM, the attacker exfil&#8217;ed the host and network files as well as a passwd file in the home directory."
  ]
  edge [
    source 6
    target 6
    action ""
    sequence 10
    nlp "The attacker escalated privileges using the new File System Filter Driver, which looks for processes opening specific files which don&#8217;t exist and elevates them."
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 15
    nlp "Once SYSTEM, the attacker exfil&#8217;ed the host and network files as well as a passwd file in the home directory."
  ]
]
