graph [
  directed 1
  node [
    id 0
    label "apt#file#16"
    type "file"
    nlp "Drakon APT"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "attacker#executable#30"
    type "executable"
    nlp "attacker"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "post#executable#45"
    type "executable"
    nlp "HTTP POST"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "network#network#49"
    type "network"
    nlp "network"
    regex "128.55.12.167"
    contraction ""
  ]
  node [
    id 4
    label "succession#network#95"
    type "network"
    nlp "succession"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "exploits#vulnerability#110"
    type "vulnerability"
    nlp "exploits"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "nginx#executable#111"
    type "executable"
    nlp "Nginx"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "cadets#file#108"
    type "file"
    nlp "CADETS"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "http#network#131"
    type "network"
    nlp "HTTP"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "commands#executable#151"
    type "executable"
    nlp "commands"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "passwd#system#169"
    type "system"
    nlp "passwd"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 8
    action ""
    sequence 1
    nlp "The attacker first tried to attack from an outside host, using network:80 to download Drakon APT and network:80 for C2."
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 0
    nlp "The attacker first tried to attack from an outside host, using network:80 to download Drakon APT and network:80 for C2."
  ]
  edge [
    source 1
    target 8
    action ""
    sequence 3
    nlp "That failed, though, so the attacker switched to ta1-pivot-2 for the attack C2."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 5
    nlp "The malformed HTTP POST was sent from network and resulted in C2 to network:80."
  ]
  edge [
    source 3
    target 8
    action ""
    sequence 6
    nlp "The malformed HTTP POST was sent from network and resulted in C2 to network:80."
  ]
  edge [
    source 4
    target 0
    action ""
    sequence 9
    nlp "The CADETS hosts were both attacked in succession using the Nginx Drakon APT simulacrum."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 10
    nlp "For the attack against CADETS the exploits Nginx by simulation of remote code execution on the listening port of the webserver TCP 80."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 11
    nlp "For the attack against CADETS the exploits Nginx by simulation of remote code execution on the listening port of the webserver TCP 80."
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 12
    nlp "For the attack against CADETS the exploits Nginx by simulation of remote code execution on the listening port of the webserver TCP 80."
  ]
  edge [
    source 7
    target 4
    action ""
    sequence 8
    nlp "The CADETS hosts were both attacked in succession using the Nginx Drakon APT simulacrum."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 13
    nlp "The callback is established to C2 and the following commands are sent to gather intellignece on the host environment: hostname, whoami, cat /etc/passwd, whoami, and hostname."
  ]
  edge [
    source 9
    target 10
    action ""
    sequence 14
    nlp "The callback is established to C2 and the following commands are sent to gather intellignece on the host environment: hostname, whoami, cat /etc/passwd, whoami, and hostname."
  ]
]
