graph [
  directed 1
  node [
    id 0
    label "archive#network#3"
    type "network"
    nlp "archive"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "document#file#2"
    type "file"
    nlp "document"
    regex "Adobe_Flash_install.rar"
    contraction ""
  ]
  node [
    id 2
    label "network#network#9"
    type "network"
    nlp "network"
    regex "baomoivietnam.com"
    contraction ""
  ]
  node [
    id 3
    label "file#file#34"
    type "file"
    nlp "file"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "executable#executable#35"
    type "executable"
    nlp "executable"
    regex "goopdate.dll"
    contraction ""
  ]
  node [
    id 5
    label "systems#system#50"
    type "system"
    nlp "systems"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "loader#network#101"
    type "network"
    nlp "loader"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "stager#executable#111"
    type "executable"
    nlp "stager"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "strike#file#110"
    type "file"
    nlp "Cobalt Strike"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "shellcode#file#131"
    type "file"
    nlp "shellcode"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "network#network#145"
    type "network"
    nlp "network"
    regex "summerevent.webhop.net"
    contraction ""
  ]
  edge [
    source 0
    target 1
    action ""
    sequence 1
    nlp "&#10;        The document archive that was returned from the network website contained the files executable and executable."
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 2
    nlp "&#10;        The document archive that was returned from the network website contained the files executable and executable."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 4
    nlp "&#10;        The file executable has the hidden file attribute set and will not show in Windows Explorer on systems using default settings."
  ]
  edge [
    source 3
    target 5
    action ""
    sequence 7
    nlp "&#10;        The file executable has the hidden file attribute set and will not show in Windows Explorer on systems using default settings."
  ]
  edge [
    source 3
    target 0
    action ""
    sequence 0
    nlp "&#10;        The document archive that was returned from the network website contained the files executable and executable."
  ]
  edge [
    source 3
    target 6
    action ""
    sequence 9
    nlp "This results in the user seeing only the executable file to execute in order to install what they believe to be an update to Flash Player."
  ]
  edge [
    source 4
    target 3
    action ""
    sequence 5
    nlp "&#10;        The file executable has the hidden file attribute set and will not show in Windows Explorer on systems using default settings."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 8
    nlp "&#10;        The file executable has the hidden file attribute set and will not show in Windows Explorer on systems using default settings."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 10
    nlp "This results in the user seeing only the executable file to execute in order to install what they believe to be an update to Flash Player."
  ]
  edge [
    source 6
    target 10
    action ""
    sequence 17
    nlp "The Cobalt Strike stager will simply try to download and execute a shellcode from a remote server, in this case using the following URL: network/QuUA&#10;    "
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 12
    nlp "executable is a highly obfuscated loader whose ultimate purpose is to load a Cobalt Strike stager into memory and then execute it."
  ]
  edge [
    source 7
    target 9
    action ""
    sequence 15
    nlp "The Cobalt Strike stager will simply try to download and execute a shellcode from a remote server, in this case using the following URL: network/QuUA&#10;    "
  ]
  edge [
    source 8
    target 6
    action ""
    sequence 13
    nlp "executable is a highly obfuscated loader whose ultimate purpose is to load a Cobalt Strike stager into memory and then execute it."
  ]
  edge [
    source 9
    target 6
    action ""
    sequence 16
    nlp "The Cobalt Strike stager will simply try to download and execute a shellcode from a remote server, in this case using the following URL: network/QuUA&#10;    "
  ]
]
