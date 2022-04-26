graph [
  directed 1
  node [
    id 0
    label "task#system#2"
    type "system"
    nlp "task"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "command#executable#30"
    type "executable"
    nlp "command"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "%#file#44"
    type "file"
    nlp "Install %"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "%#file#92"
    type "file"
    nlp "%"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "registry#registry#96"
    type "registry"
    nlp "registry"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "shdocvw.tlp#executable#104"
    type "executable"
    nlp "shdocvw.tlp COMpfun"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "system#system#142"
    type "system"
    nlp "system"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "btz#executable#182"
    type "executable"
    nlp "BTZ"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "communication#file#241"
    type "file"
    nlp "communication"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "tool#network#235"
    type "network"
    nlp "Remote Administration Tool ("
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "server#executable#247"
    type "executable"
    nlp "server"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "order#file#259"
    type "file"
    nlp "order"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "products#network#274"
    type "network"
    nlp "security products"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 11
    action ""
    sequence 0
    nlp "The first task of the malware is to install the file credprov.tlb in %APPDATA%\Microsoft\. This file is the main payload of the malware."
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 7
    nlp "The dropper executes the following command in order to install a second file: executable %APPDATA%\Microsoft\credprov.tlb,Install %APPDATA%\Microsoft\shdocvw.tlp."
  ]
  edge [
    source 1
    target 11
    action ""
    sequence 22
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 1
    target 4
    action ""
    sequence 12
    nlp "To be started during the boot process of the infected machine, the malware creates the following registry key: registry\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32 = %"
  ]
  edge [
    source 2
    target 11
    action ""
    sequence 8
    nlp "The dropper executes the following command in order to install a second file: executable %APPDATA%\Microsoft\credprov.tlb,Install %APPDATA%\Microsoft\shdocvw.tlp."
  ]
  edge [
    source 4
    target 5
    action ""
    sequence 14
    nlp "This registry key is used to associate the library shdocvw.tlp to the object 42aedc87-2188-41fd-b9a3-0c966feabec1 as previously explained in the article about COMpfun."
  ]
  edge [
    source 4
    target 3
    action ""
    sequence 13
    nlp "To be started during the boot process of the infected machine, the malware creates the following registry key: registry\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32 = %"
  ]
  edge [
    source 6
    target 12
    action ""
    sequence 24
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 18
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 9
    target 10
    action ""
    sequence 19
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 10
    target 11
    action ""
    sequence 20
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 11
    target 1
    action ""
    sequence 21
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
  edge [
    source 11
    target 6
    action ""
    sequence 23
    nlp "Its features are common for a Remote Administration Tool (RAT): ComRAT&#8217;s communication to the command and control server is performed by the browser process and not by executable in order to avoid being blocked by a firewall on the system or any additional security products."
  ]
]
