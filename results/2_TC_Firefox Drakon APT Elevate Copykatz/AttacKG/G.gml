graph [
  directed 1
  node [
    id 0
    label "network#network#19"
    type "network"
    nlp "network"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "exploited#vulnerability#22"
    type "vulnerability"
    nlp "Exploited"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "firefox#executable#37"
    type "executable"
    nlp "Firefox"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "network:443#network#45"
    type "network"
    nlp "network:443"
    regex "128.55.12.233"
    contraction ""
  ]
  node [
    id 4
    label "signing#network#56"
    type "network"
    nlp "signing"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "reboot#file#53"
    type "file"
    nlp "BBN reboot"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "driver#system#55"
    type "system"
    nlp "driver"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "module#executable#80"
    type "executable"
    nlp "module"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "c2#network#95"
    type "network"
    nlp "C2"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "system#system#87"
    type "system"
    nlp "system"
    regex ""
    contraction ""
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 1
    nlp " Exploited Firefox backdoor by again browsing to http://network."
  ]
  edge [
    source 2
    target 1
    action ""
    sequence 0
    nlp " Exploited Firefox backdoor by again browsing to http://network."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 3
    nlp "Loader Drakon was executed in Firefox memory and connected out to network:8000 and network:443 for C2."
  ]
  edge [
    source 3
    target 8
    action ""
    sequence 4
    nlp "Loader Drakon was executed in Firefox memory and connected out to network:8000 and network:443 for C2."
  ]
  edge [
    source 4
    target 5
    action ""
    sequence 6
    nlp "After the BBN reboot, driver signing was disabled, and we would now be able to use privilege escalation via our perfmon driver.  "
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 7
    nlp "After the BBN reboot, driver signing was disabled, and we would now be able to use privilege escalation via our perfmon driver.  "
  ]
  edge [
    source 7
    target 8
    action ""
    sequence 9
    nlp "We loaded the copykatz module planning to recon data from the system; however, an error in our C2 resulted in loss of connection and a premature end to the test."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 10
    nlp "We loaded the copykatz module planning to recon data from the system; however, an error in our C2 resulted in loss of connection and a premature end to the test."
  ]
  edge [
    source 8
    target 3
    action ""
    sequence 5
    nlp "Loader Drakon was executed in Firefox memory and connected out to network:8000 and network:443 for C2."
  ]
]
