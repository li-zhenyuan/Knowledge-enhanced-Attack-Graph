graph [
  directed 1
  node [
    id 0
    label "hosts#network#25"
    type "network"
    nlp "hosts"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "network#network#32"
    type "network"
    nlp "network"
    regex "http://215.237.119.171/config.html"
    contraction ""
  ]
  node [
    id 2
    label "network#network#46"
    type "network"
    nlp "network"
    regex "http://68.149.51.179/ctfhost2.exe"
    contraction ""
  ]
  node [
    id 3
    label "bits#executable#42"
    type "executable"
    nlp "BITS Micro"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "file#file#75"
    type "file"
    nlp "file"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "apt#file#88"
    type "file"
    nlp "Micro APT"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "c2#network#100"
    type "network"
    nlp "C2"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "attacker#executable#104"
    type "executable"
    nlp "attacker"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "enforcement#executable#130"
    type "executable"
    nlp "enforcement"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "driver#system#160"
    type "system"
    nlp "driver"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 3
    action ""
    sequence 0
    nlp "The activity was modified so the hosts would open Firefox and browse to network."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 2
    nlp "The simulated host then entered URL for BITS Micro APT as network."
  ]
  edge [
    source 3
    target 1
    action ""
    sequence 1
    nlp "The activity was modified so the hosts would open Firefox and browse to network."
  ]
  edge [
    source 4
    target 5
    action ""
    sequence 3
    nlp "Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to network:80 for C2."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 4
    nlp "Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to network:80 for C2."
  ]
  edge [
    source 5
    target 9
    action ""
    sequence 6
    nlp "The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement."
  ]
  edge [
    source 7
    target 5
    action ""
    sequence 5
    nlp "The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 10
    nlp " BBN tried using BCDedit to permanently disable driver signing, but it did not seem to work during the engagement as the drivers failed to work unless driver signing was explicitly disabled during boot."
  ]
  edge [
    source 9
    target 8
    action ""
    sequence 7
    nlp "The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement."
  ]
]
