graph [
  directed 1
  node [
    id 0
    label "scp#executable#3"
    type "executable"
    nlp "SCP"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "files#file#17"
    type "file"
    nlp "files"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "driver#system#25"
    type "system"
    nlp "driver"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "escalation#network#24"
    type "network"
    nlp "privilege escalation"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "passwd#system#62"
    type "system"
    nlp "passwd"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 1
    action ""
    sequence 4
    nlp "Connected to target using SSH with stolen credentials."
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 2
    nlp "Sent files to the target included the privilege escalation driver load_helper and an elevate client."
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 0
    nlp "Copied files via SCP and connected via SSH from the ta1-pivot-2 host."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 3
    nlp "Sent files to the target included the privilege escalation driver load_helper and an elevate client."
  ]
  edge [
    source 2
    target 0
    action ""
    sequence 5
    nlp "Loaded the driver, and used it to gain root privileges."
  ]
  edge [
    source 4
    target 1
    action ""
    sequence 6
    nlp "As root, exfil&#8217;d /etc/passwd, /etc/shadow, and the admin&#8217;s home directory Documents files."
  ]
]
