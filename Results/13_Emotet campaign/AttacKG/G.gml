graph [
  directed 1
  node [
    id 0
    label "email#network#12"
    type "network"
    nlp "email"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "office#file#60"
    type "file"
    nlp "Office 365"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "payload#executable#117"
    type "executable"
    nlp "payload script"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "success#network#164"
    type "network"
    nlp "success"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "c&#38;c#network#167"
    type "network"
    nlp "C&#38;C"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "infection#executable#174"
    type "executable"
    nlp "infection"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "network#network#227"
    type "network"
    nlp "network"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "credentials#file#221"
    type "file"
    nlp "credentials"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 1
    action ""
    sequence 2
    nlp "As we might expect, if the user decides to download the email attachment and open the document, it asks them to enable the macros."
  ]
  edge [
    source 1
    target 1
    action ""
    sequence 0
    nlp "As we might expect, if the user decides to download the email attachment and open the document, it asks them to enable the macros."
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 1
    nlp "As we might expect, if the user decides to download the email attachment and open the document, it asks them to enable the macros."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 12
    nlp "As we have discussed in previous posts (for example, in this post from November 9), once the payload is executed, it establishes persistence on the computer and reports its success to its C&#38;C server."
  ]
  edge [
    source 2
    target 2
    action ""
    sequence 14
    nlp "As we have discussed in previous posts (for example, in this post from November 9), once the payload is executed, it establishes persistence on the computer and reports its success to its C&#38;C server."
  ]
  edge [
    source 2
    target 4
    action ""
    sequence 15
    nlp "As we have discussed in previous posts (for example, in this post from November 9), once the payload is executed, it establishes persistence on the computer and reports its success to its C&#38;C server."
  ]
  edge [
    source 2
    target 7
    action ""
    sequence 18
    nlp "The various additional modules extend the range of malicious activities that can compromise the user&#8217;s device, in order to steal credentials, propagate itself on the network, harvest sensitive information, carry out port forwarding, and many other possibilities."
  ]
  edge [
    source 3
    target 2
    action ""
    sequence 13
    nlp "As we have discussed in previous posts (for example, in this post from November 9), once the payload is executed, it establishes persistence on the computer and reports its success to its C&#38;C server."
  ]
  edge [
    source 5
    target 2
    action ""
    sequence 16
    nlp "Having completed this initial infection, further downloads can occur, installing attack modules and secondary payloads which carry out other kinds of actions on the compromised computer."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 22
    nlp "The various additional modules extend the range of malicious activities that can compromise the user&#8217;s device, in order to steal credentials, propagate itself on the network, harvest sensitive information, carry out port forwarding, and many other possibilities."
  ]
  edge [
    source 7
    target 6
    action ""
    sequence 21
    nlp "The various additional modules extend the range of malicious activities that can compromise the user&#8217;s device, in order to steal credentials, propagate itself on the network, harvest sensitive information, carry out port forwarding, and many other possibilities."
  ]
]
