graph [
  directed 1
  node [
    id 0
    label "tactics#file#3"
    type "file"
    nlp "tactics"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "screenshots#file#54"
    type "file"
    nlp "screenshots document"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "pages#network#99"
    type "network"
    nlp "phishing pages"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "email#network#107"
    type "network"
    nlp "email course"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "ip#executable#116"
    type "executable"
    nlp "IP"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "mx#file#120"
    type "file"
    nlp "MX"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "network#network#123"
    type "network"
    nlp "network"
    regex "gelirler.gov.tr"
    contraction ""
  ]
  node [
    id 7
    label "network#network#127"
    type "network"
    nlp "network"
    regex "212.133.164.130"
    contraction ""
  ]
  node [
    id 8
    label "records#file#131"
    type "file"
    nlp "SPF records"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "genelge#network#164"
    type "network"
    nlp "SAYILI GENELGE"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "macro#executable#198"
    type "executable"
    nlp "macro"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "loader#network#271"
    type "network"
    nlp "loader runtime URLMON"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "kernel32#file#309"
    type "file"
    nlp "kernel32"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "payload#executable#321"
    type "executable"
    nlp "payload"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "network#network#324"
    type "network"
    nlp "network"
    regex "hxxp://unifscon[.]com/R9_Sys.exe"
    contraction ""
  ]
  node [
    id 15
    label "contractor#executable#336"
    type "executable"
    nlp "contractor"
    regex ""
    contraction ""
  ]
  node [
    id 16
    label "change#network#359"
    type "network"
    nlp "IP resolution change C2 network"
    regex "civita2.no-ip.biz"
    contraction ""
  ]
  edge [
    source 0
    target 3
    action ""
    sequence 0
    nlp "The group used tactics that have become extremely useful for cyber spies&#8212;spear phishing emails that social engineer the victim to download an attached or embedded file and then enable macros."
  ]
  edge [
    source 1
    target 11
    action ""
    sequence 27
    nlp "This file is a small (3kb) loader, which downloads the second stage of the attack."
  ]
  edge [
    source 1
    target 3
    action ""
    sequence 2
    nlp "The group used tactics that have become extremely useful for cyber spies&#8212;spear phishing emails that social engineer the victim to download an attached or embedded file and then enable macros."
  ]
  edge [
    source 1
    target 10
    action ""
    sequence 23
    nlp "Opening the document shows a prevalent attack flow: Macros."
  ]
  edge [
    source 1
    target 9
    action ""
    sequence 20
    nlp "The attachment is an XLS document with the title &#8220;2017-94197 SAYILI GENELGE"
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 11
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 3
    target 5
    action ""
    sequence 15
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 3
    target 1
    action ""
    sequence 8
    nlp "These macros contain executable files that download a Remote Access Trojan (RAT), which can log keystrokes, take screenshots, record audio and video from a webcam or microphone, and install and uninstall programs and manage files."
  ]
  edge [
    source 3
    target 10
    action ""
    sequence 3
    nlp "The group used tactics that have become extremely useful for cyber spies&#8212;spear phishing emails that social engineer the victim to download an attached or embedded file and then enable macros."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 13
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 4
    target 3
    action ""
    sequence 14
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 16
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 17
    nlp "While it could, of course, be a fake website, it&#8217;s more likely a compromised host as it also contained phishing pages for the dating website Match.com: Normal email for the Gelirler domain would come from the IP specified in the MX record of network, which is network."
  ]
  edge [
    source 8
    target 2
    action ""
    sequence 18
    nlp "Their SPF records, which enforce this process, have been set to &#34;v=spf1 mx -all.&#8221;"
  ]
  edge [
    source 10
    target 1
    action ""
    sequence 4
    nlp "These macros contain executable files that download a Remote Access Trojan (RAT), which can log keystrokes, take screenshots, record audio and video from a webcam or microphone, and install and uninstall programs and manage files."
  ]
  edge [
    source 10
    target 3
    action ""
    sequence 7
    nlp "These macros contain executable files that download a Remote Access Trojan (RAT), which can log keystrokes, take screenshots, record audio and video from a webcam or microphone, and install and uninstall programs and manage files."
  ]
  edge [
    source 11
    target 12
    action ""
    sequence 30
    nlp "The loader has no imports, but at runtime, resolves the UrlDownloadToFile function from the URLMON library to download stage two, and then ShellExecute from kernel32 to run the downloaded stage two."
  ]
  edge [
    source 13
    target 14
    action ""
    sequence 31
    nlp "The stage-two payload downloads from network."
  ]
  edge [
    source 16
    target 3
    action ""
    sequence 35
    nlp "Then, a little while after sending out the spear phishing emails, we can see the IP resolution change with, most likely, IP addresses of compromised machines used for SOCKS5 proxying to hide the C2."
  ]
  edge [
    source 16
    target 15
    action ""
    sequence 33
    nlp "The C2 server configured for the attack on the defense contractor is network."
  ]
]
