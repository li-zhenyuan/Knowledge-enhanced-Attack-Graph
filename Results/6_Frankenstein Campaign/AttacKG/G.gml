graph [
  directed 1
  node [
    id 0
    label "email#network#19"
    type "network"
    nlp "email"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "vector#network#43"
    type "network"
    nlp "second vector"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "document#file#92"
    type "file"
    nlp "document"
    regex "luncher.doc"
    contraction ""
  ]
  node [
    id 3
    label "scenario#network#87"
    type "network"
    nlp "first scenario"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "document#file#95"
    type "file"
    nlp "document"
    regex "MinutesofMeeting-2May19.docx"
    contraction ""
  ]
  node [
    id 5
    label "network#network#127"
    type "network"
    nlp "network"
    regex "hxxp://droobox[.]online:80/luncher.doc"
    contraction ""
  ]
  node [
    id 6
    label "exploit#vulnerability#137"
    type "vulnerability"
    nlp "exploit"
    regex "CVE-2017-11882"
    contraction ""
  ]
  node [
    id 7
    label "exploit#vulnerability#150"
    type "vulnerability"
    nlp "exploit"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "wmi#file#246"
    type "file"
    nlp "WMI"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "task#system#315"
    type "system"
    nlp "task"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "msbuild#file#311"
    type "file"
    nlp "MSBuild-"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "year#network#325"
    type "network"
    nlp "last year"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "code#file#368"
    type "file"
    nlp "arbitrary code"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "stager#executable#408"
    type "executable"
    nlp "stager MSBuild"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "functionality#network#437"
    type "network"
    nlp "functionality"
    regex ""
    contraction ""
  ]
  node [
    id 15
    label "empire#file#495"
    type "file"
    nlp "PowerShell Empire"
    regex ""
    contraction ""
  ]
  edge [
    source 0
    target 13
    action ""
    sequence 3
    nlp "In order to compromise their victims, the threat actors sent the trojanized Microsoft Word documents, probably via email."
  ]
  edge [
    source 1
    target 12
    action ""
    sequence 5
    nlp "The second vector is a trojanized Word document that prompts the victim to enable macros and run a Visual Basic script."
  ]
  edge [
    source 2
    target 3
    action ""
    sequence 11
    nlp "In the first scenario, Talos discovered a document named &#34;document&#34;, that appeared to display the national flag of Jordan."
  ]
  edge [
    source 2
    target 5
    action ""
    sequence 17
    nlp "Once the victim opens the document, it fetches a remove template from the actor-controlled website, network."
  ]
  edge [
    source 2
    target 6
    action ""
    sequence 19
    nlp "Once the document was downloaded, it used exploit, to execute code on the victim's machine."
  ]
  edge [
    source 2
    target 12
    action ""
    sequence 14
    nlp "Once the victim opens the document, it fetches a remove template from the actor-controlled website, network."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 12
    nlp "In the first scenario, Talos discovered a document named &#34;document&#34;, that appeared to display the national flag of Jordan."
  ]
  edge [
    source 4
    target 13
    action ""
    sequence 13
    nlp "In the first scenario, Talos discovered a document named &#34;document&#34;, that appeared to display the national flag of Jordan."
  ]
  edge [
    source 5
    target 13
    action ""
    sequence 18
    nlp "Once the victim opens the document, it fetches a remove template from the actor-controlled website, network."
  ]
  edge [
    source 6
    target 2
    action ""
    sequence 20
    nlp "Once the document was downloaded, it used exploit, to execute code on the victim's machine."
  ]
  edge [
    source 7
    target 13
    action ""
    sequence 24
    nlp "After the exploit, the file would run a command script to set up persistence as a scheduled task named &#34;WinUpdate&#34;."
  ]
  edge [
    source 9
    target 10
    action ""
    sequence 41
    nlp "Based on lexical analysis, we assess with high confidence that this component of the macro script was based on an open-source project called &#34;MSBuild-inline-task."
  ]
  edge [
    source 9
    target 12
    action ""
    sequence 26
    nlp "After the exploit, the file would run a command script to set up persistence as a scheduled task named &#34;WinUpdate&#34;."
  ]
  edge [
    source 9
    target 13
    action ""
    sequence 27
    nlp "That scheduled task would run a series of base64-encoded PowerShell commands that acted as a stager."
  ]
  edge [
    source 12
    target 13
    action ""
    sequence 6
    nlp "The second vector is a trojanized Word document that prompts the victim to enable macros and run a Visual Basic script."
  ]
  edge [
    source 12
    target 0
    action ""
    sequence 2
    nlp "In order to compromise their victims, the threat actors sent the trojanized Microsoft Word documents, probably via email."
  ]
  edge [
    source 12
    target 2
    action ""
    sequence 16
    nlp "Once the victim opens the document, it fetches a remove template from the actor-controlled website, network."
  ]
  edge [
    source 12
    target 7
    action ""
    sequence 4
    nlp "The first vector relies on a trojanized document that fetches a remote template and then uses a known exploit."
  ]
  edge [
    source 13
    target 7
    action ""
    sequence 23
    nlp "After the exploit, the file would run a command script to set up persistence as a scheduled task named &#34;WinUpdate&#34;."
  ]
  edge [
    source 13
    target 2
    action ""
    sequence 10
    nlp "In the first scenario, Talos discovered a document named &#34;document&#34;, that appeared to display the national flag of Jordan."
  ]
  edge [
    source 13
    target 14
    action ""
    sequence 60
    nlp "In this sample, the threat actors' C2 server was the domain msdn[.]cloud."
  ]
  edge [
    source 13
    target 12
    action ""
    sequence 38
    nlp "&#10;        Once the evasion checks were complete, the threat actors used MSbuild to execute an actor-created file named &#34;LOCALAPPDATA\Intel\instal.xml&#34;."
  ]
  edge [
    source 13
    target 9
    action ""
    sequence 25
    nlp "After the exploit, the file would run a command script to set up persistence as a scheduled task named &#34;WinUpdate&#34;."
  ]
  edge [
    source 13
    target 3
    action ""
    sequence 8
    nlp "The second vector is a trojanized Word document that prompts the victim to enable macros and run a Visual Basic script."
  ]
  edge [
    source 13
    target 8
    action ""
    sequence 36
    nlp "First, it would query Windows Management Instrumentation (WMI) to check if any of the following applications were running."
  ]
  edge [
    source 14
    target 13
    action ""
    sequence 9
    nlp "We were able to correlate these two techniques to the same threat campaign due to overlapping threat actor C2."
  ]
  edge [
    source 14
    target 15
    action ""
    sequence 62
    nlp "Once the string was RC4 decrypted, it launched a PowerShell Empire agent."
  ]
]
