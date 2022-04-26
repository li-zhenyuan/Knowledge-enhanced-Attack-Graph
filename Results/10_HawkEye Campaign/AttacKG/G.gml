graph [
  directed 1
  node [
    id 0
    label "system#system#58"
    type "system"
    nlp "system"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "url#file#67"
    type "file"
    nlp "URL FTP service"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "network#network#104"
    type "network"
    nlp "network"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "malware#executable#116"
    type "executable"
    nlp "malware"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "process#network#159"
    type "network"
    nlp "process"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "registration#executable#180"
    type "executable"
    nlp "Assembly Registration"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "tasks#system#273"
    type "system"
    nlp "tasks"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "email#network#288"
    type "network"
    nlp "email link"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "apis#file#304"
    type "file"
    nlp "APIs"
    regex ""
    contraction ""
  ]
  node [
    id 9
    label "setclipboardviewer#file#310"
    type "file"
    nlp "SetClipboardViewer"
    regex ""
    contraction ""
  ]
  node [
    id 10
    label "point#executable#452"
    type "executable"
    nlp "point"
    regex ""
    contraction ""
  ]
  node [
    id 11
    label "api#file#593"
    type "file"
    nlp "CreateProcess API"
    regex ""
    contraction ""
  ]
  node [
    id 12
    label "mpbe3d.tmp#executable#634"
    type "executable"
    nlp "mpBE3D.tmp"
    regex ""
    contraction ""
  ]
  node [
    id 13
    label "safari#executable#723"
    type "executable"
    nlp "Apple Safari"
    regex ""
    contraction ""
  ]
  node [
    id 14
    label "command#executable#787"
    type "executable"
    nlp "command"
    regex ""
    contraction ""
  ]
  node [
    id 15
    label "executable&#8221;collects#executable#836"
    type "executable"
    nlp "executable&#8221;collects"
    regex "vbc.exe"
    contraction ""
  ]
  node [
    id 16
    label "im#file#845"
    type "file"
    nlp "IM &#10;    "
    regex ""
    contraction ""
  ]
  node [
    id 17
    label "password#file#921"
    type "file"
    nlp "Password Server address"
    regex ""
    contraction ""
  ]
  node [
    id 18
    label "ollydbg#executable#998"
    type "executable"
    nlp "Ollydbg"
    regex ""
    contraction ""
  ]
  node [
    id 19
    label "file#file#1016"
    type "file"
    nlp "file IM"
    regex ""
    contraction ""
  ]
  node [
    id 20
    label "network#network#1113"
    type "network"
    nlp "network"
    regex "http://bot.whatismyipaddress.com"
    contraction ""
  ]
  node [
    id 21
    label "ip#executable#1151"
    type "executable"
    nlp "IP"
    regex ""
    contraction ""
  ]
  node [
    id 22
    label "addition#file#1165"
    type "file"
    nlp "addition IP"
    regex ""
    contraction ""
  ]
  node [
    id 23
    label "yandex.mail#file#1187"
    type "file"
    nlp "Yandex.mail"
    regex ""
    contraction ""
  ]
  node [
    id 24
    label "attacker#executable#1181"
    type "executable"
    nlp "attacker"
    regex ""
    contraction ""
  ]
  edge [
    source 1
    target 2
    action ""
    sequence 4
    nlp "It &#10;    turned out to be an FTP service, containing several related network folders about this campaign, &#10;    with most containing the same malware sample (Figure 2)."
  ]
  edge [
    source 2
    target 19
    action ""
    sequence 5
    nlp "It &#10;    turned out to be an FTP service, containing several related network folders about this campaign, &#10;    with most containing the same malware sample (Figure 2)."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 10
    nlp "Once HawkEye started, it spawned a suspended child process, &#8220;executable&#8221;, from the Microsoft .Net"
  ]
  edge [
    source 3
    target 19
    action ""
    sequence 57
    nlp "Figure 6 shows some strings defined in the ASM code of the browsers that the HawkEye &#10;    malware wants to collect credentials from."
  ]
  edge [
    source 3
    target 3
    action ""
    sequence 33
    nlp "It&#8217;s a trick that malware often performs to camouflage itself behind of a &#10;    normal process."
  ]
  edge [
    source 3
    target 14
    action ""
    sequence 62
    nlp "The collected credentials are then saved into the tmp file from its &#10;    command line parameter."
  ]
  edge [
    source 3
    target 13
    action ""
    sequence 50
    nlp "In my analysis, this variant of &#10;    HawkEye focuses on the following browsers: Microsoft Internet Explorer, Google Chrome, Apple Safari, Opera, &#10;    Mozilla Sunbird, Mozilla Firefox, Mozilla Portable Thunderbird, Mozilla SeaMonkey, YandexBrowser, &#10;    Vivaldi browser, and more."
  ]
  edge [
    source 3
    target 11
    action ""
    sequence 43
    nlp "Figure 5 shows HawkEye calling the CreateProcess API to start one of &#10;    the two &#8220;executable&#8221; processes, with the parameter shown below in the &#8220;Locals&#8221; sub-tab."
  ]
  edge [
    source 4
    target 3
    action ""
    sequence 11
    nlp "Once HawkEye started, it spawned a suspended child process, &#8220;executable&#8221;, from the Microsoft .Net"
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 19
    nlp "HawkEye_RegAsm starts a thread to perform the above &#10;    tasks, and then every 10 minutes it sends its collected information to its Yandex email address."
  ]
  edge [
    source 6
    target 19
    action ""
    sequence 88
    nlp "Now let&#8217;s go back to the main process of &#10;    HawkEye_RegAsm, which controls all tasks of HawkEye and sends the victim&#8217;s credentials."
  ]
  edge [
    source 7
    target 23
    action ""
    sequence 95
    nlp "The attacker&#8217;s email &#10;    is in Yandex.mail, whose email account and password are used when sending collected data through the Yandex SMTP &#10;    server."
  ]
  edge [
    source 7
    target 16
    action ""
    sequence 70
    nlp "The second PE file in &#8220;executable&#8221;collects profile and credential information of the email and IM &#10;    software client installed on a victim&#8217;s machine."
  ]
  edge [
    source 7
    target 19
    action ""
    sequence 37
    nlp "The other one focuses on email clients and IM clients to steal credentials and &#10;    profiles."
  ]
  edge [
    source 7
    target 13
    action ""
    sequence 21
    nlp "HawkEye_RegAsm starts a thread to perform the above &#10;    tasks, and then every 10 minutes it sends its collected information to its Yandex email address."
  ]
  edge [
    source 8
    target 9
    action ""
    sequence 23
    nlp "HawkEye_RegAsm &#10;    sets up a clipboard and keyboard logger using Windows-native APIs (such as SetWindowsHookEx, SetClipboardViewer, &#10;    etc.)"
  ]
  edge [
    source 9
    target 8
    action ""
    sequence 22
    nlp "HawkEye_RegAsm &#10;    sets up a clipboard and keyboard logger using Windows-native APIs (such as SetWindowsHookEx, SetClipboardViewer, &#10;    etc.)"
  ]
  edge [
    source 10
    target 19
    action ""
    sequence 30
    nlp "It also modifies its ThreadContext &#10;    data (It calls the API, SetThreadContext) and makes its entry point to the transfered PE file."
  ]
  edge [
    source 13
    target 19
    action ""
    sequence 73
    nlp "The clients it targets are: Qualcomm Eudora, &#10;    Mozilla Thunderbird, MS Office Outlook, IncrediMail, Groupmail, MSNMessenger, Yahoo!Pager/Yahoo!Messenger and &#10;    Windows Mail."
  ]
  edge [
    source 13
    target 17
    action ""
    sequence 85
    nlp "The second PE file in &#8220;executable&#8221; not only collects the client&#8217;s login &#10;    username and password, but also profile information, such as the recipent Server address, recipient Server Port, &#10;    protocol Type (POP3), SMTP Server, SMTP Port, etc."
  ]
  edge [
    source 15
    target 19
    action ""
    sequence 68
    nlp "The second PE file in &#8220;executable&#8221;collects profile and credential information of the email and IM &#10;    software client installed on a victim&#8217;s machine."
  ]
  edge [
    source 17
    target 19
    action ""
    sequence 81
    nlp "As you can &#10;    see, it includes login URL, Browser name, User name, Password, Created time, and the full path of the file where &#10;    the collected information came from."
  ]
  edge [
    source 17
    target 13
    action ""
    sequence 84
    nlp "The second PE file in &#8220;executable&#8221; not only collects the client&#8217;s login &#10;    username and password, but also profile information, such as the recipent Server address, recipient Server Port, &#10;    protocol Type (POP3), SMTP Server, SMTP Port, etc."
  ]
  edge [
    source 18
    target 19
    action ""
    sequence 86
    nlp "Figure 7 shows a screenshot of Ollydbg when &#8220;executable&#8221; was &#10;    about to write the collected recipient Server addresses into its tmp file."
  ]
  edge [
    source 19
    target 19
    action ""
    sequence 66
    nlp "HawkEye_RegAsm then reads the entire data of this tmp file into its memory and the deletes it &#10;    immediately."
  ]
  edge [
    source 19
    target 3
    action ""
    sequence 9
    nlp "After the downloaded 7z file was decompressed, &#10;    we retrieved the EXE file &#8220;TICKET%executable&#8221;, which is the new variant of &#10;    HawkEye."
  ]
  edge [
    source 19
    target 0
    action ""
    sequence 34
    nlp "The two &#8220;executable&#8221; processes collect credentials from the victim&#8217;s system."
  ]
  edge [
    source 19
    target 10
    action ""
    sequence 29
    nlp "It also modifies its ThreadContext &#10;    data (It calls the API, SetThreadContext) and makes its entry point to the transfered PE file."
  ]
  edge [
    source 19
    target 7
    action ""
    sequence 69
    nlp "The second PE file in &#8220;executable&#8221;collects profile and credential information of the email and IM &#10;    software client installed on a victim&#8217;s machine."
  ]
  edge [
    source 19
    target 20
    action ""
    sequence 90
    nlp "It first sends an HTTP request, &#10;    network, to ask for my machine&#8217;s public IP."
  ]
  edge [
    source 19
    target 15
    action ""
    sequence 67
    nlp "The second PE file in &#8220;executable&#8221;collects profile and credential information of the email and IM &#10;    software client installed on a victim&#8217;s machine."
  ]
  edge [
    source 19
    target 13
    action ""
    sequence 55
    nlp "In my analysis, this variant of &#10;    HawkEye focuses on the following browsers: Microsoft Internet Explorer, Google Chrome, Apple Safari, Opera, &#10;    Mozilla Sunbird, Mozilla Firefox, Mozilla Portable Thunderbird, Mozilla SeaMonkey, YandexBrowser, &#10;    Vivaldi browser, and more."
  ]
  edge [
    source 19
    target 14
    action ""
    sequence 42
    nlp "They first call a function to &#10;    collect credentials and save them in memory, and second, it reads the collected data, formats it, and saves it to &#10;    a tmp file from its command line parameter."
  ]
  edge [
    source 19
    target 17
    action ""
    sequence 82
    nlp "The second PE file in &#8220;executable&#8221; not only collects the client&#8217;s login &#10;    username and password, but also profile information, such as the recipent Server address, recipient Server Port, &#10;    protocol Type (POP3), SMTP Server, SMTP Port, etc."
  ]
  edge [
    source 20
    target 21
    action ""
    sequence 91
    nlp "It first sends an HTTP request, &#10;    network, to ask for my machine&#8217;s public IP."
  ]
  edge [
    source 21
    target 7
    action ""
    sequence 92
    nlp "If it did not reply with a public IP, it stops sending collected data to &#10;    the email box."
  ]
  edge [
    source 22
    target 7
    action ""
    sequence 94
    nlp "In addition, the IP appears in the email subject so it can identify victims."
  ]
  edge [
    source 23
    target 24
    action ""
    sequence 96
    nlp "The attacker&#8217;s email &#10;    is in Yandex.mail, whose email account and password are used when sending collected data through the Yandex SMTP &#10;    server."
  ]
  edge [
    source 24
    target 7
    action ""
    sequence 97
    nlp "The attacker&#8217;s email &#10;    is in Yandex.mail, whose email account and password are used when sending collected data through the Yandex SMTP &#10;    server."
  ]
]
