graph [
  directed 1
  node [
    id 0
    label "spyware#file#181"
    type "file"
    nlp "spyware Global\TrickBotIt"
    regex ""
    contraction ""
  ]
  node [
    id 1
    label "system#system#5"
    type "system"
    nlp "system"
    regex ""
    contraction ""
  ]
  node [
    id 2
    label "data%\{malware#executable#55"
    type "executable"
    nlp "Data%\{malware"
    regex ""
    contraction ""
  ]
  node [
    id 3
    label "windows#network#75"
    type "network"
    nlp "Windows"
    regex ""
    contraction ""
  ]
  node [
    id 4
    label "task#system#76"
    type "system"
    nlp "Task"
    regex ""
    contraction ""
  ]
  node [
    id 5
    label "%#executable#155"
    type "executable"
    nlp "%"
    regex ""
    contraction ""
  ]
  node [
    id 6
    label "data%\modules\injectdll32_configs\dinj#executable#170"
    type "executable"
    nlp "Data%\Modules\injectDll32_configs\dinj"
    regex ""
    contraction ""
  ]
  node [
    id 7
    label "application#file#160"
    type "file"
    nlp "%Application"
    regex ""
    contraction ""
  ]
  node [
    id 8
    label "network#network#197"
    type "network"
    nlp "network"
    regex "rnalip.com"
    contraction ""
  ]
  edge [
    source 0
    target 1
    action ""
    sequence 0
    nlp "This spyware arrives on a system as a file dropped by other malware or as a file downloaded unknowingly by users when visiting malicious sites."
  ]
  edge [
    source 0
    target 3
    action ""
    sequence 13
    nlp "It uses the Windows Task Scheduler to add a scheduled task that executes the copies it drops."
  ]
  edge [
    source 0
    target 5
    action ""
    sequence 27
    nlp "It adds the following mutexes to ensure that only one of its copies runs at any one time: Global\TrickBotIt injects codes into the following process(es): This spyware saves the files it downloads using the following names: %Application Data%\Modules\injectDll32; %Application Data%\Modules\systeminfo32; %Application Data%\Modules\config.conf (updated config file); %Application Data%\Modules\injectDll32_configs\dinj; %Application Data%\Modules\injectDll32_configs\dpost; %Application Data%\Modules\injectDll32_configs\sinj."
  ]
  edge [
    source 0
    target 7
    action ""
    sequence 12
    nlp "This spyware drops the following copies of itself into the affected system and executes them: %Application Data%\{malware file name}.exe It drops the following files: %Application Data%\client_id, %Application Data%\group_tag."
  ]
  edge [
    source 0
    target 2
    action ""
    sequence 5
    nlp "It may be dropped by the following malware: TROJ_UPATRE.YYSTV."
  ]
  edge [
    source 0
    target 6
    action ""
    sequence 17
    nlp "It creates the following folders: %Application Data%\Modules\, %Application Data%\Modules\injectDll32_configs."
  ]
  edge [
    source 1
    target 0
    action ""
    sequence 8
    nlp "This spyware drops the following copies of itself into the affected system and executes them: %Application Data%\{malware file name}.exe It drops the following files: %Application Data%\client_id, %Application Data%\group_tag."
  ]
  edge [
    source 1
    target 7
    action ""
    sequence 1
    nlp "This spyware arrives on a system as a file dropped by other malware or as a file downloaded unknowingly by users when visiting malicious sites."
  ]
  edge [
    source 2
    target 0
    action ""
    sequence 11
    nlp "This spyware drops the following copies of itself into the affected system and executes them: %Application Data%\{malware file name}.exe It drops the following files: %Application Data%\client_id, %Application Data%\group_tag."
  ]
  edge [
    source 2
    target 7
    action ""
    sequence 3
    nlp "This spyware arrives on a system as a file dropped by other malware or as a file downloaded unknowingly by users when visiting malicious sites."
  ]
  edge [
    source 3
    target 4
    action ""
    sequence 14
    nlp "It uses the Windows Task Scheduler to add a scheduled task that executes the copies it drops."
  ]
  edge [
    source 4
    target 0
    action ""
    sequence 16
    nlp "It uses the Windows Task Scheduler to add a scheduled task that executes the copies it drops."
  ]
  edge [
    source 5
    target 6
    action ""
    sequence 28
    nlp "It adds the following mutexes to ensure that only one of its copies runs at any one time: Global\TrickBotIt injects codes into the following process(es): This spyware saves the files it downloads using the following names: %Application Data%\Modules\injectDll32; %Application Data%\Modules\systeminfo32; %Application Data%\Modules\config.conf (updated config file); %Application Data%\Modules\injectDll32_configs\dinj; %Application Data%\Modules\injectDll32_configs\dpost; %Application Data%\Modules\injectDll32_configs\sinj."
  ]
  edge [
    source 6
    target 0
    action ""
    sequence 26
    nlp "It adds the following mutexes to ensure that only one of its copies runs at any one time: Global\TrickBotIt injects codes into the following process(es): This spyware saves the files it downloads using the following names: %Application Data%\Modules\injectDll32; %Application Data%\Modules\systeminfo32; %Application Data%\Modules\config.conf (updated config file); %Application Data%\Modules\injectDll32_configs\dinj; %Application Data%\Modules\injectDll32_configs\dpost; %Application Data%\Modules\injectDll32_configs\sinj."
  ]
  edge [
    source 6
    target 7
    action ""
    sequence 18
    nlp "It creates the following folders: %Application Data%\Modules\, %Application Data%\Modules\injectDll32_configs."
  ]
  edge [
    source 7
    target 2
    action ""
    sequence 2
    nlp "This spyware arrives on a system as a file dropped by other malware or as a file downloaded unknowingly by users when visiting malicious sites."
  ]
  edge [
    source 7
    target 1
    action ""
    sequence 7
    nlp "This spyware drops the following copies of itself into the affected system and executes them: %Application Data%\{malware file name}.exe It drops the following files: %Application Data%\client_id, %Application Data%\group_tag."
  ]
  edge [
    source 7
    target 6
    action ""
    sequence 22
    nlp "It adds the following mutexes to ensure that only one of its copies runs at any one time: Global\TrickBotIt injects codes into the following process(es): This spyware saves the files it downloads using the following names: %Application Data%\Modules\injectDll32; %Application Data%\Modules\systeminfo32; %Application Data%\Modules\config.conf (updated config file); %Application Data%\Modules\injectDll32_configs\dinj; %Application Data%\Modules\injectDll32_configs\dpost; %Application Data%\Modules\injectDll32_configs\sinj."
  ]
  edge [
    source 8
    target 1
    action ""
    sequence 35
    nlp "This spyware connects to the following URL(s) to get the affected system's IP address: network"
  ]
]
