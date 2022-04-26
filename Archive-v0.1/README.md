# AttacKG: Practical CTI Report Parsing & Threat Intelligence KG Building
Building a Knowledge Graph for cyber attack with information extracted from Cyber Threat Intelligence reports.

![overview](Paper/Image/Framework_00.png)

## S0: Crawler Mitre Cross-reference
`Mitre_TTPs/mitre_attack_retrieve.ipynb`

## S1: NLP- Structure CTI Extraction

![overview](Paper/Image/nlp_overview.png)

### S1-1 Regex-based IoC extraction 
`NLP/iocRegex.py`

### S1-2 Embedding-basd NER
`NLP/iocNer.py`


# Requirement

## spacy

Install pre-trained model.
> python -m spacy download en_core_web_sm

## [coreferee](https://github.com/msg-systems/coreferee)

Need to be installed from source.
> pip install -e $[DOWNLOAD_PATH]

## [tensorflow](https://tensorflow.juejin.im/install/install_windows.html)

## Doccano
`Ubuntu`
> export PATH=/home/zhenyuan/.local/bin:$PATH
> doccano webserver --port 8000
> workshop doccano task