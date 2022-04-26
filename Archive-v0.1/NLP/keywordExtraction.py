import Mitre_TTPs.mitreGraphReader

from keybert import KeyBERT
import re


def extract_keywords_from_example_list(example_list: list) -> list:
    keyword_list = []

    kw_model = KeyBERT()
    for example in example_list:
        example = re.sub("\[[0-9]+\]+", "", example)
        keywords = kw_model.extract_keywords(example, keyphrase_ngram_range=(1, 1))
        print(keywords)
        keyword_list += keywords

    return keyword_list

def keywords_statistics(keyword_list: list) -> dict:
    keywords_count_dict = {}

    for keyword in keyword_list:
        keyword_string = keyword[0]

        if keyword_string not in keywords_count_dict.keys():
            keywords_count_dict[keyword_string] = 1
        else:
            keywords_count_dict[keyword_string] += 1

    return keywords_count_dict


# %%

# example_file = "produce_examples_picked.txt"
# output_file = "produce_examples_picked_single_keywords.txt"
#
# with open(example_file, 'r') as example_input, open(output_file, 'w+') as output:
#     example_list = example_input.readlines()
#     keyword_list = extract_keywords_from_example_list(example_list)
#     output.write(keyword_list)


# %%
if __name__ == '__main__':

    mgr = Mitre_TTPs.mitreGraphReader.MitreGraphReader()
    super_sub_technique_dict = mgr.get_super_sub_technique_dict()

    super_technique_id = "/techniques/T1003"
    example_list = []
    for technique_id in super_sub_technique_dict[super_technique_id]:
        example_list += mgr.find_examples_for_technique(technique_id)

    keyword_list = extract_keywords_from_example_list(example_list)
    keyword_count_dict = keywords_statistics(keyword_list)
