import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from nltk import tokenize
"""
PREREQUISITES:
download the following NLTK Packages using the following
nltk.download('subjectivity')
nltk.download('vader_lexicon')
"""
def analyse_sentence(text):
        
    #Initialising sentiment analyser to determine sentiment of each sentence
    sid = SentimentIntensityAnalyzer()
    results = []
    pos = []
    neg = ""
    #Iterating over each sentence of given text
    for sentence in text:
        ss = sid.polarity_scores(sentence)
        results.append(sentence)
        for k in sorted(ss):
            results.append('{0}: {1}'.format(k, ss[k]))
    #Dividing analysis list into chunks of 5 to encompass all results
    results = [results[i:i + 5] for i in range(0, len(results), 5)]
    return results
