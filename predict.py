import joblib
from urllib.parse import urlparse
import numpy as np
import requests
import json
import requests
import urllib
from features_extraction import *

class IPQS:
    key = 'uwXBbaBc5jx0fctSc03ZGYXFUxWoxIGc'
    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        url = 'https://www.ipqualityscore.com/api/json/url/%s/%s' % (self.key, urllib.parse.quote_plus(url))
        x = requests.get(url, params = vars)
        return (json.loads(x.text))

if __name__ == "__main__":
    urls = "http://aijcs.blogspot.com/2005/03/colourful-life-of-aij.html"
    #Adjustable strictness level from 0 to 2. 0 is the least strict and recommended for most use cases. Higher strictness levels can increase false-positives.
    strictness = 0

    additional_params = {
        'strictness' : strictness
    }

    ipqs = IPQS()
    result = ipqs.malicious_url_scanner_api(urls, additional_params)

    if 'success' in result and result['success'] == True:
        print(result['phishing'])

# Load the trained model
model = joblib.load("model.pickle.dat")

# Function to predict whether the URL is phishing or legitimate
def predict(url):
    features = features_extract(url)[1:] #domain removed
    features_array = np.array(features).reshape(1,-1)
    prediction = model.predict(features_array)
    # print(prediction, features)
    return 'Phishing' if prediction == 1 else 'Legitimate'

# Example usage
result = predict(urls)
features = features_extract(urls)
print(f'The URL "{urls}" is {result}.')
print(features)

