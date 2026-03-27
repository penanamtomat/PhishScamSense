from flask import Flask, request, jsonify
import pickle
from flask_cors import CORS
import pandas as pd
import numpy as np
from feature import extract_features

app = Flask(__name__)
CORS(app, origins=["chrome-extension://*"])

# you can change this to load the model you want to use (LR, SVM, or RF) based on folder name in pickle
with open("pickle/model_rf.pkl", "rb") as f:
    model = pickle.load(f)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data["url"]

    features = extract_features(url)
    
    # change this features to match the features used in the model training
    selected = {
        # model LR and SVM
        # 'url_length': features['url_length'],
        # 'has_ip_address': features['has_ip_address'],
        # 'dot_count': features['dot_count'],
        # 'https_flag': features['https_flag'],
        # 'token_count': features['token_count'],
        # 'subdomain_count': features['subdomain_count'],
        # 'query_param_count': features['query_param_count'],
        # 'path_length': features['path_length'],
        # 'tld_popularity': features['tld_popularity'],
        # 'suspicious_file_extension': features['suspicious_file_extension'],
        # 'domain_name_length': features['domain_name_length'],
        # 'percentage_numeric_chars': features['percentage_numeric_chars'],

        #model RF
        'token_count': features['token_count'],
        'path_length': features['path_length'],
    }

    X = pd.DataFrame([selected])
    prediction = model.predict(X)[0]

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0][1]
    else:
        score = model.decision_function(X)[0]
        proba = 1 / (1 + np.exp(-score))

    print("URL:", url)
    print("Prediction:", prediction)
    print("Confidence:", proba)

    return jsonify({
        "prediction": int(prediction),
        "confidence": float(proba)
    })

if __name__ == "__main__":
    app.run(port=5000)