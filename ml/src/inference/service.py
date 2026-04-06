"""
BentoML inference service for PhishScamSense model.
Serves the hybrid model with adaptive micro-batching.
"""

import bentoml
import numpy as np
import torch
from bentoml.io import JSON

from ml.src.features.url_features import extract_url_features
from ml.src.models.nlp_branch import URLTokenizer

# Load models from MLflow or local artifacts
fusion_model_runner = bentoml.pytorch.get("phishscamsense_fusion:latest").to_runner()
xgb_runner = bentoml.xgboost.get("phishscamsense_xgb:latest").to_runner()

svc = bentoml.Service("phishscamsense", runners=[fusion_model_runner, xgb_runner])

tokenizer = URLTokenizer()


@svc.api(
    input=JSON(),
    output=JSON(),
    route="/predict",
)
async def predict(input_data: dict) -> dict:
    """Predict if a URL is phishing."""
    url = input_data["url"]

    # Tokenize URL for NLP branch
    tokens = tokenizer.tokenize([url])
    input_ids = tokens["input_ids"]
    attention_mask = tokens["attention_mask"]

    # Extract numerical features
    features = extract_url_features(url)
    numerical = torch.tensor([list(features.values())], dtype=torch.float32)

    # Get fused features from neural network
    fused = await fusion_model_runner.async_run(input_ids, attention_mask, numerical)

    # XGBoost prediction
    if isinstance(fused, torch.Tensor):
        fused = fused.numpy()
    proba = await xgb_runner.predict_proba.async_run(fused)
    confidence = float(proba[0][1])

    return {
        "phishing": confidence > 0.5,
        "confidence": confidence,
        "features": features,
    }


@svc.api(input=JSON(), output=JSON(), route="/health")
async def health(_: dict) -> dict:
    return {"status": "healthy"}
