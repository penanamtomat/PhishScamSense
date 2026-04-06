"""
Multimodal Fusion Model: Combines NLP branch and Numerical branch outputs,
then feeds into XGBoost for final classification.

Supports 4-class classification: 0=benign, 1=phishing, 2=malware, 3=spam.
"""

import numpy as np
import torch
import torch.nn as nn
import xgboost as xgb

from ml.src.models.nlp_branch import NLPBranch
from ml.src.models.numerical_branch import MLPBranch

NUM_CLASSES = 4  # benign, phishing, malware, spam


class PhishScamSenseFusionModel(nn.Module):
    """
    Hierarchical fusion model that combines:
    1. NLP Branch (DistilBERT + BiLSTM + Attention) for URL text
    2. Numerical Branch (MLP) for engineered features

    Output: fused embedding of shape (batch, fusion_dim).
    """

    def __init__(
        self,
        num_features: int = 23,
        nlp_output_dim: int = 128,
        numerical_output_dim: int = 64,
        freeze_bert: bool = True,
    ):
        super().__init__()

        self.nlp_branch = NLPBranch(
            output_dim=nlp_output_dim,
            freeze_bert=freeze_bert,
        )
        self.numerical_branch = MLPBranch(
            input_dim=num_features,
            output_dim=numerical_output_dim,
        )

        self.fusion_dim = nlp_output_dim + numerical_output_dim

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        numerical_features: torch.Tensor,
    ) -> torch.Tensor:
        """Extract fused feature vector from both branches."""
        nlp_output = self.nlp_branch(input_ids, attention_mask)
        numerical_output = self.numerical_branch(numerical_features)

        fused = torch.cat([nlp_output, numerical_output], dim=1)
        return fused


class PhishScamSenseClassifier:
    """
    Complete PhishScamSense classifier:
    Neural network feature extractor + XGBoost final classifier (4-class).
    """

    def __init__(self, fusion_model: PhishScamSenseFusionModel):
        self.fusion_model = fusion_model
        self.xgb_classifier = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            objective="multi:softmax",
            num_class=NUM_CLASSES,
            eval_metric="mlogloss",
            n_jobs=-1,
        )

    def extract_features(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        numerical_features: torch.Tensor,
    ) -> np.ndarray:
        """Extract fused features using neural network."""
        self.fusion_model.eval()
        with torch.no_grad():
            fused = self.fusion_model(input_ids, attention_mask, numerical_features)
        return fused.cpu().numpy()

    def fit(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        numerical_features: torch.Tensor,
        labels: np.ndarray,
        eval_set: list | None = None,
    ):
        """Train XGBoost on fused features."""
        features = self.extract_features(input_ids, attention_mask, numerical_features)
        fit_kwargs = {"verbose": 50}
        if eval_set is not None:
            fit_kwargs["eval_set"] = eval_set
            fit_kwargs["early_stopping_rounds"] = 10
        self.xgb_classifier.fit(features, labels, **fit_kwargs)

    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        numerical_features: torch.Tensor,
    ) -> np.ndarray:
        """Predict class labels (int array)."""
        features = self.extract_features(input_ids, attention_mask, numerical_features)
        return self.xgb_classifier.predict(features)

    def predict_proba(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        numerical_features: torch.Tensor,
    ) -> np.ndarray:
        """Predict class probabilities, shape (n, 4)."""
        features = self.extract_features(input_ids, attention_mask, numerical_features)
        return self.xgb_classifier.predict_proba(features)
