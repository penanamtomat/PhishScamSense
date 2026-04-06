"""
Training pipeline for PhishScamSense hybrid model.
"""

import logging

import mlflow
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

from ml.src.features.url_features import extract_url_features
from ml.src.models.fusion_model import PhishScamSenseClassifier, PhishScamSenseFusionModel
from ml.src.models.nlp_branch import URLTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def prepare_dataset(urls: list[str], labels: list[int]) -> dict:
    """Prepare dataset with both NLP and numerical features."""
    tokenizer = URLTokenizer()
    tokens = tokenizer.tokenize(urls)

    numerical_features = []
    for url in urls:
        features = extract_url_features(url)
        numerical_features.append(list(features.values()))

    return {
        "input_ids": tokens["input_ids"],
        "attention_mask": tokens["attention_mask"],
        "numerical_features": torch.tensor(numerical_features, dtype=torch.float32),
        "labels": np.array(labels),
    }


def train_fusion_model(
    fusion_model: PhishScamSenseFusionModel,
    train_data: dict,
    epochs: int = 10,
    batch_size: int = 32,
    learning_rate: float = 1e-4,
    device: str = "cpu",
) -> PhishScamSenseFusionModel:
    """Pre-train the neural network branches with contrastive/supervised loss."""
    fusion_model = fusion_model.to(device)
    fusion_model.train()

    classifier_head = torch.nn.Linear(fusion_model.fusion_dim, 1).to(device)
    optimizer = torch.optim.Adam(
        list(fusion_model.parameters()) + list(classifier_head.parameters()),
        lr=learning_rate,
    )
    criterion = torch.nn.BCEWithLogitsLoss()

    dataset = TensorDataset(
        train_data["input_ids"],
        train_data["attention_mask"],
        train_data["numerical_features"],
        torch.tensor(train_data["labels"], dtype=torch.float32),
    )
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    for epoch in range(epochs):
        total_loss = 0
        for input_ids, attention_mask, num_feat, labels in dataloader:
            input_ids = input_ids.to(device)
            attention_mask = attention_mask.to(device)
            num_feat = num_feat.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            fused = fusion_model(input_ids, attention_mask, num_feat)
            logits = classifier_head(fused).squeeze(-1)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        avg_loss = total_loss / len(dataloader)
        logger.info(f"Epoch {epoch + 1}/{epochs} - Loss: {avg_loss:.4f}")
        mlflow.log_metric("train_loss", avg_loss, step=epoch)

    return fusion_model


def train_pipeline(
    urls: list[str],
    labels: list[int],
    experiment_name: str = "phishscamsense",
    epochs: int = 10,
):
    """Full training pipeline with MLflow tracking."""
    mlflow.set_experiment(experiment_name)

    with mlflow.start_run():
        logger.info("Preparing dataset...")
        data = prepare_dataset(urls, labels)

        logger.info("Training fusion model...")
        fusion_model = PhishScamSenseFusionModel()
        mlflow.log_params({
            "epochs": epochs,
            "model_type": "DistilBERT+BiLSTM+Attention+MLP+XGBoost",
            "num_samples": len(urls),
        })

        fusion_model = train_fusion_model(fusion_model, data, epochs=epochs)

        logger.info("Training XGBoost classifier...")
        classifier = PhishScamSenseClassifier(fusion_model)
        classifier.fit(
            data["input_ids"],
            data["attention_mask"],
            data["numerical_features"],
            data["labels"],
        )

        predictions = classifier.predict(
            data["input_ids"],
            data["attention_mask"],
            data["numerical_features"],
        )
        accuracy = np.mean((predictions > 0.5).astype(int) == data["labels"])
        mlflow.log_metric("train_accuracy", accuracy)
        logger.info(f"Training accuracy: {accuracy:.4f}")

        # Save models
        mlflow.pytorch.log_model(fusion_model, "fusion_model")
        mlflow.xgboost.log_model(classifier.xgb_classifier, "xgb_classifier")

        logger.info("Training pipeline complete")

    return classifier
