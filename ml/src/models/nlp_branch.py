"""
NLP Branch: DistilBERT + BiLSTM + Attention for URL semantic analysis.
Extracts contextual embeddings from URL text.
"""

import torch
import torch.nn as nn
from transformers import DistilBertModel, DistilBertTokenizer


class AttentionLayer(nn.Module):
    """Attention mechanism to weight important tokens in URL."""

    def __init__(self, hidden_size: int):
        super().__init__()
        self.attention = nn.Linear(hidden_size, 1)

    def forward(self, lstm_output: torch.Tensor) -> torch.Tensor:
        weights = torch.softmax(self.attention(lstm_output), dim=1)
        return torch.sum(weights * lstm_output, dim=1)


class NLPBranch(nn.Module):
    """
    DistilBERT -> BiLSTM -> Attention -> FC
    Processes URL string to extract semantic features.
    """

    def __init__(
        self,
        output_dim: int = 128,
        lstm_hidden: int = 256,
        lstm_layers: int = 2,
        dropout: float = 0.3,
        freeze_bert: bool = True,
    ):
        super().__init__()

        self.distilbert = DistilBertModel.from_pretrained("distilbert-base-uncased")
        if freeze_bert:
            for param in self.distilbert.parameters():
                param.requires_grad = False

        bert_hidden = self.distilbert.config.hidden_size  # 768

        self.bilstm = nn.LSTM(
            input_size=bert_hidden,
            hidden_size=lstm_hidden,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0,
        )

        self.attention = AttentionLayer(lstm_hidden * 2)
        self.fc = nn.Linear(lstm_hidden * 2, output_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        bert_output = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        sequence_output = bert_output.last_hidden_state

        lstm_output, _ = self.bilstm(sequence_output)
        attended = self.attention(lstm_output)
        output = self.fc(self.dropout(attended))

        return output


class URLTokenizer:
    """Tokenizes URLs for DistilBERT input."""

    def __init__(self, max_length: int = 128):
        self.tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
        self.max_length = max_length

    def tokenize(self, urls: list[str]) -> dict:
        return self.tokenizer(
            urls,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
