"""
Numerical Branch: MLP and CapsNet for processing engineered URL features.
Handles tabular/structural features extracted from URLs.
"""

import torch
import torch.nn as nn


class MLPBranch(nn.Module):
    """
    Multi-Layer Perceptron for processing numerical URL features.
    """

    def __init__(
        self,
        input_dim: int = 24,
        hidden_dims: list[int] | None = None,
        output_dim: int = 64,
        dropout: float = 0.3,
    ):
        super().__init__()

        if hidden_dims is None:
            hidden_dims = [128, 64]

        layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = hidden_dim

        layers.append(nn.Linear(prev_dim, output_dim))
        self.network = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class PrimaryCapsule(nn.Module):
    """Primary capsule layer for CapsNet."""

    def __init__(self, in_channels: int, out_channels: int, capsule_dim: int):
        super().__init__()
        self.capsule_dim = capsule_dim
        self.conv = nn.Linear(in_channels, out_channels * capsule_dim)
        self.out_channels = out_channels

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        output = self.conv(x)
        return output.view(-1, self.out_channels, self.capsule_dim)


def squash(tensor: torch.Tensor, dim: int = -1) -> torch.Tensor:
    """Squash activation function for capsule networks."""
    squared_norm = (tensor**2).sum(dim=dim, keepdim=True)
    scale = squared_norm / (1 + squared_norm)
    return scale * tensor / (torch.sqrt(squared_norm) + 1e-8)


class CapsNetBranch(nn.Module):
    """
    Capsule Neural Network for preserving hierarchical structural information
    from engineered URL features.
    """

    def __init__(
        self,
        input_dim: int = 24,
        primary_caps: int = 8,
        capsule_dim: int = 8,
        output_dim: int = 64,
    ):
        super().__init__()

        self.fc1 = nn.Linear(input_dim, 128)
        self.bn1 = nn.BatchNorm1d(128)
        self.primary_capsules = PrimaryCapsule(128, primary_caps, capsule_dim)
        self.fc_out = nn.Linear(primary_caps * capsule_dim, output_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = torch.relu(self.bn1(self.fc1(x)))
        capsules = self.primary_capsules(x)
        capsules = squash(capsules)
        flattened = capsules.view(capsules.size(0), -1)
        return self.fc_out(flattened)
