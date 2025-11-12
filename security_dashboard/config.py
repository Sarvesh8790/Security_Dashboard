"""Configuration helpers for the security dashboard application."""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional


@dataclass
class AWSConfig:
    """Configuration options required to connect to AWS Security Hub."""

    region_name: str = "us-east-1"
    profile_name: Optional[str] = None

    @classmethod
    def from_env(cls) -> "AWSConfig":
        """Build the configuration from environment variables."""
        return cls(
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            profile_name=os.getenv("AWS_PROFILE"),
        )


@dataclass
class GitHubConfig:
    """Configuration options required to connect to the GitHub API."""

    token: str
    api_url: str = "https://api.github.com"
    owner: Optional[str] = None
    repo: Optional[str] = None

    @classmethod
    def from_env(cls) -> "GitHubConfig":
        """Build the configuration from environment variables."""
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ValueError(
                "GITHUB_TOKEN environment variable must be set to query GHAS alerts."
            )
        return cls(
            token=token,
            api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
            owner=os.getenv("GITHUB_OWNER"),
            repo=os.getenv("GITHUB_REPO"),
        )


@dataclass
class DashboardConfig:
    """Top level configuration container for the dashboard."""

    aws: AWSConfig
    github: Optional[GitHubConfig] = None

    @classmethod
    def from_env(cls, *, require_github: bool = False) -> "DashboardConfig":
        aws_config = AWSConfig.from_env()
        github_config: Optional[GitHubConfig] = None
        if require_github or os.getenv("GITHUB_TOKEN"):
            github_config = GitHubConfig.from_env()
        return cls(aws=aws_config, github=github_config)
