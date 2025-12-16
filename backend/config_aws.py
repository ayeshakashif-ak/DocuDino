"""
AWS-specific configuration for DocuDino backend.
This extends the base config with AWS service integrations.
"""
import os
from config import Config, DevelopmentConfig, ProductionConfig
from urllib.parse import urlparse


class AWSProductionConfig(ProductionConfig):
    """Production configuration optimized for AWS deployment."""
    
    # Database - RDS PostgreSQL
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        os.environ.get("RDS_DATABASE_URL")
    )
    
    # Redis/ElastiCache for session storage
    REDIS_URL = os.environ.get("REDIS_URL")
    SESSION_TYPE = "redis" if os.environ.get("REDIS_URL") else "filesystem"
    
    # S3 Configuration
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "docudino-documents")
    S3_DOCUMENTS_PREFIX = os.environ.get("S3_DOCUMENTS_PREFIX", "documents/")
    
    # CloudWatch Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_GROUP_NAME = os.environ.get("LOG_GROUP_NAME", "/ecs/docudino-backend")
    
    # CORS - Allow CloudFront and ALB
    CORS_ORIGINS = os.environ.get(
        "CORS_ORIGINS",
        "https://*.cloudfront.net,https://*.amazonaws.com"
    ).split(",")
    
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Performance
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "connect_args": {
            "connect_timeout": 10,
            "sslmode": "require"
        }
    }
    
    # JWT Settings
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", 604800))


def get_aws_config():
    """Get AWS configuration based on environment."""
    env = os.environ.get("FLASK_ENV", "production")
    
    if env == "production":
        return AWSProductionConfig
    else:
        return DevelopmentConfig

