# AWS Connector Enforcement

Governed operations must require KRONYX tokens and must not execute with ambient instance profile credentials.
Use STS `AssumeRole` with session policy derived from token claims and action bounds.
