S3Flow: Intelligent AWS S3 Lifecycle & Cost Management
🚀 Overview
S3Flow is a lightweight, self-hosted web application designed to help you effortlessly manage your AWS S3 storage, optimize costs, and enhance security. Built with Python Flask, it provides an intuitive dashboard to view S3 bucket information, set automated expiry rules based on object tags, detect publicly accessible buckets, and estimate your monthly S3 storage costs.

Move beyond manual cleanup and gain peace of mind with intelligent automation for your S3 data lifecycle.

✨ Features
Automated Lifecycle Rules (Tag-Based Expiry): Define and manage S3 lifecycle rules for your buckets based on object tags and prefixes, ensuring objects are automatically expired (deleted) after a specified number of days. This is crucial for data hygiene and cost optimization.

Public Bucket Alerts: Proactively identify any publicly accessible S3 buckets configured with your AWS credentials, mitigating critical security risks.

S3 Storage Cost Estimation: Get an approximate monthly cost for your total S3 Standard storage, helping you understand and optimize your cloud spending.

Centralized S3 Object Management: Easily list and navigate through your S3 buckets and their contained objects.

Direct Object Actions: Download or set individual object expiry dates directly from the web interface.

Secure Credential Storage: Your sensitive AWS Secret Access Keys are encrypted at rest using Fernet symmetric encryption.

Action Logging: Track all key activities performed within the S3Flow application.

Responsive UI: A clean, modern, and responsive user interface built with Tailwind CSS, ensuring usability across devices.

🛠️ Technologies Used
Backend: Python 3.9+ (Flask)

Database: SQLite (for development, easily swappable for production)

AWS Interaction: Boto3 (AWS SDK for Python)

Encryption: Cryptography (Fernet for AES encryption)

Frontend: HTML, CSS (Tailwind CSS), JavaScript

Deployment: Designed for easy deployment on platforms like Render, EC2, etc.

🚀 Getting Started
Follow these steps to get S3Flow up and running on your local machine.

Prerequisites
Python 3.9+ installed

pip (Python package installer)

An AWS Account with an IAM User/Role having the necessary S3 permissions (details below).

Installation
Clone the repository:

git clone https://github.com/kopamak990/s3-expiry-manager
cd s3-expiry-manager

Create and activate a virtual environment:

python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Configuration
S3Flow requires two crucial environment variables for security: FLASK_SECRET_KEY and FERNET_KEY.

FLASK_SECRET_KEY: Used by Flask for secure sessions.

Generate a strong, random key: You can generate one in a Python console:

import os
print(os.urandom(24).hex())

Set it as an environment variable.

On Linux/macOS: export FLASK_SECRET_KEY='your_generated_key'

On Windows (Command Prompt): set FLASK_SECRET_KEY=your_generated_key

On Windows (PowerShell): $env:FLASK_SECRET_KEY='your_generated_key'

For production: Use your hosting provider's method for securely setting environment variables.

FERNET_KEY: Used for encrypting your AWS Secret Access Key before storing it in the database.

Generate a Fernet key: This must be a 32-URL-safe-base64-encoded-byte key. Generate it once:

from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode()) # This is your FERNET_KEY

Set it as an environment variable (similar to FLASK_SECRET_KEY):

export FERNET_KEY='your_generated_fernet_key'

For production: Use your hosting provider's method for securely setting environment variables. Do NOT lose this key; data encrypted with it will be irrecoverable.

Running the Application
Ensure your virtual environment is active (as shown in installation steps).

Run the Flask application:

flask run

This will typically start the server on http://127.0.0.1:5000/.

🧑‍💻 Usage
Register/Login: Navigate to the application URL. If you're a new user, register for an account.

Set AWS Credentials: On the Dashboard, enter your AWS Access Key ID and Secret Access Key. These are securely encrypted before being stored.

Explore Dashboard: View your total S3 storage, estimated costs, and any alerts for publicly accessible buckets.

Manage Buckets & Objects: Go to the "Buckets" section to browse your S3 buckets, view their contents, download objects, or set individual object expiry dates.

Automate Lifecycle Rules: Visit "Lifecycle Rules" to create new tag-based expiry rules for your buckets. This is where the real automation happens!

View Action Logs: Keep track of all S3Flow activities under "Action Logs."

🔒 AWS IAM Permissions
For S3Flow to function correctly and securely, the AWS IAM User/Role associated with the credentials you provide must have the following minimum permissions:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketLifecycleConfiguration",
                "s3:PutBucketLifecycleConfiguration",
                "s3:DeleteBucketLifecycleConfiguration",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::*",
                "arn:aws:s3:::*/*"
            ]
        }
    ]
}

Explanation of Permissions:

s3:ListAllMyBuckets: Required to list all buckets in your AWS account.

s3:ListBucket: Required to list objects within a specific bucket (for storage calculation and object listing).

s3:GetBucketAcl: Required to check if a bucket's Access Control List allows public access.

s3:GetBucketPolicy: Required to check if a bucket's policy allows public access.

s3:GetBucketLifecycleConfiguration: Required to read existing lifecycle rules for a bucket.

s3:PutBucketLifecycleConfiguration: Required to create or update lifecycle rules.

s3:DeleteBucketLifecycleConfiguration: Required to remove lifecycle configurations.

s3:GetObject: Required to generate presigned URLs for object downloads.

s3:DeleteObject: Required to delete individual objects.

Security Best Practice: Always adhere to the principle of least privilege. Grant only the permissions necessary for S3Flow to perform its intended functions.

🗄️ Database
S3Flow uses SQLite for user management and action logging by default, which is perfect for local development and light use.

For a production environment, especially with multiple users or high traffic, it's highly recommended to switch to a more robust database solution like PostgreSQL, MySQL, or Amazon RDS. Flask-SQLAlchemy makes this transition relatively straightforward by changing the SQLALCHEMY_DATABASE_URI configuration.

🛡️ Security Considerations
FLASK_SECRET_KEY: Keep this key absolutely secret and unique. It's vital for session security.

FERNET_KEY: This key encrypts your AWS Secret Access Key. Treat it with the highest level of security. Losing this key means you lose access to decrypt your stored AWS credentials.

AWS Credentials: S3Flow never stores your raw AWS Secret Access Key in plaintext. It's encrypted using the FERNET_KEY before being saved to the database.

Limited AWS Permissions: Provide S3Flow with only the minimum necessary IAM permissions (as detailed above) to reduce your attack surface.

🗺️ Roadmap (Future Enhancements)
Advanced Reporting: Detailed breakdowns of storage by region, storage class, and cost trends.

Notification System: Email or dashboard notifications for public bucket detections, upcoming expiries, etc.

Multi-Account Support: Manage S3 resources across multiple AWS accounts.

Additional Lifecycle Actions: Support for transitioning objects to different storage classes (e.g., Glacier, Infrequent Access).

User Management UI: Dedicated admin interface for managing S3Flow users.

🤝 Contributing
Contributions are welcome! If you have suggestions, bug reports, or want to contribute code, please feel free to:

Fork the repository.

Create a new branch (git checkout -b feature/YourFeatureName).

Make your changes.

Commit your changes (git commit -m 'feat: Add new feature').

Push to the branch (git push origin feature/YourFeatureName).

Open a Pull Request.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

📞 Contact
For questions or support, please open an issue in the GitHub repository.

S3Flow - Your proactive partner in cloud storage optimization.
