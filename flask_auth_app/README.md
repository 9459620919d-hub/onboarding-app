# Flask Onboarding Application

A complete onboarding application built with Python Flask:
- Client & Server-side input validations
- Welcome email sent via Gmail SMTP SSL (`smtplib`)
- Persistent 30-day session cookies surviving browser restarts
- Minimal homepage with hero banner and sign-out functionality

## Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Add your Gmail address and 16-character Google App Password.

3. **Run the App**:
   ```bash
   python app.py
   ```
   Open `http://localhost:5000` in your browser.
