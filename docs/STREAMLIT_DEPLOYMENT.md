# Streamlit interface and deployment

TriageBloom includes a browser interface in `streamlit_app.py` while keeping the core CLI dependency-free.

## Privacy boundary

The CLI remains the preferred mode for confidential investigations because processing stays on the analyst's computer.

A public Streamlit deployment is **not** a confidential-log processing service. Use the hosted interface only with synthetic, redacted, or explicitly authorised non-confidential data. Never upload employer, client, production, regulated, or sensitive telemetry to a public deployment.

## Run locally

```bash
python -m venv .venv
```

Activate the environment, then install the UI extra:

```bash
python -m pip install -e ".[ui]"
streamlit run streamlit_app.py
```

Open the local URL displayed by Streamlit.

## Streamlit Community Cloud

Use:

- Repository: `Briella009/Triagebloom`
- Branch: `main`
- Entrypoint: `streamlit_app.py`

The repository includes `requirements.txt` and `.streamlit/config.toml`, so Community Cloud can install and configure the app directly.

After deployment, add the live URL to the README and repository About section.

## Container deployment

A `Dockerfile` is included for environments that support containers:

```bash
docker build -t triagebloom .
docker run --rm -p 8501:8501 triagebloom
```

Then open `http://localhost:8501`.
